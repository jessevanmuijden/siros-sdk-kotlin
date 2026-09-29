// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.siros.sdk.credentials.mdoc.DocumentMdoc
import org.siros.sdk.credentials.mdoc.MdocCbor
import timber.log.Timber
import java.security.MessageDigest
import java.util.Base64

/**
 * Utilities for working with verifiable credentials and VCTM metadata.
 *
 * Provides helpers for:
 * - Parsing JWT/SD-JWT payloads
 * - Extracting claims with VCTM display labels
 * - Building [CredentialMetadata] from issuer metadata and VCTM
 * - Formatting claim keys for display
 */
object CredentialUtils {

    private val json = Json { ignoreUnknownKeys = true }

    private val JWT_SKIP_KEYS = setOf(
        "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
        "_sd", "_sd_alg", "cnf", "vct", "status", "type",
    )

    /**
     * Parse the JWT payload from a raw credential string (JWT or SD-JWT).
     *
     * @return the payload as a [JsonObject], or null if parsing fails.
     */
    fun parseJwtPayload(raw: String): JsonObject? {
        return try {
            val jwtPart = raw.split("~").first()
            val parts = jwtPart.split(".")
            if (parts.size < 2) return null
            val payload = String(
                Base64.getUrlDecoder().decode(padBase64(parts[1])),
                Charsets.UTF_8,
            )
            json.parseToJsonElement(payload).jsonObject
        } catch (e: Exception) {
            Timber.w(e, "Failed to parse JWT payload")
            null
        }
    }

    /**
     * Split a raw SD-JWT VC (`<jwt>~<disclosure>~<disclosure>~...`) into its
     * individually-decoded parts, for display purposes (e.g. a "Raw" debug
     * tab) - each disclosure is a separate JSON array per the SD-JWT spec, not
     * part of one opaque blob.
     */
    fun parseSdJwtParts(raw: String): SdJwtParts {
        val segments = raw.split("~")
        val jwtSegments = segments.firstOrNull()?.split(".") ?: emptyList()
        val header = jwtSegments.getOrNull(0)?.let { decodeJsonSegment(it) } as? JsonObject
        val payload = jwtSegments.getOrNull(1)?.let { decodeJsonSegment(it) } as? JsonObject
        val disclosures = segments.drop(1)
            .filter { it.isNotBlank() }
            .mapNotNull { decodeJsonSegment(it) }
        return SdJwtParts(header = header, payload = payload, disclosures = disclosures)
    }

    private fun decodeJsonSegment(base64url: String): JsonElement? {
        return try {
            val decoded = String(Base64.getUrlDecoder().decode(padBase64(base64url)), Charsets.UTF_8)
            json.parseToJsonElement(decoded)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Extract user-facing claims from a credential, optionally using VCTM
     * (or, for `mso_mdoc` credentials, MDDL) claim metadata for display labels.
     *
     * @param credential the stored credential
     * @return list of [DisplayClaim] with label, value, and optional description
     */
    fun extractClaims(credential: StoredCredential): List<DisplayClaim> {
        if (credential.format == "mso_mdoc") return extractMdocClaims(credential)
        val rawPayload = parseJwtPayload(credential.raw) ?: return emptyList()
        // The JWT payload alone only ever carries whatever the issuer chose
        // NOT to selectively disclose (typically just iss/vct/exp/_sd/cnf) -
        // every real user-facing claim in a properly-issued SD-JWT VC (the
        // entire point of "selective disclosure") lives in the `~`-separated
        // disclosure segments instead, keyed into the payload only by SHA-256
        // digest under `_sd`. Without merging those back in, VCTM path
        // resolution below silently finds nothing for any disclosed claim -
        // confirmed via live testing: an mdoc (whose claims live directly in
        // CBOR namespaces, no disclosure indirection) rendered fine while an
        // SD-JWT PID showed claim labels with no values at all.
        val payload = mergeSdJwtDisclosures(credential.raw, rawPayload)
        val vctmClaims = credential.metadata?.claims.orEmpty()

        // VCTM claim paths can be arbitrarily nested (e.g. diploma's ELM schema
        // nests everything under credentialSubject) - each claim must be
        // resolved by walking its own full path, not just matched by its first
        // segment against a top-level key.
        val vctmResolved = vctmClaims.mapNotNull { claim ->
            if (claim.path.isEmpty()) return@mapNotNull null
            val value = resolveClaimPath(payload, claim.path) ?: return@mapNotNull null
            DisplayClaim(
                key = claim.path.joinToString("."),
                label = claim.label ?: formatClaimKey(claim.path.last()),
                value = formatClaimValue(value),
                description = claim.description,
                mandatory = claim.mandatory,
                svgId = claim.svgId,
            )
        }

        // Top-level keys already resolved (as an ancestor) via a VCTM path
        // shouldn't ALSO be dumped raw - e.g. once "credentialSubject.foo" is
        // resolved, don't separately dump the whole "credentialSubject" blob.
        val coveredTopLevelKeys = vctmClaims.mapNotNull { it.path.firstOrNull() }.toSet()
        val uncovered = payload.entries
            .filter { it.key !in JWT_SKIP_KEYS && it.key !in coveredTopLevelKeys }
            .map { (key, value) ->
                DisplayClaim(
                    key = key,
                    label = formatClaimKey(key),
                    value = formatClaimValue(value),
                )
            }

        return vctmResolved + uncovered
    }

    /**
     * Recursively flattens every claim path in a JSON-based credential's
     * merged SD-JWT/JWT payload, regardless of VCTM coverage.
     *
     * [extractClaims] is a *display* function: a claim only gets its own
     * entry there if VCTM explicitly labels it (by path, however deeply
     * nested), or - for everything VCTM doesn't cover - as a single,
     * un-recursed dump of the WHOLE top-level value, so a nested object
     * like `registered_address` becomes one opaque claim, never one claim
     * per field inside it. DCQL matching (OID4VP 1.0 §6.4.1) needs the
     * opposite: every path a verifier might request, including a nested
     * claim (e.g. `registered_address.full_address`) whose VCTM happens not
     * to declare that specific sub-path even though the credential itself
     * genuinely has it - confirmed via a real user report: a verifier
     * asking for exactly that path against a real `eucc` credential got
     * "you do not have any credentials that match this request" because
     * the deep path was never exposed for matching at all, VCTM coverage
     * or not.
     *
     * Returns every (path, value) pair reachable by walking nested JSON
     * objects - both each intermediate node (so a verifier asking for the
     * whole parent object, e.g. just `["registered_address"]`, still
     * matches) and every leaf beneath it. Real path arrays throughout,
     * never a joined-then-resplit string - see [SharedDcqlMatcher]'s own
     * doc comment on why that mattered too.
     *
     * `mso_mdoc` credentials have their own flat namespace/element shape
     * (see [extractMdocClaims]) and are not walked here - returns empty for
     * them.
     */
    fun flattenClaimPaths(credential: StoredCredential): List<Pair<List<String>, JsonElement>> {
        if (credential.format.equals("mso_mdoc", ignoreCase = true)) return emptyList()
        val rawPayload = parseJwtPayload(credential.raw) ?: return emptyList()
        val payload = mergeSdJwtDisclosures(credential.raw, rawPayload)
        return flattenJsonObject(payload, emptyList())
    }

    private fun flattenJsonObject(obj: JsonObject, prefix: List<String>): List<Pair<List<String>, JsonElement>> {
        val result = mutableListOf<Pair<List<String>, JsonElement>>()
        for ((key, value) in obj) {
            if (prefix.isEmpty() && key in JWT_SKIP_KEYS) continue
            val path = prefix + key
            result += path to value
            if (value is JsonObject) {
                result += flattenJsonObject(value, path)
            }
        }
        return result
    }

    /**
     * mdoc analogue of [extractClaims]: parse a stored mdoc credential's
     * REAL disclosed namespace/element values (via [MdocCbor], not
     * [parseJwtPayload] which assumes a JWT-shaped `raw`) into [DisplayClaim]s,
     * using MDDL claim metadata (`credential.metadata.claims`, populated by
     * [buildMdocMetadata]) for labels/descriptions when available.
     *
     * Claim keys/paths use the `["namespace", "elementIdentifier"]` shape,
     * consistent with how [buildMdocMetadata] populates [ClaimMeta.path].
     */
    fun extractMdocClaims(credential: StoredCredential): List<DisplayClaim> {
        val document = parseMdocDocument(credential) ?: return emptyList()

        val claimMetaByPath = credential.metadata?.claims.orEmpty()
            .associateBy { it.path.joinToString("/") }

        return document.issuerSigned.nameSpaces.flatMap { (namespace, items) ->
            items.map { entry ->
                val elementId = entry.item.elementIdentifier
                val meta = claimMetaByPath["$namespace/$elementId"]
                DisplayClaim(
                    key = "$namespace.$elementId",
                    label = meta?.label ?: formatClaimKey(elementId),
                    value = formatCborValue(entry.item.elementValue),
                    description = meta?.description,
                    mandatory = meta?.mandatory ?: false,
                    svgId = meta?.svgId,
                )
            }
        }
    }

    /**
     * Parse a stored mdoc credential's raw bytes into its [DocumentMdoc] - the
     * credential's own authoritative content (namespaces/items, and the real
     * `docType` embedded in its MSO), independent of [CredentialMetadata]
     * (which is best-effort display data from a network fetch that can fail,
     * e.g. for an mdoc issued by a third party with no MDDL schema endpoint at
     * all). DC API registry entries need the real docType for DCQL matching
     * even when display metadata never arrived - see the sample app's
     * DCAPICredentialEntryBuilder.
     */
    fun parseMdocDocument(credential: StoredCredential): DocumentMdoc? {
        return try {
            MdocCbor.parseStoredCredential(Base64.getUrlDecoder().decode(padBase64(credential.raw)))
        } catch (e: Exception) {
            Timber.w(e, "Failed to parse mdoc credential ${credential.id}")
            null
        }
    }

    /** Decode [StoredCredential.raw]'s base64url encoding, without the CBOR parsing [parseMdocDocument] also does - for callers (e.g. proximity presentation) that need the raw bytes to pass to a `KeystoreManager` signing method. */
    fun decodeMdocRawBytes(credential: StoredCredential): ByteArray =
        Base64.getUrlDecoder().decode(padBase64(credential.raw))

    /**
     * Build [CredentialMetadata] for an mdoc credential from its MDDL schema -
     * the mdoc analogue of [buildMetadata]. Populates [CredentialMetadata.doctype]
     * (unused for SD-JWT credentials) instead of [CredentialMetadata.vct].
     */
    fun buildMdocMetadata(offer: CredentialOffer, mddlSchema: MddlSchema? = null): CredentialMetadata {
        val locale = java.util.Locale.getDefault().toLanguageTag()
        val display = mddlSchema?.display?.let { displays ->
            displays.find { it.locale == locale }
                ?: displays.find { it.locale.startsWith(locale.take(2)) }
                ?: displays.firstOrNull()
        }

        val claims = mddlSchema?.claims?.flatMap { (namespace, elements) ->
            elements.map { (elementId, meta) ->
                val claimDisplay = meta.display?.let { displays ->
                    displays.find { it.locale == locale }
                        ?: displays.find { it.locale.startsWith(locale.take(2)) }
                        ?: displays.firstOrNull()
                }
                ClaimMeta(
                    path = listOf(namespace, elementId),
                    label = claimDisplay?.name,
                    mandatory = meta.mandatory,
                    svgId = meta.svgId,
                )
            }
        }

        val svgTemplates = display?.rendering?.svgTemplates?.map { template ->
            SvgTemplateInfo(
                uri = template.uri,
                colorScheme = template.properties?.colorScheme,
                contrast = template.properties?.contrast,
                orientation = template.properties?.orientation,
            )
        }

        return CredentialMetadata(
            name = display?.name ?: offer.credentialName,
            description = display?.description ?: offer.credentialDescription,
            issuer = IssuerInfo(name = offer.issuerName, url = offer.credentialIssuerIdentifier),
            doctype = mddlSchema?.doctype,
            backgroundColor = display?.backgroundColor ?: offer.backgroundColor,
            textColor = display?.textColor ?: offer.textColor,
            logo = display?.logo?.let { LogoInfo(uri = it.uri, altText = it.altText) }
                ?: offer.logoUri?.let { LogoInfo(uri = it) },
            claims = claims,
            svgTemplates = svgTemplates,
        )
    }

    /**
     * Format a decoded CBOR element value for display. A byte string that
     * sniffs as a JPEG or PNG (e.g. an ISO 18013-5/23220 `portrait`) is
     * turned into a `data:image/...;base64,...` URI so it can be embedded
     * directly in an SVG rendering card - see [SvgTemplateRenderer]. Any
     * other byte string (including JPEG 2000 - see this SDK's issue #229
     * "Decision: JPEG 2000": no image-decoding dependency is added here,
     * issuers targeting SVG cards are expected to transcode JP2 themselves)
     * keeps today's plain `"<N bytes>"` placeholder.
     */
    private fun formatCborValue(value: com.upokecenter.cbor.CBORObject): String {
        return when (value.type) {
            com.upokecenter.cbor.CBORType.TextString -> value.AsString()
            com.upokecenter.cbor.CBORType.ByteString -> {
                val bytes = value.GetByteString()
                imageDataUri(bytes) ?: "<${bytes.size} bytes>"
            }
            else -> value.toString()
        }
    }

    /**
     * Sniffs [bytes] for a JPEG or PNG magic number and, if found, returns a
     * `data:image/...;base64,...` URI. Returns null for anything else
     * (including JPEG 2000, deliberately not decoded - see [formatCborValue]),
     * so callers fall back to their own non-image placeholder.
     */
    private fun imageDataUri(bytes: ByteArray): String? {
        val mimeType = when {
            bytes.size >= 3 &&
                bytes[0] == 0xFF.toByte() && bytes[1] == 0xD8.toByte() && bytes[2] == 0xFF.toByte() -> "image/jpeg"
            bytes.size >= 4 &&
                bytes[0] == 0x89.toByte() && bytes[1] == 0x50.toByte() &&
                bytes[2] == 0x4E.toByte() && bytes[3] == 0x47.toByte() -> "image/png"
            else -> return null
        }
        // Defensive copy: some CBOR decoders (notably in other language
        // runtimes this behavior was ported from) can hand back a view into
        // a larger shared buffer rather than a standalone array.
        val base64 = Base64.getEncoder().encodeToString(bytes.copyOf())
        return "data:$mimeType;base64,$base64"
    }

    /**
     * Walk a VCTM claim path (e.g. ["credentialSubject", "hasClaim", "awardedBy"])
     * through nested JSON to the leaf value it selects. Returns null if any
     * segment is missing - the claim just isn't present in this credential.
     */
    private fun resolveClaimPath(root: JsonElement, path: List<String>): JsonElement? {
        var current: JsonElement = root
        for (segment in path) {
            current = (current as? JsonObject)?.get(segment) ?: return null
        }
        return current
    }

    /**
     * Splices an SD-JWT VC's `~`-separated disclosures back into its JWT
     * [payload], so [resolveClaimPath]/the top-level "uncovered claims" dump
     * in [extractClaims] can actually find them - per the SD-JWT spec, a
     * disclosed claim is NOT present in the payload directly; only a
     * SHA-256 digest of its disclosure is, listed under an `_sd` array
     * (which can appear at any nesting level, not just the top). Returns
     * [payload] unchanged if there are no disclosures, none decode, or
     * `_sd_alg` declares an algorithm other than the default `sha-256`
     * (not attempted - logged and left as-is rather than guessing).
     *
     * Deliberately does NOT re-verify each disclosure's digest against the
     * issuer's signature the way a verifier would - this credential was
     * already accepted and stored, so for display purposes matching digests
     * to disclosures is just reassembling the claim tree, not re-trusting
     * it. Array-element disclosures (`[salt, value]`, no claim name) are
     * skipped - there's no key to splice them in under for a flat claims
     * list; only object-property disclosures (`[salt, claimName, value]`)
     * are useful here.
     */
    private fun mergeSdJwtDisclosures(raw: String, payload: JsonObject): JsonObject {
        val disclosureSegments = raw.split("~").drop(1).filter { it.isNotBlank() }
        if (disclosureSegments.isEmpty()) return payload

        val sdAlg = (payload["_sd_alg"] as? JsonPrimitive)?.contentOrNull ?: "sha-256"
        if (sdAlg != "sha-256") {
            Timber.w("Unsupported _sd_alg '$sdAlg' - selectively disclosed claims will not be shown")
            return payload
        }

        val sha256 = MessageDigest.getInstance("SHA-256")
        val byDigest = mutableMapOf<String, Pair<String, JsonElement>>()
        for (segment in disclosureSegments) {
            val array = decodeJsonSegment(segment) as? JsonArray ?: continue
            if (array.size != 3) continue // not an object-property disclosure
            val claimName = (array[1] as? JsonPrimitive)?.contentOrNull ?: continue
            // Digest is over the disclosure's own compact (base64url) string,
            // exactly as it appears in `raw` - never a re-serialization of
            // the decoded JSON, which could byte-for-byte differ from what
            // the issuer originally hashed.
            val digest = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(sha256.digest(segment.toByteArray(Charsets.UTF_8)))
            byDigest[digest] = claimName to array[2]
        }
        if (byDigest.isEmpty()) return payload

        fun mergeObject(obj: JsonObject): JsonObject {
            val result = LinkedHashMap<String, JsonElement>()
            for ((key, value) in obj) {
                if (key == "_sd") continue // replaced by the spliced-in claims below
                result[key] = if (value is JsonObject) mergeObject(value) else value
            }
            val digests = (obj["_sd"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
            for (digest in digests) {
                val (claimName, claimValue) = byDigest[digest] ?: continue
                result[claimName] = if (claimValue is JsonObject) mergeObject(claimValue) else claimValue
            }
            return JsonObject(result)
        }

        return mergeObject(payload)
    }

    /**
     * Build [CredentialMetadata] by combining issuer display metadata with VCTM.
     *
     * Call this when storing a new credential to populate its metadata from
     * the issuer metadata and VCTM response.
     *
     * @param offer the credential offer used during issuance
     * @param vctm the fetched VCTM, if available
     * @param rawCredential the raw credential string (for extracting vct/exp/iat)
     * @return populated [CredentialMetadata]
     */
    fun buildMetadata(
        offer: CredentialOffer,
        vctm: Vctm? = null,
        rawCredential: String? = null,
    ): CredentialMetadata {
        // Use VCTM display if available, prefer user's locale
        val locale = java.util.Locale.getDefault().toLanguageTag()
        val vctmDisplay = vctm?.display?.let { displays ->
            displays.find { it.locale == locale }
                ?: displays.find { it.locale.startsWith(locale.take(2)) }
                ?: displays.firstOrNull()
        }

        val simple = vctmDisplay?.rendering?.simple

        // Extract VCT from credential payload
        val payload = rawCredential?.let { parseJwtPayload(it) }
        val vct = payload?.get("vct")?.jsonPrimitive?.content

        // Build claim metadata from VCTM
        val claims = vctm?.claims?.map { claim ->
            val claimDisplay = claim.display?.let { displays ->
                displays.find { it.locale == locale }
                    ?: displays.find { it.locale.startsWith(locale.take(2)) }
                    ?: displays.firstOrNull()
            }
            ClaimMeta(
                path = claim.path.filterNotNull(),
                label = claimDisplay?.label,
                description = claimDisplay?.description,
                sd = claim.sd,
                mandatory = claim.mandatory ?: false,
                svgId = claim.svgId,
            )
        }

        val svgTemplates = vctmDisplay?.rendering?.svgTemplates?.map { template ->
            SvgTemplateInfo(
                uri = template.uri,
                colorScheme = template.properties?.colorScheme,
                contrast = template.properties?.contrast,
                orientation = template.properties?.orientation,
            )
        }

        return CredentialMetadata(
            name = vctmDisplay?.name ?: offer.credentialName,
            description = vctmDisplay?.description ?: offer.credentialDescription,
            issuer = IssuerInfo(
                name = offer.issuerName,
                url = offer.credentialIssuerIdentifier,
            ),
            vct = vct,
            backgroundColor = simple?.backgroundColor
                ?: offer.backgroundColor,
            textColor = simple?.textColor
                ?: offer.textColor,
            logo = (simple?.logo?.let { LogoInfo(uri = it.uri, altText = it.altText) })
                ?: offer.logoUri?.let { LogoInfo(uri = it) },
            claims = claims,
            svgTemplates = svgTemplates,
        )
    }

    /**
     * Build the minimal stand-in [CredentialMetadata] for a credential whose
     * VCTM/MDDL document could not be obtained (see
     * [CredentialMetadata.hydration]).
     *
     * Everything here is derived from what the wallet already holds - nothing
     * is fetched. The name is the credential configuration ID (the closest
     * thing to a type name the issuer gave us, humanised via
     * [formatClaimKey] so `eu.europa.ec.eudi.pid_mdoc` reads as a word rather
     * than an identifier), falling back to the format. The issuer is shown by
     * host name, which is what a user recognises an issuer by when no display
     * name was published. `vct`/`doctype` come from the credential itself so
     * the DC API registry can still match it. No logo, no colours, no claim
     * labels, no SVG templates: the UI's flat layout handles all of those
     * being absent.
     */
    /**
     * The credential type the credential itself declares: `vct` for an SD-JWT
     * VC, `docType` for an mdoc. Null when it declares none, or cannot be read.
     *
     * This is what the holder actually received, as opposed to
     * [CredentialOffer.credentialConfigurationId], which is what the issuer
     * advertised. The two are checked against each other at issuance - see
     * SirosWallet's issued-type verification - because everything else in the
     * issuance path (entitlement, type metadata, WSCD selection) keys off the
     * advertised type, so an issuer that advertises one type and issues another
     * would have every one of those decisions made about the wrong credential.
     */
    fun declaredType(format: String, raw: String): String? = try {
        if (format == "mso_mdoc") {
            MdocCbor.parseStoredCredential(Base64.getUrlDecoder().decode(padBase64(raw)))?.docType
        } else {
            parseJwtPayload(raw)?.get("vct")?.jsonPrimitive?.contentOrNull
        }
    } catch (e: Exception) {
        Timber.w(e, "Could not read the declared type of a $format credential")
        null
    }

    /**
     * The `vct` a credential declares, read from the credential itself and
     * only then from its metadata.
     *
     * `metadata` is a rendering artefact: it is absent until an issuance flow
     * has an offer to build it from, and hydration - which repopulates it -
     * skips any credential whose metadata is already real. Anything that
     * decides what a credential *is* must therefore read the credential, or
     * it will disagree with the issuer about a credential that is perfectly
     * valid. mdocs answer this from their MSO instead; see
     * [parseMdocDocument].
     */
    fun vctOf(credential: StoredCredential): String? =
        parseJwtPayload(credential.raw)?.get("vct")?.jsonPrimitive?.contentOrNull
            ?: credential.metadata?.vct

    fun buildFallbackMetadata(credential: StoredCredential): CredentialMetadata {
        val configId = credential.credentialConfigurationId?.takeIf { it.isNotBlank() }
        val issuerIdent = credential.credentialIssuerIdentifier?.takeIf { it.isNotBlank() }
        val isMdoc = credential.format == "mso_mdoc"
        val doctype = if (isMdoc) parseMdocDocument(credential)?.docType else null
        val vct = if (!isMdoc) parseJwtPayload(credential.raw)?.get("vct")?.jsonPrimitive?.contentOrNull else null
        return CredentialMetadata(
            name = configId?.let { formatClaimKey(it.substringAfterLast('.')) } ?: credential.format,
            issuer = IssuerInfo(
                name = issuerIdent?.let { hostOf(it) } ?: issuerIdent,
                url = issuerIdent,
            ),
            vct = vct,
            doctype = doctype,
            hydration = CredentialMetadata.HYDRATION_FALLBACK,
        )
    }

    /** The host of [url], or the whole string if it doesn't parse as one. */
    private fun hostOf(url: String): String =
        try {
            java.net.URI(url).host ?: url
        } catch (_: Exception) {
            url
        }

    /**
     * Format a raw claim key like "given_name" into "Given Name".
     */
    fun formatClaimKey(key: String): String {
        return key.split("_", "-")
            .joinToString(" ") { it.replaceFirstChar { c -> c.uppercase() } }
    }

    /**
     * Format a JSON value for display. Internal (not private): also used by
     * [SharedDcqlMatcher] to render a value pulled from [flattenClaimPaths]
     * for the shared DCQL engine.
     */
    internal fun formatClaimValue(value: kotlinx.serialization.json.JsonElement): String {
        return when (value) {
            is kotlinx.serialization.json.JsonPrimitive -> value.content
            else -> value.toString()
        }
    }

    private fun padBase64(s: String): String {
        val rem = s.length % 4
        return if (rem == 0) s else s + "=".repeat(4 - rem)
    }

    /**
     * Group stored credentials into display-ready families, mirroring
     * wallet-frontend's `CredentialsContextProvider.fetchVcData`: only the
     * `instanceId == 0` credential of a batch (see [StoredCredential.batchId])
     * is returned as a visible entry, with every sibling copy's usage count
     * and key availability attached as [CredentialWithInstances.instances] -
     * the UI derives its "remaining copies" badge, and whether the whole
     * batch has entered the "shadow" (renew-only) display state, from
     * `instances.count { it.sigCount == 0 && it.hasKey }` - a batch down to
     * zero by either consumption or lost keys looks the same to the UI, and
     * [availableKeyIds] (see [hasAvailableKey]) is what makes the latter
     * visible at all, not just silently excluded from presentation like
     * [eligibleInstances] alone would do.
     * A credential with no [StoredCredential.batchId] (single-copy issuance)
     * is returned as its own one-instance family.
     */
    fun groupForDisplay(
        credentials: List<StoredCredential>,
        presentationHistory: List<PresentationRecord>,
        availableKeyIds: Set<String>,
    ): List<CredentialWithInstances> {
        fun sigCountFor(credentialId: Long) =
            presentationHistory.count { credentialId in it.credentialIds }

        // Every issuance response - batch of one or of many - shares one
        // batchId (see StoredCredential.batchId), so grouping is uniform:
        // no separate "standalone" case, matching wallet-frontend exactly.
        val results = credentials.groupBy { it.batchId }.values.mapNotNull { members ->
            val visible = members.find { it.instanceId == 0 } ?: return@mapNotNull null
            val instances = members
                .sortedBy { it.instanceId }
                .map {
                    CredentialInstance(
                        it.instanceId,
                        sigCountFor(it.id),
                        hasAvailableKey(it.kid, availableKeyIds),
                    )
                }
            CredentialWithInstances(visible, instances)
        }

        return results.sortedByDescending { it.credential.issuedAt ?: 0 }
    }

    /**
     * True for `"mso_mdoc_zk"` - a real ZKP predicate-proof format now exists
     * (`LongfellowZkProofSystem`, wired into `SirosWallet.handleDCAPIRequest`),
     * unlike every other format this SDK supports, which discloses via
     * salted-hash element digests (mdoc's MSO, SD-JWT's `_sd` array).
     *
     * Note this checks a *requested/presented* format, not necessarily
     * [StoredCredential.format] - a ZK presentation is a presentation-time
     * transform of an ordinarily-stored `"mso_mdoc"` credential (see
     * `CredentialMatcher.matchesFormat`'s doc comment), so the stored
     * instance's own format is never `"mso_mdoc_zk"`. Callers that know which
     * *query* format matched a given instance for the presentation in
     * progress should pass that via [eligibleInstances]'s `isZkPresentation`
     * parameter rather than relying on this function's default fallback of
     * checking [StoredCredential.format] directly (which - for exactly the
     * reason above - never returns true).
     */
    private fun isZkpFormat(format: String): Boolean = format.equals("mso_mdoc_zk", ignoreCase = true)

    /**
     * Instances from [instances] (all copies of one batch - see
     * [StoredCredential.batchId]) that are still allowed to be used for a
     * NEW presentation under [policy], given what [presentationHistory]
     * shows has already been presented. Mirrors [groupForDisplay]'s own
     * `sigCountFor` usage-counting exactly, so "eligible" and the
     * "remaining copies" ribbon never disagree.
     *
     * [CredentialConsumptionPolicy.NEVER_CONSUME] (the default - today's
     * actual behavior) skips the usage check, but every policy still
     * requires the instance's bound signing key to actually exist in
     * [availableKeyIds] - a real, recurring bug found via live testing:
     * a software key only ever lives in the WSCD's process memory plus
     * whatever was last folded into the persisted container, so a lost
     * sync (or, per privatedata-spec#1/siros-wscd-manager#68, a concurrent-
     * write merge conflict on the legacy, non-namespaced `S.keypairs` field)
     * can silently strand a credential with no usable key. Without this
     * check, NEVER_CONSUME made every such credential report "available"
     * forever, right up until a live presentation attempt failed deep
     * inside key selection with no user-facing signal at all. See
     * [hasAvailableKey] for how a null [StoredCredential.kid] is handled.
     *
     * Otherwise, an instance is eligible only if it hasn't already been
     * presented (`sigCount == 0`) - each instance is bound to its own device
     * key specifically so a verifier can't correlate repeated presentations
     * by a reused key/signature; reusing an already-presented instance
     * would throw that guarantee away.
     *
     * @param isZkPresentation Whether presenting [instances]'s given member
     * THIS time will be a ZK proof rather than a raw disclosure - defaults to
     * checking [StoredCredential.format] via [isZkpFormat] (which, per that
     * function's own doc comment, is never true, since ZK-ness lives in the
     * matched DCQL query's format, not the stored credential's). Callers that
     * know the matched query format for each candidate (e.g.
     * `SirosWallet.handleDCAPIRequest`) should pass a real resolver so
     * [CredentialConsumptionPolicy.CONSUME_NON_ZKP] actually distinguishes
     * ZK presentations (never consumed) from raw ones (consumed).
     */
    fun eligibleInstances(
        instances: List<StoredCredential>,
        policy: CredentialConsumptionPolicy,
        presentationHistory: List<PresentationRecord>,
        availableKeyIds: Set<String>,
        isZkPresentation: (StoredCredential) -> Boolean = { isZkpFormat(it.format) },
    ): List<StoredCredential> {
        // A single pass building this set, rather than rescanning all of
        // presentationHistory per instance (O(instances x history) before),
        // matters once either grows - this can run on every UI recomposition.
        val usedCredentialIds = presentationHistory.flatMapTo(HashSet()) { it.credentialIds }
        return instances.filter { instance ->
            val keyAvailable = hasAvailableKey(instance.kid, availableKeyIds)
            val consumptionEligible = policy == CredentialConsumptionPolicy.NEVER_CONSUME || run {
                val consumes = policy == CredentialConsumptionPolicy.CONSUME_ALL || !isZkPresentation(instance)
                !consumes || instance.id !in usedCredentialIds
            }
            keyAvailable && consumptionEligible
        }
    }

    /**
     * Whether [kid] (a [StoredCredential.kid]) can actually be used to sign,
     * given the signer's current [availableKeyIds] - shared by
     * [eligibleInstances] (gates presentation) and [groupForDisplay] (gates
     * the "shadow" display state, see [CredentialInstance.hasKey]) so the
     * two never disagree about whether a credential is really usable.
     *
     * A null [kid] can't be matched against a specific entry, but every
     * credential issued through the current per-credential-key architecture
     * gets a kid at storage time (`SirosWallet`'s `activeAttestedKeyIds`
     * wiring) - a real [StoredCredential] with a null kid reaching here is a
     * sign its binding was silently lost (e.g. a concurrent-flow race, task
     * #403), not a legitimate legacy case. The best check still possible
     * without a specific kid to match is whether the signer holds *any* key
     * at all; with zero keys, a null-kid credential is certain to fail to
     * sign exactly like a known-but-missing kid would.
     */
    private fun hasAvailableKey(kid: String?, availableKeyIds: Set<String>): Boolean =
        if (kid != null) kid in availableKeyIds else availableKeyIds.isNotEmpty()

    /**
     * Default fallback for [isBelowRenewThreshold] when no per-credential-
     * type override is configured (see `SirosWallet.renewThresholds` in
     * `sdk:wallet`) - below this many eligible (unused) instances
     * remaining, the wallet should proactively offer to renew rather than
     * let it silently run out (EUDI ARF ISSU_50/54; OID4VCI itself has no
     * wire slot for the issuer to communicate this, so v1 is
     * wallet-local-threshold-only - see the credential re-issuance/renewal
     * plan §6 item 1).
     */
    const val RENEW_THRESHOLD = 0

    /**
     * True when [instances]' eligible (unused) count under [policy]/
     * [presentationHistory] has dropped to or below [threshold] - the
     * proactive-renewal trigger (plan §4.3). Note [CredentialConsumptionPolicy.NEVER_CONSUME]
     * (this SDK's default policy) makes [eligibleInstances] always return
     * every instance, so this only ever fires under a consuming policy.
     */
    fun isBelowRenewThreshold(
        instances: List<StoredCredential>,
        policy: CredentialConsumptionPolicy,
        presentationHistory: List<PresentationRecord>,
        availableKeyIds: Set<String>,
        threshold: Int = RENEW_THRESHOLD,
    ): Boolean = eligibleInstances(instances, policy, presentationHistory, availableKeyIds).size <= threshold

    /**
     * Group stored credentials into one [CredentialFamily] per
     * [StoredCredential.batchId], for callers (mdoc proximity consent) that
     * need every instance's full [StoredCredential] - not just its usage
     * count, as [groupForDisplay]'s [CredentialInstance] carries - because a
     * proximity session signs with whichever approved instance it picks.
     *
     * Uses the same convention as [groupForDisplay]: a batch is only
     * representable if it has an `instanceId == 0` member; a batch missing
     * one (shouldn't happen in practice, but [groupForDisplay] treats it as
     * unrepresentable rather than guessing) is skipped rather than falling
     * back to an arbitrary member, so the two grouping functions never
     * disagree about which batches are displayable.
     */
    fun groupIntoFamilies(credentials: List<StoredCredential>): List<CredentialFamily> {
        return credentials.groupBy { it.batchId }.values.mapNotNull { members ->
            val representative = members.find { it.instanceId == 0 } ?: return@mapNotNull null
            CredentialFamily(representative = representative, instances = members)
        }
    }

    /**
     * Compares two claim sets (typically [extractClaims]'s output for a
     * credential batch before and after a renewal) - the credential
     * re-issuance/renewal plan's `AttributeDiffService`-equivalent
     * (wallet-frontend #68 parity, ISSU_59's mandatory attribute-diff
     * notification). Compares by claim [DisplayClaim.key], not by list
     * position, since claim ordering isn't a stability guarantee of any
     * issuer.
     */
    fun computeAttributeDiff(before: List<DisplayClaim>, after: List<DisplayClaim>): CredentialAttributeDiff {
        val beforeByKey = before.associateBy { it.key }
        val afterByKey = after.associateBy { it.key }
        val changed = afterByKey.keys.intersect(beforeByKey.keys)
            .mapNotNull { key ->
                val old = beforeByKey.getValue(key)
                val new = afterByKey.getValue(key)
                if (old.value != new.value) AttributeChange(key = key, label = new.label, oldValue = old.value, newValue = new.value) else null
            }
        val added = afterByKey.keys.minus(beforeByKey.keys).map { afterByKey.getValue(it) }
        val removed = beforeByKey.keys.minus(afterByKey.keys).map { beforeByKey.getValue(it) }
        return CredentialAttributeDiff(changed = changed, added = added, removed = removed)
    }
}

/** One claim whose value changed between two versions of the same credential. */
data class AttributeChange(
    val key: String,
    val label: String,
    val oldValue: String,
    val newValue: String,
)

/**
 * The result of [CredentialUtils.computeAttributeDiff]. [hasChanges] is
 * false (the fully-silent-renewal case per plan §4.4) only when all three
 * lists are empty.
 */
data class CredentialAttributeDiff(
    val changed: List<AttributeChange>,
    val added: List<DisplayClaim>,
    val removed: List<DisplayClaim>,
) {
    val hasChanges: Boolean get() = changed.isNotEmpty() || added.isNotEmpty() || removed.isNotEmpty()
}

/**
 * Governs whether a successful presentation exhausts the specific credential
 * instance it used, so that instance can never be presented again.
 *
 * Defaults to [NEVER_CONSUME] - today's actual behavior - so introducing
 * this setting doesn't silently change existing wallets' behavior.
 */
enum class CredentialConsumptionPolicy {
    /** Every successful presentation exhausts the instance it used, regardless of format. */
    CONSUME_ALL,

    /**
     * A raw disclosure exhausts the instance; a ZK proof of it does not, since
     * the verifier learns nothing that links two proofs. Which of the two a
     * presentation is comes from the matched query's format - see the
     * `isZkPresentation` parameter of [CredentialUtils.eligibleInstances].
     */
    CONSUME_NON_ZKP,

    /** Instances are never exhausted - a presentation may reuse any matching instance. */
    NEVER_CONSUME,
}

/**
 * A credential claim ready for display.
 */
data class DisplayClaim(
    /** Raw claim key (e.g. "given_name"). */
    val key: String,
    /** User-facing label from VCTM or formatted key (e.g. "Given Name"). */
    val label: String,
    /** Claim value as a string. */
    val value: String,
    /** Optional description from VCTM. */
    val description: String? = null,
    /** Whether this claim is mandatory. */
    val mandatory: Boolean = false,
    /** VCTM SVG template placeholder ID this claim fills, if any. */
    val svgId: String? = null,
)

/** One member of a batch-issued credential family, alongside its usage count. */
data class CredentialInstance(
    val instanceId: Int,
    val sigCount: Int,
    /**
     * Whether this instance's bound signing key currently exists (see
     * `CredentialUtils.hasAvailableKey`). An instance that's unused
     * (`sigCount == 0`) but keyless still can't actually be presented - the
     * UI's "remaining copies" count and "shadow" (renew-only) display state
     * both gate on `sigCount == 0 && hasKey`, not `sigCount == 0` alone, so a
     * lost key can't masquerade as a live, presentable copy. Defaults to
     * `true` so call sites that only construct/assert instances by their
     * consumption state (most existing tests) don't need to reason about
     * key availability at all.
     */
    val hasKey: Boolean = true,
)

/** A visible credential card plus every instance in its batch (see [CredentialUtils.groupForDisplay]). */
data class CredentialWithInstances(val credential: StoredCredential, val instances: List<CredentialInstance>)

/**
 * One credential "type" as the user should see it: every [StoredCredential]
 * instance sharing a [StoredCredential.batchId] is the SAME credential from
 * a batch issuance (see [CredentialUtils.groupForDisplay]'s doc comment for
 * why - each instance is bound to its own device key purely for
 * unlinkability, not a distinct credential the user chose to hold multiple
 * of). A proximity consent prompt must offer one choice per family, never
 * one per raw instance, or a 5-instance batch reads as "you have 5 driver's
 * licenses." See [CredentialUtils.groupIntoFamilies].
 */
data class CredentialFamily(
    /** The instance shown to the user for display (matches [CredentialUtils.groupForDisplay]'s convention of the `instanceId == 0` member). */
    val representative: StoredCredential,
    /** Every instance in this batch - the proximity session picks one of these to actually sign with once the family is approved. */
    val instances: List<StoredCredential>,
)

/**
 * The individually-decoded parts of a raw SD-JWT VC string, for display.
 */
data class SdJwtParts(
    val header: JsonObject?,
    val payload: JsonObject?,
    /** Each disclosure is a JSON array (`[salt, name, value]` or `[salt, value]`). */
    val disclosures: List<JsonElement>,
)
