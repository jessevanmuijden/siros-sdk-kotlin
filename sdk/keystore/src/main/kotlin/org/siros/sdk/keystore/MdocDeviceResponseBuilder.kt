// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import org.siros.sdk.credentials.mdoc.MdocCbor
import org.siros.sdk.credentials.mdoc.NamespaceItem
import org.siros.sdk.keystore.mdoc.MdocCose
import java.security.MessageDigest

/**
 * Builds an ISO 18013-5 DeviceResponse for mDoc credential presentation
 * via OID4VP (OpenID for Verifiable Presentations).
 *
 * The credential's raw bytes are a full DeviceResponse-shaped envelope as
 * issued (`{documents: [{docType, issuerSigned}], ...}` - confirmed via
 * `sirosfoundation/wallet-frontend#191`), not a bare IssuerSigned blob; this
 * builder parses that envelope with [MdocCbor], applies real selective
 * disclosure by filtering `issuerSigned.nameSpaces` down to [disclosedClaims]
 * (preserving each kept item's original tag-24-wrapped bytes so the issuer's
 * MSO digests remain valid - disclosure selects a subset of already-digested
 * items, it never re-hashes), and signs a fresh device authentication over
 * the OpenID4VPHandover session transcript.
 *
 * Usage:
 * ```kotlin
 * val builder = MdocDeviceResponseBuilder(credentialBytes, algorithm = "ES256")
 * val response = builder.build(
 *     nonce = "verifier-nonce",
 *     audience = "verifier-client-id",
 *     responseUri = "https://verifier.example.com/response",
 *     verifierJwkThumbprint = "base64url-thumbprint",
 *     disclosedClaims = listOf("given_name", "family_name"),
 *     signer = { data -> signer.sign(keyId, data) },
 * )
 * ```
 */
class MdocDeviceResponseBuilder(
    /** Raw credential bytes: a full DeviceResponse-shaped envelope as issued. */
    private val credentialBytes: ByteArray,
    /** Algorithm for signing (ES256 or EdDSA). */
    private val algorithm: String = "ES256",
) {

    /**
     * Build the CBOR-encoded DeviceResponse.
     *
     * @param nonce Verifier nonce from the sign request.
     * @param audience Verifier client ID.
     * @param responseUri Response endpoint URI.
     * @param verifierJwkThumbprint Optional JWK thumbprint of the verifier key.
     * @param disclosedClaims Element identifiers to disclose (null = disclose all namespaces/elements).
     * @param signer Function that signs raw bytes with the device key; must return a raw (not DER) signature.
     * @return CBOR-encoded DeviceResponse bytes.
     */
    suspend fun build(
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        disclosedClaims: List<String>?,
        signer: suspend (ByteArray) -> ByteArray,
    ): ByteArray {
        val disclosedDocument = parseAndFilter(disclosedClaims)
        val sessionTranscript = buildSessionTranscript(
            clientId = audience,
            nonce = nonce,
            responseUri = responseUri,
            verifierJwkThumbprint = verifierJwkThumbprint,
        )
        val deviceAuthBytes = buildDeviceAuthentication(disclosedDocument.docType, sessionTranscript)
        val coseSign1 = MdocCose.sign1Detached(algorithm, deviceAuthBytes, signer)

        return assembleFinalResponse(disclosedDocument, coseSign1)
    }

    /**
     * Build the CBOR-encoded DeviceResponse for a W3C Digital Credentials API
     * (DC API) presentation, using the `OpenID4VPDCAPIHandover` session
     * transcript (OpenID4VP 1.0 Appendix B.2.6) instead of the redirect
     * flow's `OpenID4VPHandover` - there is no `responseUri`/`clientId` in
     * this flow (the response is returned via the browser's synchronous
     * `navigator.credentials.get()` callback, not an HTTP POST), and the
     * handover binds to the verified browser origin instead.
     *
     * @param nonce Verifier nonce from the request.
     * @param origin The verified browser/page origin that called `navigator.credentials.get()`.
     * @param encryptionPublicJwkThumbprint JWK thumbprint of the verifier's response-encryption
     *   key (present when `response_mode=dc_api.jwt`), null otherwise.
     * @param disclosedClaims Element identifiers to disclose (null = disclose all namespaces/elements).
     * @param signer Function that signs raw bytes with the device key; must return a raw (not DER) signature.
     * @return CBOR-encoded DeviceResponse bytes.
     */
    suspend fun buildForDCAPI(
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        disclosedClaims: List<String>?,
        signer: suspend (ByteArray) -> ByteArray,
    ): ByteArray {
        val disclosedDocument = parseAndFilter(disclosedClaims)
        val sessionTranscript = Companion.buildDCAPISessionTranscript(
            origin = origin,
            nonce = nonce,
            encryptionPublicJwkThumbprint = encryptionPublicJwkThumbprint,
        )
        val deviceAuthBytes = buildDeviceAuthentication(disclosedDocument.docType, sessionTranscript)
        val coseSign1 = MdocCose.sign1Detached(algorithm, deviceAuthBytes, signer)

        return assembleFinalResponse(disclosedDocument, coseSign1)
    }

    /**
     * Build the CBOR-encoded DeviceResponse for an ISO 18013-5 proximity
     * (BLE) presentation, using the caller-supplied proximity
     * `SessionTranscript` bytes (§9.1.5.1: `[DeviceEngagementBytes,
     * EReaderKeyBytes, Handover]`) instead of building an
     * `OpenID4VPHandover`/`OpenID4VPDCAPIHandover` transcript here - unlike
     * those two remote-presentation flows, this transcript depends on
     * BLE-session-specific context (the engagement and reader key) that
     * lives in the proximity transport layer, not this builder.
     *
     * @param sessionTranscriptBytes CBOR-encoded `SessionTranscript`, from
     *   `ProximitySessionTranscript.build`.
     * @param disclosedClaims Element identifiers to disclose (null = disclose all namespaces/elements).
     * @param signer Function that signs raw bytes with the device key; must return a raw (not DER) signature.
     * @return CBOR-encoded DeviceResponse bytes.
     */
    suspend fun buildForProximity(
        sessionTranscriptBytes: ByteArray,
        disclosedClaims: List<String>?,
        signer: suspend (ByteArray) -> ByteArray,
    ): ByteArray = buildForProximity(sessionTranscriptBytes, disclosedClaims, signer, guarded = true)

    /**
     * The fully-signed DeviceResponse a ZK prover takes as its PRIVATE witness
     * (see [LongfellowZkProofSystem]): it never leaves the wallet and is not a
     * disclosure, so the non-disclosure guard does not apply to it.
     */
    internal suspend fun buildPrivateWitnessResponse(
        sessionTranscriptBytes: ByteArray,
        signer: suspend (ByteArray) -> ByteArray,
    ): ByteArray = buildForProximity(sessionTranscriptBytes, null, signer, guarded = false)

    private suspend fun buildForProximity(
        sessionTranscriptBytes: ByteArray,
        disclosedClaims: List<String>?,
        signer: suspend (ByteArray) -> ByteArray,
        guarded: Boolean,
    ): ByteArray {
        val disclosedDocument = parseAndFilter(disclosedClaims, guarded)
        val deviceAuthBytes = buildDeviceAuthentication(disclosedDocument.docType, sessionTranscriptBytes)
        val coseSign1 = MdocCose.sign1Detached(algorithm, deviceAuthBytes, signer)

        return assembleFinalResponse(disclosedDocument, coseSign1)
    }

    private fun parseAndFilter(disclosedClaims: List<String>?, guarded: Boolean = true): org.siros.sdk.credentials.mdoc.DocumentMdoc {
        val document = MdocCbor.parseStoredCredential(credentialBytes)
        val selected = if (disclosedClaims == null) {
            document
        } else {
            document.copy(
                issuerSigned = document.issuerSigned.copy(
                    nameSpaces = filterNamespaces(document.issuerSigned.nameSpaces, disclosedClaims),
                )
            )
        }
        // Fail closed: a presentation that would disclose a protected element is refused, never stripped.
        if (guarded) org.siros.sdk.credentials.CredentialDisclosureGuard.requireNoneProtected(
            selected.docType,
            selected.issuerSigned.nameSpaces.mapValues { (_, items) -> items.map { it.item.elementIdentifier } },
        )
        return selected
    }

    /**
     * Filter each namespace's items down to those whose `elementIdentifier`
     * is in [disclosedClaims], preserving each kept item's ORIGINAL
     * tag-24-wrapped [CBORObject] (never re-encoded from the parsed model -
     * the issuer's MSO digests were computed over those exact bytes).
     * Namespaces with no disclosed elements are dropped entirely.
     */
    private fun filterNamespaces(
        nameSpaces: Map<String, List<NamespaceItem>>,
        disclosedClaims: List<String>,
    ): Map<String, List<NamespaceItem>> {
        val disclosed = disclosedClaims.toSet()
        return nameSpaces.mapValues { (_, items) ->
            items.filter { it.item.elementIdentifier in disclosed }
        }.filterValues { it.isNotEmpty() }
    }

    /**
     * Build the OpenID4VPHandover session transcript per OID4VP mdoc profile.
     *
     * SessionTranscript = [
     *   null,  // reserved
     *   null,  // reserved
     *   [
     *     "OpenID4VPHandover",
     *     SHA-256([clientId, nonce, verifierJwkThumbprint, responseUri])
     *   ]
     * ]
     */
    private fun buildSessionTranscript(
        clientId: String,
        nonce: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
    ): ByteArray = Companion.buildOpenID4VPSessionTranscript(
        clientId = clientId,
        nonce = nonce,
        responseUri = responseUri,
        verifierJwkThumbprint = verifierJwkThumbprint,
    )

    /**
     * Build the OpenID4VPDCAPIHandover session transcript per OID4VP 1.0
     * Appendix B.2.6 (Digital Credentials API).
     *
     * SessionTranscript = [
     *   null,  // reserved
     *   null,  // reserved
     *   [
     *     "OpenID4VPDCAPIHandover",
     *     SHA-256([origin, nonce, encryptionPublicJwkThumbprint])
     *   ]
     * ]
     *
     * Unlike [buildSessionTranscript] (the redirect flow's OpenID4VPHandover),
     * there is no clientId or responseUri here - the handover binds to the
     * browser-verified origin instead, since the response never travels over
     * HTTP to a responseUri.
     */

    /**
     * Assemble the final DeviceResponse CBOR structure.
     *
     * DeviceResponse = { "version": "1.0", "documents": [Document], "status": 0 }
     * Document = { "docType", "issuerSigned" (filtered), "deviceSigned" }
     */
    private fun assembleFinalResponse(document: org.siros.sdk.credentials.mdoc.DocumentMdoc, coseSign1: CBORObject): ByteArray {
        val documentObj = MdocCbor.encodeDocument(document)

        val deviceSignatureMap = CBORObject.NewMap()
        deviceSignatureMap["deviceSignature"] = coseSign1
        val deviceSignedMap = CBORObject.NewMap()
        deviceSignedMap["nameSpaces"] = emptyDeviceNameSpacesTag()
        deviceSignedMap["deviceAuth"] = deviceSignatureMap
        documentObj["deviceSigned"] = deviceSignedMap

        val documentsArray = CBORObject.NewArray()
        documentsArray.Add(documentObj)

        val response = CBORObject.NewMap()
        response["version"] = CBORObject.FromObject("1.0")
        response["documents"] = documentsArray
        response["status"] = CBORObject.FromObject(0)
        return response.EncodeToBytes()
    }

    private fun sha256(data: ByteArray): ByteArray = Companion.sha256(data)

    companion object {
        /**
         * DeviceAuthentication = ["DeviceAuthentication", SessionTranscript,
         * DocType, DeviceNameSpacesBytes], the whole 4-element array itself
         * tag-24-wrapped (an "encoded CBOR data item"), per ISO 18013-5 §9.1.3.4
         * and matching Google's reference wallet's `generateDeviceResponse()`
         * (https://github.com/digitalcredentialsdev/CMWallet). This was
         * previously a bare, untagged 3-element array (missing the namespaces
         * element entirely and never tag-24-wrapped) - since deviceAuth's
         * signature is computed over these exact bytes, a verifier
         * reconstructing the correct 4-element tag-24 form (as Google's own
         * https://digital-credentials.dev/ demo does) would always disagree with
         * a signature computed over the old, different bytes.
         */
        internal fun buildDeviceAuthentication(docType: String, sessionTranscript: ByteArray): ByteArray {
            // sessionTranscript is already CBOR-encoded; decode it back to embed
            // as a nested CBOR item rather than a byte string.
            val deviceAuth = CBORObject.NewArray()
            deviceAuth.Add(CBORObject.FromObject("DeviceAuthentication"))
            deviceAuth.Add(CBORObject.DecodeFromBytes(sessionTranscript))
            deviceAuth.Add(CBORObject.FromObject(docType))
            deviceAuth.Add(emptyDeviceNameSpacesTag())
            val tagged = CBORObject.FromObjectAndTag(deviceAuth.EncodeToBytes(), 24)
            return tagged.EncodeToBytes()
        }

        /**
         * Tag-24-wrapped empty map: this SDK never discloses claims via
         * `deviceSigned.nameSpaces` (everything comes from `issuerSigned`
         * instead), so this is always empty - but it must be the SAME bytes
         * both here (embedded in the signed DeviceAuthentication) and in
         * [assembleFinalResponse]'s actual `deviceSigned.nameSpaces` field,
         * since a verifier reconstructs DeviceAuthentication from the latter.
         */
        internal fun emptyDeviceNameSpacesTag(): CBORObject =
            CBORObject.FromObjectAndTag(CBORObject.NewMap().EncodeToBytes(), 24)

        /**
         * Builds the `OpenID4VPDCAPIHandover` session transcript (OpenID4VP
         * 1.0 Appendix B.2.6) from just the DC API request parameters - a
         * pure function of [origin]/[nonce]/[encryptionPublicJwkThumbprint],
         * with no dependency on any particular credential's bytes. Exposed
         * here (not only via [buildForDCAPI]) so callers that need this
         * exact transcript for something OTHER than building a normal signed
         * DeviceResponse - e.g. as the `sessionTranscript` fed to a
         * [org.siros.sdk.credentials.ZkProofSystem.generateProof] call for a
         * ZK-wrapped DC API presentation - can compute it without
         * constructing an unrelated `MdocDeviceResponseBuilder` instance.
         *
         * SessionTranscript = [null, null, [ "OpenID4VPDCAPIHandover",
         * Handover ]], per OpenID4VP 1.0 (#dc_api):
         *
         * ```
         * OpenID4VPDCAPIHandoverInfo = [
         *   origin,
         *   nonce,
         *   jwk_thumbprint / null
         * ]
         * ```
         *
         * Unlike the redirect flow's OpenID4VPHandover, there is no
         * clientId or responseUri here - the handover binds to the
         * browser-verified origin instead, since the response never travels
         * over HTTP to a responseUri.
         */
        fun buildDCAPISessionTranscript(
            origin: String,
            nonce: String,
            encryptionPublicJwkThumbprint: String?,
        ): ByteArray {
            val handoverInfo = CBORObject.NewArray()
            handoverInfo.Add(CBORObject.FromObject(origin))
            handoverInfo.Add(CBORObject.FromObject(nonce))
            handoverInfo.Add(
                if (encryptionPublicJwkThumbprint != null) {
                    // OpenID4VP 1.0 (#dc_api) requires this element to be the
                    // thumbprint encoded as a CBOR Byte String - the raw SHA-256
                    // digest bytes, not a text string of the base64url form the
                    // JOSE side (JWK.computeThumbprint().toString()) hands us.
                    // Encoding it as a CBOR text string here (a real bug, found
                    // via a verifier rejecting every mso_mdoc DC API response
                    // with no error) means the wallet's OpenID4VPDCAPIHandover
                    // hash never matches what a spec-conformant verifier
                    // reconstructs, so it silently disagrees with our
                    // DeviceAuthentication signature and rejects the response.
                    CBORObject.FromObject(java.util.Base64.getUrlDecoder().decode(encryptionPublicJwkThumbprint))
                } else {
                    CBORObject.Null
                }
            )
            val handoverHash = sha256(handoverInfo.EncodeToBytes())

            val handover = CBORObject.NewArray()
            handover.Add(CBORObject.FromObject("OpenID4VPDCAPIHandover"))
            handover.Add(CBORObject.FromObject(handoverHash))

            val sessionTranscript = CBORObject.NewArray()
            sessionTranscript.Add(CBORObject.Null)
            sessionTranscript.Add(CBORObject.Null)
            sessionTranscript.Add(handover)
            return sessionTranscript.EncodeToBytes()
        }

        /**
         * Builds the `OpenID4VPHandover` session transcript (the redirect
         * flow's handover, OID4VP mdoc profile) from just the request
         * parameters - a pure function of [clientId]/[nonce]/[responseUri]/
         * [verifierJwkThumbprint], with no dependency on any particular
         * credential's bytes. Exposed here (not only via the instance
         * [build] method) so callers that need this exact transcript for
         * something OTHER than building a normal signed DeviceResponse -
         * e.g. as the `sessionTranscript` fed to a
         * [org.siros.sdk.credentials.ZkProofSystem.generateProof] call for a
         * ZK-wrapped redirect-flow presentation - can compute it without
         * constructing an unrelated [MdocDeviceResponseBuilder] instance.
         * Mirrors [buildDCAPISessionTranscript]'s existing precedent for the
         * DC API flow.
         *
         * SessionTranscript = [
         *   null,  // reserved
         *   null,  // reserved
         *   [
         *     "OpenID4VPHandover",
         *     SHA-256([clientId, nonce, verifierJwkThumbprint, responseUri])
         *   ]
         * ]
         */
        fun buildOpenID4VPSessionTranscript(
            clientId: String,
            nonce: String,
            responseUri: String,
            verifierJwkThumbprint: String?,
        ): ByteArray {
            val handoverInfo = CBORObject.NewArray()
            handoverInfo.Add(CBORObject.FromObject(clientId))
            handoverInfo.Add(CBORObject.FromObject(nonce))
            handoverInfo.Add(
                // Per OpenID4VP's mdoc profile, this element MUST be a CBOR
                // Byte String of the raw thumbprint digest, not a text string
                // of its base64url form - see buildDCAPISessionTranscript's
                // matching fix.
                if (verifierJwkThumbprint != null) {
                    CBORObject.FromObject(java.util.Base64.getUrlDecoder().decode(verifierJwkThumbprint))
                } else {
                    CBORObject.Null
                }
            )
            handoverInfo.Add(CBORObject.FromObject(responseUri))
            val handoverHash = sha256(handoverInfo.EncodeToBytes())

            val handover = CBORObject.NewArray()
            handover.Add(CBORObject.FromObject("OpenID4VPHandover"))
            handover.Add(CBORObject.FromObject(handoverHash))

            val sessionTranscript = CBORObject.NewArray()
            sessionTranscript.Add(CBORObject.Null)
            sessionTranscript.Add(CBORObject.Null)
            sessionTranscript.Add(handover)
            return sessionTranscript.EncodeToBytes()
        }

        /**
         * The `OpenID4VPHandover` session transcript a `circuit_zk` presentation over a REDIRECT (OpenID4VP QR) request is bound to:
         * [buildOpenID4VPSessionTranscript] with the JWK thumbprint REQUIRED, because over redirects the response is always
         * encrypted (`direct_post.jwt`): [verifierJwkThumbprint] is the base64url RFC 7638 thumbprint of the verifier's
         * response-encryption key and must decode to exactly 32 bytes. `clientId` is the prefixed client id
         * (`x509_san_dns:...`). A null thumbprint (valid only in the DC API handover, for an unencrypted response) is not
         * representable here. The DC API path keeps [buildDCAPISessionTranscript].
         *
         * @throws IllegalArgumentException if the thumbprint is not unpadded base64url of 32 bytes.
         */
        fun buildCircuitZkRedirectSessionTranscript(
            clientId: String,
            nonce: String,
            responseUri: String,
            verifierJwkThumbprint: String,
        ): ByteArray {
            require(verifierJwkThumbprint.none { it == '=' || it == '+' || it == '/' }) { "the JWK thumbprint is unpadded base64url" }
            val thumbprint = try {
                java.util.Base64.getUrlDecoder().decode(verifierJwkThumbprint)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("the JWK thumbprint is not base64url")
            }
            require(thumbprint.size == 32) { "the JWK thumbprint is 32 bytes" }
            return buildOpenID4VPSessionTranscript(clientId, nonce, responseUri, verifierJwkThumbprint)
        }

        fun sha256(data: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(data)

        /**
         * Builds a ZK-wrapped `DeviceResponse` CBOR structure - multipaz's
         * own `zkDocuments` extension to the standard DeviceResponse (see
         * `org.multipaz.mdoc.response.DeviceResponseParser`/`ZkDocument`/
         * `ZkDocumentData` in balfanz/multipaz's ppid branch). Confirmed
         * live against a real verifier: a plain base64-encoded proof-bytes
         * string as the whole `vp_token` value silently produces an EMPTY
         * result (`deviceResponse.getOrNull("zkDocuments")` finds nothing,
         * with no error) - the verifier's parser only recognizes `documents`
         * (plain disclosure) or `zkDocuments` (ZK) as top-level keys, never
         * bare proof bytes.
         *
         * SessionTranscript/proof binding is the ZK circuit's job (already
         * handled by [org.siros.sdk.credentials.ZkProofSystem.generateProof]
         * itself) - this function only assembles the wire envelope the
         * verifier expects to receive the proof and its disclosed claims in.
         *
         * @param proofBytes the raw ZK proof from [ZkProofSystem.generateProof].
         * @param zkSystemId the resolved [ZkSystemSpec.id] - the full circuit
         *   id string the verifier requested and this wallet satisfied.
         * @param docType the credential's mdoc docType.
         * @param timestamp the exact same RFC 3339 timestamp string passed to
         *   the native prover call - it's part of what the proof attests to,
         *   so it must match byte-for-byte here.
         * @param namespace the mdoc namespace [disclosedClaims] belong to.
         * @param disclosedClaims element identifier -> disclosed CBOR value,
         *   for every claim actually being revealed - including the derived
         *   pseudonym under its own DCQL-facing name (e.g.
         *   `"pairwise_pseudonym"`), never the raw seed value.
         * @param digestIds element identifier -> the credential's own
         *   `digestID` for that element (from the real, issuer-signed
         *   `IssuerSignedItem` - not something the wallet invents). Optional
         *   per identifier (a missing entry simply omits `digestId` from
         *   that item); harmless/unused by a Longfellow presentation
         *   (matched by position, not digestID - see
         *   `ZkPresentationContext.RequestedClaimIDs`'s doc comment in
         *   `vc`'s `zk_verifier.go`), but REQUIRED for a Vega presentation's
         *   verifier-side claim matching, since Vega's fixed claim slots are
         *   ordered by the credential's own document order rather than the
         *   request's order - see `VegaProofSystem.buildWitness`'s doc
         *   comment.
         * @param issuerSignedItemBytes element identifier -> that element's
         *   exact original `IssuerSignedItem` bytes
         *   (`NamespaceItem.original.EncodeToBytes()` - the same bytes
         *   [VegaProofSystem.buildWitness] feeds into `FfiClaim
         *   .issuerSignedItemBytes` when proving). Vega-only, as of the r12
         *   circuit revision: `zk_cred_vega::verify()` no longer returns a
         *   disclosed claim's plaintext as part of the proof - the caller
         *   must supply it, and the verifier re-derives its blinded digest
         *   to check the binding. See
         *   `docs/ZK_VEGA_DIGESTID_WIRE_EXTENSION.md` in `vc` (this field is
         *   documented there as an extension of that same wire format).
         *   Omitted (no `issuerSignedItemBytes` key) for a Longfellow
         *   presentation, which never needs it.
         * @param claimSlotDigestIds Vega-only: the credential's FULL,
         *   fixed-shape claim-slot list (`VegaProofSystem.MAX_CLAIMS_V1`
         *   entries, in the credential's own document order - the same
         *   order `VegaProofSystem.buildWitness` assigns to `FfiClaim`
         *   slots), each entry being that slot's `digestID` regardless of
         *   whether this presentation discloses it. A Vega verifier has no
         *   independent way to learn which proof slot corresponds to which
         *   digestID otherwise - see the doc referenced above. `null` for a
         *   Longfellow presentation (positional matching, no slot concept).
         * @param issuerAuth the credential's own COSE_Sign1 `issuerAuth`
         *   structure, to extract its x5chain (COSE header label 33) from.
         * @return CBOR-encoded `{version, status, zkDocuments}` bytes, ready
         *   to become the `vp_token` value for this credential's query id.
         */
        fun buildZkDeviceResponse(
            proofBytes: ByteArray,
            zkSystemId: String,
            docType: String,
            timestamp: String,
            namespace: String,
            disclosedClaims: Map<String, CBORObject>,
            issuerAuth: CBORObject,
            digestIds: Map<String, UInt> = emptyMap(),
            issuerSignedItemBytes: Map<String, ByteArray> = emptyMap(),
            claimSlotDigestIds: List<UInt>? = null,
        ): ByteArray {
            // Fail closed at the final ZK response builder too: it is public, so a host running its
            // own prover or replaying a proof reaches it without going through present().
            org.siros.sdk.credentials.CredentialDisclosureGuard.requireNoneProtected(
                docType,
                mapOf(namespace to disclosedClaims.keys),
            )
            val documentData = CBORObject.NewMap()
            documentData["zkSystemId"] = CBORObject.FromObject(zkSystemId)
            documentData["docType"] = CBORObject.FromObject(docType)
            documentData["timestamp"] = CBORObject.FromObjectAndTag(CBORObject.FromObject(timestamp), 0)

            val issuerSignedItems = CBORObject.NewArray()
            disclosedClaims.forEach { (elementId, elementValue) ->
                val item = CBORObject.NewMap()
                item["elementIdentifier"] = CBORObject.FromObject(elementId)
                item["elementValue"] = elementValue
                digestIds[elementId]?.let { item["digestId"] = CBORObject.FromObject(it.toLong()) }
                issuerSignedItemBytes[elementId]?.let { item["issuerSignedItemBytes"] = CBORObject.FromObject(it) }
                issuerSignedItems.Add(item)
            }
            val issuerSignedMap = CBORObject.NewMap()
            issuerSignedMap[namespace] = issuerSignedItems
            documentData["issuerSigned"] = issuerSignedMap

            claimSlotDigestIds?.let { slots ->
                val slotsArray = CBORObject.NewArray()
                slots.forEach { slotsArray.Add(CBORObject.FromObject(it.toLong())) }
                documentData["claimSlotDigestIds"] = slotsArray
            }

            // We never disclose deviceSigned claims (everything comes from
            // issuerSigned) - matches assembleFinalResponse's identical
            // convention for the non-ZK path.
            documentData["deviceSigned"] = CBORObject.NewMap()

            extractX5Chain(issuerAuth)?.let { documentData["msoX5chain"] = it }

            val documentDataTagged = CBORObject.FromObjectAndTag(
                CBORObject.FromObject(documentData.EncodeToBytes()), 24,
            )

            val zkDocument = CBORObject.NewMap()
            zkDocument["proof"] = CBORObject.FromObject(proofBytes)
            zkDocument["documentData"] = documentDataTagged

            val zkDocumentsArray = CBORObject.NewArray()
            zkDocumentsArray.Add(zkDocument)

            val response = CBORObject.NewMap()
            response["version"] = CBORObject.FromObject("1.0")
            response["status"] = CBORObject.FromObject(0)
            response["zkDocuments"] = zkDocumentsArray
            return response.EncodeToBytes()
        }

        /**
         * Extracts the x5chain (COSE header label 33) from a COSE_Sign1
         * `issuerAuth`'s unprotected header map (index 1 of the 4-element
         * array) - already encoded exactly as multipaz's own
         * `X509CertChain.toDataItem()` expects (a single cert as a bare
         * bstr, or multiple as an array of bstr - the same encoding COSE
         * itself uses for this header, so it can be passed through as-is).
         */
        private fun extractX5Chain(issuerAuth: CBORObject): CBORObject? {
            if (issuerAuth.type != com.upokecenter.cbor.CBORType.Array || issuerAuth.size() < 2) return null
            val unprotected = issuerAuth[1]
            if (unprotected.type != com.upokecenter.cbor.CBORType.Map) return null
            return unprotected[CBORObject.FromObject(33)]
        }
    }
}
