// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORType
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import org.siros.sdk.credentials.mdoc.MdocCbor

/**
 * Credential Auxiliary Data v0.1 (nym_auth rulebook PR 12; vc PR 850), as an [AuxiliaryDataShape].
 *
 * - Advertisement, in the issuer metadata of a configuration: `auxiliary_data_supported` = `{"to_wallet": [...], "to_issuer": [...]}`,
 *   entries `{"type": "hash_commitment", "alg": "sha-256", "path": [<claims path>], "required"?: bool}`. Names and slots only.
 * - Delivery, in the DECRYPTED response `credential_metadata.auxiliary_data[]`: `{"type": "hash_commitment", "alg", "path",
 *   "opening": <base64url, 16 bytes>}`. The wallet checks `SHA-256(opening) ==` the claim at `path` of every issued credential.
 * - Holder commitment, in the SIGNED part of every key proof: the claim `auxiliary_data` = `[{"type", "alg", "path", "commitment":
 *   <base64url>}]`, the same value in every proof of a request ([placeInProof] is a pure function of its input).
 * - The `auxiliary_data` member is stripped before display metadata is merged, cached or shown.
 *
 * Strict and fail-closed: an unknown `type` or `alg`, a malformed `path`, duplicate paths, an opening that is not exactly 16
 * bytes of unpadded base64url, a delivered path nobody advertised, or an advertised one that did not arrive refuses the response.
 * Nothing here logs or returns an opening other than inside [SecretDelivery].
 */
object AuxiliaryDataV01 : AuxiliaryDataShape {
    override val id = "auxiliary_data.v0.1"

    const val ADVERTISEMENT_MEMBER = "auxiliary_data_supported"
    const val RESPONSE_MEMBER = "auxiliary_data"
    const val PROOF_CLAIM = "auxiliary_data"
    const val TYPE = "hash_commitment"
    const val ALG = "sha-256"

    /** The issuer's error code for a commitment that conflicts with the one it holds: retrying never helps. */
    const val ERROR_CONFLICT = "auxiliary_data_conflict"

    /** The text encodings of a commitment claim the advertisement may name (vc pull 850 `encoding`); absent means the format's default. */
    val ENCODINGS: Set<String> = setOf("base64url", "base64", "hex")

    /**
     * The advertised `encoding` of [o]: null when absent; [UNSUPPORTED_ENCODING] for a string this wallet cannot read;
     * [INVALID_ENCODING] when present but not a string at all (malformed).
     */
    private fun encodingOf(o: JsonObject): String? = o["encoding"]?.let { e ->
        val text = (e as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return INVALID_ENCODING
        if (text in ENCODINGS) text else UNSUPPORTED_ENCODING
    }

    private const val INVALID_ENCODING = "\u0000invalid"
    private const val UNSUPPORTED_ENCODING = "\u0000unsupported"

    private const val MAX_ENTRIES = 8
    private const val MAX_PATH = 8
    private const val OPENING_BYTES = 16
    private const val COMMITMENT_BYTES = 32
    private val json = Json { ignoreUnknownKeys = true }

    private fun path(e: JsonElement?): List<String>? {
        val arr = e as? JsonArray ?: return null
        if (arr.isEmpty() || arr.size > MAX_PATH) return null
        return arr.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content?.takeIf { s -> s.isNotEmpty() } ?: return null }
    }

    /**
     * The recognised slots of one advertised direction. Spec section 3: an entry of a type (or algorithm) this wallet does not
     * recognise is IGNORED, except that an unrecognised REQUIRED `to_issuer` entry cannot be satisfied and makes the whole
     * configuration unusable (null here, section 5). A recognised entry must be well formed, and a direction that is present
     * must carry entries.
     */
    private fun entries(e: JsonElement?, allowRequired: Boolean, format: String): List<AuxiliaryAdvertisement.Slot>? {
        if (e == null) return emptyList()
        val arr = e as? JsonArray ?: return null
        // A direction that is present must carry entries: an explicitly empty one is a configuration the engine rejects too.
        if (arr.isEmpty()) return null
        if (arr.size > MAX_ENTRIES) return null
        val out = ArrayList<AuxiliaryAdvertisement.Slot>()
        for (item in arr) {
            val o = item as? JsonObject ?: return null
            val required = o["required"]?.let { r ->
                if (!allowRequired) return null
                (r as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull ?: return null
            } ?: false
            // The mandatory members are validated BEFORE deciding whether an entry is an extension to ignore: a missing or non-string
            // type, or a hash_commitment without a string alg or a valid path, is malformed (the configuration is not offered).
            val type = (o["type"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
            var recognised = false
            var usable = true
            if (type == TYPE) {
                val alg = (o["alg"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
                val p0 = path(o["path"]) ?: return null
                // A value in public metadata is not an advertisement: checked on EVERY hash_commitment, before an unsupported
                // algorithm can make the entry skippable (an opening or commitment is a secret or a value, never advertised).
                if ("opening" in o || "commitment" in o) return null
                recognised = alg == ALG
                val enc = encodingOf(o)
                if (enc == INVALID_ENCODING) return null
                if (recognised) {
                    // What this wallet cannot READ at receipt is unusable: an encoding it does not know, an absent one outside an
                    // mdoc (bytes only an mdoc byte string holds), an encoding on a format it cannot read at all, or a path the
                    // receipt reader does not handle (SD-JWT: one segment; mdoc: exactly two).
                    usable = enc != UNSUPPORTED_ENCODING &&
                        !(enc != null && !isSdJwt(format) && !isMdoc(format)) &&
                        !(enc == null && !isMdoc(format)) &&
                        pathReadable(format, p0)
                }
            }
            if (recognised && !usable) {
                // Spec 4.1: an OPTIONAL to_issuer entry the wallet cannot honour is omitted; anything the wallet is expected to
                // read or send (to_wallet, a required to_issuer) makes the configuration unusable.
                if (allowRequired && !required) continue
                return null
            }
            if (!recognised) {
                // A well-formed entry of a type (or algorithm) this wallet does not recognise: ignored, unless it is REQUIRED.
                if (required) return null
                continue
            }
            val p = path(o["path"]) ?: return null
            // A value in public metadata is not an advertisement.
            if ("opening" in o || "commitment" in o) return null
            out += AuxiliaryAdvertisement.Slot(p, ALG, required, encodingOf(o))
        }
        if (out.map { it.path }.toSet().size != out.size) return null
        return out
    }

    private fun isSdJwt(format: String) = format.contains("sd-jwt", ignoreCase = true)

    /** Whether the receipt reader can read a claim at [path] in [format]: an SD-JWT top-level claim, an mdoc `[namespace, element]`. */
    private fun pathReadable(format: String, path: List<String>) = when {
        isSdJwt(format) -> path.size == 1
        isMdoc(format) -> path.size == 2
        else -> false
    }
    private fun isMdoc(format: String) = format.equals("mso_mdoc", ignoreCase = true)

    override fun advertisement(config: CredentialConfiguration): AuxiliarySelection {
        // `auxiliary_data` belongs to a RESPONSE only: in public issuer metadata it is forbidden, whatever else the configuration says.
        if (config.credentialMetadata?.auxiliaryData != null) return AuxiliarySelection.Malformed
        val raw = config.auxiliaryDataSupported ?: return AuxiliarySelection.None
        val obj = raw as? JsonObject ?: return AuxiliarySelection.Malformed
        // Section 5: at least one direction. An empty object is a malformed advertisement, not "nothing advertised".
        if (obj.isEmpty()) return AuxiliarySelection.Malformed
        if (!obj.keys.all { it == "to_wallet" || it == "to_issuer" }) return AuxiliarySelection.Malformed
        val toWallet = entries(obj["to_wallet"], allowRequired = false, config.format) ?: return AuxiliarySelection.Malformed
        val toIssuer = entries(obj["to_issuer"], allowRequired = true, config.format) ?: return AuxiliarySelection.Malformed
        // Only extensions this wallet does not know: the SHAPE is still the advertised one (section 3: unrecognised entries are
        // ignored, not a reason to treat the response as a foreign shape), it just has no recognised slots to act on.
        return AuxiliarySelection.Selected(this, AuxiliaryAdvertisement(toWallet, toIssuer))
    }

    /**
     * Whether the response carries a secret in this shape: a malformed member, or at least one RECOGNISED delivery. A member of only
     * unrecognised extension entries (spec section 3) carries none, so it is ignored like everywhere else (also in a deferred response).
     */
    override fun carriesSecret(metadata: JsonObject): Boolean {
        if (RESPONSE_MEMBER !in metadata) return false
        return when (val parsed = parseDeliveries(metadata)) {
            is AuxiliaryParse.Malformed -> true
            is AuxiliaryParse.Parsed -> parsed.deliveries.isNotEmpty().also { parsed.deliveries.forEach { d -> d.bytes.fill(0) } }
        }
    }

    override fun parseDeliveries(metadata: JsonObject): AuxiliaryParse {
        val member = metadata[RESPONSE_MEMBER] ?: return AuxiliaryParse.Parsed(emptyList())
        val arr = member as? JsonArray ?: return AuxiliaryParse.Malformed
        if (arr.isEmpty() || arr.size > MAX_ENTRIES) return AuxiliaryParse.Malformed
        val out = ArrayList<SecretDelivery>()
        fun fail(): AuxiliaryParse { out.forEach { it.bytes.fill(0) }; return AuxiliaryParse.Malformed }
        for (item in arr) {
            val o = item as? JsonObject ?: return fail()
            // Mandatory members first: a missing or non-string type, or a hash_commitment without a string alg or a valid path, refuses
            // the whole response (nothing is stored); only a well-formed entry of an unrecognised type or algorithm is an extension.
            val type = (o["type"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return fail()
            if (type != TYPE) continue
            val alg = (o["alg"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return fail()
            val p = path(o["path"]) ?: return fail()
            // `encoding` occurs only in metadata and `commitment` only in wallet key proofs: in a RESPONSE entry either is malformed
            // (fail closed, before the opening is decoded).
            if ("encoding" in o || "commitment" in o) return fail()
            if (alg != ALG) continue
            val text = (o["opening"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return fail()
            val bytes = decodeB64(text, OPENING_BYTES) ?: return fail()
            out += SecretDelivery(p, ALG, bytes)
        }
        if (out.map { it.path }.toSet().size != out.size) return fail()
        return AuxiliaryParse.Parsed(out)
    }

    /** Unpadded base64url of exactly [size] bytes; null otherwise (padding, standard alphabet, whitespace, wrong length). */
    private fun decodeB64(text: String, size: Int): ByteArray? {
        if (text.any { !(it.isLetterOrDigit() && it.code < 128 || it == '-' || it == '_') }) return null
        return try {
            Base64.getUrlDecoder().decode(text).takeIf { it.size == size && Base64.getUrlEncoder().withoutPadding().encodeToString(it) == text }
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    override fun deliveriesToVerify(deliveries: List<SecretDelivery>, secretNamespace: String, advertised: AuxiliaryAdvertisement?): List<SecretDelivery>? {
        // Everything delivered is verified, and the delivery must be exactly what was advertised: no extra secret, none missing.
        val want = advertised?.toWallet?.map { it.path }?.toSet() ?: return null
        val got = deliveries.map { it.path }.toSet()
        // Nothing recognised advertised and nothing recognised delivered (only extensions): nothing to verify, nothing missing.
        if (!(got == want && (deliveries.isNotEmpty() || want.isEmpty()))) return null
        // How each claim writes its commitment comes from the advertisement (the response entries do not carry it).
        deliveries.forEach { d -> d.encoding = advertised.toWallet.first { it.path == d.path }.encoding }
        return deliveries
    }

    override fun commitmentOf(format: String, credential: String, delivery: SecretDelivery): ByteArray? = claimAt(format, credential, delivery.path, delivery.encoding)

    /** The 32-byte commitment claim at [path] of an issued credential (see [commitmentOf]); null when absent, ambiguous or malformed. */
    fun claimAt(format: String, credential: String, path: List<String>, encoding: String? = null): ByteArray? = (claimStatus(format, credential, path, encoding) as? Claim.Value)?.bytes

    /** What [claimStatus] found at a path. */
    sealed interface Claim {
        /** There is no such claim in the credential. */
        object Absent : Claim

        /**
         * There is something there that is not exactly one well-formed 32-byte commitment (wrong representation or length,
         * duplicated, ambiguous), or the credential cannot be read. [shape] says what was found (type and length only, NEVER the
         * value): it is what a refusal names.
         */
        class Invalid(val shape: String) : Claim

        /** The commitment; the caller zeroes [bytes]. */
        class Value(val bytes: ByteArray) : Claim
    }

    /** [claimAt] that tells an absent claim from a present but malformed or ambiguous one, and says what the malformed one was. */
    fun claimStatus(format: String, credential: String, path: List<String>, encoding: String? = null): Claim = try {
        when {
            format.equals("mso_mdoc", ignoreCase = true) -> mdocClaim(credential, path, encoding)
            format.contains("sd-jwt", ignoreCase = true) -> sdJwtClaim(credential, path, encoding)
            else -> Claim.Invalid("a credential format this wallet cannot read a commitment from")
        }
    } catch (e: Exception) {
        Claim.Invalid("the credential could not be read")
    }

    /** An mdoc claim at `[namespace, element]`: a 32-byte bstr, present exactly once. */
    private fun mdocClaim(rawBase64Url: String, path: List<String>, encoding: String?): Claim {
        if (path.size != 2) return Claim.Invalid("a path of ${path.size} segments (an mdoc claim needs [namespace, element])")
        val doc = MdocCbor.parseStoredCredential(Base64.getUrlDecoder().decode(rawBase64Url))
        val matches = doc.issuerSigned.nameSpaces[path[0]].orEmpty().filter { it.item.elementIdentifier == path[1] }
        if (matches.isEmpty()) return Claim.Absent
        val v = matches.singleOrNull()?.item?.elementValue ?: return Claim.Invalid("present ${matches.size} times")
        if (encoding == null) {
            // The default: the commitment is a byte string.
            return when (v.type) {
                CBORType.ByteString -> v.GetByteString().let { if (it.size == COMMITMENT_BYTES) Claim.Value(it) else Claim.Invalid("a byte string of ${it.size} bytes, expected $COMMITMENT_BYTES") }
                CBORType.TextString -> Claim.Invalid("a text string of ${v.AsString().length} characters, a byte string is required (no encoding was advertised)")
                else -> Claim.Invalid("CBOR type ${v.type}, a byte string is required")
            }
        }
        // An advertised text encoding: the commitment is a text string in that encoding.
        return when (v.type) {
            CBORType.TextString -> textClaim(v.AsString(), encoding)
            CBORType.ByteString -> Claim.Invalid("a byte string of ${v.GetByteString().size} bytes where text in $encoding was advertised")
            else -> Claim.Invalid("CBOR type ${v.type} where text in $encoding was advertised")
        }
    }

    /** A top-level SD-JWT claim (one path segment): in the signed payload, or one disclosure bound by the payload's `_sd`; unpadded base64url of 32 bytes. */
    private fun sdJwtClaim(credential: String, path: List<String>, encoding: String?): Claim {
        if (path.size != 1) return Claim.Invalid("a path of ${path.size} segments (an SD-JWT claim here is top level)")
        val name = path[0]
        val parts = credential.split('~')
        val payload = parts[0].split('.').getOrNull(1) ?: return Claim.Invalid("the credential could not be read")
        val obj = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(payload), Charsets.UTF_8)) as? JsonObject
            ?: return Claim.Invalid("the credential could not be read")
        // The digests below are SHA-256: under another (or an unreadable) algorithm a disclosure cannot be matched, which is
        // NOT the same as the claim being absent: a different value could be hidden behind it.
        obj["_sd_alg"]?.let { if ((it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content != "sha-256") return Claim.Invalid("a disclosure digest algorithm other than sha-256") }
        val inClear = obj[name]
        val disclosed = disclosureValues(parts, obj, name)
        if (inClear != null) {
            // Present in the clear AND selectively disclosable is ambiguous: nothing is read.
            if (disclosed.isNotEmpty()) return Claim.Invalid("both in the clear and disclosed")
            return decodeClaim(inClear, encoding)
        }
        if (disclosed.isEmpty()) return Claim.Absent
        return decodeClaim(disclosed.singleOrNull() ?: return Claim.Invalid("disclosed ${disclosed.size} times"), encoding)
    }

    private fun decodeClaim(v: JsonElement, encoding: String?): Claim {
        val text = (v as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return Claim.Invalid("not a text value, text in ${encoding ?: "base64url"} is required")
        return textClaim(text, encoding ?: "base64url")
    }

    /** A commitment written as text in [encoding] (base64url unpadded, base64 padded, or lower-case hex): exactly 32 bytes, in that form only. */
    private fun textClaim(text: String, encoding: String): Claim {
        val bytes = when (encoding) {
            "base64url" -> decodeB64(text, COMMITMENT_BYTES)
            "base64" -> try {
                Base64.getDecoder().decode(text).takeIf { it.size == COMMITMENT_BYTES && Base64.getEncoder().encodeToString(it) == text }
            } catch (e: IllegalArgumentException) {
                null
            }
            "hex" -> text.takeIf { it.length == COMMITMENT_BYTES * 2 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } }
                ?.chunked(2)?.map { it.toInt(16).toByte() }?.toByteArray()
            else -> null
        }
        if (bytes != null) return Claim.Value(bytes)
        // Why it is not readable, from its SHAPE only (never the value), against what was advertised (or the default).
        val found = when {
            text.endsWith("=") -> "text of ${text.length} characters with padding"
            text.length == COMMITMENT_BYTES * 2 && text.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' } -> "text of ${text.length} characters that looks like hex"
            text.any { it == '+' || it == '/' } -> "text of ${text.length} characters in the standard base64 alphabet"
            else -> "text of ${text.length} characters"
        }
        return Claim.Invalid("$found, which is not $encoding of $COMMITMENT_BYTES bytes as advertised")
    }

    private fun disclosureValues(parts: List<String>, payload: JsonObject, name: String): List<JsonElement> {
        payload["_sd_alg"]?.let { if ((it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content != "sha-256") return emptyList() }
        val digests = (payload["_sd"] as? JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
        val out = ArrayList<JsonElement>()
        for (segment in parts.drop(1).filter { it.isNotEmpty() }) {
            val array = try {
                json.parseToJsonElement(String(Base64.getUrlDecoder().decode(segment), Charsets.UTF_8)) as? JsonArray
            } catch (e: Exception) {
                null
            } ?: continue
            if (array.size != 3 || (array[1] as? JsonPrimitive)?.takeIf { it.isString }?.content != name) continue
            if (CredentialDisclosureGuard.digestOf(segment) !in digests) continue
            out += array[2]
        }
        return out
    }

    /**
     * The slots of the engine's `auxiliary_data_to_issuer` ([entries], the advertised `to_issuer` entries verbatim) this wallet will
     * commit to. A `hash_commitment` / `sha-256` entry with a well-formed path is answered; any other entry that is `required` refuses
     * the proof ([WalletException], `holder_commitment_unsupported`: the issuer would reject it after the user has waited), and any
     * other optional entry is skipped. Duplicate paths are refused.
     */
    fun slotsToAnswer(entries: List<JsonObject>): List<AuxiliaryAdvertisement.Slot> {
        val out = ArrayList<AuxiliaryAdvertisement.Slot>()
        for (o in entries.take(MAX_ENTRIES + 1)) {
            val required = (o["required"] as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull == true
            val supported = (o["type"] as? JsonPrimitive)?.takeIf { it.isString }?.content == TYPE &&
                (o["alg"] as? JsonPrimitive)?.takeIf { it.isString }?.content == ALG
            val enc = if (supported) encodingOf(o) else null
            val p = if (supported && enc != INVALID_ENCODING && enc != UNSUPPORTED_ENCODING) path(o["path"]) else null
            if (p == null) {
                if (required) {
                    throw WalletException(
                        "The issuer requires auxiliary data this wallet does not support",
                        errorCode = "holder_commitment_unsupported",
                    )
                }
                continue
            }
            out += AuxiliaryAdvertisement.Slot(p, ALG, required, enc)
        }
        if (entries.size > MAX_ENTRIES || out.map { it.path }.toSet().size != out.size) {
            throw WalletException("The issuer's auxiliary data request is not acceptable", errorCode = "holder_commitment_unsupported")
        }
        return out
    }

    override fun stripFromMetadata(metadata: JsonObject): JsonObject = JsonObject(metadata - RESPONSE_MEMBER)

    override fun placeInProof(commitments: List<HolderCommitment>): Map<String, JsonElement> {
        if (commitments.isEmpty()) return emptyMap()
        if (commitments.size > MAX_ENTRIES) throw WalletException("Too many holder commitments", errorCode = "holder_commitment_unsupported")
        val entries = commitments.map { c ->
            if (c.alg != ALG || c.commitment.size != COMMITMENT_BYTES || c.path.isEmpty()) {
                throw WalletException("A holder commitment is not a $ALG commitment of $COMMITMENT_BYTES bytes", errorCode = "holder_commitment_unavailable")
            }
            JsonObject(
                mapOf(
                    "type" to JsonPrimitive(TYPE),
                    "alg" to JsonPrimitive(ALG),
                    "path" to JsonArray(c.path.map { JsonPrimitive(it) }),
                    "commitment" to JsonPrimitive(Base64.getUrlEncoder().withoutPadding().encodeToString(c.commitment)),
                ),
            )
        }
        return mapOf(PROOF_CLAIM to JsonArray(entries))
    }
}
