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
    private fun entries(e: JsonElement?, allowRequired: Boolean): List<AuxiliaryAdvertisement.Slot>? {
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
            if (type == TYPE) {
                val alg = (o["alg"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
                path(o["path"]) ?: return null
                recognised = alg == ALG
            }
            if (!recognised) {
                // A well-formed entry of a type (or algorithm) this wallet does not recognise: ignored, unless it is REQUIRED.
                if (required) return null
                continue
            }
            val p = path(o["path"]) ?: return null
            // A value in public metadata is not an advertisement.
            if ("opening" in o || "commitment" in o) return null
            out += AuxiliaryAdvertisement.Slot(p, ALG, required)
        }
        if (out.map { it.path }.toSet().size != out.size) return null
        return out
    }

    override fun advertisement(config: CredentialConfiguration): AuxiliarySelection {
        // `auxiliary_data` belongs to a RESPONSE only: in public issuer metadata it is forbidden, whatever else the configuration says.
        if (config.credentialMetadata?.auxiliaryData != null) return AuxiliarySelection.Malformed
        val raw = config.auxiliaryDataSupported ?: return AuxiliarySelection.None
        val obj = raw as? JsonObject ?: return AuxiliarySelection.Malformed
        // Section 5: at least one direction. An empty object is a malformed advertisement, not "nothing advertised".
        if (obj.isEmpty()) return AuxiliarySelection.Malformed
        if (!obj.keys.all { it == "to_wallet" || it == "to_issuer" }) return AuxiliarySelection.Malformed
        val toWallet = entries(obj["to_wallet"], allowRequired = false) ?: return AuxiliarySelection.Malformed
        val toIssuer = entries(obj["to_issuer"], allowRequired = true) ?: return AuxiliarySelection.Malformed
        // Only extensions this wallet does not know: the SHAPE is still the advertised one (section 3: unrecognised entries are
        // ignored, not a reason to treat the response as a foreign shape), it just has no recognised slots to act on.
        return AuxiliarySelection.Selected(this, AuxiliaryAdvertisement(toWallet, toIssuer))
    }

    override fun carriesSecret(metadata: JsonObject): Boolean = RESPONSE_MEMBER in metadata

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
        return if (got == want && (deliveries.isNotEmpty() || want.isEmpty())) deliveries else null
    }

    override fun commitmentOf(format: String, credential: String, delivery: SecretDelivery): ByteArray? = claimAt(format, credential, delivery.path)

    /** The 32-byte commitment claim at [path] of an issued credential (see [commitmentOf]); null when absent, ambiguous or malformed. */
    fun claimAt(format: String, credential: String, path: List<String>): ByteArray? = (claimStatus(format, credential, path) as? Claim.Value)?.bytes

    /** What [claimStatus] found at a path. */
    sealed interface Claim {
        /** There is no such claim in the credential. */
        object Absent : Claim

        /** There is something there that is not exactly one well-formed 32-byte commitment (wrong type or length, duplicated, ambiguous), or the credential cannot be read. */
        object Invalid : Claim

        /** The commitment; the caller zeroes [bytes]. */
        class Value(val bytes: ByteArray) : Claim
    }

    /** [claimAt] that tells an absent claim from a present but malformed or ambiguous one. */
    fun claimStatus(format: String, credential: String, path: List<String>): Claim = try {
        when {
            format.equals("mso_mdoc", ignoreCase = true) -> mdocClaim(credential, path)
            format.contains("sd-jwt", ignoreCase = true) -> sdJwtClaim(credential, path)
            else -> Claim.Invalid
        }
    } catch (e: Exception) {
        Claim.Invalid
    }

    /** An mdoc claim at `[namespace, element]`: a 32-byte bstr, present exactly once. */
    private fun mdocClaim(rawBase64Url: String, path: List<String>): Claim {
        if (path.size != 2) return Claim.Invalid
        val doc = MdocCbor.parseStoredCredential(Base64.getUrlDecoder().decode(rawBase64Url))
        val matches = doc.issuerSigned.nameSpaces[path[0]].orEmpty().filter { it.item.elementIdentifier == path[1] }
        if (matches.isEmpty()) return Claim.Absent
        val v = matches.singleOrNull()?.item?.elementValue ?: return Claim.Invalid
        if (v.type != CBORType.ByteString) return Claim.Invalid
        return v.GetByteString().takeIf { it.size == COMMITMENT_BYTES }?.let { Claim.Value(it) } ?: Claim.Invalid
    }

    /** A top-level SD-JWT claim (one path segment): in the signed payload, or one disclosure bound by the payload's `_sd`; base64url of 32 bytes. */
    private fun sdJwtClaim(credential: String, path: List<String>): Claim {
        if (path.size != 1) return Claim.Invalid
        val name = path[0]
        val parts = credential.split('~')
        val payload = parts[0].split('.').getOrNull(1) ?: return Claim.Invalid
        val obj = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(payload), Charsets.UTF_8)) as? JsonObject ?: return Claim.Invalid
        // The digests below are SHA-256: under another (or an unreadable) algorithm a disclosure cannot be matched, which is
        // NOT the same as the claim being absent: a different value could be hidden behind it.
        obj["_sd_alg"]?.let { if ((it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content != "sha-256") return Claim.Invalid }
        val inClear = obj[name]
        val disclosed = disclosureValues(parts, obj, name)
        if (inClear != null) {
            // Present in the clear AND selectively disclosable is ambiguous: nothing is read.
            if (disclosed.isNotEmpty()) return Claim.Invalid
            return decodeClaim(inClear)
        }
        if (disclosed.isEmpty()) return Claim.Absent
        return decodeClaim(disclosed.singleOrNull() ?: return Claim.Invalid)
    }

    private fun decodeClaim(v: JsonElement): Claim =
        (v as? JsonPrimitive)?.takeIf { it.isString }?.content?.let { decodeB64(it, COMMITMENT_BYTES) }?.let { Claim.Value(it) } ?: Claim.Invalid

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
            val p = if (supported) path(o["path"]) else null
            if (p == null) {
                if (required) {
                    throw WalletException(
                        "The issuer requires auxiliary data this wallet does not support",
                        errorCode = "holder_commitment_unsupported",
                    )
                }
                continue
            }
            out += AuxiliaryAdvertisement.Slot(p, ALG, required)
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
