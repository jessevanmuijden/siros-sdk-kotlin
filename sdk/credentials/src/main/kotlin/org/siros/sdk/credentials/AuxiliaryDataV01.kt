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

    private fun entries(e: JsonElement?, allowRequired: Boolean): List<AuxiliaryAdvertisement.Slot>? {
        if (e == null) return emptyList()
        val arr = e as? JsonArray ?: return null
        // A direction that is present must carry entries: an explicitly empty one is a configuration the engine rejects too.
        if (arr.isEmpty()) return null
        if (arr.size > MAX_ENTRIES) return null
        val out = ArrayList<AuxiliaryAdvertisement.Slot>()
        for (item in arr) {
            val o = item as? JsonObject ?: return null
            if ((o["type"] as? JsonPrimitive)?.takeIf { it.isString }?.content != TYPE) return null
            if ((o["alg"] as? JsonPrimitive)?.takeIf { it.isString }?.content != ALG) return null
            val p = path(o["path"]) ?: return null
            val required = o["required"]?.let { r ->
                if (!allowRequired) return null
                (r as? JsonPrimitive)?.booleanOrNull ?: return null
            } ?: false
            // A value in public metadata is not an advertisement.
            if ("opening" in o || "commitment" in o) return null
            out += AuxiliaryAdvertisement.Slot(p, ALG, required)
        }
        if (out.map { it.path }.toSet().size != out.size) return null
        return out
    }

    override fun advertisement(config: CredentialConfiguration): AuxiliarySelection {
        val raw = config.auxiliaryDataSupported ?: return AuxiliarySelection.None
        val obj = raw as? JsonObject ?: return AuxiliarySelection.Malformed
        if (!obj.keys.all { it == "to_wallet" || it == "to_issuer" }) return AuxiliarySelection.Malformed
        val toWallet = entries(obj["to_wallet"], allowRequired = false) ?: return AuxiliarySelection.Malformed
        val toIssuer = entries(obj["to_issuer"], allowRequired = true) ?: return AuxiliarySelection.Malformed
        if (toWallet.isEmpty() && toIssuer.isEmpty()) return AuxiliarySelection.Malformed
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
            if ((o["type"] as? JsonPrimitive)?.takeIf { it.isString }?.content != TYPE) return fail()
            if ((o["alg"] as? JsonPrimitive)?.takeIf { it.isString }?.content != ALG) return fail()
            val p = path(o["path"]) ?: return fail()
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
        return if (got == want && deliveries.isNotEmpty()) deliveries else null
    }

    override fun commitmentOf(format: String, credential: String, delivery: SecretDelivery): ByteArray? = claimAt(format, credential, delivery.path)

    /** The 32-byte commitment claim at [path] of an issued credential (see [commitmentOf]); null when absent, ambiguous or malformed. */
    fun claimAt(format: String, credential: String, path: List<String>): ByteArray? = try {
        when {
            format.equals("mso_mdoc", ignoreCase = true) -> mdocClaim(credential, path)
            format.contains("sd-jwt", ignoreCase = true) -> sdJwtClaim(credential, path)
            else -> null
        }
    } catch (e: Exception) {
        null
    }

    /** An mdoc claim at `[namespace, element]`: a 32-byte bstr, present exactly once. */
    private fun mdocClaim(rawBase64Url: String, path: List<String>): ByteArray? {
        if (path.size != 2) return null
        val doc = MdocCbor.parseStoredCredential(Base64.getUrlDecoder().decode(rawBase64Url))
        val matches = doc.issuerSigned.nameSpaces[path[0]].orEmpty().filter { it.item.elementIdentifier == path[1] }
        val v = matches.singleOrNull()?.item?.elementValue ?: return null
        if (v.type != CBORType.ByteString) return null
        return v.GetByteString().takeIf { it.size == COMMITMENT_BYTES }
    }

    /** A top-level SD-JWT claim (one path segment): in the signed payload, or one disclosure bound by the payload's `_sd`; base64url of 32 bytes. */
    private fun sdJwtClaim(credential: String, path: List<String>): ByteArray? {
        if (path.size != 1) return null
        val name = path[0]
        val parts = credential.split('~')
        val payload = parts[0].split('.').getOrNull(1) ?: return null
        val obj = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(payload), Charsets.UTF_8)) as? JsonObject ?: return null
        val inClear = obj[name]
        if (inClear != null) {
            // Present in the clear AND selectively disclosable is ambiguous: nothing is read.
            if (disclosureValues(parts, obj, name).isNotEmpty()) return null
            return decodeB64((inClear as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null, COMMITMENT_BYTES)
        }
        val found = disclosureValues(parts, obj, name).singleOrNull() ?: return null
        return decodeB64((found as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null, COMMITMENT_BYTES)
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
            val required = (o["required"] as? JsonPrimitive)?.booleanOrNull == true
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
