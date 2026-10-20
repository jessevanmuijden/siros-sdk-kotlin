// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.mdoc.DocumentMdoc
import org.siros.sdk.credentials.mdoc.MdocCbor

/**
 * The `nym_auth` commitment `ssc = SHA256(secret_seed)` and how to read it from an issuer-signed
 * credential (privatedata-spec §5A).
 *
 * Every read is strict and fails closed: a value that is absent, duplicated, of the wrong type or of
 * the wrong length is `null`, never a best guess. Nothing here logs or returns a seed.
 */
object SecretSeedCommitment {
    /** `secret_seed` length in bytes (rulebook). */
    const val SEED_BYTES = 16

    /** `ssc` length in bytes: a SHA-256 digest. */
    const val COMMITMENT_BYTES = 32

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * The value of the element [name] in the credential's own doctype namespace (the one a nym_auth
     * credential carries its claims in, and the one the circuit binds), or null when that namespace or
     * element is absent or the element occurs more than once there. The same element name in another
     * namespace is never consulted.
     */
    fun doctypeElement(document: DocumentMdoc, name: String): CBORObject? {
        val matches = document.issuerSigned.nameSpaces[document.docType].orEmpty().filter { it.item.elementIdentifier == name }
        return matches.singleOrNull()?.item?.elementValue
    }

    /** The 32-byte `ssc` of an mdoc [document], or null (absent, duplicated, not a bstr, or not 32 bytes). */
    fun sscOf(document: DocumentMdoc): ByteArray? {
        val v = doctypeElement(document, "ssc") ?: return null
        if (v.type != CBORType.ByteString) return null
        return v.GetByteString().takeIf { it.size == COMMITMENT_BYTES }
    }

    /** The `ssc` of a stored mdoc credential given as base64url CBOR, or null when unreadable. */
    fun sscOfMdoc(rawBase64Url: String): ByteArray? = try {
        sscOf(MdocCbor.parseStoredCredential(Base64.getUrlDecoder().decode(rawBase64Url)))
    } catch (e: Exception) {
        null
    }

    /**
     * The `ssc` of a compact SD-JWT VC: its one top-level `ssc` disclosure, as 64 lowercase hex
     * characters. Null when there is no such disclosure, more than one, the claim is also present in
     * the clear, the disclosure is not referenced from the signed payload's top-level `_sd`, the
     * value is not 64 lowercase hex characters, or the payload's `_sd_alg` names a digest algorithm
     * other than `sha-256` (the digests could not be matched, so nothing is read). A disclosure of a
     * same-named claim of a NESTED object is not the top-level one and is ignored.
     */
    fun sscOfSdJwt(credential: String): ByteArray? {
        try {
            val parts = credential.split('~')
            val payload = parts[0].split('.').getOrNull(1) ?: return null
            val payloadObj = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(payload), Charsets.UTF_8)) as? JsonObject
                ?: return null
            if ("ssc" in payloadObj) return null
            // Fail closed: the digests below are SHA-256; under another (or a malformed) algorithm they mean something else.
            payloadObj["_sd_alg"]?.let { alg -> if ((alg as? JsonPrimitive)?.takeIf { it.isString }?.content != "sha-256") return null }
            val digests = (payloadObj["_sd"] as? JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
            val found = ArrayList<Pair<String, String>>() // disclosure text to value
            for (segment in parts.drop(1).filter { it.isNotEmpty() }) {
                val array = try {
                    json.parseToJsonElement(String(Base64.getUrlDecoder().decode(segment), Charsets.UTF_8)) as? JsonArray
                } catch (e: Exception) {
                    null
                } ?: continue
                if (array.size != 3) continue
                val name = (array[1] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: continue
                if (name != "ssc") continue
                // Bound to the issuer signature: only a disclosure whose digest sits in the payload's TOP-LEVEL `_sd` is
                // the top-level claim. Any other `ssc` disclosure belongs to a nested object (or to nothing) and is ignored.
                if (CredentialDisclosureGuard.digestOf(segment) !in digests) continue
                val value = (array[2] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
                found.add(segment to value)
            }
            val (_, value) = found.singleOrNull() ?: return null
            if (!HEX_64.matches(value)) return null
            return hexToBytes(value)
        } catch (e: Exception) {
            return null
        }
    }

    /**
     * `secret_seed` from its delivered form: exactly 32 lowercase hex characters, no prefix, no
     * whitespace. Null otherwise. The caller owns (and zeroes) the returned array.
     */
    fun seedFromHex(hex: String): ByteArray? = if (HEX_32.matches(hex)) hexToBytes(hex) else null

    /** Whether `SHA256(seed) == ssc`, compared in constant time. False for any wrong length. */
    fun opens(seed: ByteArray, ssc: ByteArray): Boolean {
        if (seed.size != SEED_BYTES || ssc.size != COMMITMENT_BYTES) return false
        val digest = MessageDigest.getInstance("SHA-256").digest(seed)
        return try {
            MessageDigest.isEqual(digest, ssc)
        } finally {
            digest.fill(0)
        }
    }

    private val HEX_32 = Regex("[0-9a-f]{32}")
    private val HEX_64 = Regex("[0-9a-f]{64}")

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> ((Character.digit(hex[2 * i], 16) shl 4) or Character.digit(hex[2 * i + 1], 16)).toByte() }
}
