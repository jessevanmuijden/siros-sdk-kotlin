// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/**
 * The wallet's half of "the engine never sees credential contents": the keys and the JWE work that used to run
 * inside the engine, so the engine relays ciphertext only (see the engine-blind encryption contract).
 *
 * Nothing here logs, and no object here prints a key or a plaintext.
 */

/**
 * A fresh ephemeral P-256 key for ONE OpenID4VCI credential request's response encryption (OpenID4VCI 1.0 section 8.3.1).
 * The engine sends the issuer only [publicJwk]; the issuer's JWE can be opened here and nowhere else.
 *
 * Held in memory only, for the life of one flow, and never serialised: there is deliberately no way to export the
 * private half. [alg] and [enc] are the pair the engine negotiated against the issuer's metadata, and the issuer's JWE
 * must use exactly that pair ([decrypt] refuses anything else).
 */
internal class CredentialResponseKey private constructor(
    private val key: ECKey,
    val alg: String,
    val enc: String,
) {
    /** The public JWK to put in `credential_response_encryption.jwk`: `{kty, crv, x, y, use: "enc", alg}`. */
    val publicJwk: JsonObject = Json.parseToJsonElement(key.toPublicJWK().toJSONString()) as JsonObject

    /**
     * Opens a compact JWE the issuer returned and returns its plaintext (the Credential Response JSON).
     *
     * @throws IllegalArgumentException when [jwe] is not a compact JWE, uses an algorithm other than the negotiated
     *   pair, or does not decrypt under this key. The message never carries the JWE or any plaintext.
     */
    fun decrypt(jwe: String): String {
        val obj = try {
            JWEObject.parse(jwe)
        } catch (e: Exception) {
            throw IllegalArgumentException("The credential response is not a compact JWE")
        }
        val header = obj.header
        require(header.algorithm.name == alg && header.encryptionMethod.name == enc) {
            "The credential response uses ${header.algorithm.name}/${header.encryptionMethod.name}, not the negotiated $alg/$enc"
        }
        try {
            obj.decrypt(ECDHDecrypter(key))
        } catch (e: Exception) {
            throw IllegalArgumentException("The credential response could not be decrypted")
        }
        return obj.payload.toString()
    }

    override fun toString() = "CredentialResponseKey($alg/$enc, <redacted>)"

    companion object {
        /** The key-agreement algorithms the engine may negotiate: ECDH-ES direct, or with an AES key wrap. */
        val SUPPORTED_ALGS = setOf("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW")

        /** The content encryption methods the engine may negotiate. */
        val SUPPORTED_ENCS = setOf("A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512")

        /**
         * @return a fresh key for the negotiated pair, or null when the wallet cannot decrypt that pair (the caller
         *   then declines, which the engine treats as a refusal when the issuer REQUIRES encryption).
         */
        fun generate(alg: String, enc: String): CredentialResponseKey? {
            if (alg !in SUPPORTED_ALGS || enc !in SUPPORTED_ENCS) return null
            val key = ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(JWEAlgorithm.parse(alg))
                .generate()
            return CredentialResponseKey(key, alg, enc)
        }
    }
}

/**
 * Builds the OpenID4VP `direct_post.jwt` response (JARM, OpenID4VP 1.0 section 8.3) on the wallet, so the engine can
 * POST ciphertext to the verifier without ever holding the `vp_token`.
 */
internal object AuthorizationResponseEncryption {
    private const val JARM_ISSUER = "https://self-issued.me/v2"
    private const val JARM_LIFETIME_SECONDS = 300L

    /** The engine refuses a larger `response_jwe`. */
    const val MAX_RESPONSE_JWE_BYTES = 4 * 1024 * 1024

    /**
     * Whether [jwe] is a compact JWE the engine accepts: five base64url segments, none empty (the encrypted-key segment
     * may be empty only for direct `ECDH-ES`), at most [MAX_RESPONSE_JWE_BYTES], whose protected header carries exactly
     * [alg], [enc] and, when the verifier's JWK has one, its [kid] (and none when it has not).
     */
    fun isConformant(jwe: String, alg: String, enc: String, kid: String?): Boolean {
        if (jwe.isEmpty() || jwe.length > MAX_RESPONSE_JWE_BYTES) return false
        val segments = jwe.split('.')
        if (segments.size != 5) return false
        val b64 = Regex("^[A-Za-z0-9_-]*$")
        if (segments.any { !b64.matches(it) }) return false
        if (segments.withIndex().any { (i, s) -> s.isEmpty() && !(i == 1 && alg == "ECDH-ES") }) return false
        val header = try {
            JWEHeader.parse(com.nimbusds.jose.util.Base64URL(segments[0]))
        } catch (e: Exception) {
            return false
        }
        return header.algorithm.name == alg && header.encryptionMethod.name == enc && header.keyID == kid
    }

    /**
     * The compact JWE of the response: claims `iss`, `aud`, `iat`, `exp` (`iat` + 300 s), `vp_token` and, when the
     * request had one, `state`; protected header `alg`, `enc`, the verifier key's `kid` and `cty: JWT`.
     *
     * @param vpToken the DCQL `{queryId: [tokens]}` object, or the bare token string for a request without DCQL.
     * @param verifierJwk the verifier's public key exactly as the engine resolved it (EC or RSA, with its `kid`).
     * @throws IllegalArgumentException when [verifierJwk] is not a usable public EC or RSA key, or [alg]/[enc] is
     *   not one this wallet can apply to it.
     */
    fun encrypt(
        vpToken: kotlinx.serialization.json.JsonElement,
        audience: String,
        state: String?,
        verifierJwk: JsonObject,
        alg: String,
        enc: String,
        nowSeconds: Long = System.currentTimeMillis() / 1000,
    ): String {
        val claims = buildJsonObject {
            put("iss", JsonPrimitive(JARM_ISSUER))
            put("aud", JsonPrimitive(audience))
            put("iat", JsonPrimitive(nowSeconds))
            put("exp", JsonPrimitive(nowSeconds + JARM_LIFETIME_SECONDS))
            put("vp_token", vpToken)
            if (!state.isNullOrEmpty()) put("state", JsonPrimitive(state))
        }
        val jwk = try {
            JWK.parse(verifierJwk.toString())
        } catch (e: Exception) {
            throw IllegalArgumentException("The verifier's encryption key is not a JWK")
        }
        require(!jwk.isPrivate) { "The verifier's encryption key must be a public key" }
        val header = JWEHeader.Builder(JWEAlgorithm.parse(alg), EncryptionMethod.parse(enc))
            .contentType("JWT")
            .apply { jwk.keyID?.let { keyID(it) } }
            .build()
        val encrypter = when (jwk) {
            is ECKey -> ECDHEncrypter(jwk)
            is RSAKey -> RSAEncrypter(jwk)
            else -> throw IllegalArgumentException("Unsupported verifier key type ${jwk.keyType}")
        }
        val obj = JWEObject(header, Payload(claims.toString()))
        try {
            obj.encrypt(encrypter)
        } catch (e: Exception) {
            throw IllegalArgumentException("The response could not be encrypted to the verifier's key with $alg/$enc")
        }
        val serialized = obj.serialize()
        // The engine refuses anything else, so a response it would refuse is never sent.
        require(isConformant(serialized, alg, enc, jwk.keyID)) { "The encrypted response is not a conformant compact JWE (too large or malformed)" }
        return serialized
    }
}
