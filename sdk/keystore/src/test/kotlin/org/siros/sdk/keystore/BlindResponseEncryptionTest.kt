// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** The wallet-held response-encryption key and the JARM builder of the engine-blind encryption contract. */
class BlindResponseEncryptionTest {

    /** What an issuer does: encrypt [plaintext] to the wallet's public JWK. */
    private fun issuerEncrypt(jwk: JsonObject, alg: String, enc: String, plaintext: String): String {
        val key = ECKey.parse(jwk.toString())
        val header = JWEHeader.Builder(JWEAlgorithm.parse(alg), EncryptionMethod.parse(enc)).build()
        val obj = JWEObject(header, Payload(plaintext))
        obj.encrypt(ECDHEncrypter(key))
        return obj.serialize()
    }

    private val algs = listOf("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW")
    private val encs = listOf("A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512")

    @Test
    fun theKeyOpensAnIssuerJweForEveryNegotiableAlgAndEnc() {
        for (alg in algs) for (enc in encs) {
            val key = CredentialResponseKey.generate(alg, enc)!!
            val plaintext = """{"credentials":[{"credential":"c-$alg-$enc"}]}"""
            assertEquals("$alg/$enc", plaintext, key.decrypt(issuerEncrypt(key.publicJwk, alg, enc, plaintext)))
        }
    }

    @Test
    fun theAdvertisedPublicJwkIsAnEncryptionP256KeyWithoutTheirPrivatePart() {
        val jwk = CredentialResponseKey.generate("ECDH-ES+A256KW", "A128GCM")!!.publicJwk
        assertEquals("EC", jwk["kty"]!!.jsonPrimitive.content)
        assertEquals("P-256", jwk["crv"]!!.jsonPrimitive.content)
        assertEquals("enc", jwk["use"]!!.jsonPrimitive.content)
        assertEquals("ECDH-ES+A256KW", jwk["alg"]!!.jsonPrimitive.content)
        assertTrue(jwk.containsKey("x") && jwk.containsKey("y"))
        assertFalse("the private part must never leave the wallet", jwk.containsKey("d"))
        assertFalse(ECKey.parse(jwk.toString()).isPrivate)
    }

    @Test
    fun everyGenerateYieldsAFreshKey() {
        val a = CredentialResponseKey.generate("ECDH-ES", "A256GCM")!!
        val b = CredentialResponseKey.generate("ECDH-ES", "A256GCM")!!
        assertNotEquals(a.publicJwk, b.publicJwk)
        // A JWE for one key does not open under the other.
        val forA = issuerEncrypt(a.publicJwk, "ECDH-ES", "A256GCM", "x")
        assertThrows(IllegalArgumentException::class.java) { b.decrypt(forA) }
    }

    @Test
    fun aPairTheWalletCannotDecryptYieldsNoKey() {
        assertNull(CredentialResponseKey.generate("RSA-OAEP", "A128GCM"))
        assertNull(CredentialResponseKey.generate("ECDH-ES", "A128KW"))
        assertNull(CredentialResponseKey.generate("A256KW", "A256GCM"))
        assertNull(CredentialResponseKey.generate("dir", "A128GCM"))
    }

    @Test
    fun aResponseUsingAnotherPairThanTheNegotiatedOneIsRefused() {
        val key = CredentialResponseKey.generate("ECDH-ES", "A256GCM")!!
        val otherEnc = issuerEncrypt(key.publicJwk, "ECDH-ES", "A128GCM", "x")
        assertThrows(IllegalArgumentException::class.java) { key.decrypt(otherEnc) }
        val otherAlg = issuerEncrypt(key.publicJwk, "ECDH-ES+A256KW", "A256GCM", "x")
        assertThrows(IllegalArgumentException::class.java) { key.decrypt(otherAlg) }
    }

    @Test
    fun aValueThatIsNotACompactJweIsRefusedWithoutEchoingIt() {
        val key = CredentialResponseKey.generate("ECDH-ES", "A256GCM")!!
        for (bad in listOf("", "not-a-jwe", "a.b.c.d.e", """{"credentials":[]}""")) {
            val e = assertThrows(IllegalArgumentException::class.java) { key.decrypt(bad) }
            if (bad.isNotEmpty()) assertFalse(e.message!!.contains(bad))
        }
    }

    @Test
    fun aTamperedCiphertextIsRefused() {
        val key = CredentialResponseKey.generate("ECDH-ES", "A256GCM")!!
        val jwe = issuerEncrypt(key.publicJwk, "ECDH-ES", "A256GCM", "secret-credential")
        val parts = jwe.split(".").toMutableList()
        parts[3] = parts[3].reversed()
        val e = assertThrows(IllegalArgumentException::class.java) { key.decrypt(parts.joinToString(".")) }
        assertFalse(e.message!!.contains("secret-credential"))
    }

    @Test
    fun theKeyPrintsNothing() {
        val key = CredentialResponseKey.generate("ECDH-ES", "A256GCM")!!
        assertFalse(key.toString().contains(key.publicJwk["x"]!!.jsonPrimitive.content))
    }

    // ---- JARM ----

    private val verifier: ECKey = ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).keyID("verifier-key-1").generate()
    private fun publicJwk(k: ECKey): JsonObject = Json.parseToJsonElement(k.toPublicJWK().toJSONString()).jsonObject

    private fun decryptJarm(jwe: String, key: ECKey = verifier): Pair<JWEHeader, JsonObject> {
        val obj = JWEObject.parse(jwe)
        obj.decrypt(ECDHDecrypter(key))
        return obj.header to Json.parseToJsonElement(obj.payload.toString()).jsonObject
    }

    @Test
    fun theJarmResponseDecryptsAtTheVerifierWithTheContractClaimsAndHeader() {
        val vpToken = buildJsonObject { put("pid", JsonArray(listOf(JsonPrimitive("tok-1")))) }
        val jwe = AuthorizationResponseEncryption.encrypt(
            vpToken, "x509_san_dns:verifier.example", "state-123", publicJwk(verifier), "ECDH-ES", "A128GCM", nowSeconds = 1_700_000_000,
        )
        val (header, claims) = decryptJarm(jwe)
        assertEquals("ECDH-ES", header.algorithm.name)
        assertEquals("A128GCM", header.encryptionMethod.name)
        assertEquals("verifier-key-1", header.keyID)
        assertEquals("JWT", header.contentType)
        assertEquals("https://self-issued.me/v2", claims["iss"]!!.jsonPrimitive.content)
        assertEquals("x509_san_dns:verifier.example", claims["aud"]!!.jsonPrimitive.content)
        assertEquals(1_700_000_000L, claims["iat"]!!.jsonPrimitive.content.toLong())
        assertEquals(1_700_000_300L, claims["exp"]!!.jsonPrimitive.content.toLong())
        assertEquals("state-123", claims["state"]!!.jsonPrimitive.content)
        assertEquals(vpToken, claims["vp_token"])
    }

    @Test
    fun theJarmResponseOmitsStateWhenTheRequestHadNone() {
        for (state in listOf(null, "")) {
            val jwe = AuthorizationResponseEncryption.encrypt(JsonPrimitive("tok"), "aud", state, publicJwk(verifier), "ECDH-ES", "A128GCM")
            val claims = decryptJarm(jwe).second
            assertFalse(claims.containsKey("state"))
            assertEquals("tok", claims["vp_token"]!!.jsonPrimitive.content)
        }
    }

    @Test
    fun theJarmResponseHonoursTheRequestedAlgAndEnc() {
        for ((alg, enc) in listOf("ECDH-ES+A256KW" to "A256GCM", "ECDH-ES" to "A128CBC-HS256", "ECDH-ES+A128KW" to "A256CBC-HS512")) {
            val header = decryptJarm(AuthorizationResponseEncryption.encrypt(JsonPrimitive("t"), "a", null, publicJwk(verifier), alg, enc)).first
            assertEquals(alg, header.algorithm.name)
            assertEquals(enc, header.encryptionMethod.name)
        }
    }

    @Test
    fun theJarmResponseCanBeEncryptedToAnRsaVerifierKey() {
        val rsa = RSAKeyGenerator(2048).keyUse(KeyUse.ENCRYPTION).keyID("rsa-1").generate()
        val jwe = AuthorizationResponseEncryption.encrypt(
            JsonPrimitive("tok"), "aud", "s", Json.parseToJsonElement(rsa.toPublicJWK().toJSONString()).jsonObject, "RSA-OAEP-256", "A128GCM",
        )
        val obj = JWEObject.parse(jwe)
        obj.decrypt(RSADecrypter(rsa as RSAKey))
        assertEquals("tok", Json.parseToJsonElement(obj.payload.toString()).jsonObject["vp_token"]!!.jsonPrimitive.content)
        assertEquals("rsa-1", obj.header.keyID)
    }

    @Test
    fun theJarmBuilderRefusesAPrivateKeyAnUnknownPairAndAGarbageJwk() {
        val priv = Json.parseToJsonElement(verifier.toJSONString()).jsonObject
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationResponseEncryption.encrypt(JsonPrimitive("t"), "a", null, priv, "ECDH-ES", "A128GCM")
        }
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationResponseEncryption.encrypt(JsonPrimitive("t"), "a", null, publicJwk(verifier), "ECDH-ES", "NOPE")
        }
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationResponseEncryption.encrypt(JsonPrimitive("t"), "a", null, buildJsonObject { put("kty", JsonPrimitive("EC")) }, "ECDH-ES", "A128GCM")
        }
        // An EC key cannot take an RSA key-management algorithm.
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationResponseEncryption.encrypt(JsonPrimitive("t"), "a", null, publicJwk(verifier), "RSA-OAEP", "A128GCM")
        }
    }

    @Test
    fun theJarmJweCarriesNoPlaintextToken() {
        val jwe = AuthorizationResponseEncryption.encrypt(JsonPrimitive("very-secret-vp-token"), "aud", null, publicJwk(verifier), "ECDH-ES", "A128GCM")
        assertFalse(jwe.contains("very-secret-vp-token"))
    }
}
