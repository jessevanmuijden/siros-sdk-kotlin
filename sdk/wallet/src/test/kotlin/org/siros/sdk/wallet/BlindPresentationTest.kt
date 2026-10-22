// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.siros.sdk.transport.ResponseEncryptionRequest

/** The `vp_token` shape and the encrypted response of an engine-blind `direct_post.jwt` presentation. */
class BlindPresentationTest {
    private val verifier: ECKey = ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).keyID("v-1").generate()
    private val request = ResponseEncryptionRequest(
        jwk = Json.parseToJsonElement(verifier.toPublicJWK().toJSONString()).jsonObject,
        alg = "ECDH-ES",
        enc = "A128GCM",
    )

    @Test
    fun aDcqlPresentationIsAnObjectKeyedByQueryIdWithTokensGroupedInOrder() {
        val token = BlindPresentation.vpToken(listOf("pid" to "t1", "age" to "t2", "pid" to "t3"))
        assertEquals(
            JsonObject(
                mapOf(
                    "pid" to JsonArray(listOf(JsonPrimitive("t1"), JsonPrimitive("t3"))),
                    "age" to JsonArray(listOf(JsonPrimitive("t2"))),
                ),
            ),
            token,
        )
    }

    @Test
    fun aDcqlEntryWithoutAQueryIdIsLeftOutAsTheEngineDidAndNoQueryIdsMeansTheTokensAsOneString() {
        assertEquals(
            JsonObject(mapOf("pid" to JsonArray(listOf(JsonPrimitive("t1"))))),
            BlindPresentation.vpToken(listOf("pid" to "t1", null to "orphan", "" to "empty")),
        )
        assertEquals(JsonPrimitive("only"), BlindPresentation.vpToken(listOf(null to "only")))
        assertEquals(JsonPrimitive("a\nb"), BlindPresentation.vpToken(listOf(null to "a", null to "b")))
    }

    @Test
    fun theResponseJweDecryptsAtTheVerifierWithTheClaimsOfTheRequest() {
        // A sentinel with characters outside the base64url alphabet (a space, '!' and a non-ASCII one) cannot occur by
        // chance in a valid compact JWE, so its absence from the JWE says something and the same value must come back out.
        val sentinel = "secret vp token! \u2713"
        val jwe = BlindPresentation.responseJwe(request, "client-id", "st-1", listOf("pid" to sentinel))
        val obj = JWEObject.parse(jwe)
        obj.decrypt(ECDHDecrypter(verifier))
        val claims = Json.parseToJsonElement(obj.payload.toString()).jsonObject
        assertEquals("client-id", claims["aud"]!!.jsonPrimitive.content)
        assertEquals("st-1", claims["state"]!!.jsonPrimitive.content)
        assertEquals(JsonObject(mapOf("pid" to JsonArray(listOf(JsonPrimitive(sentinel))))), claims["vp_token"])
        assertEquals("v-1", obj.header.keyID)
        assertFalse("the token must not be readable in the JWE", jwe.contains(sentinel))
        assertFalse("nor in its decoded protected header", String(java.util.Base64.getUrlDecoder().decode(jwe.substringBefore('.'))).contains(sentinel))
    }

    @Test
    fun aVpTokenTheCallerAlreadyShapedIsEncryptedAsIs() {
        val shaped = JsonObject(mapOf("q" to JsonArray(listOf(JsonPrimitive("base64url-cbor")))))
        val jwe = BlindPresentation.responseJwe(request, "client-id", null, shaped)
        val obj = JWEObject.parse(jwe)
        obj.decrypt(ECDHDecrypter(verifier))
        assertEquals(shaped, Json.parseToJsonElement(obj.payload.toString()).jsonObject["vp_token"])
    }
}
