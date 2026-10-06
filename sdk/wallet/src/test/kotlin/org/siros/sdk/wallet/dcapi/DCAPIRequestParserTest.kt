// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class DCAPIRequestParserTest {

    @Test
    fun `unwraps the requests envelope for an unsigned request`() {
        val rawRequestJson = """
            {"requests":[{"protocol":"openid4vp-v1-unsigned","data":{
                "client_id":"web-origin:https://verifier.example.com",
                "response_mode":"dc_api",
                "nonce":"test-nonce",
                "state":"test-state",
                "dcql_query":{"credentials":[]}
            }}]}
        """.trimIndent()

        val result = DCAPIRequestParser.parse(rawRequestJson)

        assertEquals("web-origin:https://verifier.example.com", result.clientId)
        assertEquals("dc_api", result.responseMode)
        assertEquals("test-nonce", result.nonce)
        assertEquals("test-state", result.state)
        assertEquals("openid4vp-v1-unsigned", result.protocol)
        assertNull(result.keyMaterial)
    }

    @Test
    fun `unwraps the requests envelope for a signed request`() {
        val ecKey = ECKeyGenerator(Curve.P_256).generate()
        val claims = JWTClaimsSet.Builder()
            .claim("client_id", "x509_san_dns:verifier.example.com")
            .claim("response_mode", "dc_api.jwt")
            .claim("nonce", "test-nonce")
            .claim("state", "test-state")
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).jwk(ecKey.toPublicJWK()).build()
        val signedJwt = SignedJWT(header, claims)
        signedJwt.sign(ECDSASigner(ecKey))
        val jwt = signedJwt.serialize()

        val rawRequestJson = """{"requests":[{"protocol":"openid4vp-v1-signed","data":{"request":"$jwt"}}]}"""

        val result = DCAPIRequestParser.parse(rawRequestJson)

        assertEquals("x509_san_dns:verifier.example.com", result.clientId)
        assertEquals("dc_api.jwt", result.responseMode)
        assertEquals("test-nonce", result.nonce)
        assertEquals("test-state", result.state)
        assertEquals("openid4vp-v1-signed", result.protocol)
        assertEquals(ecKey.keyID, result.keyMaterial?.jwk?.get("kid")?.toString()?.trim('"'))
    }

    @Test
    fun `state is null when absent from the request`() {
        val rawRequestJson = """
            {"requests":[{"protocol":"openid4vp-v1-unsigned","data":{
                "nonce":"test-nonce"
            }}]}
        """.trimIndent()

        val result = DCAPIRequestParser.parse(rawRequestJson)

        assertNull(result.state)
    }

    @Test
    fun `throws when the requests array is missing`() {
        val exception = assertThrows(DCAPIRequestException::class.java) {
            DCAPIRequestParser.parse("""{"client_id":"x"}""")
        }
        assertEquals("DC API request missing 'requests' array", exception.message)
    }

    @Test
    fun `throws when the requests array is empty`() {
        val exception = assertThrows(DCAPIRequestException::class.java) {
            DCAPIRequestParser.parse("""{"requests":[]}""")
        }
        assertEquals("DC API request's 'requests' array is empty", exception.message)
    }

    @Test
    fun `throws when the first entry has no data`() {
        val exception = assertThrows(DCAPIRequestException::class.java) {
            DCAPIRequestParser.parse("""{"requests":[{"protocol":"openid4vp-v1-unsigned"}]}""")
        }
        assertEquals("DC API request's first entry is missing 'data'", exception.message)
    }

    @Test
    fun `an unsigned request without transaction_data reports none`() {
        val raw = """{"requests":[{"protocol":"openid4vp-v1-unsigned","data":{"nonce":"n"}}]}"""

        assertEquals(false, DCAPIRequestParser.parse(raw).hasTransactionData)
    }

    @Test
    fun `an unsigned request carrying transaction_data reports it whatever the value`() {
        for (value in listOf("""["eyJ0eXBlIjoieCJ9"]""", "[]", "null", "\"x\"", "5")) {
            val raw = """{"requests":[{"protocol":"openid4vp-v1-unsigned","data":{"nonce":"n","transaction_data":$value}}]}"""

            assertEquals(value, true, DCAPIRequestParser.parse(raw).hasTransactionData)
        }
    }

    @Test
    fun `a signed request reports transaction_data from the verified payload only`() {
        val ecKey = ECKeyGenerator(Curve.P_256).generate()
        fun parse(claims: JWTClaimsSet): DCAPIRequest {
            val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.ES256).jwk(ecKey.toPublicJWK()).build(), claims)
            jwt.sign(ECDSASigner(ecKey))
            return DCAPIRequestParser.parse(
                """{"requests":[{"protocol":"openid4vp-v1-signed","data":{"request":"${jwt.serialize()}"}}]}"""
            )
        }

        val with = parse(
            JWTClaimsSet.Builder().claim("nonce", "n").claim("transaction_data", listOf("eyJ0eXBlIjoieCJ9")).build()
        )
        val without = parse(JWTClaimsSet.Builder().claim("nonce", "n").build())

        assertEquals(true, with.hasTransactionData)
        assertEquals(false, without.hasTransactionData)
    }
}
