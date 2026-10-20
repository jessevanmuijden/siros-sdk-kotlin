package org.siros.sdk.wallet.dcapi

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** [DCAPIRequestRules] and the entry selection of [DCAPIRequestParser.parse]. */
class DCAPIRequestRulesTest {
    private val ecKey = ECKeyGenerator(Curve.P_256).generate()
    private val origin = "https://rp.example"

    private fun query(format: String) = """{"credentials":[{"id":"q","format":"$format"}]}"""

    /** A signed entry; [expectedOrigins] is raw JSON, or null to omit the member. */
    private fun signed(format: String, expectedOrigins: String?, protocol: String = "openid4vp-v1-signed", nonce: String = "n"): String {
        val claims = JWTClaimsSet.parse(
            """{"client_id":"x509_san_dns:rp.example","nonce":"$nonce","dcql_query":${query(format)}""" +
                (expectedOrigins?.let { ""","expected_origins":$it""" } ?: "") + "}"
        )
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.ES256).jwk(ecKey.toPublicJWK()).build(), claims)
        jwt.sign(ECDSASigner(ecKey))
        return """{"protocol":"$protocol","data":{"request":"${jwt.serialize()}"}}"""
    }

    private fun unsigned(format: String, nonce: String = "n") =
        """{"protocol":"openid4vp-v1-unsigned","data":{"nonce":"$nonce","dcql_query":${query(format)}}}"""

    private fun envelope(vararg entries: String) = """{"requests":[${entries.joinToString(",")}]}"""

    private fun parse(
        raw: String,
        mode: ExpectedOriginsMode = ExpectedOriginsMode.OFF,
        callingOrigin: String = origin,
        hook: ((kotlinx.serialization.json.JsonObject?) -> Boolean)? = null,
    ): DCAPIRequest = DCAPIRequestParser.parse(
        raw,
        if (hook == null) DCAPIRequestRules(callingOrigin, mode) else DCAPIRequestRules(callingOrigin, mode, hook),
    )

    private fun assertRefused(raw: String, mode: ExpectedOriginsMode = ExpectedOriginsMode.OFF, callingOrigin: String = origin, message: String? = null) {
        val e = assertThrows(message, DCAPIRequestRefused::class.java) { parse(raw, mode, callingOrigin) }
        assertFalse(e.message!!.contains(callingOrigin))
        assertFalse(e.message!!.contains("zkp_req"))
    }

    // ---- circuit_zk: always signed + origin ----

    @Test
    fun `circuit_zk signed with a listed origin is accepted`() {
        val r = parse(envelope(signed("zkp_req", """["$origin","https://other.example"]""")))
        assertEquals("openid4vp-v1-signed", r.protocol)
        assertEquals(listOf(origin, "https://other.example"), r.expectedOrigins)
        assertTrue(r.hasExpectedOrigins)
    }

    @Test
    fun `circuit_zk with an origin that is not listed is refused, comparing exactly`() {
        for (listed in listOf("https://other.example", "https://rp.example/", "https://RP.example", "http://rp.example", "https://rp.example:443")) {
            assertRefused(envelope(signed("zkp_req", """["$listed"]""")), message = listed)
        }
    }

    @Test
    fun `circuit_zk with a missing or malformed expected_origins is refused`() {
        for (value in listOf(null, "[]", "\"$origin\"", "[1]", "[null]", "[\"$origin\",1]", "{}", "null")) {
            assertRefused(envelope(signed("zkp_req", value)), message = value.toString())
        }
    }

    @Test
    fun `circuit_zk unsigned is refused`() {
        assertRefused(envelope(unsigned("zkp_req")))
    }

    @Test
    fun `circuit_zk entry that claims the signed protocol but carries an unsigned body is refused`() {
        assertRefused(envelope("""{"protocol":"openid4vp-v1-signed","data":{"nonce":"n","dcql_query":${query("zkp_req")},"expected_origins":["$origin"]}}"""))
    }

    @Test
    fun `circuit_zk with the multisigned protocol is refused`() {
        assertRefused(envelope(signed("zkp_req", """["$origin"]""", protocol = "openid4vp-v1-multisigned")))
    }

    @Test
    fun `a circuit_zk query among other credential queries still needs the signed request`() {
        val claims = JWTClaimsSet.parse(
            """{"nonce":"n","dcql_query":{"credentials":[{"id":"a","format":"dc+sd-jwt"},{"id":"b","format":"zkp_req"}]}}"""
        )
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.ES256).jwk(ecKey.toPublicJWK()).build(), claims).also { it.sign(ECDSASigner(ecKey)) }
        // signed, but no expected_origins
        assertRefused(envelope("""{"protocol":"openid4vp-v1-signed","data":{"request":"${jwt.serialize()}"}}"""))
    }

    @Test
    fun `circuit_zk ignores the config mode`() {
        for (mode in ExpectedOriginsMode.values()) {
            assertRefused(envelope(signed("zkp_req", null)), mode)
            parse(envelope(signed("zkp_req", """["$origin"]""")), mode)
        }
    }

    // ---- entry selection ----

    @Test
    fun `an unsigned first entry is skipped in favour of a signed second one`() {
        val r = parse(envelope(unsigned("zkp_req", nonce = "first"), signed("zkp_req", """["$origin"]""", nonce = "second")))
        assertEquals("second", r.nonce)
        assertEquals("openid4vp-v1-signed", r.protocol)
    }

    @Test
    fun `the first acceptable entry wins when several are`() {
        val r = parse(envelope(signed("zkp_req", """["$origin"]""", nonce = "one"), signed("zkp_req", """["$origin"]""", nonce = "two")))
        assertEquals("one", r.nonce)
    }

    @Test
    fun `the refusal names the protocol of the first refused entry only`() {
        val e = assertThrows(DCAPIRequestRefused::class.java) {
            parse(envelope(unsigned("zkp_req"), signed("zkp_req", null, protocol = "openid4vp-v1-multisigned")))
        }
        assertEquals("openid4vp-v1-unsigned", e.protocol)
        assertEquals("DC API request refused (protocol=openid4vp-v1-unsigned)", e.message)
    }

    @Test
    fun `the default parse takes the first entry, unchanged`() {
        val raw = envelope(unsigned("zkp_req", nonce = "first"), signed("zkp_req", """["$origin"]""", nonce = "second"))
        assertEquals("first", DCAPIRequestParser.parse(raw).nonce)
        assertEquals("first", DCAPIRequestParser.parse(raw, DCAPIEntryPolicy.FIRST_ENTRY).nonce)
    }

    @Test
    fun `a malformed entry still fails the request instead of being skipped`() {
        assertThrows(DCAPIRequestException::class.java) {
            parse(envelope("""{"protocol":"openid4vp-v1-unsigned"}""", signed("zkp_req", """["$origin"]""")))
        }
    }

    // ---- gate for existing formats ----

    @Test
    fun `OFF ignores expected_origins for an existing format`() {
        parse(envelope(signed("dc+sd-jwt", """["https://other.example"]""")), ExpectedOriginsMode.OFF)
        parse(envelope(signed("dc+sd-jwt", null)), ExpectedOriginsMode.OFF)
        parse(envelope(signed("dc+sd-jwt", "[1]")), ExpectedOriginsMode.OFF)
    }

    @Test
    fun `IF_PRESENT enforces expected_origins only when the member exists`() {
        val mode = ExpectedOriginsMode.IF_PRESENT
        parse(envelope(signed("dc+sd-jwt", null)), mode)
        parse(envelope(signed("dc+sd-jwt", """["$origin"]""")), mode)
        assertRefused(envelope(signed("dc+sd-jwt", """["https://other.example"]""")), mode)
        assertRefused(envelope(signed("dc+sd-jwt", "[1]")), mode)
        assertRefused(envelope(signed("dc+sd-jwt", "[]")), mode)
    }

    @Test
    fun `REQUIRED rejects a signed request without a valid expected_origins`() {
        val mode = ExpectedOriginsMode.REQUIRED
        assertRefused(envelope(signed("dc+sd-jwt", null)), mode)
        assertRefused(envelope(signed("dc+sd-jwt", """["https://other.example"]""")), mode)
        parse(envelope(signed("dc+sd-jwt", """["$origin"]""")), mode)
    }

    @Test
    fun `the gate never touches an unsigned request`() {
        for (mode in ExpectedOriginsMode.values()) parse(envelope(unsigned("dc+sd-jwt")), mode)
    }

    @Test
    fun `an unsigned request's own expected_origins is not trusted or parsed`() {
        val raw = envelope("""{"protocol":"openid4vp-v1-unsigned","data":{"nonce":"n","expected_origins":["$origin"]}}""")
        val r = DCAPIRequestParser.parse(raw)
        assertNull(r.expectedOrigins)
        assertFalse(r.hasExpectedOrigins)
    }

    // ---- hook ----

    @Test
    fun `the requiresSignedRequest hook decides which queries need a signed request`() {
        val raw = envelope(unsigned("dc+sd-jwt"))
        parse(raw)
        assertThrows(DCAPIRequestRefused::class.java) { parse(raw, hook = { true }) }
    }

    @Test
    fun `the hook can only add requirements, a circuit_zk query is always signed and origin-bound`() {
        // A hook returning false does not let an unsigned (or unlisted-origin) circuit_zk request through.
        assertThrows(DCAPIRequestRefused::class.java) { parse(envelope(unsigned("zkp_req")), hook = { false }) }
        assertThrows(DCAPIRequestRefused::class.java) { parse(envelope(unsigned("zkp_req")), hook = { it == null }) }
    }

    @Test
    fun `without a query nothing requires a signed request by default`() {
        parse(envelope("""{"protocol":"openid4vp-v1-unsigned","data":{"nonce":"n"}}"""))
    }
}
