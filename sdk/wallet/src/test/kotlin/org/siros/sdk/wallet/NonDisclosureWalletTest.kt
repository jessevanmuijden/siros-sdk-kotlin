package org.siros.sdk.wallet

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.wallet.dcapi.DCAPIRequest
import org.siros.sdk.wallet.dcapi.DCAPIRequestKeyMaterial

/** The consent summary of a circuit_zk request: no credential values, a verifier label from authenticated sources. */
class NonDisclosureWalletTest {
    private val plan = CircuitZkPlan(
        listOf(
            CircuitZkFunction("pseudonym", "n", Json.parseToJsonElement("""{"config":"known-offender-matching-psc"}""").jsonObject),
            CircuitZkFunction("age_check", "a", Json.parseToJsonElement("""{"ge":"2000-01-01"}""").jsonObject),
        ),
    )

    private fun request(clientId: String?, signed: Boolean) = DCAPIRequest(
        clientId = clientId, responseMode = "dc_api", nonce = "n", dcqlQuery = null, clientMetadata = null,
        keyMaterial = if (signed) DCAPIRequestKeyMaterial(x5c = listOf("AAAA")) else null,
        protocol = if (signed) "openid4vp-v1-signed" else "openid4vp-v1-unsigned", state = null,
    )

    @Test
    fun `the consent summary names the verifier from authenticated sources only and holds no credential value`() {
        val origin = "https://rp.example"
        // The PDP's name wins.
        assertEquals("Example RP", circuitZkConsentSummary(plan, TrustResult(trusted = true, entityName = "Example RP"), request("x509_san_dns:rp.example", true), origin).verifierLabel)
        // Else the verified client id of a signed request.
        val fromClientId = circuitZkConsentSummary(plan, TrustResult(trusted = true), request("x509_san_dns:rp.example", true), origin)
        assertTrue(fromClientId.verifierLabel.contains("rp.example"))
        assertFalse(fromClientId.verifierLabel.contains("x509_san_dns:"))
        // An unsigned request's client_id is unauthenticated: the platform origin is used.
        assertEquals(origin, circuitZkConsentSummary(plan, TrustResult(trusted = true), request("evil.example", false), origin).verifierLabel)
        assertEquals("known-offender-matching-psc", fromClientId.pseudonym?.config)
        assertEquals("2000-01-01", fromClientId.ageRange?.ge)
        assertNull(fromClientId.ageRange?.le)
    }
}
