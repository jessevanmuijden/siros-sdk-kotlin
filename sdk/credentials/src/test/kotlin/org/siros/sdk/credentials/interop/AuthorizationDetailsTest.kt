package org.siros.sdk.credentials.interop

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthorizationDetailsTest {

    @Test
    fun `a known configuration is asked for by credential_configuration_id`() {
        val details = AuthorizationDetails.build("pid")
        assertEquals(1, details!!.size)
        assertEquals("openid_credential", details[0].type)
        assertEquals("pid", details[0].credentialConfigurationId)
    }

    @Test
    fun `nothing is asked for when the configuration is unknown`() {
        // The offer could not be resolved, so there is nothing to name. The
        // `scope` path is left exactly as it was.
        assertNull(AuthorizationDetails.build(null))
        assertNull(AuthorizationDetails.build(""))
        assertNull(AuthorizationDetails.build("   "))
    }

    @Test
    fun `an Authorization Server that lists its types without openid_credential is taken at its word`() {
        assertNull(AuthorizationDetails.build("pid", advertisedTypes = listOf("something_else")))
        assertNull(AuthorizationDetails.build("pid", advertisedTypes = emptyList()))
    }

    @Test
    fun `an Authorization Server that lists openid_credential gets the details`() {
        val details = AuthorizationDetails.build("pid", advertisedTypes = listOf("openid_credential"))
        assertEquals("pid", details!!.single().credentialConfigurationId)
    }

    @Test
    fun `unknown Authorization Server capability is not a reason to withhold`() {
        // On the engine-driven transports the AS is discovered server-side, so
        // the wallet usually holds no metadata. Sending intent the Issuer may
        // ignore is safe; withholding it fails the requirement outright.
        val details = AuthorizationDetails.build("pid", advertisedTypes = null)
        assertEquals("pid", details!!.single().credentialConfigurationId)
    }

    @Test
    fun `the wire shape is what OID4VCI and the engine expect`() {
        // Field names have to match go-wallet-backend's FlowStartMessage and
        // wallet-frontend's flow_start exactly - all three talk to the same
        // issuers.
        val encoded = Json.encodeToString(
            kotlinx.serialization.builtins.ListSerializer(AuthorizationDetail.serializer()),
            AuthorizationDetails.build("pid")!!,
        )
        assertTrue(encoded, encoded.contains("\"type\":\"openid_credential\""))
        assertTrue(encoded, encoded.contains("\"credential_configuration_id\":\"pid\""))
    }
}
