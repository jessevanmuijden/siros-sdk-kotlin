package org.siros.sdk.wallet.dcapi

import org.junit.Assert.assertEquals
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkCircuit
import uniffi.siros_dc_matcher_ffi.FfiCapability

/** How the wallet's circuits are declared to the matcher (the blob itself is built natively; see the device tests). */
class SirosCredentialRegistryCircuitZkTest {
    @Test
    fun aCircuitRegistersUnderItsIdAndUnderEachAlias() {
        val c = CircuitZkCircuit("sys", "c1", setOf("d"), aliases = setOf("old", "older"))
        assertEquals(
            listOf(
                FfiCapability("sys", mapOf("system_id" to "c1")),
                FfiCapability("sys", mapOf("system_id" to "old")),
                FfiCapability("sys", mapOf("system_id" to "older")),
            ),
            SirosCredentialRegistry.circuitCapabilities(c),
        )
    }

    @Test
    fun functionsAreDeclaredOnlyWhenTheCatalogSaysWhichThereAre() {
        val declared = CircuitZkCircuit("sys", "c1", setOf("d"), functions = setOf("pseudonym", "age_check"))
        assertEquals(
            mapOf("system_id" to "c1", "functions" to "age_check,pseudonym"),
            SirosCredentialRegistry.circuitCapabilities(declared).single().params,
        )
        val undeclared = CircuitZkCircuit("sys", "c1", setOf("d"))
        assertEquals(mapOf("system_id" to "c1"), SirosCredentialRegistry.circuitCapabilities(undeclared).single().params)
    }

    @Test
    fun credentialTypeAndCapabilitiesArePassedThroughVerbatim() {
        val caps = """{"schema":1,"unknown":"not read here"}"""
        val c = CircuitZkCircuit("sys", "c1", setOf("d"), functions = setOf("f"), credentialType = "d", capabilities = caps)
        assertEquals(
            mapOf("system_id" to "c1", "functions" to "f", "credential_type" to "d", "capabilities" to caps),
            SirosCredentialRegistry.circuitCapabilities(c).single().params,
        )
        // Each alias is registered with the same values.
        val aliased = SirosCredentialRegistry.circuitCapabilities(c.copy(aliases = setOf("old")))
        assertEquals(listOf("c1", "old"), aliased.map { it.params["system_id"] })
        assertEquals(listOf(caps, caps), aliased.map { it.params["capabilities"] })
    }

    @Test
    fun neitherIsRegisteredWhenTheCircuitHasNone() {
        val params = SirosCredentialRegistry.circuitCapabilities(CircuitZkCircuit("sys", "c1", setOf("d"))).single().params
        assertEquals(setOf("system_id"), params.keys)
    }
}
