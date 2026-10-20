// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import androidx.credentials.registry.provider.ClearCredentialRegistryRequest
import androidx.credentials.registry.provider.RegistryManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Does the platform accept a matcher the SDK supplies, and does the blob it
 * registers decode?
 *
 * On a device rather than in Robolectric because neither answer can be faked:
 * one is Play Services' own acceptance of our bytes, the other needs the real
 * native library behind the UniFFI bindings, which a JVM test cannot load at
 * all.
 *
 * Needs no wallet login and no credentials, which is what makes it automatable
 * when the full picker flow is not.
 */
@RunWith(AndroidJUnit4::class)
class SirosCredentialRegistryInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    /** The matcher ships in the AAR and is a real WebAssembly module. */
    @Test
    fun matcher_is_bundled_and_is_a_wasm_module() {
        val wasm = context.assets.open("matcher.wasm").use { it.readBytes() }

        // \0asm followed by version 1. A truncated or text-mangled asset would
        // still load as bytes and then fail deep inside Play Services with
        // nothing useful in the log.
        assertTrue("matcher.wasm is too small to be a module", wasm.size > 1024)
        assertEquals(0x00.toByte(), wasm[0])
        assertEquals('a'.code.toByte(), wasm[1])
        assertEquals('s'.code.toByte(), wasm[2])
        assertEquals('m'.code.toByte(), wasm[3])
        assertEquals(0x01.toByte(), wasm[4])
    }

    /**
     * The blob encoder runs, which means the native library loaded.
     *
     * Worth asserting separately from registration: a missing or wrong-ABI
     * `.so` fails here with a linkage error, while a registration failure
     * looks the same from the outside as the platform refusing us.
     */
    @Test
    fun the_native_encoder_produces_a_blob() {
        val blob = SirosCredentialRegistry.buildBlob(emptyList(), emptyList())
        assertTrue("expected CBOR from the encoder", blob.isNotEmpty())
    }

    /** ISO namespaces keep their dots; only the element identifier splits off. */
    @Test
    fun mdoc_claim_keys_split_on_the_last_dot() {
        assertEquals(
            listOf("org.iso.18013.5.1", "family_name"),
            SirosCredentialRegistry.splitClaimKey("mso_mdoc", "org.iso.18013.5.1.family_name"),
        )
        // JSON-based credentials keep the key whole - theirs are not paths.
        assertEquals(
            listOf("given_name"),
            SirosCredentialRegistry.splitClaimKey("dc+sd-jwt", "given_name"),
        )
    }

    /**
     * The platform accepts a registration carrying our own matcher.
     *
     * A rejection surfaces as an exception, so completing without throwing is
     * the assertion. Registering an empty credential set would clear the
     * registry instead, so this goes through the encoder with nothing to
     * encode and registers that.
     */
    @Test
    fun play_services_accepts_our_matcher() = runTest {
        val matcher = context.assets.open("matcher.wasm").use { it.readBytes() }
        val blob = SirosCredentialRegistry.buildBlob(emptyList(), emptyList())

        try {
            RegistryManager.create(context).registerCredentials(
                object : androidx.credentials.registry.provider.digitalcredentials
                .DigitalCredentialRegistry(
                    id = SirosCredentialRegistry.REGISTRY_ID,
                    credentials = blob,
                    matcher = matcher,
                ) {},
            )
        } finally {
            // Device-global and outliving the test process, so a leftover
            // registry would change what a later run starts from.
            RegistryManager.create(context)
                .clearCredentialRegistry(ClearCredentialRegistryRequest(true))
        }
    }

    /**
     * The circuits the wallet registers decide what the matcher offers for a
     * `circuit_zk` request: with the circuit registered a request is
     * satisfiable, the verifier's `system_id_values` are honoured (by id and
     * by alias), and with no circuit registered nothing is offered.
     */
    @Test
    fun registered_circuits_decide_circuit_zk_matching() {
        val nym = "eu.europa.ec.eudi.nym_auth.1"
        val credential = org.siros.sdk.credentials.StoredCredential(
            id = 7L, format = "mso_mdoc", raw = "",
            metadata = org.siros.sdk.credentials.CredentialMetadata(doctype = nym), batchId = 7L, instanceId = 0,
        )
        val circuit = org.siros.sdk.credentials.CircuitZkCircuit(
            "longfellow-libzk-v1", "urn:c:1", setOf(nym), functions = setOf("age_check"), aliases = setOf("urn:c:old"),
        )
        val query = """{"credentials":[{"id":"q","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"$nym"},
            "_req":[{"fn_id":"age_check","return":"a","params":{"ge":"2008-10-10"}}]}]}"""
        fun satisfiable(circuits: List<org.siros.sdk.credentials.CircuitZkCircuit>, circuitIds: String?, q: String = query): Boolean {
            val blob = SirosCredentialRegistry.buildBlob(listOf(credential), emptyList(), icons = mapOf(7L to byteArrayOf(1)), circuitZkCircuits = circuits)
            val cm = circuitIds?.let { """{"vp_formats_supported":{"zkp_req":{"system_id_values":$it}}}""" }
            return uniffi.siros_dc_matcher_ffi.matchDcqlWithContext(blob, q, cm).satisfiable
        }
        assertTrue(satisfiable(listOf(circuit), null))
        assertTrue(satisfiable(listOf(circuit), """["urn:c:1"]"""))
        assertTrue("an alias is registered too", satisfiable(listOf(circuit), """["urn:c:old"]"""))
        assertEquals(false, satisfiable(listOf(circuit), """["urn:other"]"""))
        assertEquals(false, satisfiable(emptyList(), null))
        // The declared functions bound what is offered.
        val other = query.replace("age_check", "pseudonym")
        assertEquals(false, satisfiable(listOf(circuit), null, other))
    }

    /** A circuit's `credential_type` reaches the matcher: it is offered only for a request naming that type. */
    @Test
    fun a_circuits_credential_type_restricts_what_it_is_offered_for() {
        val nym = "eu.europa.ec.eudi.nym_auth.1"
        val credential = org.siros.sdk.credentials.StoredCredential(
            id = 7L, format = "mso_mdoc", raw = "",
            metadata = org.siros.sdk.credentials.CredentialMetadata(doctype = nym), batchId = 7L, instanceId = 0,
        )
        fun satisfiable(credentialType: String?, meta: String): Boolean {
            val circuit = org.siros.sdk.credentials.CircuitZkCircuit("longfellow-libzk-v1", "urn:c:1", setOf(nym), credentialType = credentialType)
            val blob = SirosCredentialRegistry.buildBlob(listOf(credential), emptyList(), icons = mapOf(7L to byteArrayOf(1)), circuitZkCircuits = listOf(circuit))
            val q = """{"credentials":[{"id":"q","format":"zkp_req","meta":$meta,
                "_req":[{"fn_id":"age_check","return":"a","params":{"ge":"2008-10-10"}}]}]}"""
            return uniffi.siros_dc_matcher_ffi.matchDcqlWithContext(blob, q, null).satisfiable
        }
        assertTrue(satisfiable(nym, """{"source_format":"mso_mdoc","doctype_value":"$nym"}"""))
        assertEquals("a circuit for another type", false, satisfiable("eu.example.other.1", """{"source_format":"mso_mdoc","doctype_value":"$nym"}"""))
        assertEquals("a restricted circuit needs the request to name a type", false, satisfiable(nym, "{}"))
        assertTrue("unrestricted, as before", satisfiable(null, "{}"))
    }
}
