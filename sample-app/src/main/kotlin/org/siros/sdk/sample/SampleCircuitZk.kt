package org.siros.sdk.sample

import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkCircuitSource
import org.siros.sdk.credentials.NonDisclosurePolicy

/**
 * DEMO `circuit_zk` plumbing for the sample app, only used when the Request
 * policy setting turns `circuit_zk` on. Requests are planned by the SDK's
 * default planner (the shared matcher's); all the app supplies is the circuit
 * table, which is a stand-in too: one circuit, from the fake proof system, so a
 * verifier cannot accept what it makes.
 */
internal object SampleCircuitZk {
    /**
     * The circuit table of the REAL path (the policy's fake-prover switch off): the circuits of the circuit catalog, kept
     * current by the wallet it is given to. The default prover and its native libraries are the SDK's.
     */
    val catalogCircuits = org.siros.sdk.credentials.CatalogCircuitZkCircuitSource()

    /** The circuit table of the demo: one circuit serving nym_auth (and declaring that credential type), from the fake proof system. */
    val circuits = CircuitZkCircuitSource {
        listOf(CircuitZkCircuit(system = "demo-fake", circuitId = "demo-fake-circuit-v1", docTypes = setOf(NonDisclosurePolicy.NYM_AUTH_DOCTYPE), credentialType = NonDisclosurePolicy.NYM_AUTH_DOCTYPE))
    }
}
