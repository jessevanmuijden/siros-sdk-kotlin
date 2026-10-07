// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertThrows
import org.junit.Test
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor

/**
 * [VegaProofSystem.validateCircuitParams] - checks the real circuit
 * catalog's own published `params` (confirmed live against the deployed
 * `vega-mc-p256-v1-*-key-r12` entries: `curve: "P-256"`, `numClaims: "4"`)
 * against what this class hardcodes, so a future circuit version whose
 * shape has genuinely changed fails fast and locally, with a clear
 * diagnostic - instead of only surfacing as an opaque native prove()/verify()
 * failure much later, after spending a real 100+MB download+decompress on a
 * circuit this class can't actually use anyway.
 */
class VegaProofSystemTest {

    private fun descriptor(params: Map<String, String>) = ZkCircuitDescriptor(
        id = "vega-mc-p256-v1-prover-key-r12",
        system = "vega-mc",
        systemVersion = "12",
        params = JsonObject(params.mapValues { JsonPrimitive(it.value) }),
    )

    private fun vegaProofSystem() = VegaProofSystem(ZkCircuitClient())

    @Test
    fun validateCircuitParams_realCatalogShape_passes() {
        vegaProofSystem().validateCircuitParams(
            descriptor(mapOf("curve" to "P-256", "numClaims" to "4", "maxClaimBytes" to "176")),
        )
    }

    @Test
    fun validateCircuitParams_wrongCurve_throws() {
        assertThrows(IllegalArgumentException::class.java) {
            vegaProofSystem().validateCircuitParams(
                descriptor(mapOf("curve" to "P-384", "numClaims" to "4")),
            )
        }
    }

    @Test
    fun validateCircuitParams_wrongNumClaims_throws() {
        assertThrows(IllegalArgumentException::class.java) {
            vegaProofSystem().validateCircuitParams(
                descriptor(mapOf("curve" to "P-256", "numClaims" to "8")),
            )
        }
    }

    @Test
    fun validateCircuitParams_missingParams_throws() {
        assertThrows(IllegalArgumentException::class.java) {
            vegaProofSystem().validateCircuitParams(descriptor(emptyMap()))
        }
    }
}
