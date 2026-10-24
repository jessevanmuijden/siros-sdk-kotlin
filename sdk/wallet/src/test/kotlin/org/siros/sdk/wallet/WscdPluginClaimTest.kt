// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

class WscdPluginClaimTest {
    @Test
    fun theDefaultClaimsNothing() {
        assertNull(WalletConfig(backendUrl = "https://b.example").wscdPluginClaim)
    }

    @Test
    fun aWellFormedPluginNameIsAccepted() {
        for (ok in listOf("soft", "fido2", "r2ps", "a_b-c9", "x".repeat(64))) {
            assertEquals(ok, WalletConfig(backendUrl = "https://b.example", wscdPluginClaim = ok).wscdPluginClaim)
        }
    }

    @Test
    fun anythingElseIsRefusedAtConfigurationTime() {
        for (bad in listOf("", " ", "Soft", "so ft", "soft\n", "x".repeat(65), "sôft", "soft)(verified")) {
            try {
                WalletConfig(backendUrl = "https://b.example", wscdPluginClaim = bad)
                fail("accepted '$bad'")
            } catch (_: IllegalArgumentException) {
            }
        }
    }
}
