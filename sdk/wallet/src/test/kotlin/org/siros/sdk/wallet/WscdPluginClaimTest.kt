// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.keystore.KeystoreManager

class WscdPluginClaimTest {
    private val keystores = mapOf("softkey" to mockk<KeystoreManager>(), "fido2" to mockk<KeystoreManager>())

    private fun config(claims: Map<String, String>, available: Map<String, KeystoreManager>? = keystores) =
        WalletConfig(backendUrl = "https://b.example", availableKeystores = available, wscdPluginClaims = claims)

    @Test
    fun theDefaultClaimsNothing() {
        assertTrue(WalletConfig(backendUrl = "https://b.example").wscdPluginClaims.isEmpty())
    }

    @Test
    fun aClaimPerRegisteredKeystoreIsAccepted() {
        for (ok in listOf("soft", "fido2", "r2ps", "a_b-c9", "x".repeat(64))) {
            assertEquals(mapOf("softkey" to ok), config(mapOf("softkey" to ok)).wscdPluginClaims)
        }
        assertEquals(mapOf("softkey" to "soft", "fido2" to "fido2"), config(mapOf("softkey" to "soft", "fido2" to "fido2")).wscdPluginClaims)
    }

    @Test
    fun aMalformedClaimIsRefusedAtConfigurationTime() {
        for (bad in listOf("", " ", "Soft", "so ft", "soft\n", "x".repeat(65), "sôft", "soft)(verified")) {
            try {
                config(mapOf("softkey" to bad))
                fail("accepted '$bad'")
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    @Test
    fun aClaimForAKeystoreThatIsNotRegisteredIsRefused() {
        for (c in listOf(mapOf("unknown" to "soft"))) {
            try { config(c); fail("accepted a claim for an unregistered keystore") } catch (_: IllegalArgumentException) { }
        }
        try { config(mapOf("softkey" to "soft"), available = null); fail("accepted a claim with no registry") } catch (_: IllegalArgumentException) { }
    }
}
