// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.siros.sdk.wallet.WalletState

/**
 * The wallet reports its own pre-engine steps (WalletState.FlowActive.STEP_*)
 * so the flow screen can show something from the instant the user taps. A
 * token the sample app has no label for would render as the generic
 * "Processing…" - technically feedback, but the "initializing" state is the
 * whole point of those steps.
 */
class FlowStepLabelTest {

    private val preEngineSteps = listOf(
        WalletState.FlowActive.STEP_INITIALIZING,
        WalletState.FlowActive.STEP_CONNECTING_ENGINE,
        WalletState.FlowActive.STEP_ESTABLISHING_SESSION,
        WalletState.FlowActive.STEP_CHECKING_ENTITLEMENT,
        WalletState.FlowActive.STEP_PREPARING_ISSUANCE,
        WalletState.FlowActive.STEP_STARTING_FLOW,
    )

    @Test
    fun `every pre-engine step has its own label, not the generic fallback`() {
        for (step in preEngineSteps) {
            assertNotEquals(step, R.string.flow_step_unknown, flowStepLabelRes(step))
        }
        assertEquals(R.string.flow_step_initializing, flowStepLabelRes(WalletState.FlowActive.STEP_INITIALIZING))
    }

    @Test
    fun `pre-engine steps show an indeterminate spinner, not a bogus fraction`() {
        for (step in preEngineSteps) {
            assertNull(step, flowStepProgress("issuance", step))
        }
    }

    @Test
    fun `the initializing label exists in every shipped language`() {
        val expected = mapOf(
            "values" to "Initializing…",
            "values-sv" to "Initierar…",
            "values-fi" to "Alustetaan…",
            "values-el" to "Αρχικοποίηση…",
            "values-pt" to "A iniciar…",
        )
        for ((dir, text) in expected) {
            val file = File("src/main/res/$dir/strings.xml")
            assertNotNull("$file must exist (tests run from the module directory)", file.takeIf { it.exists() })
            val line = file.readLines().singleOrNull { it.contains("name=\"flow_step_initializing\"") }
            assertNotNull("$dir is missing flow_step_initializing", line)
            // Resource files escape the ellipsis as …; compare on the unescaped form.
            val value = line!!.substringAfter(">").substringBefore("</string>").replace("\\u2026", "…")
            assertEquals(dir, text, value)
        }
    }
}

class SilentCancellationTest {
    @org.junit.Test
    fun `a user cancel is silent, an internal timeout is a failure`() {
        org.junit.Assert.assertTrue(isSilentCancellation(kotlinx.coroutines.CancellationException("cancelled")))
        org.junit.Assert.assertFalse(isSilentCancellation(IllegalStateException("x")))
        val timeout = try {
            kotlinx.coroutines.runBlocking { kotlinx.coroutines.withTimeout(1) { kotlinx.coroutines.delay(1000) } }
            null
        } catch (e: kotlinx.coroutines.TimeoutCancellationException) { e }
        org.junit.Assert.assertNotNull(timeout)
        org.junit.Assert.assertFalse(isSilentCancellation(timeout!!))
    }
}
