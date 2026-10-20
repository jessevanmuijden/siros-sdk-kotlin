package org.siros.sdk.sample

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.siros.sdk.credentials.ConsentEntry
import org.siros.sdk.credentials.ConsentItem
import org.siros.sdk.credentials.ConsentVerifier
import org.siros.sdk.credentials.CredentialRef
import org.siros.sdk.credentials.PresentationConsentRequest
import org.siros.sdk.credentials.PseudonymScope

@OptIn(ExperimentalCoroutinesApi::class)
class PresentationConsentGateTest {
    private fun request() = PresentationConsentRequest(
        ConsentVerifier("Shop", verifierId = "shop.example"),
        listOf(ConsentEntry(CredentialRef("Nym", null), listOf(ConsentItem.Pseudonym("known-offender-matching-ssc", PseudonymScope.PER_VERIFIER, true, false, "shop.example", null)))),
        requestSigned = true,
        locale = "en",
    )

    @Test
    fun `the gate shows the SDK's request and returns the user's answer`() = runTest(StandardTestDispatcher()) {
        val gate = PresentationConsentGate()
        assertNull(gate.pending.value)
        val shown = request()
        val result = async { gate.handler.confirm(shown) }
        advanceUntilIdle()
        assertEquals("Shop", gate.pending.value?.request?.verifier?.label)
        gate.answer(gate.pending.value!!, true)
        assertEquals(true, result.await())
        assertNull(gate.pending.value)
    }

    @Test
    fun `a decline is passed on, and an answer with nothing waiting is ignored`() = runTest(StandardTestDispatcher()) {
        val gate = PresentationConsentGate()
                val shown = request()
        val result = async { gate.handler.confirm(shown) }
        advanceUntilIdle()
        gate.answer(gate.pending.value!!, false)
        assertEquals(false, result.await())
    }

    @Test
    fun `when the SDK stops waiting the dialog goes away`() = runTest(StandardTestDispatcher()) {
        val gate = PresentationConsentGate()
        val result = async { gate.handler.confirm(request()) }
        advanceUntilIdle()
        assertNotNull(gate.pending.value)
        result.cancel()
        advanceUntilIdle()
        assertNull(gate.pending.value)
    }

    @Test
    fun `an overlapping request waits its turn, and a stale dialog cannot approve it - even with equal content`() = runTest(StandardTestDispatcher()) {
        val gate = PresentationConsentGate()
        // Equal content (a data class): identity, not equality, tells them apart.
        val a = request()
        val b = request()
        assertEquals(a, b)
        val first = async { gate.handler.confirm(a) }
        val second = async { gate.handler.confirm(b) }
        advanceUntilIdle()
        val onScreenA = gate.pending.value!!
        assertEquals(true, onScreenA.request === a)
        gate.answer(onScreenA, false)
        assertEquals(false, first.await())
        advanceUntilIdle()
        // B is shown even though its content equals A's, and A's late callback cannot approve it.
        val onScreenB = gate.pending.value
        assertNotNull(onScreenB)
        assertEquals(true, onScreenB!!.request === b)
        gate.answer(onScreenA, true)
        advanceUntilIdle()
        assertEquals(true, gate.pending.value === onScreenB)
        gate.answer(onScreenB, true)
        assertEquals(true, second.await())
    }
}
