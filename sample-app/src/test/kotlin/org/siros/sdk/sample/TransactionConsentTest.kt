package org.siros.sdk.sample

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.wallet.TransactionConsentEntry
import org.siros.sdk.wallet.TransactionConsentField
import org.siros.sdk.wallet.TransactionConsentRequest

@OptIn(ExperimentalCoroutinesApi::class)
class TransactionConsentTest {
    private fun entry(vararg levels: Int) = TransactionConsentEntry(
        title = "t", typeName = "Payment Confirmation",
        fields = levels.mapIndexed { i, l -> TransactionConsentField("label$i", "value$i", l) },
        affirmativeLabel = "Pay", denialLabel = null, securityHint = null,
    )

    private fun request() = TransactionConsentRequest("Shop", "Card", listOf(entry(1)), requestSigned = null, locale = "en")

    @Test
    fun `level 1 is prominent, 2 and 3 are on the main screen, 4 is omitted`() {
        val layout = TransactionConsentLayout.of(entry(4, 3, 1, 2, 4, 1))

        assertEquals(listOf("label2", "label5"), layout.prominent.map { it.label })
        assertEquals(listOf("label1", "label3"), layout.main.map { it.label })
    }

    @Test
    fun `every reason has its own wording`() {
        val res = TransactionDataReason.values().map { transactionRefusalMessageRes(it) }

        assertEquals(TransactionDataReason.values().size, res.toSet().size)
        assertTrue(res.all { it != 0 })
    }

    @Test
    fun `the gate shows the request and returns the user's answer`() = runTest(StandardTestDispatcher()) {
        val gate = TransactionConsentGate()
        assertNull(gate.pending.value)

        val result = async { gate.handler.confirm(request()) }
        advanceUntilIdle()
        assertNotNull(gate.pending.value)
        gate.answer(true)

        assertEquals(true, result.await())
        assertNull(gate.pending.value)
    }

    @Test
    fun `a decline is passed on`() = runTest(StandardTestDispatcher()) {
        val gate = TransactionConsentGate()
        val result = async { gate.handler.confirm(request()) }
        advanceUntilIdle()

        gate.answer(false)

        assertEquals(false, result.await())
    }

    @Test
    fun `when the SDK stops waiting the dialog goes away`() = runTest(StandardTestDispatcher()) {
        val gate = TransactionConsentGate()
        val result = async { gate.handler.confirm(request()) }
        advanceUntilIdle()
        assertNotNull(gate.pending.value)

        result.cancel()
        advanceUntilIdle()

        assertNull(gate.pending.value)
    }

    @Test
    fun `an answer with nothing waiting is ignored`() {
        TransactionConsentGate().answer(true)
    }
}
