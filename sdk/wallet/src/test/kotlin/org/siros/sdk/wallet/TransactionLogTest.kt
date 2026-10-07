package org.siros.sdk.wallet

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class TransactionLogTest {
    private var slot: String? = null
    private var corrupt: String? = null
    private var readFails = false
    private var writeOk = true

    private fun store(max: Int = 3, maxRefused: Int = 100, dedup: Long = 60_000) = JsonTransactionLogStore(
        read = { if (readFails) throw IOException("keystore unavailable") else slot },
        write = { v -> if (writeOk) { slot = v; true } else false },
        keepCorrupt = { corrupt = it },
        maxEntries = max, maxRefused = maxRefused, refusalDedupMillis = dedup,
    )

    private fun entry(
        id: String,
        outcome: TransactionOutcome = TransactionOutcome.CONSENTED,
        at: Long = 1,
        reason: String? = null,
        verifier: String? = "v",
    ) = TransactionLogEntry(
        transactionId = id, transactionType = "urn:eudi:sca:payment:1", typeName = "Payment Confirmation",
        entities = mapOf("payee" to "Shop"), verifier = verifier, credential = "c", timestampMillis = at, outcome = outcome, reason = reason,
    )

    @Test
    fun `entries come back newest first and survive a restart`() = runBlocking {
        store().append(entry("a"))
        store().append(entry("b", TransactionOutcome.DECLINED))

        val reloaded = store().entries()

        assertEquals(listOf("b", "a"), reloaded.map { it.transactionId })
        assertEquals(TransactionOutcome.DECLINED, reloaded.first().outcome)
        assertEquals(mapOf("payee" to "Shop"), reloaded.first().entities)
    }

    @Test
    fun `the oldest entries are dropped past the cap`() = runBlocking {
        val s = store(max = 3)
        listOf("a", "b", "c", "d").forEach { s.append(entry(it)) }

        assertEquals(listOf("d", "c", "b"), s.entries().map { it.transactionId })
    }

    @Test
    fun `a flood of refusals never evicts a consented or declined record`() = runBlocking {
        val s = store(max = 5, maxRefused = 3, dedup = 0)
        s.append(entry("consented", TransactionOutcome.CONSENTED))
        s.append(entry("declined", TransactionOutcome.DECLINED))
        repeat(50) { s.append(entry("r$it", TransactionOutcome.REFUSED, reason = "r$it", at = it.toLong())) }

        val ids = s.entries().map { it.transactionId }
        assertTrue(ids.toString(), "consented" in ids && "declined" in ids)
        assertEquals(3, s.entries().count { it.outcome == TransactionOutcome.REFUSED })
        assertEquals(listOf("r49", "r48", "r47"), s.entries().filter { it.outcome == TransactionOutcome.REFUSED }.map { it.transactionId })
    }

    @Test
    fun `when the log is full of real attempts the oldest of those goes, and refusals go first`() = runBlocking {
        val s = store(max = 3, maxRefused = 3, dedup = 0)
        s.append(entry("a")); s.append(entry("b")); s.append(entry("x", TransactionOutcome.REFUSED, reason = "x")); s.append(entry("c"))

        assertEquals(listOf("c", "b", "a"), s.entries().map { it.transactionId })
    }

    @Test
    fun `an identical refusal within the window is written once`() = runBlocking {
        val s = store(max = 10, dedup = 60_000)
        s.append(entry("1", TransactionOutcome.REFUSED, at = 1_000, reason = "schemaViolation"))
        s.append(entry("2", TransactionOutcome.REFUSED, at = 2_000, reason = "schemaViolation"))
        s.append(entry("3", TransactionOutcome.REFUSED, at = 3_000, reason = "unsupportedType"))
        s.append(entry("4", TransactionOutcome.REFUSED, at = 4_000, reason = "schemaViolation", verifier = "other"))
        s.append(entry("5", TransactionOutcome.REFUSED, at = 90_000, reason = "unsupportedType"))

        assertEquals(listOf("5", "4", "3", "1"), s.entries().map { it.transactionId })
    }

    @Test
    fun `a slot that cannot be read is never overwritten from an empty list`() = runBlocking {
        val s = store()
        s.append(entry("precious"))
        val before = slot

        readFails = true
        val failure = runCatching { s.append(entry("new")) }.exceptionOrNull()
        val readFailure = runCatching { s.entries() }.exceptionOrNull()

        assertTrue("$failure", failure is IOException)
        assertTrue("$readFailure", readFailure is IOException)
        assertEquals("history untouched", before, slot)

        readFails = false
        assertEquals(listOf("new").filter { false } + listOf("precious"), s.entries().map { it.transactionId })
    }

    @Test
    fun `corrupt text is kept aside before a fresh log starts`() = runBlocking {
        slot = "{not json"
        val s = store()

        s.append(entry("z"))

        assertEquals("{not json", corrupt)
        assertEquals(listOf("z"), s.entries().map { it.transactionId })
    }

    @Test
    fun `a failed write is reported to the caller`() = runBlocking {
        val s = store()
        writeOk = false

        val failure = runCatching { s.append(entry("a")) }.exceptionOrNull()
        val clearFailure = runCatching { s.clear() }.exceptionOrNull()

        assertTrue("$failure", failure is IOException)
        assertTrue("$clearFailure", clearFailure is IOException)
    }

    @Test
    fun `clear empties the log`() = runBlocking {
        val s = store()
        s.append(entry("a"))
        s.clear()
        assertEquals(emptyList<TransactionLogEntry>(), s.entries())
        assertNull(slot)
    }

    @Test
    fun `the outcome is written in the contract's words`() = runBlocking {
        store().append(entry("a", TransactionOutcome.REFUSED, reason = "x"))
        assertTrue(slot!!.contains("\"outcome\":\"refused\""))
    }
}
