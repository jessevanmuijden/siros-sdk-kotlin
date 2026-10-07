package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.FakeSource
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.metadata
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.raw
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.request

/**
 * Issuer-supplied schemas are validated against verifier-supplied payloads:
 * unbounded work in either. Each case must come back as a TransactionDataError
 * within the time limit, never as a hang or a raw exception/Error.
 */
class TransactionSchemaBoundsTest {
    private var savedTimeout = 0L

    @Before fun lowerTimeout() { savedTimeout = TransactionSchemas.timeoutMillis; TransactionSchemas.timeoutMillis = 400 }
    @After fun restoreTimeout() { TransactionSchemas.timeoutMillis = savedTimeout }

    private val custom = "https://bank.example/trx"

    private fun run(schema: String, payload: String): Result<*> {
        val src = FakeSource(metadata(types = """{"$custom":{"schema":$schema}}"""))
        val e = TransactionDataEntry(raw(type = custom, payload = payload))
        return runCatching { runBlocking { TransactionDataValidator(src).validate(request(listOf(e))) } }
    }

    private fun assertRefusedQuickly(schema: String, payload: String, vararg reasons: TransactionDataReason) {
        val started = System.nanoTime()
        val r = run(schema, payload)
        val ms = (System.nanoTime() - started) / 1_000_000
        val e = r.exceptionOrNull()
        assertTrue("expected a TransactionDataError, got $e", e is TransactionDataError)
        assertTrue("${(e as TransactionDataError).reason}", e.reason in reasons)
        assertTrue("took ${ms}ms", ms < 5_000)
    }

    // `^(a+)+$` is NOT slow on the JDK's regex engine (it optimises that shape); `^(.*a){25}$` is, on this JVM.
    @Test
    fun `a catastrophic regex times out and is refused`() {
        val schema = """{"type":"object","properties":{"a":{"type":"string","pattern":"^(.*a){25}${'$'}"}}}"""
        assertRefusedQuickly(schema, """{"a":"${"a".repeat(30)}b"}""", TransactionDataReason.METADATA_UNAVAILABLE)
    }

    @Test
    fun `a reference loop is refused`() {
        assertRefusedQuickly(
            """{"${'$'}ref":"#"}""", """{"x":1}""",
            TransactionDataReason.METADATA_UNAVAILABLE, TransactionDataReason.SCHEMA_VIOLATION,
        )
        assertRefusedQuickly(
            """{"allOf":[{"${'$'}ref":"#"}]}""", """{"x":1}""",
            TransactionDataReason.METADATA_UNAVAILABLE, TransactionDataReason.SCHEMA_VIOLATION,
        )
    }

    @Test
    fun `a schema nested far beyond sanity is refused, not a stack overflow`() {
        val deep = "{\"not\":".repeat(20_000) + "{}" + "}".repeat(20_000)
        assertRefusedQuickly(deep, """{"x":1}""", TransactionDataReason.METADATA_UNAVAILABLE, TransactionDataReason.SCHEMA_VIOLATION)
    }

    @Test
    fun `a huge exponent in the payload neither hangs nor throws raw`() {
        val started = System.nanoTime()
        val r = run("""{"type":"object","properties":{"n":{"type":"number","multipleOf":7,"maximum":10}}}""", """{"n":1e999999999}""")
        assertTrue((System.nanoTime() - started) / 1_000_000 < 5_000)
        val e = r.exceptionOrNull()
        assertTrue("$e", e == null || e is TransactionDataError)
        // and the built-in path, which validates the amount as a number
        val builtIn = runCatching {
            runBlocking {
                TransactionDataValidator(FakeSource()).validate(
                    request(listOf(TransactionDataEntry(raw(payload = """{"transaction_id":"t","payee":{"name":"a","id":"b"},"currency":"EUR","amount":1e999999999}""")))),
                )
            }
        }.exceptionOrNull()
        assertTrue("$builtIn", builtIn == null || builtIn is TransactionDataError)
    }

    @Test
    fun `a healthy schema still validates quickly after the timeouts above`() {
        assertEquals(null, run("""{"type":"object","required":["n"]}""", """{"n":1}""").exceptionOrNull())
    }
}
