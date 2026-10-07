package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.keystore.AuthenticationCategory
import org.siros.sdk.keystore.AuthenticationFactor
import org.siros.sdk.wallet.AuthenticationFactorsProvider
import org.siros.sdk.wallet.ConservativeAuthenticationFactorsProvider
import org.siros.sdk.wallet.TransactionConsentHandler
import org.siros.sdk.wallet.TransactionConsentRequest
import org.siros.sdk.wallet.TransactionLogEntry
import org.siros.sdk.wallet.TransactionLogStore
import org.siros.sdk.wallet.TransactionOutcome
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.FakeSource
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.PAYMENT_TYPES
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.metadata
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.raw

class TransactionDataCoordinatorTest {
    private class MemoryLog : TransactionLogStore {
        val items = mutableListOf<TransactionLogEntry>()
        override suspend fun append(entry: TransactionLogEntry) { items += entry }
        override suspend fun entries() = items.toList()
        override suspend fun clear() { items.clear() }
    }

    private val twoFactors = listOf(
        AuthenticationFactor(AuthenticationCategory.KNOWLEDGE, "other"),
        AuthenticationFactor(AuthenticationCategory.POSSESSION, "key_in_remote_wscd"),
    )

    private class Harness(
        val handler: TransactionConsentHandler?,
        val factors: AuthenticationFactorsProvider,
        val log: MemoryLog = MemoryLog(),
        source: TransactionMetadataSource = FakeSource(metadata(types = PAYMENT_TYPES)),
        timeoutMs: Long = 5_000,
    ) {
        val coordinator = TransactionDataCoordinator(
            validator = TransactionDataValidator(source),
            display = TransactionDisplayBuilder(source, "en"),
            consentHandler = { handler },
            factorsProvider = { factors },
            log = { log },
            nowMillis = { 1234L },
            consentTimeoutMillis = timeoutMs,
        )
    }

    private fun req(vararg raws: String, verifier: String? = "Shop") = TransactionDataRequest(
        entries = raws.map { TransactionDataEntry(it) },
        responseMode = "direct_post",
        credentials = mapOf("pay" to listOf(TransactionTestFixtures.credential())),
        verifier = verifier,
    )

    private fun run(h: Harness, r: TransactionDataRequest): Result<ScaPresentationPlan> =
        runCatching { runBlocking { h.coordinator.process(r) } }

    private fun reason(result: Result<*>) = (result.exceptionOrNull() as? TransactionDataError)?.reason

    @Test
    fun `consent, factors and a log entry yield the binding`() {
        var seen: TransactionConsentRequest? = null
        val h = Harness(TransactionConsentHandler { seen = it; true }, AuthenticationFactorsProvider { twoFactors })
        val raw = raw()

        val plan = run(h, req(raw)).getOrThrow()

        assertEquals(TransactionDataHashing.hash(raw, "sha-256"), plan.bindingFor("pay")!!.hashes.single())
        assertNull(plan.bindingFor("other"))
        assertNull(plan.bindingFor(null))
        assertEquals("Payee", seen!!.entries.single().fields.first().label)
        val entry = h.log.items.single()
        assertEquals(TransactionOutcome.CONSENTED, entry.outcome)
        assertEquals("tx-0001", entry.transactionId)
        assertEquals("urn:eudi:sca:payment:1", entry.transactionType)
        assertEquals("Payment Confirmation", entry.typeName)
        assertEquals(mapOf("payee" to "Shop AB"), entry.entities)
        assertEquals("Shop", entry.verifier)
        assertEquals("Pay Card", entry.credential)
        assertEquals(1234L, entry.timestampMillis)
        assertNull(entry.reason)
    }

    @Test
    fun `the log holds the TS12 5_3 items and not the payload`() {
        val h = Harness(TransactionConsentHandler { true }, AuthenticationFactorsProvider { twoFactors })

        run(h, req(raw(payload = """{"transaction_id":"tx-9","payee":{"name":"Shop AB","id":"SE-SECRET-ID","website":"https://s.example"},"pisp":{"legal_name":"PayCo AB","brand_name":"b","domain_name":"d"},"currency":"EUR","amount":777.77}""")))

        val text = h.log.items.single().toString()
        assertEquals(mapOf("payee" to "Shop AB", "pisp" to "PayCo AB"), h.log.items.single().entities)
        assertTrue(text, !text.contains("SE-SECRET-ID") && !text.contains("777.77") && !text.contains("s.example"))
    }

    @Test
    fun `entity names per built-in type`() {
        fun names(type: String, payload: String) =
            TransactionDataCoordinator.entityNames(type, kotlinx.serialization.json.Json.parseToJsonElement(payload) as kotlinx.serialization.json.JsonObject)
        assertEquals(mapOf("service" to "Bank"), names("urn:eudi:sca:login_risk_transaction:1", """{"transaction_id":"t","service":"Bank","action":"a"}"""))
        assertEquals(emptyMap<String, String>(), names("urn:eudi:sca:login_risk_transaction:1", """{"transaction_id":"t","action":"a"}"""))
        assertEquals(mapOf("aisp" to "AISP AB"), names("urn:eudi:sca:account_access:1", """{"transaction_id":"t","aisp":{"legal_name":"AISP AB","brand_name":"b","domain_name":"d"}}"""))
        assertEquals(
            mapOf("payee" to "P", "pisp" to "L"),
            names("urn:eudi:sca:emandate:1", """{"transaction_id":"t","payment_payload":{"payee":{"name":"P","id":"1"},"pisp":{"legal_name":"L"}}}"""),
        )
        assertEquals(emptyMap<String, String>(), names("https://custom/x", """{"payee":{"name":"P"}}"""))
    }

    @Test
    fun `a declined transaction signs nothing and is logged as declined`() {
        val h = Harness(TransactionConsentHandler { false }, AuthenticationFactorsProvider { twoFactors })

        val r = run(h, req(raw()))

        assertEquals(TransactionDataReason.DECLINED, reason(r))
        assertEquals("access_denied", (r.exceptionOrNull() as TransactionDataError).verifierError)
        assertEquals(TransactionOutcome.DECLINED, h.log.items.single().outcome)
        assertEquals("declined", h.log.items.single().reason)
    }

    @Test
    fun `a handler that throws or never answers is a decline, never consent`() {
        val throwing = Harness(TransactionConsentHandler { throw IllegalStateException("ui crashed") }, AuthenticationFactorsProvider { twoFactors })
        assertEquals(TransactionDataReason.DECLINED, reason(run(throwing, req(raw()))))

        val gate = CompletableDeferred<Boolean>()
        val silent = Harness(TransactionConsentHandler { gate.await() }, AuthenticationFactorsProvider { twoFactors }, timeoutMs = 50)
        assertEquals(TransactionDataReason.DECLINED, reason(run(silent, req(raw()))))
        assertEquals(TransactionOutcome.DECLINED, silent.log.items.single().outcome)
    }

    @Test
    fun `no handler registered refuses`() {
        val h = Harness(null, AuthenticationFactorsProvider { twoFactors })

        assertEquals(TransactionDataReason.NO_CONSENT_HANDLER, reason(run(h, req(raw()))))
        assertEquals(TransactionOutcome.REFUSED, h.log.items.single().outcome)
    }

    @Test
    fun `the default provider refuses before the user is asked anything`() {
        var asked = false
        val h = Harness(TransactionConsentHandler { asked = true; true }, ConservativeAuthenticationFactorsProvider)

        val r = run(h, req(raw()))

        assertEquals(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, reason(r))
        assertTrue("the user must not read and confirm what will be refused", !asked)
        assertEquals(TransactionOutcome.REFUSED, h.log.items.single().outcome)
        assertEquals("insufficientAuthenticationFactors", h.log.items.single().reason)
    }

    @Test
    fun `a provider that can establish factors only after consent is still asked, and fewer than two categories refuses after`() {
        var asked = false
        val few = Harness(TransactionConsentHandler { asked = true; true }, AuthenticationFactorsProvider { twoFactors.take(1) })

        assertEquals(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, reason(run(few, req(raw()))))
        assertTrue("canEstablish defaults to true, so consent was sought", asked)
        assertEquals("insufficientAuthenticationFactors", few.log.items.single().reason)

        val failing = Harness(TransactionConsentHandler { true }, AuthenticationFactorsProvider { throw IllegalStateException("x") })
        assertEquals(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, reason(run(failing, req(raw()))))
    }

    @Test
    fun `the probe is asked per bound credential, and a probe that throws means no`() {
        val probed = mutableListOf<Long>()
        val provider = object : AuthenticationFactorsProvider {
            override suspend fun factorsFor(operation: org.siros.sdk.wallet.SigningOperation) = twoFactors
            override suspend fun canEstablish(operation: org.siros.sdk.wallet.SigningOperation): Boolean { probed += operation.credential.id; return true }
        }
        run(Harness(TransactionConsentHandler { true }, provider), req(raw())).getOrThrow()
        assertEquals(listOf(1L), probed)

        val throwing = object : AuthenticationFactorsProvider {
            override suspend fun factorsFor(operation: org.siros.sdk.wallet.SigningOperation) = twoFactors
            override suspend fun canEstablish(operation: org.siros.sdk.wallet.SigningOperation): Boolean = throw IllegalStateException("x")
        }
        assertEquals(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, reason(run(Harness(TransactionConsentHandler { true }, throwing), req(raw()))))
    }

    @Test
    fun `a validation refusal never reaches the user and is logged with what could be read`() {
        var asked = false
        val h = Harness(TransactionConsentHandler { asked = true; true }, AuthenticationFactorsProvider { twoFactors })

        val r = run(h, req(raw(payload = """{"transaction_id":"tx-bad","currency":"EUR","amount":1}""")))

        assertEquals(TransactionDataReason.SCHEMA_VIOLATION, reason(r))
        assertTrue(!asked)
        val entry = h.log.items.single()
        assertEquals(TransactionOutcome.REFUSED, entry.outcome)
        assertEquals("tx-bad", entry.transactionId)
        assertEquals("schemaViolation", entry.reason)

        val garbage = Harness(TransactionConsentHandler { true }, AuthenticationFactorsProvider { twoFactors })
        run(garbage, req("###"))
        assertNull(garbage.log.items.single().transactionId)
        assertNull(garbage.log.items.single().transactionType)
    }

    @Test
    fun `a log store that fails does not change the decision`() {
        val failing = object : TransactionLogStore {
            override suspend fun append(entry: TransactionLogEntry) = throw java.io.IOException("disk full")
            override suspend fun entries() = emptyList<TransactionLogEntry>()
            override suspend fun clear() {}
        }
        val source = FakeSource(metadata(types = PAYMENT_TYPES))
        val c = TransactionDataCoordinator(
            TransactionDataValidator(source), TransactionDisplayBuilder(source, "en"),
            { TransactionConsentHandler { true } }, { AuthenticationFactorsProvider { twoFactors } }, { failing },
        )

        assertNotNull(runBlocking { c.process(req(raw())) })
    }

    @Test
    fun `refuse and recordUnreadable log a refusal`() {
        val h = Harness(null, AuthenticationFactorsProvider { twoFactors })
        val err = TransactionDataError(TransactionDataReason.DISABLED, "off")

        val r = runCatching { runBlocking { h.coordinator.refuse(req(raw()), err) } }
        runBlocking { h.coordinator.recordUnreadable("V", TransactionDataError(TransactionDataReason.INVALID_ENTRY, "no raw")) }

        assertEquals(TransactionDataReason.DISABLED, reason(r))
        assertEquals(listOf("disabled", "invalidEntry"), h.log.items.map { it.reason })
        assertEquals("tx-0001", h.log.items[0].transactionId)
        assertNull(h.log.items[1].transactionId)
        assertEquals("V", h.log.items[1].verifier)
    }

    // ── handler failures ──────────────────────────────────────────

    @Test
    fun `a handler cancelled from its own scope, or throwing an Error, is a decline that is logged`() {
        val cancelled = Harness(TransactionConsentHandler { throw kotlinx.coroutines.CancellationException("dialog gone") }, AuthenticationFactorsProvider { twoFactors })
        assertEquals(TransactionDataReason.DECLINED, reason(run(cancelled, req(raw()))))
        assertEquals(TransactionOutcome.DECLINED, cancelled.log.items.single().outcome)

        class Boom : Error("boom")
        val error = Harness(TransactionConsentHandler { throw Boom() }, AuthenticationFactorsProvider { twoFactors })
        assertEquals(TransactionDataReason.DECLINED, reason(run(error, req(raw()))))
        assertEquals(TransactionOutcome.DECLINED, error.log.items.single().outcome)
    }

    @Test
    fun `when the wallet's own coroutine is cancelled that propagates and nothing is logged as consent`() {
        val gate = CompletableDeferred<Boolean>()
        val h = Harness(TransactionConsentHandler { gate.await() }, AuthenticationFactorsProvider { twoFactors })
        runBlocking {
            val job = launch(Dispatchers.Default) { h.coordinator.process(req(raw())) }
            delay(300)
            job.cancelAndJoin()
            assertTrue(job.isCancelled)
        }
        assertTrue(h.log.items.none { it.outcome == TransactionOutcome.CONSENTED })
    }

    @Test
    fun `the consent limit is below the backend's 3 minute sign timeout`() {
        assertTrue(TransactionDataCoordinator.CONSENT_TIMEOUT_MILLIS <= 150_000)
    }

    // ── the log ───────────────────────────────────────────────────

    @Test
    fun `a request with many broken entries writes one refusal record`() {
        val h = Harness(TransactionConsentHandler { true }, AuthenticationFactorsProvider { twoFactors })

        run(h, req(*Array(32) { raw(payload = """{"transaction_id":"bad$it","currency":"EUR","amount":1}""") }))

        assertEquals(1, h.log.items.size)
        assertEquals(TransactionOutcome.REFUSED, h.log.items.single().outcome)
    }

    @Test
    fun `a refusal after validation of many entries is also one record`() {
        val h = Harness(TransactionConsentHandler { true }, ConservativeAuthenticationFactorsProvider)
        val many = Array(5) { raw(payload = """{"transaction_id":"t$it","payee":{"name":"B","id":"2"},"currency":"EUR","amount":1}""") }

        assertEquals(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, reason(run(h, req(*many))))

        assertEquals(1, h.log.items.size)
    }

    @Test
    fun `attacker-sized fields are capped in the log, with a marker`() {
        val huge = "x".repeat(50_000)
        val h = Harness(TransactionConsentHandler { true }, AuthenticationFactorsProvider { twoFactors })

        run(h, req(raw(type = "urn:eudi:sca:payment:1", payload = """{"transaction_id":"${"i".repeat(30)}","payee":{"name":"$huge","id":"1"},"currency":"EUR","amount":1}"""), verifier = huge))

        // the payee name is refused for length by the display builder (a refusal record), so also check a consent
        val ok = Harness(TransactionConsentHandler { true }, AuthenticationFactorsProvider { twoFactors })
        run(ok, req(raw(payload = """{"transaction_id":"${"i".repeat(36)}","payee":{"name":"${"n".repeat(1500)}","id":"1"},"currency":"EUR","amount":1}"""), verifier = "v".repeat(5_000)))
        val e = ok.log.items.single()
        assertEquals(TransactionDataCoordinator.MAX_LOG_FIELD + "…[truncated]".length, e.entities.getValue("payee").length)
        assertEquals(TransactionDataCoordinator.MAX_LOG_FIELD + "…[truncated]".length, e.verifier!!.length)
        assertTrue(e.verifier!!.endsWith("…[truncated]"))
        assertTrue(h.log.items.all { (it.verifier ?: "").length <= TransactionDataCoordinator.MAX_LOG_FIELD + 20 })
        assertEquals("a short field is untouched", "abc", TransactionDataCoordinator.capped("abc"))
    }

    @Test
    fun `a signing failure after consent adds a refused record`() {
        val h = Harness(TransactionConsentHandler { true }, AuthenticationFactorsProvider { twoFactors })

        val plan = run(h, req(raw())).getOrThrow()
        runBlocking { plan.signingFailed() }

        assertEquals(listOf(TransactionOutcome.CONSENTED, TransactionOutcome.REFUSED), h.log.items.map { it.outcome })
        assertEquals(TransactionDataCoordinator.SIGNING_FAILED, h.log.items.last().reason)
    }

    @Test
    fun `nothing sensitive is logged by the coordinator in any outcome`() {
        val payload = """{"transaction_id":"tx-SECRET-9","payee":{"name":"Distinctive Payee","id":"PAYEE-ID-888"},"currency":"EUR","amount":98765.43}"""
        val e = raw(payload = payload)
        val sensitive = listOf("tx-SECRET-9", "Distinctive Payee", "PAYEE-ID-888", "98765.43", e, TransactionDataHashing.hash(e, "sha-256"), "pay.example.com", "Pay Card")
        val tree = object : timber.log.Timber.Tree() {
            val lines = mutableListOf<String>()
            override fun log(priority: Int, tag: String?, message: String, t: Throwable?) { lines += message + (t?.toString() ?: "") }
        }
        timber.log.Timber.plant(tree)
        try {
            for (handler in listOf(TransactionConsentHandler { true }, TransactionConsentHandler { false }, TransactionConsentHandler { throw IllegalStateException("tx-SECRET-9") })) {
                run(Harness(handler, AuthenticationFactorsProvider { twoFactors }), req(e))
                run(Harness(handler, AuthenticationFactorsProvider { throw IllegalStateException("PAYEE-ID-888") }), req(e))
            }
            run(Harness(TransactionConsentHandler { true }, ConservativeAuthenticationFactorsProvider), req(e))
            val failing = object : TransactionLogStore {
                override suspend fun append(entry: TransactionLogEntry) = throw java.io.IOException("cannot write tx-SECRET-9 Distinctive Payee")
                override suspend fun entries() = emptyList<TransactionLogEntry>()
                override suspend fun clear() {}
            }
            run(Harness(TransactionConsentHandler { true }, AuthenticationFactorsProvider { twoFactors }, log = MemoryLog()), req(e))
            val src = FakeSource(metadata(types = PAYMENT_TYPES))
            TransactionDataCoordinator(TransactionDataValidator(src), TransactionDisplayBuilder(src, "en"), { TransactionConsentHandler { true } }, { AuthenticationFactorsProvider { twoFactors } }, { failing })
                .let { runCatching { runBlocking { it.process(req(e)) } } }
        } finally {
            timber.log.Timber.uproot(tree)
        }
        val text = tree.lines.joinToString("\n")
        assertTrue("something must have been logged to make this meaningful", tree.lines.isNotEmpty())
        for (secret in sensitive) assertTrue("log contains '$secret': $text", !text.contains(secret))
    }

    @Test
    fun `validation, display and log I-O do not run on the caller's thread`() {
        val threads = java.util.concurrent.CopyOnWriteArrayList<String>()
        val src = object : TransactionMetadataSource {
            override suspend fun typeMetadata(credential: org.siros.sdk.credentials.StoredCredential): kotlinx.serialization.json.JsonObject? {
                threads += "validate:" + Thread.currentThread().name
                return metadata(types = PAYMENT_TYPES)
            }
            override suspend fun document(uri: String): String? = null
        }
        val log = object : TransactionLogStore {
            override suspend fun append(entry: TransactionLogEntry) { threads += "log:" + Thread.currentThread().name }
            override suspend fun entries() = emptyList<TransactionLogEntry>()
            override suspend fun clear() {}
        }
        val caller = Thread.currentThread().name
        val c = TransactionDataCoordinator(
            TransactionDataValidator(src), TransactionDisplayBuilder(src, "en"),
            { TransactionConsentHandler { true } }, { AuthenticationFactorsProvider { twoFactors } }, { log },
        )

        runBlocking { c.process(req(raw())) }

        assertTrue(threads.toString(), threads.size >= 2)
        assertTrue("$caller vs $threads", threads.none { it.contains(caller) })
    }
}
