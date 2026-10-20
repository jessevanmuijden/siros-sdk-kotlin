package org.siros.sdk.wallet

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Duration

class TrustDecisionCacheTest {
    private var now = 0L
    private fun cache(ttlMs: Long = 300_000, max: Int = 256) =
        TrustDecisionCache(Duration.ofMillis(ttlMs), max) { now }

    private fun decision(v: Boolean) = buildJsonObject { put("decision", JsonPrimitive(v)) }

    @Test
    fun hitWithinTtl_doesNotCallTheClient_missAfterTtl_does() = runTest {
        val c = cache()
        var calls = 0
        val call: suspend () -> JsonObject = { calls++; decision(true) }
        c.getOrEvaluate("k", call)
        now = 299_999
        c.getOrEvaluate("k", call)
        assertEquals(1, calls)
        now = 300_000
        c.getOrEvaluate("k", call)
        assertEquals(2, calls)
    }

    @Test
    fun negativeDecisionsAreCached() = runTest {
        val c = cache()
        var calls = 0
        repeat(3) { assertEquals(decision(false), c.getOrEvaluate("k") { calls++; decision(false) }) }
        assertEquals(1, calls)
    }

    @Test
    fun errorsAreNotCached() = runTest {
        val c = cache()
        var calls = 0
        repeat(2) {
            try {
                c.getOrEvaluate("k") { calls++; throw java.io.IOException("down") }
            } catch (_: java.io.IOException) {
            }
        }
        assertEquals(2, calls)
        assertEquals(0, c.size)
    }

    @Test
    fun responseWithoutADecisionIsNotCached() = runTest {
        val c = cache()
        var calls = 0
        repeat(2) { c.getOrEvaluate("k") { calls++; buildJsonObject { put("x", JsonPrimitive(1)) } } }
        assertEquals(2, calls)
    }

    @Test
    fun expiredEntryIsNotUsedWhenTheBackendIsUnreachable() = runTest {
        val c = cache()
        c.getOrEvaluate("k") { decision(true) }
        now = 300_001
        var threw = false
        try {
            c.getOrEvaluate("k") { throw java.io.IOException("unreachable") }
        } catch (_: java.io.IOException) {
            threw = true
        }
        assertTrue("an expired entry must not stand in for an unreachable backend", threw)
        assertEquals(0, c.size)
    }

    @Test
    fun ttlZeroDisables() = runTest {
        val c = cache(ttlMs = 0)
        var calls = 0
        repeat(3) { c.getOrEvaluate("k") { calls++; decision(true) } }
        assertEquals(3, calls)
    }

    @Test
    fun differentKeysDoNotShareEntries_andKeyCoversTheWholeRequest() = runTest {
        fun req(cert: String, docType: String?) = buildJsonObject {
            put("subject", buildJsonObject { put("id", JsonPrimitive("s")) })
            put("resource", buildJsonObject { put("key", JsonPrimitive(cert)) })
            docType?.let { put("context", buildJsonObject { put("doc_type", JsonPrimitive(it)) }) }
        }
        val keys = setOf(
            TrustDecisionCache.keyFor(req("A", null)),
            TrustDecisionCache.keyFor(req("B", null)),
            TrustDecisionCache.keyFor(req("A", "mDL")),
            TrustDecisionCache.keyFor(req("A", "pid")),
        )
        assertEquals(4, keys.size)
        assertEquals(TrustDecisionCache.keyFor(req("A", "mDL")), TrustDecisionCache.keyFor(req("A", "mDL")))
    }

    @Test
    fun lruBound() = runTest {
        val c = cache(max = 2)
        c.getOrEvaluate("a") { decision(true) }
        c.getOrEvaluate("b") { decision(true) }
        c.getOrEvaluate("a") { decision(true) } // touch a
        c.getOrEvaluate("c") { decision(true) } // evicts b
        assertEquals(2, c.size)
        var calls = 0
        c.getOrEvaluate("b") { calls++; decision(true) }
        assertEquals(1, calls)
    }

    @Test
    fun clearInvalidates_andDropsAnInFlightResult() = runTest {
        val c = cache()
        c.getOrEvaluate("k") { decision(true) }
        c.clear()
        var calls = 0
        c.getOrEvaluate("k") { calls++; decision(true) }
        assertEquals(1, calls)

        val gate = CompletableDeferred<Unit>()
        val inflight = async { c.getOrEvaluate("z") { gate.await(); decision(true) } }
        advanceUntilIdle()
        c.clear()
        gate.complete(Unit)
        inflight.await()
        assertEquals("a result obtained before clear() must not be stored", 0, c.size)
    }

    @Test
    fun concurrentIdenticalEvaluationsShareOneRequest() = runTest {
        val c = cache()
        var calls = 0
        val gate = CompletableDeferred<Unit>()
        val results = (1..5).map {
            async { c.getOrEvaluate("k") { calls++; gate.await(); decision(true) } }
        }
        advanceUntilIdle()
        gate.complete(Unit)
        results.forEach { assertEquals(decision(true), it.await()) }
        assertEquals(1, calls)
    }

    @Test
    fun singleFlight_sharedFailureIsNotCached() = runTest {
        val c = cache()
        var calls = 0
        val gate = CompletableDeferred<Unit>()
        val results = (1..3).map {
            async {
                runCatching { c.getOrEvaluate("k") { calls++; gate.await(); throw java.io.IOException("x") } }
            }
        }
        advanceUntilIdle()
        gate.complete(Unit)
        results.forEach { assertTrue(it.await().isFailure) }
        assertEquals(1, calls)
        assertEquals(0, c.size)
    }

    @Test
    fun requestAfterClearDoesNotJoinTheOldInFlightEvaluation() = runTest {
        val c = cache()
        val gate = CompletableDeferred<Unit>()
        val old = async { c.getOrEvaluate("k") { gate.await(); decision(true) } }
        advanceUntilIdle()
        c.clear()
        var calls = 0
        val fresh = c.getOrEvaluate("k") { calls++; decision(false) }
        assertEquals("the new connection must ask its own backend", 1, calls)
        assertEquals(decision(false), fresh)
        gate.complete(Unit)
        old.await()
        // The old leader must not have evicted or overwritten the newer state.
        var again = 0
        assertEquals(decision(false), c.getOrEvaluate("k") { again++; decision(true) })
        assertEquals(0, again)
    }

    @Test
    fun followerRetryingAfterClearAndLeaderCancellationDoesNotRepopulateTheCache() = runTest {
        val c = cache()
        val gate = CompletableDeferred<Unit>()
        val leader = async { c.getOrEvaluate("k") { gate.await(); decision(true) } }
        advanceUntilIdle()
        val followerGate = CompletableDeferred<Unit>()
        val follower = async { c.getOrEvaluate("k") { followerGate.await(); decision(true) } }
        advanceUntilIdle()
        c.clear()
        leader.cancel()
        advanceUntilIdle()
        // A caller on the NEW connection asks while the old follower retries.
        var newCalls = 0
        val fresh = async { c.getOrEvaluate("k") { newCalls++; decision(false) } }
        advanceUntilIdle()
        followerGate.complete(Unit)
        follower.await()
        assertEquals(decision(false), fresh.await())
        assertEquals("the new connection must ask its own backend", 1, newCalls)
        assertEquals(1, c.size) // only the new connection's decision
    }
}
