package org.siros.sdk.keystore

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ZkProverResidencyTest {

    private class FakeProver(val name: String) : AutoCloseable {
        var closed = false
        override fun close() {
            closed = true
        }
    }

    @Test
    fun `the same key reuses the resident prover without reloading`() = runBlocking {
        val residency = ZkProverResidency()
        var loads = 0
        val first = residency.use("a", { loads++; FakeProver("a") }) { it }
        val second = residency.use("a", { loads++; FakeProver("a") }) { it }
        assertSame(first, second)
        assertEquals(1, loads)
        assertEquals("a", residency.residentKey)
        assertFalse(first.closed)
    }

    @Test
    fun `a different key evicts and destroys the resident prover - one at a time`() = runBlocking {
        val residency = ZkProverResidency()
        val a = residency.use("a", { FakeProver("a") }) { it }
        val b = residency.use("b", { FakeProver("b") }) { it }
        assertTrue(a.closed)
        assertFalse(b.closed)
        assertEquals("b", residency.residentKey)
        // Coming back to a reloads it (and evicts b): the bound is one, not a set.
        var reloaded = false
        residency.use("a", { reloaded = true; FakeProver("a") }) { }
        assertTrue(reloaded)
        assertTrue(b.closed)
    }

    @Test
    fun `release destroys an idle prover and forgets it`() = runBlocking {
        val residency = ZkProverResidency()
        val a = residency.use("a", { FakeProver("a") }) { it }
        residency.release()
        assertTrue(a.closed)
        assertNull(residency.residentKey)
        residency.release() // nothing resident: a no-op
    }

    @Test
    fun `release during a proof waits for the proof, then destroys`() = runBlocking {
        val residency = ZkProverResidency()
        val proofStarted = CompletableDeferred<Unit>()
        val letProofFinish = CompletableDeferred<Unit>()
        var proverInUse: FakeProver? = null
        val proof = async(Dispatchers.Default) {
            residency.use("a", { FakeProver("a") }) { p ->
                proverInUse = p
                proofStarted.complete(Unit)
                letProofFinish.await()
                assertFalse("the prover must not be destroyed under a running proof", p.closed)
                "done"
            }
        }
        withTimeout(5_000) { proofStarted.await() }
        residency.release() // from "the main thread", mid-proof
        yield()
        assertFalse(proverInUse!!.closed)
        letProofFinish.complete(Unit)
        assertEquals("done", withTimeout(5_000) { proof.await() })
        assertTrue(proverInUse!!.closed)
        assertNull(residency.residentKey)
    }

    @Test
    fun `a load failure leaves nothing resident and the next use loads again`() = runBlocking {
        val residency = ZkProverResidency()
        try {
            residency.use<FakeProver, Unit>("a", { error("no network") }) { }
        } catch (e: IllegalStateException) {
            assertEquals("no network", e.message)
        }
        assertNull(residency.residentKey)
        val p = residency.use("a", { FakeProver("a") }) { it }
        assertEquals("a", residency.residentKey)
        assertFalse(p.closed)
    }

    @Test
    fun `a destroy that throws does not stop the switch`() = runBlocking {
        val residency = ZkProverResidency()
        val bad = object : AutoCloseable {
            override fun close() = throw RuntimeException("native teardown failed")
        }
        residency.use("bad", { bad }) { }
        val b = residency.use("b", { FakeProver("b") }) { it }
        assertEquals("b", residency.residentKey)
        assertFalse(b.closed)
    }

    @Test
    fun `releaseCircuit drops only the prover of that circuit, matched on a whole key segment`() = runBlocking {
        val residency = ZkProverResidency()
        val v = residency.use("vega-mc-p256-v1:circ-1", { FakeProver("v") }) { it }
        residency.releaseCircuit("circ")      // a prefix of the id is not the id
        residency.releaseCircuit("circ-2")
        assertFalse(v.closed)
        assertEquals("vega-mc-p256-v1:circ-1", residency.residentKey)
        residency.releaseCircuit("circ-1")
        assertTrue(v.closed)
        assertNull(residency.residentKey)

        // The nymauth key carries the artifact hash after a "sha256:" colon, and the id is still found.
        val n = residency.use("longfellow-nymauth:nymauth-x:sha256:abc", { FakeProver("n") }) { it }
        residency.releaseCircuit("nymauth-x")
        assertTrue(n.closed)
    }

    @Test
    fun `releaseCircuit during a proof waits for it to end, and ignores another circuit`() = runBlocking {
        val residency = ZkProverResidency()
        val started = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        val job = async(Dispatchers.Default) {
            residency.use("sys:circ-1", { FakeProver("a") }) { p ->
                started.complete(Unit)
                finish.await()
                p
            }
        }
        withTimeout(5000) { started.await() }
        residency.releaseCircuit("other")
        residency.releaseCircuit("circ-1")
        finish.complete(Unit)
        val p = withTimeout(5000) { job.await() }
        assertTrue("released once the proof ended", p.closed)
        assertNull(residency.residentKey)

        // A release for another circuit during a proof does not drop this one.
        val started2 = CompletableDeferred<Unit>()
        val finish2 = CompletableDeferred<Unit>()
        val job2 = async(Dispatchers.Default) {
            residency.use("sys:circ-2", { FakeProver("b") }) { q ->
                started2.complete(Unit)
                finish2.await()
                q
            }
        }
        withTimeout(5000) { started2.await() }
        residency.releaseCircuit("circ-1")
        finish2.complete(Unit)
        val q = withTimeout(5000) { job2.await() }
        assertFalse(q.closed)
        assertEquals("sys:circ-2", residency.residentKey)
    }

    @Test
    fun `a circuit id that itself contains colons is found in the key`() = runBlocking {
        val residency = ZkProverResidency()
        val id = "urn:circuits:longfellow:nym_auth:v1"
        val p = residency.use("longfellow-libzk-v1:$id:2", { FakeProver("a") }) { it }
        residency.releaseCircuit("urn:circuits:long")   // part of a segment is not the id
        residency.releaseCircuit("auth:v1")
        assertFalse(p.closed)
        residency.releaseCircuit(id)
        assertTrue(p.closed)
        assertNull(residency.residentKey)
    }

    @Test
    fun `a retirement that arrives while the prover is still loading is applied when the proof ends`() = runBlocking {
        val residency = ZkProverResidency()
        val loading = CompletableDeferred<Unit>()
        val finishLoad = CompletableDeferred<Unit>()
        val job = async(Dispatchers.Default) {
            residency.use("sys:circ-1", { loading.complete(Unit); finishLoad.await(); FakeProver("a") }) { it }
        }
        withTimeout(5000) { loading.await() }
        // resident is still null here: the retirement used to be lost.
        residency.releaseCircuit("circ-1")
        finishLoad.complete(Unit)
        val p = withTimeout(5000) { job.await() }
        assertTrue("retired while loading, so released when the use ended", p.closed)
        assertNull(residency.residentKey)

        // A retirement of another circuit while loading changes nothing.
        val loading2 = CompletableDeferred<Unit>()
        val finish2 = CompletableDeferred<Unit>()
        val job2 = async(Dispatchers.Default) {
            residency.use("sys:circ-2", { loading2.complete(Unit); finish2.await(); FakeProver("b") }) { it }
        }
        withTimeout(5000) { loading2.await() }
        residency.releaseCircuit("circ-1")
        finish2.complete(Unit)
        assertFalse(withTimeout(5000) { job2.await() }.closed)
    }

    @Test
    fun `a retirement decided while a use is in flight cannot be lost to that use's cleanup`() = runBlocking {
        val residency = ZkProverResidency()
        val started = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        val decided = java.util.concurrent.CountDownLatch(1)
        val proceed = java.util.concurrent.CountDownLatch(1)
        // The releasing thread decides to defer, then pauses before recording the request.
        residency.onRetirementDeferred = { decided.countDown(); proceed.await(10, java.util.concurrent.TimeUnit.SECONDS) }
        val job = async(Dispatchers.Default) {
            residency.use("sys:circ-1", { FakeProver("a") }) { p -> started.complete(Unit); finish.await(); p }
        }
        withTimeout(5000) { started.await() }
        val releaser = Thread { residency.releaseCircuit("circ-1") }.also { it.start() }
        assertTrue(decided.await(5, java.util.concurrent.TimeUnit.SECONDS))
        // The use finishes its proof while the releaser is paused: its cleanup must wait for (and then see) the request.
        finish.complete(Unit)
        Thread.sleep(300)
        assertFalse("the use's cleanup may not run ahead of a decided retirement", job.isCompleted)
        proceed.countDown()
        releaser.join(5000)
        val p = withTimeout(5000) { job.await() }
        assertTrue("the retired prover is released, not left resident", p.closed)
        assertNull(residency.residentKey)
    }

    @Test
    fun `a queued unconfined use resumed by an unlock does not block release while its eviction close is slow`() = runBlocking {
        val residency = ZkProverResidency()
        val closing = java.util.concurrent.CountDownLatch(1)
        val letClose = java.util.concurrent.CountDownLatch(1)
        val slow = object : AutoCloseable {
            override fun close() { closing.countDown(); letClose.await(20, java.util.concurrent.TimeUnit.SECONDS) }
        }
        val started = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        val first = async(Dispatchers.Default) {
            residency.use("sys:circ-1", { slow }) { started.complete(Unit); finish.await() }
        }
        withTimeout(5000) { started.await() }
        // A second use queues on the residency from an unconfined dispatcher: the unlock of the first resumes it INLINE.
        val second = async(Dispatchers.Unconfined) { residency.use("sys:circ-2", { FakeProver("b") }) { it } }
        finish.complete(Unit)
        // The first use's thread now runs the slow eviction close (inline resumption). A release from another thread must not wait for it.
        assertTrue(closing.await(5, java.util.concurrent.TimeUnit.SECONDS))
        val returned = java.util.concurrent.CountDownLatch(1)
        Thread { residency.release(); returned.countDown() }.start()
        val released = returned.await(3, java.util.concurrent.TimeUnit.SECONDS)
        letClose.countDown()
        assertTrue("release() must return while a close runs on another thread", released)
        first.await()
        // The deferred release is applied once the second use ends.
        val p = withTimeout(5000) { second.await() }
        assertTrue("the release recorded meanwhile closed the prover that was loaded", p.closed)
        assertNull(residency.residentKey)
    }

    @Test
    fun `a release arriving after a drain decided to keep the resident is still applied`() = runBlocking {
        val residency = ZkProverResidency()
        var recorded = false
        // A nonmatching retirement is recorded between the use's cleanup decision and its unlock.
        residency.onUseCleanupDecided = { if (!recorded) { recorded = true; residency.releaseCircuit("circ-other") } }
        var released = false
        // The drain that picks it up keeps the resident; a release arrives right after that decision.
        residency.onDrainDecided = { if (!released) { released = true; residency.release() } }
        val p = residency.use("sys:circ-1", { FakeProver("a") }) { it }
        assertTrue("the release recorded after the drain's decision closed the prover", p.closed)
        assertNull(residency.residentKey)
    }

    @Test
    fun `a release recorded while nothing is resident is consumed by the drain, never recursed on`() = runBlocking {
        val residency = ZkProverResidency()
        // The load fails, so nothing becomes resident; a release is recorded between the cleanup decision and the unlock.
        var recorded = false
        residency.onUseCleanupDecided = { if (!recorded) { recorded = true; residency.release() } }
        try {
            residency.use<FakeProver, Unit>("sys:circ-1", { throw IllegalStateException("load failed") }) { }
        } catch (e: IllegalStateException) {
            // expected
        }
        assertNull(residency.residentKey)
        // The consumed request does not linger: the next prover stays resident after its use.
        residency.use("sys:circ-2", { FakeProver("b") }) { it }
        assertEquals("sys:circ-2", residency.residentKey)
    }

    @Test
    fun `a release overlapping a nonmatching retirement is applied, not discarded`() = runBlocking {
        val residency = ZkProverResidency()
        val p = residency.use("sys:circ-1", { FakeProver("a") }) { it }
        // A release (and a matching retirement, in the second round) arrives right after the nonmatching retirement decided.
        var overlapped = false
        residency.onReleaseDecided = { if (!overlapped) { overlapped = true; residency.release() } }
        residency.releaseCircuit("circ-other")
        assertTrue("the overlapping release closed the resident prover", p.closed)
        assertNull(residency.residentKey)

        val q = residency.use("sys:circ-2", { FakeProver("b") }) { it }
        overlapped = false
        residency.onReleaseDecided = { if (!overlapped) { overlapped = true; residency.releaseCircuit("circ-2") } }
        residency.releaseCircuit("circ-other")
        assertTrue("the overlapping matching retirement closed it", q.closed)
        assertNull(residency.residentKey)
    }

    @Test
    fun `a retirement of the incoming circuit while the old prover is being evicted is not lost`() = runBlocking {
        val closing = java.util.concurrent.CountDownLatch(1)
        val letClose = java.util.concurrent.CountDownLatch(1)
        // Closing the old prover is slow: the switch is observable in the middle.
        val slow = object : AutoCloseable {
            var closed = false
            override fun close() { closing.countDown(); letClose.await(10, java.util.concurrent.TimeUnit.SECONDS); closed = true }
        }
        val other = ZkProverResidency()
        other.use("sys:circ-old", { slow }) { it }
        var incoming: FakeProver? = null
        val job = async(Dispatchers.Default) { other.use("sys:circ-new", { FakeProver("new").also { incoming = it } }) { it } }
        assertTrue(closing.await(5, java.util.concurrent.TimeUnit.SECONDS))
        // The old prover is mid-close; the incoming key must already count as being loaded.
        other.releaseCircuit("circ-new")
        letClose.countDown()
        val p = withTimeout(5000) { job.await() }
        assertTrue("retired during the switch, so released when the use ended", p.closed)
        assertNull(other.residentKey)
    }

    @Test
    fun `a retirement recorded just after a same-key use took the residency is not erased by its entry`() = runBlocking {
        val residency = ZkProverResidency()
        val p0 = residency.use("sys:circ-1", { FakeProver("a") }) { it }
        assertFalse(p0.closed)
        val entered = java.util.concurrent.CountDownLatch(1)
        val proceed = java.util.concurrent.CountDownLatch(1)
        residency.onUseEntered = { entered.countDown(); proceed.await(10, java.util.concurrent.TimeUnit.SECONDS) }
        val job = async(Dispatchers.Default) {
            residency.use<FakeProver, FakeProver>("sys:circ-1", { error("resident is reused") }) { it }
        }
        assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
        residency.releaseCircuit("circ-1")   // recorded after the use took the mutex, before it looked at the resident
        proceed.countDown()
        assertTrue(withTimeout(5000) { job.await() }.closed)
        assertNull(residency.residentKey)
    }

    @Test
    fun `a retirement between taking the residency and knowing the incoming key is kept, for an empty or a different resident`() = runBlocking {
        for (previous in listOf<String?>(null, "sys:circ-other")) {
            val residency = ZkProverResidency()
            previous?.let { residency.use(it, { FakeProver("old") }) { p -> p } }
            val entered = java.util.concurrent.CountDownLatch(1)
            val proceed = java.util.concurrent.CountDownLatch(1)
            residency.onUseEntered = { entered.countDown(); proceed.await(10, java.util.concurrent.TimeUnit.SECONDS) }
            val job = async(Dispatchers.Default) { residency.use("sys:circ-new", { FakeProver("new") }) { it } }
            assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
            // Neither the resident nor any loading key matches yet: the retirement must still be kept.
            residency.releaseCircuit("circ-new")
            proceed.countDown()
            assertTrue("previous=$previous", withTimeout(5000) { job.await() }.closed)
            assertNull(residency.residentKey)
        }
    }

    @Test
    fun `release returns at once while a deferred cleanup is paused in close`() = runBlocking {
        val residency = ZkProverResidency()
        val closing = java.util.concurrent.CountDownLatch(1)
        val letClose = java.util.concurrent.CountDownLatch(1)
        val slow = object : AutoCloseable {
            override fun close() { closing.countDown(); letClose.await(10, java.util.concurrent.TimeUnit.SECONDS) }
        }
        val started = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        val job = async(Dispatchers.Default) {
            residency.use("sys:circ-1", { slow }) { started.complete(Unit); finish.await() }
        }
        withTimeout(5000) { started.await() }
        residency.releaseCircuit("circ-1")          // deferred: applied by the use's cleanup
        finish.complete(Unit)
        assertTrue(closing.await(5, java.util.concurrent.TimeUnit.SECONDS))   // the cleanup is now inside close()
        // The main thread's memory trim must not wait for that close.
        val returned = java.util.concurrent.CountDownLatch(1)
        Thread { residency.release(); returned.countDown() }.start()
        assertTrue("release() blocked on a slow close", returned.await(2, java.util.concurrent.TimeUnit.SECONDS))
        letClose.countDown()
        withTimeout(5000) { job.await() }
        assertNull(residency.residentKey)
    }
}
