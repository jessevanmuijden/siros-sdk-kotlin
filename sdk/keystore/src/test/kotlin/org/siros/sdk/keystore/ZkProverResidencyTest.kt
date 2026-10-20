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
}
