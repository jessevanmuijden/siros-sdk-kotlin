// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.nio.ByteBuffer
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The resident, system-dispatching native prover over a fake binding (the UniFFI libraries do not load on the JVM). */
class UniffiNymAuthNativeProverTest {

    private class Handle(val id: Int) : AutoCloseable {
        var closed = false
        override fun close() {
            closed = true
        }
    }

    private class FakeBinding(override val system: String) : NymAuthBinding {
        val handles = mutableListOf<Handle>()
        var proves = 0
        var loadFails: NymAuthNativeException? = null
        var proveFails: NymAuthNativeException? = null
        var onProve: (suspend () -> Unit)? = null

        override fun load(request: NymAuthProveRequest): AutoCloseable {
            loadFails?.let { throw it }
            return Handle(handles.size).also { handles += it }
        }

        override fun prove(handle: AutoCloseable, request: NymAuthProveRequest): NymAuthProveResponse {
            proves++
            proveFails?.let { throw it }
            onProve?.let { runBlocking { it() } }
            return NymAuthProveResponse(byteArrayOf((handle as Handle).id.toByte(), 1), ByteArray(32) { 7 })
        }
    }

    private val vega = FakeBinding(NymAuthCircuitZkAdapter.VEGA_SYSTEM)
    private val lf = FakeBinding(NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM)
    private fun prover() = UniffiNymAuthNativeProver(listOf(vega, lf))

    private fun request(system: String = NymAuthCircuitZkAdapter.VEGA_SYSTEM, id: String = "nymauth-vega-mdoc-v1", hash: String = "sha256:aa") =
        NymAuthProveRequest(
            system, id, hash, JsonObject(emptyMap()), ByteBuffer.allocate(4).asReadOnlyBuffer(), ByteArray(1), ByteArray(16),
            ByteArray(32), ByteArray(32), "2026-10-20T12:00:00Z", "0000-00-00", "9999-12-31", ByteArray(32), ByteArray(64), ByteArray(32), ByteArray(1),
        )

    private fun prove(p: UniffiNymAuthNativeProver, r: NymAuthProveRequest) = runBlocking { p.prove(r) }

    @Test
    fun aSystemIsProvedByItsOwnBinding_andTheCircuitStaysResident() {
        val p = prover()
        val a = prove(p, request())
        val b = prove(p, request())
        assertArrayEquals(byteArrayOf(0, 1), a.proof)
        assertArrayEquals(a.proof, b.proof)
        assertEquals(1, vega.handles.size)
        assertEquals(2, vega.proves)
        assertEquals(0, lf.handles.size)
        assertEquals("vega-nymauth:nymauth-vega-mdoc-v1:sha256:aa", p.residentKey)
    }

    @Test
    fun anotherSystemOrCircuitOrArtifactEvictsTheResidentOneFirst() {
        val p = prover()
        prove(p, request())
        prove(p, request(NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM, "nymauth-longfellow-mdoc-v1", "sha256:bb"))
        assertTrue("one native prover at a time", vega.handles.single().closed)
        assertFalse(lf.handles.single().closed)
        // The same id with a new artifact hash is a different circuit: never proved with the stale state.
        prove(p, request(NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM, "nymauth-longfellow-mdoc-v1", "sha256:cc"))
        assertEquals(2, lf.handles.size)
        assertTrue(lf.handles[0].closed)
        assertFalse(lf.handles[1].closed)
    }

    @Test
    fun aSystemNoBindingServesIsAnUnsupportedCircuit() {
        try {
            prove(prover(), request(system = "longfellow-libzk-v1"))
            fail("expected a refusal")
        } catch (e: NymAuthNativeException) {
            assertEquals(NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT, e.kind)
        }
    }

    @Test
    fun releaseDropsTheResidentCircuit_andTheNextProofReloads() {
        val p = prover()
        prove(p, request())
        p.release()
        assertTrue(vega.handles[0].closed)
        assertNull(p.residentKey)
        p.release() // nothing resident: a no-op
        prove(p, request())
        assertEquals(2, vega.handles.size)
    }

    @Test
    fun releaseCircuitDropsOnlyThatCircuit() {
        val p = prover()
        prove(p, request())
        p.releaseCircuit("some-other-circuit")
        assertFalse(vega.handles[0].closed)
        p.releaseCircuit("nymauth-vega-mdoc-v1")
        assertTrue(vega.handles[0].closed)
        assertNull(p.residentKey)
    }

    @Test
    fun aReleaseDuringAProofWaitsForItToEnd() = runBlocking {
        val p = prover()
        val started = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        vega.onProve = { started.complete(Unit); finish.await() }
        val job = async(Dispatchers.Default) { p.prove(request()) }
        withTimeout(5000) { started.await() }
        p.release()
        assertFalse("not while it is proving", vega.handles[0].closed)
        finish.complete(Unit)
        withTimeout(5000) { job.await() }
        assertTrue(vega.handles[0].closed)
        assertNull(p.residentKey)
    }

    @Test
    fun aBindingErrorPropagatesAsItIs_andAFailedLoadLeavesNothingResident() {
        val p = prover()
        vega.loadFails = NymAuthNativeException.vega("UnknownCircuit")
        try {
            prove(p, request())
            fail("expected an error")
        } catch (e: NymAuthNativeException) {
            assertEquals(NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT, e.kind)
        }
        assertNull(p.residentKey)
        vega.loadFails = null
        vega.proveFails = NymAuthNativeException.vega("Refused", "SeedMismatch")
        try {
            prove(p, request())
            fail("expected an error")
        } catch (e: NymAuthNativeException) {
            assertEquals(NymAuthRefusal.SEED_MISMATCH, e.refusal)
        }
    }

    @Test
    fun theAdapterReleasesAndRetiresThroughTheResidentProver() = runBlocking {
        val p = prover()
        prove(p, request())
        val adapter = NymAuthCircuitZkAdapter(org.siros.sdk.credentials.ZkCircuitClient(sources = emptyList()), p)
        adapter.release()
        assertTrue(vega.handles[0].closed)
        prove(p, request())
        adapter.retire(org.siros.sdk.credentials.ZkCircuitDescriptor(id = "nymauth-vega-mdoc-v1"))
        assertTrue(vega.handles[1].closed)
    }
}
