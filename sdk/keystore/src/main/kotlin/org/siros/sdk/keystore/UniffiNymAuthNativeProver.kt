// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import timber.log.Timber

/**
 * One native nymauth binding (Vega's or Longfellow's), as [UniffiNymAuthNativeProver] drives it: build the resident
 * state of a circuit once, then prove with it. Implemented over the UniFFI Kotlin bindings by [VegaNymAuthBinding] and
 * [LongfellowNymAuthBinding]; a test supplies its own.
 */
internal interface NymAuthBinding {
    /** The catalog `system` this binding proves. */
    val system: String

    /**
     * Builds the resident state of the circuit [request] names from its verified, decompressed bytes
     * (`request.circuit`): Vega runs key setup from the shapes (about a second, 100+ MB), Longfellow loads the two
     * circuits. Throws a [NymAuthNativeException] for the binding's own errors. The handle is closed to release it.
     */
    fun load(request: NymAuthProveRequest): AutoCloseable

    /** Proves with a [handle] this binding built. Throws a [NymAuthNativeException] for the binding's own errors. */
    fun prove(handle: AutoCloseable, request: NymAuthProveRequest): NymAuthProveResponse
}

/**
 * The real [NymAuthNativeProver]: dispatches by catalog `system` to the Vega (`vega-nymauth`) or Longfellow
 * (`longfellow-nymauth`) binding, keeps ONE built circuit resident (keyed by system, circuit id and artifact hash, so
 * a changed artifact is never proved with a stale state), and drops it on [release] (memory pressure) or when its
 * circuit is retired. A different circuit evicts the resident one first: the process holds one native prover at a
 * time. The binding's errors are already [NymAuthNativeException]s (the adapter maps each deliberately); a system no
 * binding is registered for is an unsupported circuit. Proving runs off the caller's dispatcher.
 */
class UniffiNymAuthNativeProver internal constructor(
    private val bindings: List<NymAuthBinding>,
) : ResidentNymAuthNativeProver {

    /** The standard prover over the UniFFI bindings of `zk-cred-vega` and `zk-cred-longfellow`. */
    constructor() : this(listOf(VegaNymAuthBinding, LongfellowNymAuthBinding))

    private class Resident(val key: String, val circuitId: String, val binding: NymAuthBinding, val handle: AutoCloseable)

    private val mutex = Mutex()
    private var resident: Resident? = null
    @Volatile private var releaseWhenIdle = false

    /** The key of the resident circuit, or null. For diagnostics and tests. */
    val residentKey: String? get() = resident?.key

    override suspend fun prove(request: NymAuthProveRequest): NymAuthProveResponse {
        val binding = bindings.firstOrNull { it.system == request.system }
            ?: throw NymAuthNativeException(NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT)
        val key = "${request.system}:${request.circuitId}:${request.artifactHash}"
        return mutex.withLock {
            releaseWhenIdle = false
            try {
                withContext(Dispatchers.Default) {
                    val current = resident
                    val handle = if (current != null && current.key == key) {
                        current.handle
                    } else {
                        if (current != null) {
                            Timber.i("Releasing resident nymauth circuit '${current.key}' to load '$key'")
                            close(current)
                            resident = null
                        }
                        binding.load(request).also { resident = Resident(key, request.circuitId, binding, it) }
                    }
                    binding.prove(handle, request)
                }
            } finally {
                if (releaseWhenIdle) {
                    releaseWhenIdle = false
                    resident?.let { close(it) }
                    resident = null
                }
            }
        }
    }

    override fun release() {
        if (mutex.tryLock()) {
            try {
                resident?.let { close(it) }
                resident = null
            } finally {
                mutex.unlock()
            }
        } else {
            // A proof is running: it finishes first, and the release happens when it ends.
            releaseWhenIdle = true
        }
    }

    override fun releaseCircuit(circuitId: String) {
        if (mutex.tryLock()) {
            try {
                resident?.takeIf { it.circuitId == circuitId }?.let {
                    close(it)
                    resident = null
                }
            } finally {
                mutex.unlock()
            }
        } else if (resident?.circuitId == circuitId) {
            releaseWhenIdle = true
        }
    }

    private fun close(r: Resident) {
        try {
            r.handle.close()
        } catch (e: Exception) {
            Timber.w("Closing the resident nymauth circuit failed (${e.javaClass.simpleName})")
        }
    }
}
