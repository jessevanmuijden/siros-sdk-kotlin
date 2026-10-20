// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber

/**
 * At most one loaded prover in the process at a time, released when the
 * host says so.
 *
 * A decompressed Longfellow circuit is ~110 MB and a Vega prover key
 * ~140-160 MB, held as native memory outside the Java heap. Each proof
 * system used to keep every prover it had ever loaded in a map for the life
 * of the process, so two proof systems and two attribute counts could pin
 * half a gigabyte - and a 157 MB key has already caused one out-of-memory
 * crash on a real device, in a process that also hosts a WebView. This
 * replaces those maps: one slot, keyed by whatever the proof system needs to
 * tell provers apart, reloaded on a miss and destroyed on a switch.
 *
 * [release] is for the host to call when the app leaves the foreground
 * (`onTrimMemory(TRIM_MEMORY_UI_HIDDEN)` on Android, which is what
 * `SirosWallet` wires up); a proof in progress finishes first and the
 * release happens when it ends.
 *
 * One residency is shared by every proof system in a
 * [ZkMdocPresentation], so the bound really is one prover, not one per
 * system. Proving is serialized on it as a consequence: two concurrent
 * proofs would otherwise each need a resident prover, and a wallet never
 * has two presentations in flight at once anyway.
 */
class ZkProverResidency {

    private class Resident(val key: String, val prover: AutoCloseable)

    private val mutex = Mutex()
    private var resident: Resident? = null
    @Volatile private var releaseWhenIdle = false

    /** The key of the prover currently loaded, or null. For diagnostics and tests. */
    val residentKey: String? get() = resident?.key

    /**
     * Runs [block] with the prover for [key], loading it with [load] if it is
     * not the one resident (and destroying whatever was). Holds the residency
     * for the duration, so [load] and [block] never overlap with another
     * caller's.
     */
    suspend fun <T : AutoCloseable, R> use(key: String, load: suspend () -> T, block: suspend (T) -> R): R {
        mutex.withLock {
            // A release requested between a previous proof's end and this
            // call is moot: the host is proving again, so the resident
            // prover is wanted, not memory to be reclaimed.
            releaseWhenIdle = false
            val current = resident
            val prover: T = if (current != null && current.key == key) {
                @Suppress("UNCHECKED_CAST")
                current.prover as T
            } else {
                if (current != null) {
                    Timber.i("Releasing resident ZK prover '${current.key}' to load '$key'")
                    destroyQuietly(current)
                    resident = null
                }
                val loaded = load()
                resident = Resident(key, loaded)
                loaded
            }
            try {
                return block(prover)
            } finally {
                if (releaseWhenIdle) {
                    releaseWhenIdle = false
                    resident?.let { destroyQuietly(it) }
                    resident = null
                }
            }
        }
    }

    /**
     * Destroys the resident prover, or arranges for that as soon as the proof
     * using it completes. Safe to call at any time, from any thread; a no-op
     * with nothing resident.
     */
    fun release() {
        // Never blocks: this is called from lifecycle callbacks on the main
        // thread while a proof may be holding the lock for seconds. The lock
        // is held exactly while a use() is in flight, so acquiring it means
        // nothing is using the prover and it can go now; failing to means a
        // proof is running, and its finally block applies the deferred
        // release under the same lock.
        if (mutex.tryLock()) {
            try {
                resident?.let {
                    Timber.i("Releasing resident ZK prover '${it.key}'")
                    destroyQuietly(it)
                }
                resident = null
            } finally {
                mutex.unlock()
            }
        } else {
            releaseWhenIdle = true
        }
    }

    /**
     * Drops the resident prover if it belongs to the circuit [circuitId] (a retired one): the key holds the circuit
     * id as one of its `:`-separated segments (`longfellow-libzk-v1:<id>:<n>`, `vega-mc-p256-v1:<id>`,
     * `<system>:<id>:<hash>`). Like [release]: at once when idle, else when the proof using it ends.
     */
    fun releaseCircuit(circuitId: String) {
        if (mutex.tryLock()) {
            try {
                resident?.takeIf { circuitId in it.key.split(':') }?.let {
                    Timber.i("Releasing resident ZK prover '${it.key}': its circuit was retired")
                    destroyQuietly(it)
                    resident = null
                }
            } finally {
                mutex.unlock()
            }
        } else if (resident?.key?.split(':')?.contains(circuitId) == true) {
            releaseWhenIdle = true
        }
    }

    private fun destroyQuietly(r: Resident) {
        try {
            r.prover.close()
        } catch (e: Exception) {
            Timber.w(e, "Destroying resident ZK prover '${r.key}' threw")
        }
    }
}
