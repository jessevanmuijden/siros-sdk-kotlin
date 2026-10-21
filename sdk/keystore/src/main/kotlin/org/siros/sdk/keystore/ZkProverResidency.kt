// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.sync.Mutex
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

    /**
     * Guards the retirement protocol: the decision of [release]/[releaseCircuit] (idle now, or deferred) and the end-of-use decision of
     * [use] happen under it, so a request registered while a use is in flight is always seen by that use's cleanup. [mutex] is NEVER
     * unlocked under it (unlocking can resume a queued caller inline, whose own slow close would then run holding this monitor and block
     * a main-thread release): a request recorded between a decision and the unlock is picked up by [drainDeferred], which runs after
     * every unlock. Never held across a suspension or a close.
     */
    private val stateLock = Any()

    @Volatile private var resident: Resident? = null
    @Volatile private var releaseWhenIdle = false

    /**
     * Circuit ids retired while a [use] was in flight, whatever the resident or the loading prover was at that moment. They are
     * kept until that use's cleanup, which applies them to whatever prover is resident THEN: a retirement can therefore never fall
     * into a window where the incoming key is not yet known (entry, eviction, load). Guarded by [stateLock].
     */
    private val pendingRetirements = HashSet<String>()

    /** Test hook: runs right after [use] took the mutex, before it looks at the resident. */
    @Volatile internal var onUseEntered: (() -> Unit)? = null

    /** Test hook: runs inside the retirement decision, after a deferral was decided and before it is recorded. */
    @Volatile internal var onRetirementDeferred: (() -> Unit)? = null

    /** Test hook: runs in [release] and [releaseCircuit] after the decision left [stateLock], before the mutex is unlocked: a concurrent request can interleave. */
    @Volatile internal var onReleaseDecided: (() -> Unit)? = null

    /** Test hook: runs in [use]'s cleanup after its decision left [stateLock], before the mutex is unlocked. */
    @Volatile internal var onUseCleanupDecided: (() -> Unit)? = null

    /** Test hook: runs in [drainDeferred] after its decision left [stateLock], before the mutex is unlocked or the prover closed. */
    @Volatile internal var onDrainDecided: (() -> Unit)? = null

    /** The key of the prover currently loaded, or null. For diagnostics and tests. */
    val residentKey: String? get() = resident?.key

    /**
     * Runs [block] with the prover for [key], loading it with [load] if it is
     * not the one resident (and destroying whatever was). Holds the residency
     * for the duration, so [load] and [block] never overlap with another
     * caller's.
     */
    suspend fun <T : AutoCloseable, R> use(key: String, load: suspend () -> T, block: suspend (T) -> R): R {
        mutex.lock()
        try {
            onUseEntered?.invoke()
            // No reset of [releaseWhenIdle] or [pendingRetirements] here: a request is only ever recorded while a use is in flight and
            // is consumed (and cleared) by that use's cleanup before the mutex is released, so on entry they are already empty, and
            // clearing now could erase a retirement recorded after this use acquired the mutex.
            val current = resident
            val prover: T = if (current != null && current.key == key) {
                @Suppress("UNCHECKED_CAST")
                current.prover as T
            } else {
                if (current != null) {
                    Timber.i("Releasing resident ZK prover '${current.key}' to load '$key'")
                    destroyQuietly(current)
                    synchronized(stateLock) { resident = null }
                }
                val loaded = load()
                synchronized(stateLock) { resident = Resident(key, loaded) }
                loaded
            }
            return block(prover)
        } finally {
            // The decision is one step under [stateLock]: a retirement that found the mutex held registered its request under the same
            // lock, so it is either seen here or happens after the decision and is picked up by [drainDeferred] once the mutex is
            // unlocked (outside the lock). A prover that is to be closed is DETACHED under the lock and closed OUTSIDE it, with the
            // mutex still held, so a slow close never blocks a caller of [release] (the main thread, on a memory trim).
            var toClose: Resident? = null
            val close = synchronized(stateLock) {
                val retired = pendingRetirements.isNotEmpty() && resident?.let { r -> pendingRetirements.any { keyHasCircuit(r.key, it) } } == true
                if (releaseWhenIdle || retired) {
                    toClose = resident
                    resident = null
                    true
                } else {
                    releaseWhenIdle = false
                    pendingRetirements.clear()
                    false
                }
            }
            onUseCleanupDecided?.invoke()
            if (close) closeThenUnlock(toClose) else unlockThenDrain()
        }
    }

    /** Unlocks [mutex] outside [stateLock], then applies whatever was recorded in the meantime. */
    private fun unlockThenDrain() {
        mutex.unlock()
        drainDeferred()
    }

    /**
     * Applies a request recorded after the decision that preceded the last unlock: if nothing is using the residency, it is taken and
     * the prover (when the request concerns it) is closed; if a use holds it, that use's own cleanup applies the request.
     */
    private fun drainDeferred() {
        var detached: Resident? = null
        val acquired = synchronized(stateLock) {
            if ((releaseWhenIdle || pendingRetirements.isNotEmpty()) && mutex.tryLock()) {
                val r = resident
                if (r != null && (releaseWhenIdle || pendingRetirements.any { keyHasCircuit(r.key, it) })) {
                    detached = r
                    resident = null
                } else {
                    // Nothing concerns the resident: the requests just evaluated are consumed, and ONLY those (a newer one recorded
                    // after this decision stays for the next drain).
                    pendingRetirements.clear()
                    releaseWhenIdle = false
                }
                true
            } else {
                false
            }
        }
        if (!acquired) return
        onDrainDecided?.invoke()
        if (detached != null) closeThenUnlock(detached) else unlockThenDrain()
    }

    /**
     * Closes the detached [r] while still holding the mutex (so no use can start and none of its requests is lost to a stale flag),
     * then clears whatever was recorded meanwhile (the prover those requests were about is gone) and unlocks.
     */
    private fun closeThenUnlock(r: Resident?) {
        try {
            r?.let { destroyQuietly(it) }
        } finally {
            synchronized(stateLock) {
                releaseWhenIdle = false
                pendingRetirements.clear()
            }
            unlockThenDrain()
        }
    }

    /**
     * Destroys the resident prover, or arranges for that as soon as the proof
     * using it completes. Safe to call at any time, from any thread; a no-op
     * with nothing resident.
     */
    fun release() {
        // Never blocks on a proof or on a close: this is called from lifecycle callbacks on the main thread. Under [stateLock] (held
        // only briefly): acquiring the mutex means nothing is using the prover, so it is detached and closed outside the lock; failing
        // to means a proof is running, and its cleanup applies the deferred release.
        var detached: Resident? = null
        val acquired = synchronized(stateLock) {
            if (mutex.tryLock()) {
                detached = resident
                resident = null
                true
            } else {
                releaseWhenIdle = true
                false
            }
        }
        onReleaseDecided?.invoke()
        if (acquired) {
            detached?.let { Timber.i("Releasing resident ZK prover '${it.key}'") }
            // Nothing to close: the mutex is only unlocked, and a request recorded since the decision is drained.
            if (detached != null) closeThenUnlock(detached) else unlockThenDrain()
        }
    }

    /**
     * Drops the resident prover if it belongs to the circuit [circuitId] (a retired one): the key holds the circuit
     * id as a run of whole `:`-separated segments (`longfellow-libzk-v1:<id>:<n>`, `vega-mc-p256-v1:<id>`,
     * `<system>:<id>:<hash>`), and the id itself may contain colons (`urn:circuits:longfellow:nym_auth:v1`), so the id is
     * looked for as a whole run, not as one segment. Like [release]: at once when idle, else when the proof using it ends,
     * which includes a prover that is still being loaded or evicted.
     */
    fun releaseCircuit(circuitId: String) {
        var detached: Resident? = null
        val acquired = synchronized(stateLock) {
            if (mutex.tryLock()) {
                detached = resident?.takeIf { keyHasCircuit(it.key, circuitId) }?.also { resident = null }
                true
            } else {
                // A use is in flight: keep the id, whatever is resident or loading right now (see [pendingRetirements]).
                onRetirementDeferred?.invoke()
                pendingRetirements.add(circuitId)
                false
            }
        }
        onReleaseDecided?.invoke()
        if (acquired) {
            detached?.let { Timber.i("Releasing resident ZK prover '${it.key}': its circuit was retired") }
            if (detached != null) closeThenUnlock(detached) else unlockThenDrain()
        }
    }

    /** Whether [circuitId] occurs in [key] as a whole run of `:`-separated segments (never as a part of one). */
    private fun keyHasCircuit(key: String, circuitId: String): Boolean = ":$key:".contains(":$circuitId:")

    private fun destroyQuietly(r: Resident) {
        try {
            r.prover.close()
        } catch (e: Exception) {
            Timber.w(e, "Destroying resident ZK prover '${r.key}' threw")
        }
    }
}
