// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber

/**
 * Caches VEGA's `prep_prove` output (the credential's serialized prep-chain
 * state - ~100MB of Hyrax witness commitments) so a repeat presentation of
 * the SAME credential disclosing the SAME claims can skip straight to
 * `prove()`, instead of recomputing `prep_prove` every time.
 *
 * **Why this exists at all**: `prep_prove` and `prove` do genuinely
 * different work - confirmed by running `zk-cred-vega`'s own
 * `examples/perf_profile.rs` on real hardware: `prep_prove` (hashing the
 * raw attestation, verifying the issuer's ECDSA signature, building the
 * field-extraction witness) is static per credential and independent of any
 * verifier; `prove` (rerandomizing, folding, the live proof itself) is the
 * only part that's genuinely per-presentation. Neither call takes a verifier
 * nonce/session transcript at all - that binding happens entirely in the
 * outer DeviceResponse wrapper, not inside VEGA's own circuit. The prior
 * version of this SDK called `prep_prove` fresh on every single
 * presentation regardless, which is most of what made a presentation feel
 * slow - this cache is what [VegaProofSystem.generateProof] now consults
 * before doing that.
 *
 * **The key is `(credential, EXACT disclosure combination)`, not just
 * credential.** This was confirmed the hard way: an earlier version of this
 * codebase's own comment asserted a cached prep-chain stays valid across a
 * presentation disclosing a DIFFERENT subset of the same four claim slots
 * ("only the disclose flags change"). That is false - confirmed empirically
 * by calling the real crate's `prove()` with a flipped disclose pattern
 * against a prep state built for the original one: it fails outright
 * (`InternalError`, the same class of error `zk-cred-vega`'s own docs
 * describe for "Step circuit N public values changed between prep_prove and
 * prove"). The per-claim `disclose` flag is baked into the step circuit's
 * public values at `prep_prove` time, not a free choice at `prove()` time -
 * so a cached entry for `{age_over_18}` disclosed must never be handed back
 * for a request disclosing `{age_over_18, nationality}`, even for the exact
 * same stored credential.
 *
 * **The bounded-reuse policy**: `zk-cred-vega/src/lib.rs`'s own
 * `blind_digest_bytes` doc explains why this matters even for the SAME
 * disclosure combination - the blinding nonce protecting an UNDISCLOSED
 * claim's digest from cross-presentation correlation is fixed for the
 * lifetime of one prep chain (it cannot be freshened per `prove()` call;
 * the crate's own `fresh_nonce()` doc confirms this is "a real,
 * currently-latent limitation"). Reusing one entry forever would mean every
 * presentation of that credential disclosing that combination shares one
 * blinded-digest nonce, which two colluding verifiers could use to confirm
 * "same credential, same undisclosed value" - exactly what a fresh nonce
 * per presentation exists to prevent. [maxReusesPerEntry] bounds how many
 * presentations can share one prep chain before this cache forces a fresh
 * `prep_prove`, trading some of the performance win back for a bounded
 * correlation window rather than an unbounded one. This is a policy choice,
 * not a hard limit from the crate - revisit the default if real deployment
 * experience says otherwise.
 *
 * In-memory only, deliberately: losing the cache (process restart, cache
 * eviction) only means the next presentation re-runs `prep_prove` - the same
 * fresh-nonce-per-chain behavior this whole SDK shipped with before this
 * class existed - never a correctness problem, just a slower presentation.
 */
class VegaProofCache(
    private val maxReusesPerEntry: Int = DEFAULT_MAX_REUSES_PER_ENTRY,
) {
    companion object {
        /**
         * How many `prove()` calls may share one `prep_prove` output before
         * this cache forces a fresh one - see this class's own doc comment
         * for the correlation tradeoff this bounds. 5 is a starting policy:
         * conservative enough that a credential shown to many different
         * verifiers isn't trivially linkable by nonce alone, generous enough
         * that the common case (a handful of presentations of the same
         * claim combination before the credential expires) still gets the
         * `prep_prove`-skip benefit most of the time.
         */
        const val DEFAULT_MAX_REUSES_PER_ENTRY = 5
    }

    /**
     * @param state the cached `prep_prove`/`prove` chain state (whatever
     *   [uniffi.zk_cred_vega.prove]'s `nextState` or [uniffi.zk_cred_vega.prepProve]'s
     *   return value most recently produced for this key).
     * @param reuseCount how many `prove()` calls have already consumed a
     *   state derived from the SAME original `prep_prove` output - distinct
     *   from how many times this cache entry itself has been overwritten,
     *   which happens on every call regardless.
     */
    private data class Entry(val state: ByteArray, val reuseCount: Int)

    private data class Key(val credentialDigest: String, val disclosureSignature: String)

    private val mutex = Mutex()
    private val entries = mutableMapOf<Key, Entry>()

    /**
     * The cached prep-chain state for this exact (credential, disclosed
     * claims) pair, or null if nothing is cached, the cached entry has hit
     * [maxReusesPerEntry], or the disclosed-claims set doesn't match what's
     * cached. A null return means the caller must run `prep_prove` fresh -
     * this cache never fabricates a state, only ever returns one it stored
     * itself after a real `prep_prove`/`prove` call.
     */
    suspend fun priorStateFor(credentialBytes: ByteArray, disclosedClaims: List<String>): ByteArray? {
        val key = keyFor(credentialBytes, disclosedClaims)
        mutex.withLock {
            val entry = entries[key] ?: return null
            if (entry.reuseCount >= maxReusesPerEntry) {
                Timber.i("Vega prep-chain for this credential/disclosure hit its reuse limit ($maxReusesPerEntry) - forcing a fresh prep_prove")
                entries.remove(key)
                return null
            }
            return entry.state
        }
    }

    /**
     * Records the state a `prove()` (or bare `prep_prove`, for
     * [VegaProofSystem.prewarm]) call just produced, for the next call
     * against this exact (credential, disclosed claims) pair to reuse.
     * `usedCachedState` says whether THIS call itself consumed a cached
     * entry (so its reuse count continues one already in progress) or
     * started a fresh chain (so the count resets to zero) - the cache has
     * no other way to tell those apart, since both look identical from the
     * state bytes alone.
     */
    suspend fun record(credentialBytes: ByteArray, disclosedClaims: List<String>, nextState: ByteArray?, usedCachedState: Boolean) {
        if (nextState == null) return
        val key = keyFor(credentialBytes, disclosedClaims)
        mutex.withLock {
            val priorCount = if (usedCachedState) entries[key]?.reuseCount ?: 0 else 0
            entries[key] = Entry(nextState, priorCount + 1)
        }
    }

    /** Drops every cached entry - e.g. on logout, so a new account never inherits the previous one's prep chains. */
    suspend fun clear() {
        mutex.withLock { entries.clear() }
    }

    private fun keyFor(credentialBytes: ByteArray, disclosedClaims: List<String>): Key {
        val credentialDigest = sha256Hex(credentialBytes)
        // Sorted and joined so {"a","b"} and {"b","a"} hit the same entry -
        // the circuit's step-circuit slots are fixed per credential
        // (VegaProofSystem.buildWitness's own doc comment), so the ORDER
        // claims were requested in is never meaningful, only the SET.
        val disclosureSignature = disclosedClaims.sorted().joinToString(",")
        return Key(credentialDigest, disclosureSignature)
    }

    private fun sha256Hex(data: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
}
