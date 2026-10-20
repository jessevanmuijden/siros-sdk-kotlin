package org.siros.sdk.wallet

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonPrimitive
import java.time.Duration

/**
 * The one cache for AuthZEN trust decisions (`POST /v1/evaluate`), shared by
 * every evaluate call site of a [SirosWallet].
 *
 * What is cached: a SUCCESSFUL evaluation, i.e. a 2xx response carrying a
 * boolean `decision`, whether true or false. Never an exception: a network
 * failure, timeout, 4xx or 5xx is not a decision and is not remembered, and an
 * expired entry is deleted rather than served, even when the backend is
 * unreachable (an unreachable backend is handled by the explicit fallback and
 * refusal rules, never by a stale answer).
 *
 * Key: [keyFor] hashes the complete request body - action, subject type and
 * id, the whole certificate chain / key material, and the full `context` - so
 * a different certificate, doc type or any other input never reuses an entry.
 *
 * Trade-off: a revocation or registry change can take up to [ttl] to be
 * noticed by a wallet that asked the same question within that window. A
 * [ttl] of zero disables the cache (every call goes to the backend).
 *
 * In memory only, bounded ([maxSize], least recently used evicted), thread
 * safe, with concurrent identical evaluations sharing one in-flight request.
 * [clear] drops everything, detaches evaluations already in flight and keeps
 * their results from being stored.
 */
internal class TrustDecisionCache(
    private val ttl: Duration,
    private val maxSize: Int = DEFAULT_MAX_SIZE,
    // elapsedRealtime keeps counting through deep sleep; nanoTime does not, which
    // would let an entry outlive its TTL on a phone that slept.
    private val nowMillis: () -> Long = { android.os.SystemClock.elapsedRealtime() },
) {
    private class Entry(val response: JsonObject, val storedAt: Long)

    private class LeaderCancelled : RuntimeException()

    private val ttlMillis = ttl.toMillis()
    private val lock = Any()
    private var generation = 0L
    private val entries = object : LinkedHashMap<String, Entry>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>?): Boolean = size > maxSize
    }
    private val inFlight = HashMap<String, CompletableDeferred<JsonObject>>()

    val enabled: Boolean get() = ttlMillis > 0

    /** Number of live entries (expired ones may still be counted until next touched). */
    val size: Int get() = synchronized(lock) { entries.size }

    suspend fun getOrEvaluate(key: String, evaluate: suspend () -> JsonObject): JsonObject {
        if (!enabled) return evaluate()
        // Pinned for this whole call, including retries after a cancelled
        // leader: a call that began before clear() never registers a result.
        val startedGeneration = synchronized(lock) { generation }
        while (true) {
            var leader: CompletableDeferred<JsonObject>? = null
            var follow: CompletableDeferred<JsonObject>? = null
            var stale = false
            val fresh: JsonObject? = synchronized(lock) {
                if (generation != startedGeneration) {
                    // Invalidated since this call began (its connection is gone):
                    // never share or consult the new generation's state.
                    stale = true
                    return@synchronized null
                }
                val entry = entries[key]
                if (entry != null) {
                    if (nowMillis() - entry.storedAt < ttlMillis) return@synchronized entry.response
                    entries.remove(key)
                }
                val existing = inFlight[key]
                if (existing != null) {
                    follow = existing
                } else {
                    leader = CompletableDeferred<JsonObject>().also { inFlight[key] = it }
                }
                null
            }
            if (stale) return evaluate()
            if (fresh != null) return fresh
            val shared = follow
            if (shared != null) {
                try {
                    return shared.await()
                } catch (_: LeaderCancelled) {
                    continue
                }
            }
            val mine = checkNotNull(leader)
            try {
                val response = evaluate()
                synchronized(lock) {
                    if (inFlight[key] === mine) inFlight.remove(key)
                    if (generation == startedGeneration && isDecision(response)) {
                        entries[key] = Entry(response, nowMillis())
                    }
                }
                mine.complete(response)
                return response
            } catch (t: Throwable) {
                synchronized(lock) { if (inFlight[key] === mine) inFlight.remove(key) }
                mine.completeExceptionally(if (t is CancellationException) LeaderCancelled() else t)
                throw t
            }
        }
    }

    fun clear() {
        synchronized(lock) {
            generation++
            entries.clear()
            // Detach pending evaluations: a request made after clear() (e.g.
            // for a new connection) must not join the old connection's.
            inFlight.clear()
        }
    }

    private fun isDecision(response: JsonObject): Boolean =
        runCatching { response["decision"]?.jsonPrimitive?.booleanOrNull }.getOrNull() != null

    companion object {
        const val DEFAULT_MAX_SIZE = 256

        /** Cache key: SHA-256 over the full evaluation request body. */
        fun keyFor(request: JsonObject): String =
            java.security.MessageDigest.getInstance("SHA-256")
                .digest(request.toString().toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
    }
}
