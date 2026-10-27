// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import java.security.MessageDigest

/**
 * Remembers the presentation request links the wallet has just started, so the SAME link delivered again is not answered twice.
 *
 * Why: an issuer that wants a presentation before it issues sends the OpenID4VP request to the wallet's redirect URI from its web
 * page. When the user is back on that page (the browser tab is still open) it can fire the same request again, and the host app
 * receives the identical link a second time, after the first presentation was already answered. A second flow for it is a duplicate
 * consent screen for a request that is done (and that the verifier would refuse anyway: its nonce is spent).
 *
 * Each entry is IN FLIGHT until its flow completes, then COMPLETED. It remembers the engine connection generation its start was sent on
 * and, once the engine reports a flow for it, the flow id, so every release touches only the entry it belongs to:
 * - an error, a local failure or a loss of THAT flow releases that entry ([releaseFlow]);
 * - a connection replaced or lost releases the entries started on the connections that are gone ([releaseOlderThan], [releaseUpTo]):
 *   their `flow_start` can never be answered, and no flow id was ever seen for them;
 * - a session ending or a cancelled flow releases the in-flight entries only ([releaseInFlight], [releaseUnassociated]); an ANSWERED link
 *   stays recorded for its whole window (a redelivery of it is still a spent request).
 *
 * A link is admitted once per [ttlMillis]. Only a digest of the link is kept (it can carry a nonce), at most [capacity] of them.
 */
class PresentationLinkLedger(
    private val ttlMillis: Long = DEFAULT_TTL_MILLIS,
    private val capacity: Int = 16,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private class Entry(var inFlight: Boolean, var generation: Int, var flowId: String?, var at: Long)

    private val seen = LinkedHashMap<String, Entry>()

    /** True when [link] may start a presentation on connection [generation] (first time, or last seen longer than the window ago); records it in flight. */
    @Synchronized
    fun admit(link: String, generation: Int = 0): Boolean {
        val now = clock()
        seen.entries.removeAll { now - it.value.at >= ttlMillis }
        val key = digest(link)
        if (seen.containsKey(key)) return false
        seen[key] = Entry(inFlight = true, generation = generation, flowId = null, at = now)
        while (seen.size > capacity) seen.remove(seen.keys.first())
        return true
    }

    /** The start of [link] was sent on connection [generation] (it may have changed while the wallet reconnected): records that, re-admitting the entry if a loss released it meanwhile. */
    @Synchronized
    fun rebind(link: String, generation: Int) {
        val key = digest(link)
        val entry = seen[key]
        if (entry == null) seen[key] = Entry(inFlight = true, generation = generation, flowId = null, at = clock()) else entry.generation = generation
    }

    /** The engine reported [flowId] on connection [generation]: it belongs to the oldest in-flight entry of that connection that has no flow yet (a flow already known is left alone). */
    @Synchronized
    fun associate(flowId: String, generation: Int) {
        if (seen.values.any { it.flowId == flowId }) return
        seen.values.firstOrNull { it.inFlight && it.flowId == null && it.generation == generation }?.flowId = flowId
    }

    /** The flow [flowId] was answered: its entry stays for a full window from now. */
    @Synchronized
    fun completeFlow(flowId: String) {
        seen.values.firstOrNull { it.flowId == flowId }?.let { it.inFlight = false; it.at = clock() }
    }

    /** [link] was answered: it stays recorded for a full window from now. */
    @Synchronized
    fun markCompleted(link: String) {
        seen[digest(link)]?.let { it.inFlight = false; it.at = clock() }
    }

    /** The flow [flowId] failed, was lost or ended in a local failure before an answer: a retry of its link goes through. */
    @Synchronized
    fun releaseFlow(flowId: String) {
        seen.entries.removeAll { it.value.inFlight && it.value.flowId == flowId }
    }

    /** Connections older than [generation] are gone: what was started on them can never be answered. */
    @Synchronized
    fun releaseOlderThan(generation: Int) {
        seen.entries.removeAll { it.value.inFlight && it.value.generation < generation }
    }

    /** Connections up to [generation] are lost: what was started on them can never be answered. */
    @Synchronized
    fun releaseUpTo(generation: Int) {
        seen.entries.removeAll { it.value.inFlight && it.value.generation <= generation }
    }

    /** A cancelled start: the in-flight entries the engine has reported no flow for. */
    @Synchronized
    fun releaseUnassociated() {
        seen.entries.removeAll { it.value.inFlight && it.value.flowId == null }
    }

    /** The session ended: every in-flight entry is gone with it; answered ones keep their window. */
    @Synchronized
    fun releaseInFlight() {
        seen.entries.removeAll { it.value.inFlight }
    }

    /** Forgets [link]: a retry of it is admitted again. */
    @Synchronized
    fun release(link: String) {
        seen.remove(digest(link))
    }

    /** Forgets every link. */
    @Synchronized
    fun releaseAll() {
        seen.clear()
    }

    private fun digest(link: String): String =
        MessageDigest.getInstance("SHA-256").digest(link.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    companion object {
        /** One minute: long enough for a page to re-fire the request on the way back, short enough that a deliberate retry is not blocked. */
        const val DEFAULT_TTL_MILLIS = 60_000L
    }
}
