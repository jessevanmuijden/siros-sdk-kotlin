// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import java.security.MessageDigest

/**
 * Remembers the presentation request links the wallet has just started, so the SAME link delivered again is not answered twice.
 *
 * Why: an issuer that wants a presentation before it issues sends the OpenID4VP request to the wallet's redirect URI from its web
 * page. When the user comes back to that page (the browser tab is still open) it can fire the same request again, and the host app
 * receives the identical link a second time, after the first presentation was already answered. A second flow for it is a duplicate
 * consent screen for a request that is done (and that the verifier would refuse anyway: its nonce is spent).
 *
 * A link is [admit]ted once per [ttlMillis]; the same link inside the window is not. [release] forgets it, so a start that failed or
 * was cancelled can be retried at once. Only a digest of the link is kept (it can carry a nonce), at most [capacity] of them.
 */
class PresentationLinkLedger(
    private val ttlMillis: Long = DEFAULT_TTL_MILLIS,
    private val capacity: Int = 16,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val seen = LinkedHashMap<String, Long>()

    /** True when [link] may start a presentation (first time, or last seen longer than the window ago); records it. */
    @Synchronized
    fun admit(link: String): Boolean {
        val now = clock()
        seen.entries.removeAll { now - it.value >= ttlMillis }
        val key = digest(link)
        if (seen.containsKey(key)) return false
        seen[key] = now
        while (seen.size > capacity) seen.remove(seen.keys.first())
        return true
    }

    /** Forgets [link]: a retry of it is admitted again. */
    @Synchronized
    fun release(link: String) {
        seen.remove(digest(link))
    }

    /** Forgets every link (a flow was cancelled or the session ended). */
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
