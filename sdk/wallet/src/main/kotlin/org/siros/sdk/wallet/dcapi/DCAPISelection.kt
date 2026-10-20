// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

/**
 * Turns what the OS picker reported into the credential ids the wallet is asked to present.
 *
 * An empty id list means "no selection information: present the first eligible credential", which
 * is right only for a caller that intentionally omits it (a `null` `selectedCredentialIds` passed
 * to the wallet). A request that came back from the OS picker always carries a selection, so one
 * that is absent or cannot be read is never the empty list: it is [NO_SUCH_CREDENTIAL], an id no
 * credential has, which the wallet refuses as an unavailable selection. Otherwise an unreadable
 * pick would silently produce a proof for a different credential.
 */
internal object DCAPISelection {
    /** An id no credential has. */
    const val NO_SUCH_CREDENTIAL = -1L

    /**
     * @param selectedSet the selected set's credential ids; `null` when the request has none; may throw
     * @param selectedEntry the single selected entry id; `null` when absent; may throw
     */
    fun resolve(selectedSet: () -> List<String>?, selectedEntry: () -> String?): List<Long> {
        val fromSet = try {
            selectedSet()
        } catch (e: Exception) {
            return listOf(NO_SUCH_CREDENTIAL)
        }
        if (!fromSet.isNullOrEmpty()) {
            // Fail closed: one unreadable id refuses the whole selection. A readable subset must never
            // authorise a response the user's full pick did not (two queries may share a candidate).
            val ids = fromSet.map { it.toLongOrNull() ?: return listOf(NO_SUCH_CREDENTIAL) }
            return ids
        }
        val entry = try {
            selectedEntry()
        } catch (e: Exception) {
            return listOf(NO_SUCH_CREDENTIAL)
        }
        return listOf(entry?.let { it.toLongOrNull() ?: NO_SUCH_CREDENTIAL } ?: NO_SUCH_CREDENTIAL)
    }
}
