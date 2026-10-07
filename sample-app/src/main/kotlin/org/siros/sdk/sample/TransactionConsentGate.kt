// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.siros.sdk.wallet.TransactionConsentHandler
import org.siros.sdk.wallet.TransactionConsentRequest

/**
 * Hands a payment confirmation from the SDK to the UI and the answer back:
 * [handler] suspends the SDK until the user answers via [answer], while
 * [pending] is what the UI renders. Cancelling the SDK's wait (its own time
 * limit) clears [pending], so a stale dialog never outlives the request.
 */
class TransactionConsentGate {
    private val _pending = MutableStateFlow<TransactionConsentRequest?>(null)

    /** The request waiting for the user, or `null`. */
    val pending: StateFlow<TransactionConsentRequest?> = _pending

    @Volatile
    private var waiting: CompletableDeferred<Boolean>? = null

    /** Register this with `SirosWallet.transactionConsentHandler`. */
    val handler = TransactionConsentHandler { request ->
        val answer = CompletableDeferred<Boolean>()
        waiting = answer
        _pending.value = request
        try {
            answer.await()
        } finally {
            if (waiting === answer) {
                waiting = null
                _pending.value = null
            }
        }
    }

    /** The user's answer to [pending]; ignored when nothing is waiting. */
    fun answer(confirmed: Boolean) {
        waiting?.complete(confirmed)
    }
}
