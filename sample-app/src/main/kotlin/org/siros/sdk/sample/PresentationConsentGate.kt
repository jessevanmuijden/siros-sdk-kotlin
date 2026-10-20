// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.siros.sdk.credentials.PresentationConsentRequest
import org.siros.sdk.wallet.PresentationConsentHandler

/**
 * A request on screen. A plain class (identity equality) on purpose: [PresentationConsentRequest] is a data class,
 * so two requests with equal content would be conflated by a `StateFlow` and the second one never shown.
 */
class PendingPresentationConsent(val request: PresentationConsentRequest) {
    /** This request's own answer: completing it can never affect another request, whatever the timing. */
    internal val answer = CompletableDeferred<Boolean>()
}

/**
 * Hands a `circuit_zk` presentation consent from the SDK to the UI and the answer back: [handler] suspends
 * the SDK until the user answers via [answer], while [pending] is what the UI renders. Cancelling the SDK's
 * wait (its own time limit) clears [pending], so a stale dialog never outlives the request. Requests are
 * served one at a time, and an answer names the request it is for ([answer]): a callback of a replaced or
 * expired dialog can never approve another presentation. The request is never logged.
 */
class PresentationConsentGate {
    private val _pending = MutableStateFlow<PendingPresentationConsent?>(null)

    /** The request waiting for the user, or `null`. */
    val pending: StateFlow<PendingPresentationConsent?> = _pending

    private val serial = Mutex()

    /** Register this with `SirosWallet.presentationConsentHandler`. */
    val handler = PresentationConsentHandler { request ->
        // One request on screen at a time; a second waits here (and is subject to the SDK's own time limit).
        serial.withLock {
            val shown = PendingPresentationConsent(request)
            _pending.value = shown
            try {
                shown.answer.await()
            } finally {
                // Clear only our own entry.
                _pending.compareAndSet(shown, null)
            }
        }
    }

    /**
     * The user's answer to [shown]. It completes that request's own deferred, so a late callback of a replaced or
     * expired dialog is a no-op and can never approve the request now on screen.
     */
    fun answer(shown: PendingPresentationConsent, agreed: Boolean) {
        shown.answer.complete(agreed)
    }
}
