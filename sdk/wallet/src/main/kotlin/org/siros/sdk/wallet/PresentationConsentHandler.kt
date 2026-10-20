// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.PresentationConsentRequest

/**
 * Asks the user to consent to a `circuit_zk` presentation and returns their decision.
 *
 * A sibling of [TransactionConsentHandler] (EC TS12 payment confirmation): the two are separate
 * consents and neither enables the other. The SDK builds the [PresentationConsentRequest]; the host
 * only renders it (see [PresentationConsentText] for the SDK-owned wording) and reports what the user
 * chose. Register one with [SirosWallet.presentationConsentHandler]; a DC API request can bring its own
 * (see [SirosWallet.handleDCAPIRequest]).
 *
 * It is asked once per request, before anything is signed or proved and before the issuer-delivered
 * secret seed is fetched. A handler that throws, is cancelled or does not answer in time counts as
 * **declined**, never as consent. Without any handler the wallet refuses a `circuit_zk` request.
 */
fun interface PresentationConsentHandler {
    /** @return `true` if the user consented to everything in [request]; `false` if they declined. */
    suspend fun confirm(request: PresentationConsentRequest): Boolean
}
