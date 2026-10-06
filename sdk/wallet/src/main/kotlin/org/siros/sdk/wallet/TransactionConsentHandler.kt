// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

/**
 * Shows an OpenID4VP `transaction_data` request (EC TS12 payment SCA) to the
 * user and returns their decision.
 *
 * The SDK builds the [TransactionConsentRequest]; the host app only renders
 * it and reports what the user chose. Register one with
 * [SirosWallet.transactionConsentHandler]: without a handler the wallet
 * cannot show the transaction, so it behaves as if TS12 handling were
 * disabled (see [SirosWallet.isTransactionDataEffectivelyEnabled]).
 *
 * A handler that throws, or does not answer in time, counts as **declined**,
 * never as consent.
 */
fun interface TransactionConsentHandler {
    /** @return `true` if the user confirmed every entry; `false` if they declined. */
    suspend fun confirm(request: TransactionConsentRequest): Boolean
}

/** Everything a host app needs to show one `transaction_data` request (EC TS12 3.3). */
data class TransactionConsentRequest(
    /** The verifier asking for the confirmation, as the wallet identified it. */
    val verifier: String?,
    /** Display name of the SCA attestation the transaction is bound to. */
    val credentialName: String?,
    /** One element per transaction, in the verifier's order. */
    val entries: List<TransactionConsentEntry>,
    /**
     * `false` when the request was not signed: the app MUST then show a
     * warning and require explicit confirmation (EC TS12 3.1). `null` when
     * the SDK does not know (the engine and WMP deliver it pre-verified).
     */
    val requestSigned: Boolean?,
    /** The locale the labels were resolved for. */
    val locale: String,
)

/** One transaction to display. */
data class TransactionConsentEntry(
    /** The `transaction_title` UI element, if the type metadata defines one. */
    val title: String?,
    /** Localised name of the transaction type. */
    val typeName: String,
    /** Fields ordered for display; see [TransactionConsentField.level]. */
    val fields: List<TransactionConsentField>,
    /** The required `affirmative_action_label` UI element. */
    val affirmativeLabel: String,
    /** The optional `denial_action_label` UI element. */
    val denialLabel: String?,
    /** The optional `security_hint` UI element. */
    val securityHint: String?,
)

/**
 * One labelled value of a transaction.
 *
 * @property level The `visualisation` level: 1 prominent, 2 on the main
 *   screen, 3 on the main or a supplementary screen (the default when the
 *   metadata sets none), 4 may be omitted.
 */
data class TransactionConsentField(
    val label: String,
    val value: String,
    val level: Int,
)
