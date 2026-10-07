// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.annotation.StringRes
import org.siros.sdk.credentials.TransactionDataReason

/**
 * The sample app's own wording for why a payment confirmation request was
 * refused or declined. The SDK reports only the [TransactionDataReason]; what
 * to tell the user, and in which language, is the app's job.
 */
@StringRes
fun transactionRefusalMessageRes(reason: TransactionDataReason): Int = when (reason) {
    TransactionDataReason.DISABLED -> R.string.transaction_refused_disabled
    TransactionDataReason.INVALID_ENTRY -> R.string.transaction_refused_invalid_entry
    TransactionDataReason.INCONSISTENT_WITH_ORCHESTRATOR -> R.string.transaction_refused_inconsistent
    TransactionDataReason.UNSUPPORTED_FORMAT -> R.string.transaction_refused_unsupported_format
    TransactionDataReason.NOT_SCA_ATTESTATION -> R.string.transaction_refused_not_sca
    TransactionDataReason.UNSUPPORTED_TYPE -> R.string.transaction_refused_unsupported_type
    TransactionDataReason.SCHEMA_VIOLATION -> R.string.transaction_refused_schema
    TransactionDataReason.METADATA_UNAVAILABLE -> R.string.transaction_refused_metadata
    TransactionDataReason.UNSUPPORTED_HASH_ALGORITHM -> R.string.transaction_refused_hash_alg
    TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS -> R.string.transaction_refused_factors
    TransactionDataReason.NO_CONSENT_HANDLER -> R.string.transaction_refused_no_handler
    TransactionDataReason.DECLINED -> R.string.transaction_refused_declined
}
