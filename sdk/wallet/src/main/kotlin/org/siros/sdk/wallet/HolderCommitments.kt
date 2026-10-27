// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.WalletException

/**
 * The issuer refused the auxiliary data (commitment) the wallet sent: it holds a conflicting one (flow error code
 * `AUXILIARY_DATA_CONFLICT`, `error.details.error == "auxiliary_data_conflict"`). Retrying never helps, the conflict is
 * resolved out of band with the issuer, so there is no retry affordance; [userMessageRes] is the localised sentence.
 */
class AuxiliaryDataConflictException(
    val issuerMessage: String,
) : org.siros.sdk.credentials.SirosException(
    "The issuer reports a conflict with the auxiliary data the wallet sent",
    errorCode = ERROR_CODE,
) {
    /** Always false: the same request would be refused again. */
    val retryable: Boolean get() = false

    val userMessageRes: Int get() = R.string.siros_auxiliary_data_conflict

    companion object {
        const val FLOW_ERROR_CODE = "AUXILIARY_DATA_CONFLICT"
        const val DETAIL_ERROR = "auxiliary_data_conflict"
        const val ERROR_CODE = "auxiliary_data_conflict"
    }
}

/**
 * The issuer refused the auxiliary data of the key proofs: `invalid_proof` whose `error_description` starts `auxiliary_data: ` (vc pull 850).
 * Terminal and NOT retryable: the same proofs would be refused again. Only the fixed [Reason] is kept, never the issuer's free text.
 */
class AuxiliaryDataRefusedException(val reason: Reason) : org.siros.sdk.credentials.SirosException(
    "The issuer refused the auxiliary data in the key proofs (${reason.code})",
    errorCode = ERROR_CODE,
) {
    /** Always false: the same request would be refused again. */
    val retryable: Boolean get() = false

    val userMessageRes: Int get() = R.string.siros_auxiliary_data_refused

    /** The details vc names (the fixed set); everything else is [OTHER]. */
    enum class Reason(val code: String) {
        PROOFS_DIFFER("proofs_differ"),
        ENTRY_REQUIRED("entry_required"),
        NO_SUCH_ENTRY("no_such_entry"),
        ALG("alg"),
        ENTRY_MEMBERS("entry_members"),
        COMMITMENT_FORMAT("commitment_format"),
        OTHER("other"),
    }

    companion object {
        const val ERROR_CODE = "auxiliary_data_refused"
        private const val PREFIX = "auxiliary_data: "

        /** The refusal an issuer error text expresses, or null when [message] is not an `auxiliary_data: ` refusal. */
        fun fromIssuerMessage(message: String?): AuxiliaryDataRefusedException? {
            val text = message ?: return null
            val at = text.indexOf(PREFIX)
            if (at < 0) return null
            val detail = text.substring(at + PREFIX.length)
            val reason = when {
                detail.contains("different auxiliary_data") -> Reason.PROOFS_DIFFER
                detail.contains("is required") -> Reason.ENTRY_REQUIRED
                detail.contains("lists no entry") -> Reason.NO_SUCH_ENTRY
                detail.contains("alg must be") -> Reason.ALG
                detail.contains("carries only") -> Reason.ENTRY_MEMBERS
                detail.contains("base64url sha-256") -> Reason.COMMITMENT_FORMAT
                else -> Reason.OTHER
            }
            return AuxiliaryDataRefusedException(reason)
        }
    }
}
