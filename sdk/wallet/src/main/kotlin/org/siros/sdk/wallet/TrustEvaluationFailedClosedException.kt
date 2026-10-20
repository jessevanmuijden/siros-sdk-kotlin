package org.siros.sdk.wallet

import org.siros.sdk.credentials.SirosException

/**
 * A trust evaluation that must fail closed: the backend refused the caller,
 * or it was unreachable while the wallet is in
 * [MdocTrustEvaluationMode.REMOTE_ONLY]. Nothing stands in for the missing
 * answer - not a stale cached decision (the decision cache never serves an
 * expired or failed entry), and not the weaker local roots.
 */
class TrustEvaluationFailedClosedException(
    message: String,
    cause: Throwable? = null,
) : SirosException(message, cause, errorCode = "trust_evaluation_failed_closed")
