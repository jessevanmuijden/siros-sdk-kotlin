// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv.facetec

import org.siros.sdk.idv.IDVException
import org.siros.sdk.idv.IDVResult

/**
 * Turns a finished FaceTec session into the provider's result.
 *
 * What facetec-api said wins over the session status: an issued credential is returned even if
 * the SDK reports the session oddly, and a refusal is reported as such rather than as whatever
 * status the session ended with.
 *
 * @param status Name of the `FaceTecSessionStatus` constant, or `null` if the SDK returned none.
 */
internal fun sessionOutcome(status: String?, relay: FaceTecSessionRequestRelay): IDVResult {
    relay.credentialOfferURI?.let { return IDVResult(it, relay.transactionId) }
    relay.credentialIssueErrorCode?.let { throw refusalToException(it, relay.credentialIssueError) }

    throw when (status) {
        "USER_CANCELLED_FACE_SCAN", "USER_CANCELLED_ID_SCAN" -> IDVException.Cancelled()
        "CAMERA_PERMISSIONS_DENIED" -> IDVException.Unavailable("camera permission denied")
        "CAMERA_ERROR" -> IDVException.Unavailable("the camera could not be used")
        "LOCKED_OUT" -> IDVException.ProviderError("locked_out", "Too many attempts; FaceTec has locked this device out for a while")
        "REQUEST_ABORTED" -> relay.transportError?.let { IDVException.NetworkError(it) }
            ?: IDVException.ProviderError("request_aborted", "The FaceTec session was aborted")
        "SESSION_COMPLETED" -> IDVException.VerificationFailed("The scan completed, but no credential was issued")
        null -> IDVException.ProviderError("no_session_result", "FaceTec returned no session result")
        else -> IDVException.ProviderError(status.lowercase(), "FaceTec session ended with $status")
    }
}

/**
 * Maps facetec-api's `credentialIssueErrorCode` to an [IDVException].
 *
 * - `nfc_*`: the document's chip was not read and authenticated
 *   ([IDVException.DocumentChipNotVerified]).
 * - `liveness_failed`: [IDVException.LivenessFailed].
 * - `match_failed`, `policy_rejected`, `document_unreadable`: [IDVException.VerificationFailed].
 * - Anything else, e.g. `chip_untrusted`, `issuance_failed`, `internal_error`, `session_expired`:
 *   [IDVException.ProviderError], which keeps the code (`errorCode` = `idv_provider_<code>`) so
 *   an app can still explain it.
 */
internal fun refusalToException(code: String, message: String?): IDVException {
    val text = message ?: "No credential was issued ($code)"
    return when {
        code.startsWith("nfc_") -> IDVException.DocumentChipNotVerified(code, text)
        code == "liveness_failed" -> IDVException.LivenessFailed(text)
        code == "match_failed" || code == "policy_rejected" || code == "document_unreadable" ->
            IDVException.VerificationFailed(text)
        else -> IDVException.ProviderError(code, text)
    }
}
