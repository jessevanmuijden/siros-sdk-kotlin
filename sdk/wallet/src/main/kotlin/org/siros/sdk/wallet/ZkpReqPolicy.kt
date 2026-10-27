package org.siros.sdk.wallet

import org.siros.sdk.transport.VerifiedRequest

/**
 * The wallet's policy for a `zkp_req` presentation on the engine transport (the engine does not apply it; same rule as the web
 * wallet's `zkpReqRefusal`): the request must be a signed request object whose signature the engine VERIFIED, and the response must be
 * encrypted (`direct_post.jwt` with a `response_encryption` key). A missing `verified_request` reads as not signed (fail closed).
 */
internal object ZkpReqPolicy {
    const val STEP_UNSIGNED = "unsigned-request"
    const val STEP_NOT_ENCRYPTED = "response-not-encrypted"

    /** The refusal step, or `null` when the request may proceed. */
    fun refusalStep(verifiedRequest: VerifiedRequest?, hasResponseEncryption: Boolean): String? {
        if (verifiedRequest?.signed != true || verifiedRequest.signatureVerification != "verified") return STEP_UNSIGNED
        if (verifiedRequest.responseMode != "direct_post.jwt" || !hasResponseEncryption) return STEP_NOT_ENCRYPTED
        return null
    }
}
