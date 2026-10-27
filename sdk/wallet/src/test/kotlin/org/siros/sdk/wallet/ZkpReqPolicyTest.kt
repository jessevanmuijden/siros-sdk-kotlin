package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.siros.sdk.transport.VerifiedRequest

class ZkpReqPolicyTest {
    private fun vr(signed: Boolean = true, verification: String? = "verified", mode: String? = "direct_post.jwt") =
        VerifiedRequest(clientId = "x509_san_dns:rp.example", responseMode = mode, signed = signed, signatureVerification = verification)

    @Test fun signedVerifiedAndEncrypted_isAccepted() = assertNull(ZkpReqPolicy.refusalStep(vr(), true))

    @Test fun missingVerifiedRequest_isUnsigned_failClosed() =
        assertEquals(ZkpReqPolicy.STEP_UNSIGNED, ZkpReqPolicy.refusalStep(null, true))

    @Test fun notSigned_isRefused() =
        assertEquals(ZkpReqPolicy.STEP_UNSIGNED, ZkpReqPolicy.refusalStep(vr(signed = false, verification = "none"), true))

    @Test fun signedFlagWithoutVerifiedSignature_isRefused() {
        assertEquals(ZkpReqPolicy.STEP_UNSIGNED, ZkpReqPolicy.refusalStep(vr(verification = "deferred"), true))
        assertEquals(ZkpReqPolicy.STEP_UNSIGNED, ZkpReqPolicy.refusalStep(vr(verification = null), true))
    }

    @Test fun signedButPlainResponseMode_isRefused() =
        assertEquals(ZkpReqPolicy.STEP_NOT_ENCRYPTED, ZkpReqPolicy.refusalStep(vr(mode = "direct_post"), true))

    @Test fun signedAndJwtModeButNoResponseEncryptionKey_isRefused() =
        assertEquals(ZkpReqPolicy.STEP_NOT_ENCRYPTED, ZkpReqPolicy.refusalStep(vr(), false))
}
