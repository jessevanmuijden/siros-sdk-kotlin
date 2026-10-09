// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv.facetec

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.idv.IDVException
import org.siros.sdk.idv.IDVResult
import java.io.IOException

/** The relay's bookkeeping and how a finished session becomes a result or an error. */
class FaceTecSessionTest {
    @Test
    fun `every request of one session carries the same externalDatabaseRefID`() {
        val refs = mutableListOf<String>()
        val relay = FaceTecSessionRequestRelay { _, ref -> refs += ref; ProcessRequestResponse("r") }

        relay.onSessionRequest("liveness")
        relay.onSessionRequest("id-scan")
        relay.onSessionRequest("nfc")

        assertEquals(1, refs.toSet().size)
        assertEquals(relay.externalDatabaseRefID, refs.first())
        assertTrue(relay.externalDatabaseRefID.startsWith("siros-sdk-android-"))
    }

    @Test
    fun `two sessions never share an externalDatabaseRefID`() {
        val a = FaceTecSessionRequestRelay { _, _ -> ProcessRequestResponse("r") }
        val b = FaceTecSessionRequestRelay { _, _ -> ProcessRequestResponse("r") }

        assertNotEquals(a.externalDatabaseRefID, b.externalDatabaseRefID)
    }

    @Test
    fun `an issued credential is the session's result, whatever the status`() {
        val relay = relayAnswering(ProcessRequestResponse("r", credentialOfferURI = "openid-credential-offer://x", transactionId = "tx-1"))

        for (status in listOf("SESSION_COMPLETED", "USER_CANCELLED_ID_SCAN", null)) {
            assertEquals(IDVResult("openid-credential-offer://x", "tx-1"), sessionOutcome(status, relay))
        }
    }

    @Test
    fun `an offer from an earlier request survives later requests without one`() {
        val responses = ArrayDeque(
            listOf(
                ProcessRequestResponse("r1", credentialOfferURI = "openid-credential-offer://x"),
                ProcessRequestResponse("r2"),
            ),
        )
        val relay = FaceTecSessionRequestRelay { _, _ -> responses.removeFirst() }
        relay.onSessionRequest("a")
        relay.onSessionRequest("b")

        assertEquals("openid-credential-offer://x", sessionOutcome("SESSION_COMPLETED", relay).credentialOfferURI)
    }

    @Test
    fun `a refusal is reported with facetec-api's code and message`() {
        val relay = relayAnswering(
            ProcessRequestResponse("r", credentialIssueErrorCode = "nfc_skipped", credentialIssueError = "NFC was skipped"),
        )

        val e = failureOf { sessionOutcome("SESSION_COMPLETED", relay) }

        assertTrue(e is IDVException.DocumentChipNotVerified)
        assertEquals("nfc_skipped", (e as IDVException.DocumentChipNotVerified).reason)
        assertEquals("NFC was skipped", e.message)
    }

    @Test
    fun `refusal codes map to the matching IDVException`() {
        for (code in listOf("nfc_not_requested", "nfc_device_not_capable", "nfc_skipped", "nfc_chip_read_failed", "nfc_not_authenticated")) {
            assertTrue(code, refusalToException(code, null) is IDVException.DocumentChipNotVerified)
        }
        assertTrue(refusalToException("liveness_failed", null) is IDVException.LivenessFailed)
        for (code in listOf("match_failed", "policy_rejected", "document_unreadable")) {
            assertTrue(code, refusalToException(code, null) is IDVException.VerificationFailed)
        }
        assertTrue(refusalToException("chip_untrusted", null) is IDVException.ChipUntrusted)
        assertTrue(refusalToException("chip_photo_mismatch", null) is IDVException.ChipPhotoMismatch)
        assertEquals("idv_chip_photo_mismatch", refusalToException("chip_photo_mismatch", null).errorCode)
        assertTrue(refusalToException("document_expired", null) is IDVException.DocumentExpired)
        assertTrue(refusalToException("session_expired", null) is IDVException.SessionExpired)
        assertEquals("idv_chip_untrusted", refusalToException("chip_untrusted", null).errorCode)
        assertEquals("idv_document_expired", refusalToException("document_expired", null).errorCode)
        assertEquals("idv_session_expired", refusalToException("session_expired", null).errorCode)
        for (code in listOf("issuance_failed", "internal_error", "something_new")) {
            val e = refusalToException(code, null)
            assertTrue(code, e is IDVException.ProviderError)
            assertEquals(code, (e as IDVException.ProviderError).providerCode)
            assertEquals("idv_provider_$code", e.errorCode)
        }
    }

    @Test
    fun `every error code facetec-api v0_16_0 returns maps to some exception`() {
        // The codes of internal/idverrors/errors.go at v0.16.0.
        val codes = listOf(
            "liveness_failed", "match_failed", "document_unreadable", "policy_rejected", "session_expired",
            "nfc_skipped", "chip_untrusted", "nfc_not_requested", "nfc_device_not_capable",
            "nfc_chip_read_failed", "nfc_not_authenticated", "document_expired", "issuance_failed", "internal_error",
            // Added by sirosfoundation/facetec-api#78.
            "chip_photo_mismatch",
        )
        for (code in codes) {
            val e = refusalToException(code, "m")
            assertEquals(code, "m", e.message?.removePrefix("[$code] "))
        }
    }

    @Test
    fun `a stale liveness proof is a LivenessFailed refusal to restart from`() {
        val relay = relayAnswering(
            ProcessRequestResponse("r", credentialIssueErrorCode = "liveness_failed", credentialIssueError = "liveness check did not pass"),
        )

        assertTrue(failureOf { sessionOutcome("SESSION_COMPLETED", relay) } is IDVException.LivenessFailed)
    }

    @Test
    fun `a new session after a refusal starts with a fresh relay and no carried-over refusal`() {
        val refused = relayAnswering(ProcessRequestResponse("r", credentialIssueErrorCode = "liveness_failed"))
        val next = relayAnswering(ProcessRequestResponse("r", credentialOfferURI = "openid-credential-offer://y"))

        assertNotEquals(refused.externalDatabaseRefID, next.externalDatabaseRefID)
        assertNull(next.credentialIssueErrorCode)
        assertEquals("openid-credential-offer://y", sessionOutcome("SESSION_COMPLETED", next).credentialOfferURI)
    }

    @Test
    fun `a refusal without a message still names the code`() {
        assertEquals("No credential was issued (policy_rejected)", refusalToException("policy_rejected", null).message)
    }

    @Test
    fun `session statuses map to the matching IDVException`() {
        val relay = relayAnswering(ProcessRequestResponse("r"))

        assertTrue(failureOf { sessionOutcome("USER_CANCELLED_FACE_SCAN", relay) } is IDVException.Cancelled)
        assertTrue(failureOf { sessionOutcome("USER_CANCELLED_ID_SCAN", relay) } is IDVException.Cancelled)
        assertTrue(failureOf { sessionOutcome("CAMERA_PERMISSIONS_DENIED", relay) } is IDVException.Unavailable)
        assertTrue(failureOf { sessionOutcome("CAMERA_ERROR", relay) } is IDVException.Unavailable)
        assertTrue(failureOf { sessionOutcome("SESSION_COMPLETED", relay) } is IDVException.VerificationFailed)
        assertEquals("locked_out", (failureOf { sessionOutcome("LOCKED_OUT", relay) } as IDVException.ProviderError).providerCode)
        assertEquals("unknown_internal_error", (failureOf { sessionOutcome("UNKNOWN_INTERNAL_ERROR", relay) } as IDVException.ProviderError).providerCode)
        assertEquals("no_session_result", (failureOf { sessionOutcome(null, relay) } as IDVException.ProviderError).providerCode)
    }

    @Test
    fun `an aborted session caused by the network is a NetworkError with the cause`() {
        val cause = IOException("offline")
        val relay = FaceTecSessionRequestRelay { _, _ -> throw cause }

        assertNull(relay.onSessionRequest("blob"))
        assertSame(cause, relay.transportError)

        val e = failureOf { sessionOutcome("REQUEST_ABORTED", relay) }
        assertTrue(e is IDVException.NetworkError)
        assertSame(cause, e.cause)
    }

    @Test
    fun `an aborted session without a network failure is a provider error`() {
        val e = failureOf { sessionOutcome("REQUEST_ABORTED", relayAnswering(ProcessRequestResponse("r"))) }

        assertEquals("request_aborted", (e as IDVException.ProviderError).providerCode)
    }

    private fun relayAnswering(response: ProcessRequestResponse) =
        FaceTecSessionRequestRelay { _, _ -> response }.also { it.onSessionRequest("blob") }

    private fun failureOf(block: () -> Any): IDVException {
        try {
            block()
        } catch (e: IDVException) {
            return e
        }
        fail("expected an IDVException")
        throw AssertionError()
    }
}
