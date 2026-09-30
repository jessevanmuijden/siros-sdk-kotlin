// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RemoteIDVClientTest {
    private val fallback: (String) -> IDVException = { IDVException.VerificationFailed(it) }

    @Test
    fun `an nfc code becomes DocumentChipNotVerified with a per-reason error code`() {
        for (reason in listOf(
            "nfc_skipped",
            "nfc_not_supported_by_document",
            "nfc_device_not_capable",
            "nfc_chip_read_failed",
            "nfc_not_authenticated",
        )) {
            val e = idvExceptionFor422(reason, "NFC verification was skipped", "{}", fallback)

            assertTrue(e is IDVException.DocumentChipNotVerified)
            assertEquals(reason, (e as IDVException.DocumentChipNotVerified).reason)
            assertEquals("idv_$reason", e.errorCode)
            assertEquals("NFC verification was skipped", e.message)
        }
    }

    @Test
    fun `an nfc code without a message falls back to the body`() {
        val e = idvExceptionFor422("nfc_skipped", null, "raw body", fallback)

        assertEquals("raw body", e.message)
    }

    @Test
    fun `any other code keeps the step's own exception and the raw body`() {
        val body = """{"error":"scan rejected by policy","error_code":"policy_rejected"}"""
        val e = idvExceptionFor422("policy_rejected", "scan rejected by policy", body, fallback)

        assertTrue(e is IDVException.VerificationFailed)
        assertEquals("idv_verification_failed", e.errorCode)
        assertEquals(body, e.message)
    }

    @Test
    fun `a body without a code keeps the step's own exception`() {
        val e = idvExceptionFor422(null, null, "not json", fallback)

        assertTrue(e is IDVException.VerificationFailed)
        assertEquals("not json", e.message)
    }
}
