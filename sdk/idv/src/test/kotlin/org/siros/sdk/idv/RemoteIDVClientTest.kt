// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
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

    // ── Through the real transport ──────────────────────────────────
    //
    // The cases above call idvExceptionFor422 directly, so they cannot catch a
    // mistake in postJson's 422 check, the JSON field names, or which step's
    // fallback applies. These drive RemoteIDVClient over HttpURLConnection.

    private lateinit var server: MockWebServer
    private lateinit var client: RemoteIDVClient

    @Before
    fun startServer() {
        server = MockWebServer().apply { start() }
        client = RemoteIDVClient(
            RemoteIDVClient.Config(serverUrl = server.url("/").toString(), authToken = "Bearer test"),
        )
    }

    @After
    fun stopServer() {
        server.shutdown()
    }

    private fun thrownBy(status: Int, body: String, step: suspend (RemoteIDVClient) -> Unit): IDVException {
        server.enqueue(MockResponse().setResponseCode(status).setBody(body))
        try {
            runBlocking { step(client) }
        } catch (e: IDVException) {
            return e
        }
        fail("expected an IDVException")
        throw AssertionError()
    }

    /**
     * What facetec-api's `/v1/id-scan` answers for a scan without an authenticated
     * chip: that path can only tell verified from not, so the code is always
     * `nfc_skipped`.
     */
    @Test
    fun `submitDocument maps an nfc refusal`() {
        val e = thrownBy(422, """{"error":"NFC verification was skipped or failed","error_code":"nfc_skipped"}""") {
            it.submitDocument(JSONObject().put("livenessSessionId", "s"))
        }

        assertTrue(e is IDVException.DocumentChipNotVerified)
        assertEquals("nfc_skipped", (e as IDVException.DocumentChipNotVerified).reason)
        assertEquals("idv_nfc_skipped", e.errorCode)
        assertEquals("NFC verification was skipped or failed", e.message)
        assertEquals("/v1/id-scan", server.takeRequest().path)
    }

    @Test
    fun `submitDocument keeps VerificationFailed for other codes`() {
        val body = """{"error":"scan rejected by policy","error_code":"policy_rejected"}"""
        val e = thrownBy(422, body) { it.submitDocument(JSONObject().put("livenessSessionId", "s")) }

        assertTrue(e is IDVException.VerificationFailed)
        assertEquals(body, e.message)
    }

    @Test
    fun `submitBiometric keeps LivenessFailed`() {
        val body = """{"error":"liveness check did not pass","error_code":"liveness_failed"}"""
        val e = thrownBy(422, body) { it.submitBiometric(JSONObject().put("faceScan", "x")) }

        assertTrue(e is IDVException.LivenessFailed)
        assertEquals(body, e.message)
    }

    @Test
    fun `a non-422 stays a NetworkError`() {
        val e = thrownBy(500, """{"error":"x","error_code":"nfc_skipped"}""") {
            it.submitDocument(JSONObject().put("livenessSessionId", "s"))
        }

        assertTrue(e is IDVException.NetworkError)
    }
}
