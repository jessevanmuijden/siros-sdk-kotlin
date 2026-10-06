// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv.facetec

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.IOException

/** The process-request call itself, against a local HTTP server. */
class FaceTecProcessRequestClientTest {
    private lateinit var server: MockWebServer
    private lateinit var client: FaceTecProcessRequestClient

    @Before
    fun setUp() {
        server = MockWebServer().apply { start() }
        client = FaceTecProcessRequestClient(
            FaceTecIDVConfig(
                processRequestUrl = server.url("/v1/process-request").toString(),
                authToken = "Bearer test-token",
                deviceKeyIdentifier = "device-key",
            ),
        )
    }

    @After
    fun tearDown() = server.shutdown()

    @Test
    fun `posts the blob and externalDatabaseRefID with the configured token`() {
        server.enqueue(MockResponse().setBody("""{"responseBlob":"rb"}"""))

        client.post("request-blob", "ref-1")

        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/v1/process-request", request.path)
        assertEquals("Bearer test-token", request.getHeader("Authorization"))
        assertTrue(request.getHeader("Content-Type")!!.startsWith("application/json"))
        val body = JSONObject(request.body.readUtf8())
        assertEquals("request-blob", body.getString("requestBlob"))
        assertEquals("ref-1", body.getString("externalDatabaseRefID"))
    }

    @Test
    fun `reads an issued credential`() {
        server.enqueue(
            MockResponse().setBody(
                """{"responseBlob":"rb","credentialOfferURI":"openid-credential-offer://x","transactionId":"tx-1","success":true}""",
            ),
        )

        val response = client.post("b", "r")

        assertEquals("rb", response.responseBlob)
        assertEquals("openid-credential-offer://x", response.credentialOfferURI)
        assertEquals("tx-1", response.transactionId)
        assertNull(response.credentialIssueErrorCode)
    }

    @Test
    fun `reads a refusal`() {
        server.enqueue(
            MockResponse().setBody(
                """{"responseBlob":"rb","credentialIssueError":"NFC was skipped","credentialIssueErrorCode":"nfc_skipped"}""",
            ),
        )

        val response = client.post("b", "r")

        assertNull(response.credentialOfferURI)
        assertEquals("nfc_skipped", response.credentialIssueErrorCode)
        assertEquals("NFC was skipped", response.credentialIssueError)
    }

    @Test
    fun `treats empty or null fields as absent`() {
        server.enqueue(MockResponse().setBody("""{"responseBlob":"rb","credentialOfferURI":"","credentialIssueErrorCode":null}"""))

        val response = client.post("b", "r")

        assertNull(response.credentialOfferURI)
        assertNull(response.credentialIssueErrorCode)
    }

    @Test
    fun `an HTTP error is an IOException that does not echo the body`() {
        server.enqueue(MockResponse().setResponseCode(502).setBody("""{"error":"upstream said: <request data>"}"""))

        val e = ioFailure { client.post("b", "r") }

        assertTrue(e.message!!.contains("502"))
        assertFalse(e.message!!.contains("request data"))
    }

    @Test
    fun `a response without a responseBlob is an IOException`() {
        server.enqueue(MockResponse().setBody("""{"success":false}"""))

        ioFailure { client.post("b", "r") }
    }

    @Test
    fun `a body that is not JSON is an IOException`() {
        server.enqueue(MockResponse().setBody("<html>proxy error</html>"))

        ioFailure { client.post("b", "r") }
    }

    @Test
    fun `the config's toString does not include the auth token`() {
        val config = FaceTecIDVConfig("https://idv.example.com/v1/process-request", "Bearer secret-token", "device-key")

        assertFalse(config.toString().contains("secret-token"))
    }

    private fun ioFailure(block: () -> Unit): IOException {
        try {
            block()
        } catch (e: IOException) {
            return e
        }
        fail("expected an IOException")
        throw AssertionError()
    }
}
