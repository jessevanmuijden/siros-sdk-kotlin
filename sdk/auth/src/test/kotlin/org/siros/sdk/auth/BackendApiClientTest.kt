package org.siros.sdk.auth

import org.siros.sdk.credentials.BackendApiException
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.Base64

class BackendApiClientTest {

    private lateinit var server: MockWebServer

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun get_account_info_sends_expected_headers() = runBlocking {
        server.enqueue(MockResponse().setBody("{}"))

        val client = newClient()
        client.setAppToken("token-abc")
        client.getAccountInfo()

        val request = server.takeRequest()
        assertEquals("/user/session/account-info", request.path)
        assertEquals("default", request.getHeader("X-Tenant-ID"))
        assertEquals("Bearer token-abc", request.getHeader("Authorization"))
    }

    @Test
    fun unauthenticated_request_omits_authorization_header() = runBlocking {
        server.enqueue(MockResponse().setBody("{}"))

        val client = newClient()
        client.healthCheck()

        val request = server.takeRequest()
        assertEquals("/health", request.path)
        assertEquals(null, request.getHeader("Authorization"))
    }

    @Test
    fun get_issuers_accepts_array_payload() = runBlocking {
        server.enqueue(MockResponse().setBody("""[{"id": 1, "visible": true}]"""))

        val client = newClient()
        val issuers = client.getIssuers()

        assertTrue(issuers is JsonArray)
    }

    @Test
    fun update_private_data_posts_json_body() = runBlocking {
        server.enqueue(MockResponse().setBody("{}"))

        val client = newClient()
        client.setAppToken("token-xyz")
        client.updatePrivateData(
            buildJsonObject {
                put("privateData", "opaque")
            }
        )

        val request = server.takeRequest()
        assertEquals("/user/session/private-data", request.path)
        assertEquals("POST", request.method)
        assertTrue(request.body.readUtf8().contains("privateData"))
    }

    @Test
    fun evaluate_trust_posts_to_expected_endpoint_with_auth_header() = runBlocking {
        server.enqueue(MockResponse().setBody("{\"decision\":true}"))

        val client = newClient()
        client.setAppToken("token-trust")
        val response = client.evaluateTrust(
            buildJsonObject {
                put("subject", "issuer-123")
            }
        )

        val request = server.takeRequest()
        assertEquals("/v1/evaluate", request.path)
        assertEquals("POST", request.method)
        assertEquals("Bearer token-trust", request.getHeader("Authorization"))
        assertTrue(request.body.readUtf8().contains("issuer-123"))
        assertEquals(true, response["decision"]?.toString()?.contains("true"))
    }

    @Test
    fun resolve_key_posts_key_subject_type_to_resolve_endpoint() = runBlocking {
        server.enqueue(MockResponse().setBody("{\"context\":{}}"))

        val client = newClient()
        client.setAppToken("token-resolve")
        client.resolveKey("did:web:verifier.example.com")

        val request = server.takeRequest()
        assertEquals("/v1/resolve", request.path)
        assertEquals("POST", request.method)
        assertEquals("Bearer token-resolve", request.getHeader("Authorization"))
        val body = kotlinx.serialization.json.Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals("did:web:verifier.example.com", body["subject_id"]?.jsonPrimitive?.content)
        // subject_type: "key" is the core distinction from resolveIssuer's
        // subject_type: "url" - the two must never be confused (#219 review
        // finding).
        assertEquals("key", body["subject_type"]?.jsonPrimitive?.content)
    }

    @Test
    fun delete_credential_uses_delete_method() = runBlocking {
        server.enqueue(MockResponse().setBody("{}"))

        val client = newClient()
        client.deleteCredential("cred-42")

        val request = server.takeRequest()
        assertEquals("/storage/vc/cred-42", request.path)
        assertEquals("DELETE", request.method)
    }

    @Test
    fun tenant_config_uses_tenant_specific_path() = runBlocking {
        server.enqueue(MockResponse().setBody("{}"))

        val client = BackendApiClient(
            baseUrl = server.url("/").toString().trimEnd('/'),
            tenantId = "tenant-42",
        )
        client.getTenantConfig()

        val request = server.takeRequest()
        assertEquals("/api/v1/tenants/tenant-42/config", request.path)
        assertEquals("tenant-42", request.getHeader("X-Tenant-ID"))
    }

    @Test
    fun blank_success_body_returns_empty_json_object() = runBlocking {
        server.enqueue(MockResponse().setBody(""))

        val client = newClient()
        val response = client.healthCheck()

        assertEquals(JsonObject(emptyMap()), response)
    }

    @Test
    fun non_success_response_throws_backend_api_exception() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(500).setBody("boom"))

        val client = newClient()

        try {
            client.healthCheck()
            throw AssertionError("Expected BackendApiException")
        } catch (e: BackendApiException) {
            assertEquals(500, e.code)
            assertTrue(e.body?.contains("boom") == true)
        }
    }

    @Test
    fun requestKeyAttestation_sendsJwksNonceAndCredentialIssuer() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"key_attestation": "signed-jwt"}"""))

        val client = newClient()
        val jwk = buildJsonObject { put("kty", "EC") }
        val result = client.requestKeyAttestation(
            jwks = listOf(jwk),
            nonce = "nonce-1",
            securityProperties = org.siros.sdk.credentials.SignerSecurityProperties(
                keyStorage = listOf("iso_18045_high"),
                userAuthentication = listOf("iso_18045_high"),
            ),
            credentialIssuer = "https://issuer.example.com",
        )

        assertEquals("signed-jwt", result)
        val request = server.takeRequest()
        assertEquals("/wallet-provider/key-attestation/generate", request.path)
        val body = kotlinx.serialization.json.Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals(1, body["jwks"]!!.jsonArray.size)
        assertEquals("nonce-1", body["openid4vci"]!!.jsonObject["nonce"]!!.jsonPrimitive.content)
        assertEquals(
            "https://issuer.example.com",
            body["openid4vci"]!!.jsonObject["credential_issuer"]!!.jsonPrimitive.content,
        )
        assertEquals(
            listOf("iso_18045_high"),
            body["security_properties"]!!.jsonObject["key_storage"]!!.jsonArray.map { it.jsonPrimitive.content },
        )
    }

    @Test
    fun requestKeyAttestation_omitsCredentialIssuer_whenNotProvided() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"key_attestation": "signed-jwt"}"""))

        val client = newClient()
        client.requestKeyAttestation(
            jwks = listOf(buildJsonObject { put("kty", "EC") }),
            nonce = "nonce-1",
        )

        val request = server.takeRequest()
        val body = kotlinx.serialization.json.Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals(false, body["openid4vci"]!!.jsonObject.containsKey("credential_issuer"))
    }

    @Test
    fun requestKeyAttestation_sendsWalletInstanceId_whenProvided() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"key_attestation": "signed-jwt"}"""))

        val client = newClient()
        client.requestKeyAttestation(
            jwks = listOf(buildJsonObject { put("kty", "EC") }),
            nonce = "nonce-1",
            walletInstanceId = "test-jkt",
        )

        val request = server.takeRequest()
        val body = kotlinx.serialization.json.Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals("test-jkt", body["wallet_instance_id"]!!.jsonPrimitive.content)
    }

    @Test
    fun requestKeyAttestation_omitsWalletInstanceId_whenNotProvided() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"key_attestation": "signed-jwt"}"""))

        val client = newClient()
        client.requestKeyAttestation(
            jwks = listOf(buildJsonObject { put("kty", "EC") }),
            nonce = "nonce-1",
        )

        val request = server.takeRequest()
        val body = kotlinx.serialization.json.Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals(false, body.containsKey("wallet_instance_id"))
    }

    @Test
    fun registerFido2Attestation_sendsExpectedFields() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"verified": true}"""))

        val client = newClient()
        client.registerFido2Attestation(
            walletInstanceId = "test-jkt",
            attestationObject = byteArrayOf(0x01, 0x02, 0x03),
            clientDataHash = ByteArray(32) { 0x09 },
        )

        val request = server.takeRequest()
        assertEquals("/wallet-provider/fido2-attestation/register", request.path)
        assertEquals("POST", request.method)
        val body = kotlinx.serialization.json.Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals("test-jkt", body["wallet_instance_id"]!!.jsonPrimitive.content)
        assertEquals(
            WebAuthnAuthClient.encodeBase64Url(byteArrayOf(0x01, 0x02, 0x03)),
            body["attestation_object"]!!.jsonPrimitive.content,
        )
        assertEquals(
            WebAuthnAuthClient.encodeBase64Url(ByteArray(32) { 0x09 }),
            body["client_data_hash"]!!.jsonPrimitive.content,
        )
    }

    @Test
    fun registerFido2Attestation_throwsOnRejection() = runBlocking {
        server.enqueue(
            MockResponse().setResponseCode(400).setBody("""{"error": "ATTESTATION_INVALID"}""")
        )

        val client = newClient()

        try {
            client.registerFido2Attestation(
                walletInstanceId = "test-jkt",
                attestationObject = byteArrayOf(0x01),
                clientDataHash = ByteArray(32),
            )
            throw AssertionError("Expected BackendApiException")
        } catch (e: BackendApiException) {
            assertEquals(400, e.code)
        }
    }

    @Test
    fun non_success_401_response_registers_token_rejection() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"unauthorized"}"""))

        val authTokens = mockk<AuthTokens>(relaxed = true)
        coEvery { authTokens.ensureBackendToken() } returns fakeBackendToken()

        val client = newClient()
        client.setAuthTokens(authTokens)

        try {
            client.healthCheck()
            throw AssertionError("Expected BackendApiException")
        } catch (e: BackendApiException) {
            assertEquals(401, e.code)
        }

        verify(exactly = 1) { authTokens.registerTokenRejection(AuthTokens.TOKEN_BACKEND) }
    }

    @Test
    fun non_401_failure_does_not_register_token_rejection() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(500).setBody("boom"))

        val authTokens = mockk<AuthTokens>(relaxed = true)
        coEvery { authTokens.ensureBackendToken() } returns fakeBackendToken()

        val client = newClient()
        client.setAuthTokens(authTokens)

        try {
            client.healthCheck()
            throw AssertionError("Expected BackendApiException")
        } catch (e: BackendApiException) {
            assertEquals(500, e.code)
        }

        verify(exactly = 0) { authTokens.registerTokenRejection(any()) }
    }

    /** A syntactically valid, unexpired access token JWT for stubbing [AuthTokens.ensureBackendToken]. */
    private fun fakeBackendToken(): AccessToken {
        val exp = (System.currentTimeMillis() / 1000) + 3600
        val header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""{"alg":"RS256","typ":"JWT"}""".toByteArray())
        val body = Base64.getUrlEncoder().withoutPadding().encodeToString(
            ("""{"sub":"user-1","aud":"wallet-backend","tenant_id":"default",""" +
                """"tac":"rwlid","acr":"urn:siros:acr:passkey","exp":$exp}""").toByteArray()
        )
        val signature = Base64.getUrlEncoder().withoutPadding().encodeToString("sig".toByteArray())
        return AccessToken("$header.$body.$signature")
    }

    // ---- wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#319) ----

    @Test
    fun generate_wia_sends_credential_id_when_given_and_omits_it_otherwise() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"wallet_instance_attestation":"wia.jwt"}"""))
        server.enqueue(MockResponse().setBody("""{"wallet_instance_attestation":"wia.jwt"}"""))
        val client = newClient()
        client.setAppToken("t")

        client.generateWIA(pop = "pop.jwt", challenge = "c-1", clientId = "siros://cb", credentialId = "pk-1")
        val withId = server.takeRequest().body.readUtf8()
        assertTrue(withId, withId.contains("\"credential_id\":\"pk-1\""))

        client.generateWIA(pop = "pop.jwt", challenge = "c-2")
        val without = server.takeRequest().body.readUtf8()
        assertTrue(without, !without.contains("credential_id"))
    }

    @Test
    fun list_wallet_instances_decodes_backend_shape() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"instances":[{"id":"jkt-1","tenant_id":"default","user_id":"u1","status":"suspended",
                   "wscd_type":"native_android","credential_id":"pk-1","attestation_source":"play_integrity",
                   "last_attested_at":"2026-09-08T10:00:00Z","status_reason":"lost phone","unknown_member":1}]}"""
            )
        )
        val client = newClient()
        client.setAppToken("t")

        val instances = client.listWalletInstances()

        assertEquals("/user/session/instances", server.takeRequest().path)
        assertEquals(1, instances.size)
        assertEquals("jkt-1", instances[0].id)
        assertEquals(WalletInstance.STATUS_SUSPENDED, instances[0].status)
        assertEquals("pk-1", instances[0].credentialId)
        assertEquals("lost phone", instances[0].statusReason)
    }

    @Test
    fun list_wallet_instances_fails_on_malformed_response() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"unexpected":true}"""))
        val client = newClient()
        client.setAppToken("t")
        try {
            client.listWalletInstances()
            fail("a response without the instances array must not read as 'no instances'")
        } catch (e: BackendApiException) {
            assertTrue(e.message!!.contains("instances"))
        }
    }

    @Test
    fun set_wallet_instance_status_decodes_full_object_when_returned() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"id":"jkt-1","status":"revoked","credential_id":"pk-1","status_reason":"stolen"}"""))
        val client = newClient()
        client.setAppToken("t")

        val result = client.setWalletInstanceStatus("jkt-1", WalletInstanceStatus.REVOKED, "stolen")

        assertEquals("revoked", result.status)
        assertEquals("pk-1", result.credentialId)
        assertEquals("stolen", result.statusReason)
    }

    @Test
    fun set_wallet_instance_status_puts_status_and_reason() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"id":"jkt-1","status":"suspended"}"""))
        val client = newClient()
        client.setAppToken("t")

        val result = client.setWalletInstanceStatus("jkt-1", WalletInstanceStatus.SUSPENDED, reason = "lost phone")

        val request = server.takeRequest()
        assertEquals("PUT", request.method)
        assertEquals("/user/session/instances/jkt-1/status", request.path)
        val body = request.body.readUtf8()
        assertTrue(body, body.contains("\"status\":\"suspended\"") && body.contains("\"reason\":\"lost phone\""))
        assertEquals("suspended", result.status)
    }

    @Test
    fun revoke_all_wallet_instances_fails_on_malformed_response() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"ok":true}"""))
        val client = newClient()
        client.setAppToken("t")
        try {
            client.revokeAllWalletInstances()
            fail("a reply without the revoked count must not read as zero revoked")
        } catch (e: BackendApiException) {
            assertTrue(e.message!!.contains("revoked"))
        }
    }

    @Test
    fun revoke_all_wallet_instances_posts_and_returns_count() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"revoked":2}"""))
        val client = newClient()
        client.setAppToken("t")

        val outcome = client.revokeAllWalletInstances("device stolen")

        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/user/session/instances/revoke-all", request.path)
        assertTrue(request.body.readUtf8().contains("device stolen"))
        assertEquals(2, outcome.revoked)
        assertTrue(outcome.complete)
    }

    // ---- 409 ERASURE_INCOMPLETE retry protocol (SID-AUTH-06) ----

    /**
     * The backend records the revocations before it erases, so a 409 means
     * "the status stands, re-run the erasure" - the client repeats the
     * identical request until it gets a 200. The repeat answers
     * `{"revoked": 0}` (nothing left to revoke), so the count reported to the
     * caller must be the one from the first answer, not the last.
     */
    @Test
    fun revoke_all_repeats_the_request_until_the_erasure_completes() = runBlocking {
        server.enqueue(erasureIncomplete("""{"error":"ERASURE_INCOMPLETE","revoked":2}"""))
        server.enqueue(MockResponse().setBody("""{"revoked":0}"""))
        val client = newClient()
        client.setAppToken("t")

        val outcome = client.revokeAllWalletInstances("device stolen")

        assertEquals(2, server.requestCount)
        val first = server.takeRequest()
        val second = server.takeRequest()
        // "repeating the identical request re-runs the erasure" - same body.
        assertEquals(first.path, second.path)
        assertEquals(first.body.readUtf8(), second.body.readUtf8())
        assertEquals(2, outcome.revoked)
        assertTrue(outcome.complete)
    }

    /**
     * Five attempts, then stop: the wallet is deactivated either way, so the
     * caller is told the erasure is unfinished (residual data for an
     * administrator) rather than being handed an exception for a change that
     * did take effect.
     */
    @Test
    fun revoke_all_reports_incomplete_after_the_retry_budget() = runBlocking {
        repeat(5) { server.enqueue(erasureIncomplete("""{"error":"ERASURE_INCOMPLETE","revoked":2}""")) }
        val client = newClient()
        client.setAppToken("t")

        val outcome = client.revokeAllWalletInstances()

        assertEquals(5, server.requestCount)
        assertEquals(2, outcome.revoked)
        assertEquals(false, outcome.complete)
    }

    /**
     * The acting token's exemption from the lifecycle cut-off ends with the
     * key material. A 401 after a 409 is therefore the erasure having reached
     * the keys - the wallet is deactivated, which is exactly "complete".
     */
    @Test
    fun revoke_all_treats_a_401_after_the_409_as_a_completed_erasure() = runBlocking {
        server.enqueue(erasureIncomplete("""{"error":"ERASURE_INCOMPLETE","revoked":3}"""))
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"unauthorized"}"""))
        val client = newClient()
        client.setAppToken("t")

        val outcome = client.revokeAllWalletInstances()

        assertEquals(2, server.requestCount)
        assertEquals(3, outcome.revoked)
        assertTrue(outcome.complete)
    }

    /** A 401 that was never preceded by a 409 is an ordinary auth failure. */
    @Test
    fun revoke_all_still_fails_on_a_plain_401() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"unauthorized"}"""))
        val client = newClient()
        client.setAppToken("t")

        try {
            client.revokeAllWalletInstances()
            fail("a 401 with no preceding ERASURE_INCOMPLETE must not read as a completed erasure")
        } catch (e: BackendApiException) {
            assertEquals(401, e.code)
        }
        assertEquals(1, server.requestCount)
    }

    /** A 409 that is not ERASURE_INCOMPLETE (invalid transition) is not retried. */
    @Test
    fun set_wallet_instance_status_does_not_retry_an_invalid_transition() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(409).setBody("""{"error":"invalid status transition"}"""))
        val client = newClient()
        client.setAppToken("t")

        try {
            client.setWalletInstanceStatus("jkt-1", WalletInstanceStatus.ACTIVE)
            fail("an invalid transition must surface, not be retried")
        } catch (e: BackendApiException) {
            assertEquals(409, e.code)
        }
        assertEquals(1, server.requestCount)
    }

    /**
     * Revoking the last instance runs the same erasure cascade, so the status
     * write retries on the same budget and reports the status that was
     * recorded even when the cascade never finished.
     */
    @Test
    fun set_wallet_instance_status_retries_the_erasure_and_keeps_the_recorded_status() = runBlocking {
        repeat(5) {
            server.enqueue(erasureIncomplete("""{"error":"ERASURE_INCOMPLETE","id":"jkt-1","status":"revoked"}"""))
        }
        val client = newClient()
        client.setAppToken("t")

        val result = client.setWalletInstanceStatus("jkt-1", WalletInstanceStatus.REVOKED, "stolen")

        assertEquals(5, server.requestCount)
        assertEquals("jkt-1", result.id)
        assertEquals("revoked", result.status)
        assertEquals(WalletInstanceStatus.REVOKED, result.statusEnum)
    }

    @Test
    fun deprecated_string_status_rejects_a_value_the_backend_would_refuse() = runBlocking {
        val client = newClient()
        client.setAppToken("t")
        try {
            @Suppress("DEPRECATION")
            client.setWalletInstanceStatus("jkt-1", "disabled")
            fail("an unknown status must be rejected locally, not sent")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("disabled"))
        }
        assertEquals(0, server.requestCount)
    }

    private fun erasureIncomplete(body: String) =
        MockResponse().setResponseCode(409).setBody(body)

    private fun newClient(): BackendApiClient {
        val baseUrl = server.url("/").toString().trimEnd('/')
        // No waiting between erasure retries in tests; the production default
        // is 1 s → 8 s (see BackendApiClient.erasureRetryDelaysMs).
        return BackendApiClient(baseUrl = baseUrl, tenantId = "default")
            .apply { erasureRetryDelaysMs = listOf(0, 0, 0, 0) }
    }
}
