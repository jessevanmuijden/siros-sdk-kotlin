package org.siros.sdk.transport.engine

import app.cash.turbine.test
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.siros.sdk.credentials.AuthException

@OptIn(ExperimentalCoroutinesApi::class)
class WalletEngineSessionTest {

    private val client = mockk<OkHttpClient>()
    private val webSocket = mockk<WebSocket>(relaxed = true)
    private val response = mockk<Response>(relaxed = true)
    // doConnect() derives a per-connection client via
    // client.newBuilder().pingInterval(...).build() so a ping interval
    // learned from the server (see SessionConfig) can take effect on the
    // next connection without rebuilding [client] wholesale - see
    // WalletEngineSession.doConnect's doc comment. A class property (not
    // local to setUp()) so individual tests can also verify what interval
    // it was actually given - see
    // handshake_complete_config_ping_interval_is_adopted_on_next_connection.
    private val builder = mockk<OkHttpClient.Builder>()

    private lateinit var request: Request
    private lateinit var listener: WebSocketListener

    @Before
    fun setUp() {
        val requestSlot = slot<Request>()
        val listenerSlot = slot<WebSocketListener>()
        every { client.newWebSocket(capture(requestSlot), capture(listenerSlot)) } answers {
            request = requestSlot.captured
            listener = listenerSlot.captured
            webSocket
        }
        // Returning [client] itself from build() keeps every test's existing
        // newWebSocket stub above meaningful without needing a second one.
        every { client.newBuilder() } returns builder
        every { builder.pingInterval(any(), any()) } returns builder
        every { builder.build() } returns client
    }

    @Test
    fun connect_builds_websocket_request_and_sends_handshake_on_open() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )

        session.connect("app-token")
        listener.onOpen(webSocket, response)

        assertEquals(WalletEngineSession.State.CONNECTING, session.state.value)
        assertEquals("/api/v2/wallet", request.url.encodedPath)
        assertEquals("tenant-42", request.url.queryParameter("tenant_id"))
        assertEquals("wmp.v1", request.header("Sec-WebSocket-Protocol"))
        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"handshake\"") &&
                    text.contains("\"app_token\":\"app-token\"")
            })
        }
    }

    @Test
    fun handshake_complete_message_transitions_connected_and_emits_raw_message() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.messages().test {
            listener.onMessage(
                webSocket,
                """{"type":"handshake_complete","session_id":"session-123"}""",
            )

            val message = awaitItem()
            assertEquals(MessageTypes.HANDSHAKE_COMPLETE, message.type)
            assertEquals(WalletEngineSession.State.CONNECTED, session.state.value)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun handshake_complete_config_ping_interval_is_adopted_on_next_connection() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        // The very first connection must use the hardcoded default, not
        // whatever a server that hasn't spoken yet might eventually say.
        verify(exactly = 1) {
            builder.pingInterval(WalletEngineSession.DEFAULT_PING_INTERVAL_MS, TimeUnit.MILLISECONDS)
        }

        // onMessage only enqueues the frame for WalletEngineSession's own
        // consumer coroutine (see its rawMessageChannel doc comment); awaiting
        // it on messages() synchronizes with that coroutine actually having
        // processed it (and so updated pingIntervalMs) before this test moves on.
        session.messages().test {
            listener.onMessage(
                webSocket,
                """{"type":"handshake_complete","session_id":"session-123","config":{"ping_interval_ms":7000}}""",
            )
            awaitItem()
            cancelAndIgnoreRemainingEvents()
        }

        // Adopting a new value must not itself force a reconnect - the
        // healthy current connection is left alone.
        verify(exactly = 1) { client.newWebSocket(any(), any()) }

        session.forceReconnect()

        verify(exactly = 1) { builder.pingInterval(7000L, TimeUnit.MILLISECONDS) }
        verify(exactly = 2) { client.newWebSocket(any(), any()) }
    }

    @Test
    fun flow_progress_message_emits_to_progress_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.flowProgress().test {
            listener.onMessage(
                webSocket,
                """{"type":"flow_progress","flow_id":"flow-1","step":"issuing","payload":{"percent":50}}""",
            )

            val message = awaitItem()
            assertEquals("flow-1", message.flowId)
            assertEquals("issuing", message.step)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun flow_complete_message_emits_to_completion_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.flowComplete().test {
            listener.onMessage(
                webSocket,
                """{"type":"flow_complete","flow_id":"flow-1","redirect_uri":"https://wallet.example.com/callback"}""",
            )

            val message = awaitItem()
            assertEquals("flow-1", message.flowId)
            assertEquals("https://wallet.example.com/callback", message.redirectUri)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun flow_complete_parses_credential_notification_id() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.flowComplete().test {
            listener.onMessage(
                webSocket,
                """{"type":"flow_complete","flow_id":"flow-1","credentials":""" +
                    """[{"format":"dc+sd-jwt","credential":"jwt-token","vct":"urn:eu:pid:1",""" +
                    """"notification_id":"notif-xyz"}]}""",
            )

            val message = awaitItem()
            assertEquals("notif-xyz", message.credentials?.first()?.notificationId)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun flow_error_message_emits_to_error_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.flowErrors().test {
            listener.onMessage(
                webSocket,
                """{"type":"flow_error","flow_id":"flow-1","step":"authorize","error":{"code":"invalid_request","message":"missing parameter"}}""",
            )

            val message = awaitItem()
            assertEquals("flow-1", message.flowId)
            assertEquals("authorize", message.step)
            assertEquals("invalid_request", message.error.code)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun sign_request_message_emits_to_sign_requests_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.signRequests().test {
            listener.onMessage(
                webSocket,
                """{"type":"sign_request","flow_id":"flow-1","action":"proof","params":{"audience":"aud","nonce":"nonce","proof_type":"jwt"}}""",
            )

            val message = awaitItem()
            assertEquals("flow-1", message.flowId)
            assertEquals("proof", message.action)
            assertEquals("aud", message.params.audience)
            assertEquals("jwt", message.params.proofType)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun match_request_message_emits_to_match_requests_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.matchRequests().test {
            listener.onMessage(
                webSocket,
                """{"type":"match_request","flow_id":"flow-1","dcql_query":{"credentials":[{"id":"q-1"}]}}""",
            )

            val message = awaitItem()
            assertEquals("flow-1", message.flowId)
            assertTrue(message.dcqlQuery.toString().contains("q-1"))
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun push_message_emits_to_push_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.pushMessages().test {
            listener.onMessage(
                webSocket,
                """{"type":"push","push_type":"issuance_complete","credentials":[{"format":"dc+sd-jwt","credential":"jwt-token","vct":"urn:eu:pid:1"}]}""",
            )

            val message = awaitItem()
            assertEquals("issuance_complete", message.pushType)
            assertEquals("jwt-token", message.credentials?.single()?.credential)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun error_message_transitions_session_to_failed() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.messages().test {
            listener.onMessage(
                webSocket,
                """{"type":"error","code":"bad_request","message":"invalid flow"}""",
            )

            val message = awaitItem()
            assertEquals(MessageTypes.ERROR, message.type)
            assertEquals(WalletEngineSession.State.FAILED, session.state.value)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun send_trust_result_serializes_flow_action_payload() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendTrustResult("flow-77", true, "verified")

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"flow_action\"") &&
                    text.contains("\"flow_id\":\"flow-77\"") &&
                    text.contains("\"action\":\"trust_result\"") &&
                    text.contains("\"trusted\":true") &&
                    text.contains("\"reason\":\"verified\"")
            })
        }
    }

    @Test
    fun send_credential_notification_serializes_message() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendCredentialNotification(
            flowId = "flow-77",
            notificationId = "notif-abc",
            event = CredentialNotificationEvent.ACCEPTED,
            eventDescription = "stored",
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"credential_notification\"") &&
                    text.contains("\"flow_id\":\"flow-77\"") &&
                    text.contains("\"notification_id\":\"notif-abc\"") &&
                    text.contains("\"event\":\"credential_accepted\"") &&
                    text.contains("\"event_description\":\"stored\"")
            })
        }
    }

    @Test
    fun send_credential_notification_is_no_op_when_not_connected() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        // Never connected: webSocket is null, so the send must be dropped.
        assertTrue(!session.isConnected)

        session.sendCredentialNotification(
            flowId = "flow-77",
            notificationId = "notif-abc",
            event = CredentialNotificationEvent.ACCEPTED,
        )

        verify(exactly = 0) { webSocket.send(any<String>()) }
    }

    @Test
    fun notification_ack_message_emits_to_notification_acks_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.notificationAcks().test {
            listener.onMessage(
                webSocket,
                """{"type":"notification_ack","flow_id":"flow-77","notification_id":"notif-abc","status":"forwarded"}""",
            )

            val ack = awaitItem()
            assertEquals("flow-77", ack.flowId)
            assertEquals("notif-abc", ack.notificationId)
            assertEquals("forwarded", ack.status)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun start_issuance_serializes_flow_start_message() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.startIssuance(
            offer = "offer-json",
            credentialOfferUri = "https://issuer.example.com/offer",
            redirectUri = "app://callback",
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"flow_start\"") &&
                    text.contains("\"protocol\":\"oid4vci\"") &&
                    text.contains("\"offer\":\"offer-json\"") &&
                    text.contains("\"credential_offer_uri\":\"https://issuer.example.com/offer\"") &&
                    text.contains("\"redirect_uri\":\"app://callback\"")
            })
        }
    }

    @Test
    fun start_presentation_serializes_flow_start_message() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.startPresentation(
            requestUri = "https://verifier.example.com/request",
            requestUriRef = "urn:request:1",
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"flow_start\"") &&
                    text.contains("\"protocol\":\"oid4vp\"") &&
                    text.contains("\"request_uri\":\"https://verifier.example.com/request\"") &&
                    text.contains("\"request_uri_ref\":\"urn:request:1\"")
            })
        }
    }

    @Test
    fun send_sign_response_serializes_all_proof_fields() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendSignResponse(
            flowId = "flow-77",
            proofJwt = "proof-jwt",
            vpToken = "vp-token",
            proofs = listOf(ProofObject(proofType = "jwt", jwt = "nested-proof")),
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"sign_response\"") &&
                    text.contains("\"flow_id\":\"flow-77\"") &&
                    text.contains("\"proof_jwt\":\"proof-jwt\"") &&
                    text.contains("\"vp_token\":\"vp-token\"") &&
                    text.contains("\"proof_type\":\"jwt\"") &&
                    text.contains("\"jwt\":\"nested-proof\"")
            })
        }
    }

    /**
     * `request_attestation` reply (go-wallet-backend `SignActionRequestAttestation`):
     * the WIA + PoP ride on the sign_response under exactly the wire names the
     * backend's `SignResponseMessage` declares, alongside the message_id it
     * correlates on.
     */
    @Test
    fun send_sign_response_serializes_client_attestation_fields() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendSignResponse(
            flowId = "flow-77",
            messageId = "msg-9",
            clientAttestation = "wia-jwt",
            clientAttestationPoP = "pop-jwt",
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"sign_response\"") &&
                    text.contains("\"flow_id\":\"flow-77\"") &&
                    text.contains("\"message_id\":\"msg-9\"") &&
                    text.contains("\"client_attestation\":\"wia-jwt\"") &&
                    text.contains("\"client_attestation_pop\":\"pop-jwt\"")
            })
        }
    }

    /**
     * A declined `request_attestation` (no WIA available) is an empty
     * sign_response: no attestation values on the wire, but still the
     * message_id so the backend's RequestSign unblocks instead of waiting
     * out its 30 s timeout.
     */
    @Test
    fun send_sign_response_without_attestation_carries_no_attestation_values() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendSignResponse(flowId = "flow-77", messageId = "msg-9")

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"sign_response\"") &&
                    text.contains("\"message_id\":\"msg-9\"") &&
                    !text.contains("\"client_attestation\":\"") &&
                    !text.contains("\"client_attestation_pop\":\"")
            })
        }
    }

    /**
     * `sign_client_auth` reply (go-wallet-backend#317): the key identifier,
     * DPoP proof and fresh attestation ride on the sign_response under the
     * backend's `SignResponseMessage` wire names.
     */
    @Test
    fun send_sign_response_serializes_client_auth_fields() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendSignResponse(
            flowId = "flow-77",
            messageId = "msg-9",
            clientAttestation = "wia-jwt",
            clientAttestationPoP = "pop-jwt",
            dpopKeyId = "instance-key-1",
            dpopProof = "dpop-jwt",
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"sign_response\"") &&
                    text.contains("\"message_id\":\"msg-9\"") &&
                    text.contains("\"client_attestation\":\"wia-jwt\"") &&
                    text.contains("\"client_attestation_pop\":\"pop-jwt\"") &&
                    text.contains("\"dpop_key_id\":\"instance-key-1\"") &&
                    text.contains("\"dpop_proof\":\"dpop-jwt\"")
            })
        }
    }

    /** A renewal names the client-held key the refresh_token is bound to. */
    @Test
    fun start_renewal_serializes_dpop_key_id() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.startRenewal(
            refreshToken = "rt",
            credentialIssuer = "https://issuer.example.com",
            selectedCredentialConfigurationId = "pid",
            dpopKeyId = "instance-key-1",
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"flow_start\"") &&
                    text.contains("\"refresh_token\":\"rt\"") &&
                    text.contains("\"dpop_key_id\":\"instance-key-1\"") &&
                    !text.contains("\"dpop_jwk\":\"")
            })
        }
    }

    /** The engine's `sign_client_auth` params decode under their wire names. */
    @Test
    fun sign_request_params_decode_client_auth_fields() {
        val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
        val msg = json.decodeFromString(
            SignRequestMessage.serializer(),
            """{"type":"sign_request","flow_id":"f","message_id":"m","action":"sign_client_auth",
               "params":{"audience":"https://as.example.com","issuer":"siros-sample://callback",
               "htm":"POST","htu":"https://as.example.com/token","dpop_nonce":"n-1","ath":"h","key_id":"k-1"}}""",
        )
        assertEquals("sign_client_auth", msg.action)
        assertEquals("POST", msg.params.htm)
        assertEquals("https://as.example.com/token", msg.params.htu)
        assertEquals("n-1", msg.params.dpopNonce)
        assertEquals("h", msg.params.ath)
        assertEquals("k-1", msg.params.keyId)
        assertEquals("https://as.example.com", msg.params.audience)
        assertEquals("siros-sample://callback", msg.params.issuer)
    }

    @Test
    fun send_match_response_serializes_selected_credentials() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendMatchResponse(
            flowId = "flow-88",
            matches = listOf(
                CredentialMatch(
                    credentialQueryId = "query-1",
                    credentialId = "cred-1",
                    format = "dc+sd-jwt",
                    vct = "urn:eu:pid:1",
                    availableClaims = listOf("given_name", "family_name"),
                )
            ),
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"match_response\"") &&
                    text.contains("\"flow_id\":\"flow-88\"") &&
                    text.contains("\"credential_query_id\":\"query-1\"") &&
                    text.contains("\"credential_id\":\"cred-1\"") &&
                    text.contains("\"available_claims\":[\"given_name\",\"family_name\"]")
            })
        }
    }

    @Test
    fun send_match_response_carries_the_reason_nothing_matched() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendMatchResponse(
            flowId = "flow-89",
            matches = emptyList(),
            noMatchReason = "This wallet holds no credential matching the request",
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"match_response\"") &&
                    text.contains("\"matches\":[]") &&
                    text.contains("\"no_match_reason\":\"This wallet holds no credential matching the request\"")
            })
        }
    }

    @Test
    fun send_credentials_matched_reports_an_empty_match_set_as_a_flow_action() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendCredentialsMatched(
            flowId = "flow-90",
            matches = emptyList(),
            noMatchReason = "no PID stored",
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"flow_action\"") &&
                    text.contains("\"flow_id\":\"flow-90\"") &&
                    text.contains("\"action\":\"credentials_matched\"") &&
                    text.contains("\"matches\":[]") &&
                    text.contains("\"no_match_reason\":\"no PID stored\"")
            })
        }
    }

    @Test
    fun disconnect_closes_socket_and_resets_state() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.disconnect()

        verify(exactly = 1) { webSocket.close(1000, "client disconnect") }
        assertEquals(WalletEngineSession.State.DISCONNECTED, session.state.value)
    }

    @Test
    fun outbound_messages_require_active_connection() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )

        assertThrows(IllegalStateException::class.java) {
            session.startIssuance(offer = "offer-json")
        }
        assertThrows(IllegalStateException::class.java) {
            session.sendSignResponse(flowId = "flow-1", proofJwt = "jwt")
        }
        assertThrows(IllegalStateException::class.java) {
            session.sendMatchResponse(
                flowId = "flow-1",
                matches = listOf(CredentialMatch(credentialId = "cred-1", format = "dc+sd-jwt")),
            )
        }
    }

    @Test
    fun forceReconnect_signals_reauth_required_when_token_provider_rejects_with_401() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token", tokenProvider = { throw AuthException("session expired", code = 401) })

        session.forceReconnect()

        assertEquals(WalletEngineSession.State.REAUTH_REQUIRED, session.state.value)
        // Only the initial connect() should have opened a socket - forceReconnect
        // must not proceed to doConnect() once refresh is rejected as invalid.
        verify(exactly = 1) { client.newWebSocket(any(), any()) }
    }

    @Test
    fun forceReconnect_invokes_onAuthRejected_when_token_provider_rejects_with_401() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        var authRejectedCalls = 0
        session.connect(
            "app-token",
            tokenProvider = { throw AuthException("session expired", code = 401) },
            onAuthRejected = { authRejectedCalls++ },
        )

        session.forceReconnect()

        // Same call site AuthTokens.registerTokenRejection is wired to in
        // SirosWallet.connectEngine - this only checks the callback fires,
        // not AuthTokens' own counting logic (covered by AuthTokensTest).
        assertEquals(1, authRejectedCalls)
        assertEquals(WalletEngineSession.State.REAUTH_REQUIRED, session.state.value)
    }

    @Test
    fun forceReconnect_does_not_invoke_onAuthRejected_on_transient_failure() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        var authRejectedCalls = 0
        session.connect(
            "app-token",
            tokenProvider = { throw java.io.IOException("network blip") },
            onAuthRejected = { authRejectedCalls++ },
        )

        session.forceReconnect()

        assertEquals(0, authRejectedCalls)
    }

    @Test
    fun forceReconnect_retries_with_last_token_on_transient_provider_failure() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token", tokenProvider = { throw java.io.IOException("network blip") })

        session.forceReconnect()

        // A transient failure (not an explicit 401/403 auth rejection) must not
        // force re-authentication - it should fall back to the last good token
        // and let the normal reconnect path proceed.
        assertEquals(WalletEngineSession.State.CONNECTING, session.state.value)
        verify(exactly = 2) { client.newWebSocket(any(), any()) }
    }

    @Test
    fun forceReconnect_falls_back_to_last_token_on_non_auth_server_error() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token", tokenProvider = { throw AuthException("AS unavailable", code = 503) })

        session.forceReconnect()

        // A 5xx from the AS is a server-side/transient error, not proof the
        // session itself is invalid - must not force re-authentication.
        assertEquals(WalletEngineSession.State.CONNECTING, session.state.value)
        verify(exactly = 2) { client.newWebSocket(any(), any()) }
    }

    @Test
    fun start_presentation_declares_features_only_when_given() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.startPresentation(requestUri = "https://verifier.example.com/none")
        session.startPresentation(
            requestUri = "https://verifier.example.com/declared",
            features = listOf(FlowStartMessage.FEATURE_TRANSACTION_DATA_V1),
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("/none") && !text.contains("transaction_data.v1")
            })
        }
        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("/declared") && text.contains("\"features\":[\"transaction_data.v1\"]")
            })
        }
    }
}
