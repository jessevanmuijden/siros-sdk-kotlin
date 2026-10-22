package org.siros.sdk.transport.engine

import app.cash.turbine.test
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
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
        every { webSocket.send(any<String>()) } returns true
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
            builder.pingInterval(10_000L, TimeUnit.MILLISECONDS)
        }

        // onMessage only enqueues the frame for WalletEngineSession's own
        // consumer coroutine (see its rawMessageChannel doc comment); awaiting
        // it on messages() synchronizes with that coroutine actually having
        // processed it (and so updated pingIntervalMs) before this test moves on.
        session.messages().test {
            listener.onMessage(
                webSocket,
                """{"type":"handshake_complete","session_id":"session-123","config":{"ping_interval_ms":15000}}""",
            )
            awaitItem()
            cancelAndIgnoreRemainingEvents()
        }

        // Adopting a new value must not itself force a reconnect - the
        // healthy current connection is left alone.
        verify(exactly = 1) { client.newWebSocket(any(), any()) }

        session.forceReconnect()

        verify(exactly = 1) { builder.pingInterval(15000L, TimeUnit.MILLISECONDS) }
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
    fun flow_complete_of_an_encrypted_issuance_has_empty_credentials_and_says_so() = runTest {
        val session = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "tenant-42", client = client)
        session.connect("app-token")

        session.flowComplete().test {
            listener.onMessage(
                webSocket,
                """{"type":"flow_complete","flow_id":"flow-1","credentials":""" +
                    """[{"format":"dc+sd-jwt","vct":"urn:eu:pid:1"},{"format":"dc+sd-jwt","vct":"urn:eu:pid:1"}],""" +
                    """"credential_response_encrypted":true}""",
            )

            val message = awaitItem()
            assertEquals(true, message.credentialResponseEncrypted)
            // The engine never held the credentials: the member is absent and decodes as empty.
            assertEquals(listOf("", ""), message.credentials!!.map { it.credential })
            assertEquals("urn:eu:pid:1", message.credentials!!.first().vct)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun flow_complete_without_the_encrypted_marker_is_a_plain_issuance() = runTest {
        val session = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "tenant-42", client = client)
        session.connect("app-token")
        session.flowComplete().test {
            listener.onMessage(webSocket, """{"type":"flow_complete","flow_id":"flow-1","credentials":[{"format":"dc+sd-jwt","credential":"j"}]}""")
            val message = awaitItem()
            assertEquals(false, message.credentialResponseEncrypted)
            assertEquals("j", message.credentials!!.single().credential)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun flow_complete_with_a_non_boolean_encrypted_marker_still_emits_with_the_marker_false() = runTest {
        val session = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "tenant-42", client = client)
        session.connect("app-token")
        session.flowComplete().test {
            listOf(""""true"""", "1", "null", "{}").forEach { flag ->
                listener.onMessage(
                    webSocket,
                    """{"type":"flow_complete","flow_id":"flow-1","credentials":[{"format":"dc+sd-jwt","credential":"j",""" +
                        """"notification_id":"n1"}],"credential_response_encrypted":$flag}""",
                )
                val m = awaitItem()
                assertEquals(flag, false, m.credentialResponseEncrypted)
                assertEquals("n1", m.credentials!!.single().notificationId)
            }
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun a_plain_completion_keeps_only_the_display_members_of_the_relayed_credential_metadata_in_order() = runTest {
        val session = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "tenant-42", client = client)
        session.connect("app-token")
        session.flowComplete().test {
            listener.onMessage(
                webSocket,
                """{"type":"flow_complete","flow_id":"flow-1","credentials":[{"format":"dc+sd-jwt","credential":"j"}],""" +
                    """"credential_metadata":{"claims":[{"path":["a"]}],"org.siros.secret_seed":{"org.siros.nym_auth":"00112233445566778899aabbccddeeff"},""" +
                    """"display":[{"name":"Nym","logo":{"uri":"data:x"}}],"other.extension":{"k":1}}}""",
            )
            val metadata = awaitItem().credentialMetadata!!
            assertEquals(false, metadata.malformed)
            assertEquals(listOf("claims", "display"), metadata.members.keys.toList())
            assertTrue(!metadata.members.toString().contains("00112233445566778899aabbccddeeff"))
            assertEquals("ResponseCredentialMetadata(redacted)", metadata.toString())
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun a_relayed_credential_metadata_that_is_not_an_object_is_the_malformed_placeholder_and_an_absent_one_is_null() = runTest {
        val session = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "tenant-42", client = client)
        session.connect("app-token")
        session.flowComplete().test {
            listOf("""[{"type":"other"}]""", """"text"""", "5").forEach { md ->
                listener.onMessage(
                    webSocket,
                    """{"type":"flow_complete","flow_id":"flow-1","credentials":[{"format":"dc+sd-jwt","credential":"j","notification_id":"n1"}],"credential_metadata":$md}""",
                )
                val m = awaitItem()
                assertTrue(md, m.credentialMetadata!!.malformed)
                assertEquals(md, "n1", m.credentials!!.single().notificationId)
            }
            listener.onMessage(webSocket, """{"type":"flow_complete","flow_id":"flow-1","credentials":[{"format":"dc+sd-jwt","credential":"j"}]}""")
            assertEquals(null, awaitItem().credentialMetadata)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun the_engine_relays_no_extension_members_so_a_stray_seed_is_ignored() = runTest {
        val session = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "tenant-42", client = client)
        session.connect("app-token")
        session.flowComplete().test {
            listener.onMessage(
                webSocket,
                """{"type":"flow_complete","flow_id":"flow-1","credentials":[{"format":"dc+sd-jwt","credential":"secret-credential"}],""" +
                    """"credential_metadata":{"org.siros.secret_seed":{"org.siros.nym_auth":"00112233445566778899aabbccddeeff"}}}""",
            )
            val message = awaitItem()
            // Dropped by the allowlist, so it is in no string form of the frame either.
            assertEquals(emptySet<String>(), message.credentialMetadata!!.members.keys)
            assertTrue(!message.toString().contains("00112233445566778899aabbccddeeff"))
            assertTrue(!message.credentials.toString().contains("secret-credential"))
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun a_sign_request_decodes_the_blind_encryption_members() {
        val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
        val issuance = json.decodeFromString(
            SignRequestParams.serializer(),
            """{"audience":"a","nonce":"n","credential_response_encryption":{"alg":"ECDH-ES+A256KW","enc":"A128GCM","required":true}}""",
        )
        assertEquals("ECDH-ES+A256KW", issuance.credentialResponseEncryption!!.alg)
        assertEquals("A128GCM", issuance.credentialResponseEncryption!!.enc)
        assertEquals(true, issuance.credentialResponseEncryption!!.required)
        val decrypt = json.decodeFromString(SignRequestParams.serializer(), """{"jwe":"a.b.c.d.e","deferred":true}""")
        assertEquals("a.b.c.d.e", decrypt.jwe)
        assertEquals(true, decrypt.deferred)
        val vp = json.decodeFromString(
            SignRequestParams.serializer(),
            """{"audience":"v","nonce":"n","state":"st","response_encryption":{"jwk":{"kty":"EC","kid":"k1"},"alg":"ECDH-ES","enc":"A128GCM"}}""",
        )
        assertEquals("st", vp.state)
        assertEquals("k1", (vp.responseEncryption!!.jwk["kid"] as kotlinx.serialization.json.JsonPrimitive).content)
        assertEquals("ECDH-ES", vp.responseEncryption!!.alg)
        // No member decodes as no encryption: every other sign request is unchanged.
        val none = json.decodeFromString(SignRequestParams.serializer(), """{"audience":"a","nonce":"n"}""")
        assertEquals(null, none.credentialResponseEncryption)
        assertEquals(null, none.responseEncryption)
        assertEquals(null, none.jwe)
    }

    @Test
    fun a_sign_request_decodes_the_engines_verified_request_and_ignores_members_it_does_not_know() {
        val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
        val params = json.decodeFromString(
            SignRequestParams.serializer(),
            """{"audience":"admin","nonce":"n","verified_request":{"client_id":"x509_san_dns:v.example","client_id_scheme":"x509_san_dns",""" +
                """"response_mode":"direct_post.jwt","response_uri":"https://v.example/r","signed":true,"signature_verification":"verified",""" +
                """"client_metadata":{"jwks":{"keys":[]}},"future_member":1}}""",
        )
        val v = params.verifiedRequest!!
        assertEquals("x509_san_dns:v.example", v.clientId)
        assertEquals("https://v.example/r", v.responseUri)
        assertEquals(true, v.signed)
        assertEquals("verified", v.signatureVerification)
        assertEquals(null, json.decodeFromString(SignRequestParams.serializer(), """{"audience":"a"}""").verifiedRequest)
        // `signed` absent reads as not signed.
        assertEquals(false, json.decodeFromString(SignRequestParams.serializer(), """{"verified_request":{"client_id":"c"}}""").verifiedRequest!!.signed)
    }

    @Test
    fun a_refusal_keeps_its_error_code_and_can_never_carry_a_response_jwe() {
        val json = kotlinx.serialization.json.Json { encodeDefaults = false }
        val refusal = json.encodeToJsonElement(
            SignResponseMessage.serializer(),
            SignResponseMessage(flowId = "f", messageId = "m", errorCode = SignResponseMessage.SIGN_REFUSED),
        ) as kotlinx.serialization.json.JsonObject
        assertEquals("SIGN_REFUSED", (refusal["error_code"] as kotlinx.serialization.json.JsonPrimitive).content)
        assertEquals(null, refusal["response_jwe"])
        // The encrypted-response member cannot be set alongside either error member, so it cannot shadow a refusal.
        assertThrows(IllegalArgumentException::class.java) {
            SignResponseMessage(flowId = "f", responseJwe = "h.k.i.c.t", errorCode = SignResponseMessage.SIGN_REFUSED)
        }
        assertThrows(IllegalArgumentException::class.java) { SignResponseMessage(flowId = "f", responseJwe = "h.k.i.c.t", error = "x") }
        // And a frame that arrives that way is refused too, not read as an answer.
        assertThrows(IllegalArgumentException::class.java) {
            kotlinx.serialization.json.Json.decodeFromString(
                SignResponseMessage.serializer(),
                """{"type":"sign_response","flow_id":"f","response_jwe":"a.b.c.d.e","error_code":"SIGN_REFUSED"}""",
            )
        }
    }

    @Test
    fun a_decrypt_answer_carries_exactly_one_of_credential_count_transaction_id_or_error() {
        val json = kotlinx.serialization.json.Json { encodeDefaults = false }
        val count = json.encodeToJsonElement(SignResponseMessage.serializer(), SignResponseMessage(flowId = "f", credentialCount = 2)) as kotlinx.serialization.json.JsonObject
        assertEquals(2, (count["credential_count"] as kotlinx.serialization.json.JsonPrimitive).content.toInt())
        assertEquals(null, count["transaction_id"])
        assertThrows(IllegalArgumentException::class.java) { SignResponseMessage(flowId = "f", credentialCount = 1, transactionId = "tx") }
        assertThrows(IllegalArgumentException::class.java) { SignResponseMessage(flowId = "f", credentialCount = 1, error = "x") }
        assertThrows(IllegalArgumentException::class.java) { SignResponseMessage(flowId = "f", transactionId = "tx", error = "x") }
    }

    @Test
    fun a_sign_response_never_carries_a_response_jwe_together_with_a_vp_token() {
        assertThrows(IllegalArgumentException::class.java) { SignResponseMessage(flowId = "f", responseJwe = "a.b.c.d.e", vpToken = "t") }
        SignResponseMessage(flowId = "f", vpToken = "t")
        SignResponseMessage(flowId = "f", responseJwe = "a.b.c.d.e")
    }

    @Test
    fun a_sign_response_carries_the_blind_encryption_members_under_their_wire_names() {
        val json = kotlinx.serialization.json.Json { encodeDefaults = false }
        val jwk = kotlinx.serialization.json.buildJsonObject { put("kty", kotlinx.serialization.json.JsonPrimitive("EC")) }
        val encoded = json.encodeToJsonElement(
            SignResponseMessage.serializer(),
            SignResponseMessage(
                flowId = "f",
                credentialResponseEncryptionJwk = jwk,
                transactionId = "tx-1",
                interval = 5,
                responseJwe = "h.k.i.c.t",
            ),
        ) as kotlinx.serialization.json.JsonObject
        assertEquals(jwk, encoded["credential_response_encryption_jwk"])
        assertEquals("tx-1", (encoded["transaction_id"] as kotlinx.serialization.json.JsonPrimitive).content)
        assertEquals(5, (encoded["interval"] as kotlinx.serialization.json.JsonPrimitive).content.toInt())
        assertEquals("h.k.i.c.t", (encoded["response_jwe"] as kotlinx.serialization.json.JsonPrimitive).content)
        val failed = json.encodeToJsonElement(SignResponseMessage.serializer(), SignResponseMessage(flowId = "f", error = "nope")) as kotlinx.serialization.json.JsonObject
        assertEquals("nope", (failed["error"] as kotlinx.serialization.json.JsonPrimitive).content)
        // An ordinary proof answer stays free of them.
        val plain = json.encodeToJsonElement(SignResponseMessage.serializer(), SignResponseMessage(flowId = "f", proofJwt = "p")) as kotlinx.serialization.json.JsonObject
        assertEquals(null, plain["credential_response_encryption_jwk"])
        assertEquals(null, plain["response_jwe"])
    }

    @Test
    fun flow_complete_carries_the_issuer_trust_report_received_before_it() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.flowComplete().test {
            listener.onMessage(
                webSocket,
                """{"type":"flow_progress","flow_id":"flow-1","step":"trust_evaluated","payload":""" +
                    """{"issuer_trust_evaluated":true,"issuer":"https://i.example","trusted":false,"reason":"no"}}""",
            )
            listener.onMessage(webSocket, """{"type":"flow_complete","flow_id":"flow-1"}""")
            listener.onMessage(webSocket, """{"type":"flow_complete","flow_id":"flow-2"}""")

            val first = awaitItem()
            assertEquals("https://i.example", first.issuerTrust?.issuer)
            assertEquals(false, first.issuerTrust?.trusted)
            assertEquals("no", first.issuerTrust?.reason)
            // Another flow's completion carries nothing, and the report is consumed.
            assertEquals(null, awaitItem().issuerTrust)
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
    fun connectionGenerations_publishesEachNewSocketOnItsOwn_independentlyOfTheState() = runTest {
        val session = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "tenant-42", client = client)
        assertEquals(0, session.connectionGenerations.value)
        session.connect("app-token")
        assertEquals(1, session.connectionGenerations.value)
        assertEquals(session.connectionGeneration, session.connectionGenerations.value)
        session.forceReconnect()
        assertEquals("the replacement socket is published", 2, session.connectionGenerations.value)
        assertEquals(session.connectionGeneration, session.connectionGenerations.value)
    }

    @Test
    fun forceReconnect_discardsFlowRepliesBufferedFromTheReplacedConnection() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")
        // A reply the old connection delivered that nobody has consumed yet. The
        // handshake frame after it is awaited so the consumer has certainly
        // routed the progress frame into its (buffered) channel.
        listener.onMessage(webSocket, """{"type":"flow_progress","flow_id":"old-flow","step":"parsing_offer"}""")
        listener.onMessage(webSocket, """{"type":"match_request","flow_id":"old-flow","dcql_query":{}}""")
        session.messages().test {
            listener.onMessage(webSocket, """{"type":"handshake_complete","session_id":"s1"}""")
            // Handling is sequential: once the handshake envelope is seen, every
            // frame sent before it has been routed to its channel.
            while (awaitItem().type != MessageTypes.HANDSHAKE_COMPLETE) { /* keep consuming */ }
            cancelAndIgnoreRemainingEvents()
        }

        session.forceReconnect()

        // The reader processes the purge marker before anything the new connection
        // delivers: once the new handshake envelope is seen, the purge has run.
        session.messages().test {
            listener.onMessage(webSocket, """{"type":"handshake_complete","session_id":"s2"}""")
            while (awaitItem().type != MessageTypes.HANDSHAKE_COMPLETE) { /* keep consuming */ }
            cancelAndIgnoreRemainingEvents()
        }
        session.matchRequests().test {
            listener.onMessage(webSocket, """{"type":"match_request","flow_id":"new-flow","dcql_query":{}}""")
            assertEquals("new-flow", awaitItem().flowId)
            cancelAndIgnoreRemainingEvents()
        }
        session.flowProgress().test {
            listener.onMessage(webSocket, """{"type":"flow_progress","flow_id":"new-flow","step":"parsing_offer"}""")
            assertEquals("new-flow", awaitItem().flowId)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun forceReconnect_keepsTheIssuerTrustReportOfAFlowCompletedAcrossIt() = runTest {
        val session = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "t", client = client)
        session.connect("app-token")
        // Both frames are still queued (not awaited) when the connection is replaced.
        listener.onMessage(
            webSocket,
            """{"type":"flow_progress","flow_id":"f","step":"trust_evaluated","payload":{"issuer_trust_evaluated":true,"issuer":"https://i.example","trusted":false,"reason":"no"}}""",
        )
        listener.onMessage(webSocket, """{"type":"flow_complete","flow_id":"f"}""")
        session.forceReconnect()

        session.flowComplete().test {
            val done = awaitItem()
            assertEquals(false, done.issuerTrust?.trusted)
            assertEquals("no", done.issuerTrust?.reason)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun forceReconnect_keepsABufferedCredentialBearingFlowComplete() = runTest {
        val session = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "t", client = client)
        session.connect("app-token")
        listener.onMessage(webSocket, """{"type":"flow_complete","flow_id":"done-flow","credentials":[{"format":"dc+sd-jwt","credential":"jwt"}]}""")
        session.messages().test {
            listener.onMessage(webSocket, """{"type":"handshake_complete","session_id":"s1"}""")
            while (awaitItem().type != MessageTypes.HANDSHAKE_COMPLETE) { /* keep consuming */ }
            cancelAndIgnoreRemainingEvents()
        }

        session.forceReconnect()

        session.flowComplete().test {
            val done = awaitItem()
            assertEquals("done-flow", done.flowId)
            // Still tagged with the connection that delivered it, not the current one.
            assertEquals(1, done.connectionGeneration)
            assertEquals(2, session.connectionGeneration)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun overlappingForceReconnect_supersededCallDoesNotReplaceTheNewerSocket() = runTest {
        val session = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "t", client = client)
        val gate = kotlinx.coroutines.CompletableDeferred<String>()
        var calls = 0
        session.connect("app-token", tokenProvider = { if (calls++ == 0) gate.await() else "fresh-token" })

        val first = launch(start = CoroutineStart.UNDISPATCHED) {
            session.forceReconnect() // parked in the token refresh
        }
        session.forceReconnect()      // the newer caller opens the new socket
        verify(exactly = 2) { client.newWebSocket(any(), any()) }
        gate.complete("stale-token")
        first.join()

        // The superseded call must not cancel/replace the newer caller's socket.
        verify(exactly = 2) { client.newWebSocket(any(), any()) }
        verify(exactly = 1) { webSocket.cancel() }
    }

    @Test
    fun overlappingForceReconnect_publishesOnlyTheSocketThatWasActuallyInstalled() = runTest {
        val session = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "t", client = client)
        val gate = kotlinx.coroutines.CompletableDeferred<String>()
        var calls = 0
        session.connect("app-token", tokenProvider = { if (calls++ == 0) gate.await() else "fresh-token" })
        assertEquals(1, session.connectionGenerations.value)

        val first = launch(start = CoroutineStart.UNDISPATCHED) { session.forceReconnect() }
        session.forceReconnect()
        assertEquals("the newer caller's socket is published", 2, session.connectionGenerations.value)
        gate.complete("stale-token")
        first.join()
        // The superseded call installed nothing, so nothing more is published, and the flow and the counter agree.
        assertEquals(2, session.connectionGenerations.value)
        assertEquals(session.connectionGeneration, session.connectionGenerations.value)
    }

    @Test
    fun overlappingForceReconnect_supersededRejectionDoesNotSignalReauthOverTheNewerConnection() = runTest {
        val session = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "t", client = client)
        val gate = kotlinx.coroutines.CompletableDeferred<String>()
        var calls = 0
        var rejected = 0
        session.connect(
            "app-token",
            tokenProvider = { if (calls++ == 0) { gate.await(); throw AuthException("expired", code = 401) } else "fresh-token" },
            onAuthRejected = { rejected++ },
        )
        val first = launch(start = CoroutineStart.UNDISPATCHED) { session.forceReconnect() }
        session.forceReconnect()
        val stateBefore = session.state.value
        gate.complete("unused") // the older call now fails with 401, after the newer one succeeded
        first.join()

        assertEquals("the stale rejection must not reach the wallet", 0, rejected)
        assertEquals(stateBefore, session.state.value)
        assertTrue(session.state.value != WalletEngineSession.State.REAUTH_REQUIRED)
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
