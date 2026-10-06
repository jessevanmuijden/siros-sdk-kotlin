package org.siros.sdk.flow

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockkClass
import io.mockk.mockk
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.keystore.KeystoreManager
import org.siros.sdk.transport.Transport
import org.siros.sdk.transport.TransportState
import org.siros.sdk.transport.wmp.JsonRpcRequest
import org.siros.sdk.transport.wmp.JsonRpcResponse
import org.siros.sdk.transport.wmp.WmpCodec
import org.siros.sdk.transport.wmp.WmpSession
import org.siros.sdk.transport.wmp.WmpSessionConfig
import org.siros.sdk.transport.wmp.WmpSessionState
import kotlinx.coroutines.channels.Channel

class FlowClientTest {
    private val codec = WmpCodec()

    @Test
    fun startIssuanceSendsFlowStartRequest() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(requestTimeoutMs = 2_000),
        )

        val createJob = launch { session.create("token") }
        waitForRequestMethod(transport, "wmp.session.create")
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        assertNotNull(createReq.id)
        transport.receiveFromServer(createResponse(createReq.id!!).toByteArray())
        createJob.join()

        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns true

        val client = FlowClient(session, keystore)
        val flowIdDeferred = async {
            client.startIssuance(
            OID4VCIFlowParams(
                credentialOfferUri = "openid-credential-offer://offer",
                issuerUrl = "https://issuer.example.com",
            )
            )
        }

        val flowStartReq = waitForRequestMethod(transport, "wmp.flow.start")
        transport.receiveFromServer(successResponse(flowStartReq.id!!).toByteArray())
        val flowId = flowIdDeferred.await()

        assertTrue(flowId.isNotBlank())
        assertTrue(flowStartReq.params.toString().contains("\"flow_type\":\"issuance\""))
        assertTrue(flowStartReq.params.toString().contains("\"credential_offer_uri\":\"openid-credential-offer://offer\""))
        assertTrue(flowStartReq.params.toString().contains("\"issuer_url\":\"https://issuer.example.com\""))

        session.close()
    }

    @Test
    fun progressNotificationEmitsProgressEvent() = runBlocking {
        val notifications = MutableSharedFlow<JsonRpcRequest>(extraBufferCapacity = 10)
        val session = mockkClass(WmpSession::class, relaxed = true)
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns true
        every { session.notifications() } returns notifications

        val client = FlowClient(session, keystore, autoSign = false)
        client.start()
        delay(50)

        val eventDeferred = async { client.events().first() }
        notifications.emit(
            JsonRpcRequest(
                method = "wmp.flow.progress",
                params = jsonObj(
                    "flow_id" to "flow-1",
                    "step" to "processing",
                    "payload" to "{\"status\":\"ok\"}",
                ),
            )
        )

        val event = withTimeout(2_000) { eventDeferred.await() }
        assertTrue(event is FlowEvent.Progress)
        event as FlowEvent.Progress
        assertEquals("flow-1", event.flowId)
        assertEquals("processing", event.step)
    }

    @Test
    fun autoSignGenerateProofSendsFlowActionNotification() = runBlocking {
        val notifications = MutableSharedFlow<JsonRpcRequest>(extraBufferCapacity = 10)
        val session = mockkClass(WmpSession::class, relaxed = true)
        val keystore = mockk<KeystoreManager>()
        every { session.notifications() } returns notifications
        every { keystore.isUnlocked } returns true

        coEvery { keystore.generateProof("https://issuer.example.com", "nonce-1", false, null) } returns "proof.jwt"
        coEvery { session.sendNotification(any(), any()) } returns Unit

        val client = FlowClient(session, keystore, autoSign = true)
        client.start()
        delay(50)

        notifications.emit(
            JsonRpcRequest(
                method = "wmp.flow.progress",
                params = jsonObj(
                    "flow_id" to "flow-1",
                    "step" to "sign_request",
                    "message_id" to "msg-1",
                    "payload" to "{\"action\":\"generate_proof\",\"audience\":\"https://issuer.example.com\",\"nonce\":\"nonce-1\"}",
                ),
            )
        )

        coVerify(timeout = 2_000, exactly = 1) {
            // The four-argument form: FlowClient always states the holder
            // binding, which is null here because no holderBindingFor was
            // supplied. Verifying the shorter overload would watch a method
            // this code path never calls.
            keystore.generateProof("https://issuer.example.com", "nonce-1", false, null)
        }
        coVerify(timeout = 2_000, exactly = 1) {
            session.sendNotification(
                "wmp.flow.action",
                match { params ->
                    params?.toString()?.contains("\"flow_id\":\"flow-1\"") == true &&
                        params.toString().contains("\"message_id\":\"msg-1\"") &&
                        params.toString().contains("\"proof_jwt\":\"proof.jwt\"")
                }
            )
        }
    }

    @Test
    fun autoSignFailureFallsBackToSignRequestEvent() = runBlocking {
        val notifications = MutableSharedFlow<JsonRpcRequest>(extraBufferCapacity = 10)
        val session = mockkClass(WmpSession::class, relaxed = true)
        val keystore = mockk<KeystoreManager>()
        every { session.notifications() } returns notifications
        every { keystore.isUnlocked } returns true

        coEvery { keystore.generateProof(any(), any(), any(), any()) } throws RuntimeException("keystore locked")

        val client = FlowClient(session, keystore, autoSign = true)
        client.start()
        delay(50)

        val eventDeferred = async { client.events().first { it is FlowEvent.SignRequest } }
        notifications.emit(
            JsonRpcRequest(
                method = "wmp.flow.progress",
                params = jsonObj(
                    "flow_id" to "flow-2",
                    "step" to "sign_request",
                    "message_id" to "msg-2",
                    "payload" to "{\"action\":\"generate_proof\",\"audience\":\"https://issuer.example.com\",\"nonce\":\"nonce-2\"}",
                ),
            )
        )

        val event = withTimeout(2_000) { eventDeferred.await() }
        assertTrue(event is FlowEvent.SignRequest)
        event as FlowEvent.SignRequest
        assertEquals("flow-2", event.flowId)
        assertEquals("msg-2", event.messageId)
        assertEquals(SignAction.GENERATE_PROOF, event.action)
    }

    @Test
    fun matchRequestNotificationEmitsMatchRequestEvent() = runBlocking {
        val notifications = MutableSharedFlow<JsonRpcRequest>(extraBufferCapacity = 10)
        val session = mockkClass(WmpSession::class, relaxed = true)
        val keystore = mockk<KeystoreManager>()
        every { session.notifications() } returns notifications
        every { keystore.isUnlocked } returns true

        val client = FlowClient(session, keystore, autoSign = false)
        client.start()
        delay(50)

        val eventDeferred = async { client.events().first { it is FlowEvent.MatchRequest } }
        notifications.emit(
            JsonRpcRequest(
                method = "wmp.flow.progress",
                params = jsonObj(
                    "flow_id" to "flow-3",
                    "step" to "match_request",
                    "message_id" to "msg-3",
                    "payload" to "{\"dcql_query\":{\"query\":\"name\"}}",
                ),
            )
        )

        val event = withTimeout(2_000) { eventDeferred.await() }
        assertTrue(event is FlowEvent.MatchRequest)
        event as FlowEvent.MatchRequest
        assertEquals("flow-3", event.flowId)
        assertEquals("msg-3", event.messageId)
        assertTrue(event.dcqlQuery.toString().contains("\"query\":\"name\""))
    }

    private fun jsonObj(vararg pairs: Pair<String, String>): JsonObject {
        return buildJsonObject {
            for ((key, value) in pairs) {
                val trimmed = value.trim()
                if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                    put(key, kotlinx.serialization.json.Json.parseToJsonElement(value))
                } else {
                    put(key, JsonPrimitive(value))
                }
            }
        }
    }

    @Test
    fun sendCredentialNotificationSendsWmpNotification() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(requestTimeoutMs = 2_000),
        )

        // Connect the session so it's ACTIVE
        val createJob = launch { session.create("token") }
        waitForRequestMethod(transport, "wmp.session.create")
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(createResponse(createReq.id!!).toByteArray())
        createJob.join()

        assertEquals(WmpSessionState.ACTIVE, session.state.value)

        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns true

        val client = FlowClient(session, keystore)
        client.sendCredentialNotification(
            flowId = "flow-123",
            notificationId = "notif-456",
            event = "credential_accepted",
        )

        // Wait briefly for the fire-and-forget coroutine to complete
        delay(200)

        // Find the notification in sent messages
        val notifications = transport.sentMessages
            .mapNotNull { runCatching { codec.decodeRequest(it) }.getOrNull() }
            .filter { it.method == "wmp.credential.notification" }

        assertEquals(1, notifications.size)
        val params = notifications.first().params!!
        assertEquals("flow-123", (params["flow_id"] as? JsonPrimitive)?.content)
        assertEquals("notif-456", (params["notification_id"] as? JsonPrimitive)?.content)
        assertEquals("credential_accepted", (params["event"] as? JsonPrimitive)?.content)

        session.close()
    }

    @Test
    fun sendCredentialNotificationNoOpWhenNotActive() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(requestTimeoutMs = 2_000),
        )

        // Session is CLOSED (not connected)
        assertEquals(WmpSessionState.CLOSED, session.state.value)

        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns true

        val client = FlowClient(session, keystore)
        val sentBefore = transport.sentMessages.size
        client.sendCredentialNotification(
            flowId = "flow-123",
            notificationId = "notif-456",
            event = "credential_accepted",
        )

        delay(200)
        // No messages should have been sent
        assertEquals(sentBefore, transport.sentMessages.size)
    }

    private suspend fun waitForRequestMethod(transport: FakeTransport, method: String): JsonRpcRequest {
        lateinit var found: JsonRpcRequest
        withTimeout(2_000) {
            while (true) {
                val request = transport.sentMessages
                    .map { codec.decodeRequest(it) }
                    .firstOrNull { it.method == method }
                if (request != null) {
                    found = request
                    return@withTimeout
                }
                delay(10)
            }
        }
        return found
    }

    private fun createResponse(requestId: String): String {
        return """{"jsonrpc":"2.0","id":"$requestId","result":{"wmp":{"version":"0.1","session_id":"session-flow"},"resumption_token":"resume-flow"}}"""
    }

    private fun successResponse(requestId: String): String {
        return """{"jsonrpc":"2.0","id":"$requestId","result":{"ok":true}}"""
    }

    private class FakeTransport : Transport {
        private val _state = MutableStateFlow(TransportState.DISCONNECTED)
        override val state: StateFlow<TransportState> = _state

        private val incomingChannel = Channel<ByteArray>(Channel.BUFFERED)
        private val sent = mutableListOf<ByteArray>()
        val sentMessages: List<ByteArray> get() = sent.toList()

        override suspend fun connect() {
            _state.value = TransportState.CONNECTED
        }

        override suspend fun send(message: ByteArray) {
            sent.add(message)
        }

        override fun incoming(): Flow<ByteArray> = incomingChannel.receiveAsFlow()

        override suspend fun disconnect() {
            _state.value = TransportState.DISCONNECTED
        }

        suspend fun receiveFromServer(message: ByteArray) {
            incomingChannel.send(message)
        }
    }
}
