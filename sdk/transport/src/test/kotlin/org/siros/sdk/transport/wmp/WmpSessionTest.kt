package org.siros.sdk.transport.wmp

import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WmpSessionTest {

    private val codec = WmpCodec()

    @Test
    fun createSendsSessionCreateAndTransitionsActive() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(requestTimeoutMs = 2_000),
        )

        val createJob = launch {
            session.create(authToken = "app-token", sender = "sample-wallet")
        }

        waitForSentCount(transport, 1)
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        assertEquals("wmp.session.create", createReq.method)
        assertNotNull(createReq.id)
        val createText = transport.sentMessages.last().toString(Charsets.UTF_8)
        assertTrue(createText.contains("\"type\":\"bearer\""))
        assertTrue(createText.contains("\"token\":\"app-token\""))

        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()

        assertEquals(WmpSessionState.ACTIVE, session.state.value)

        session.close()
    }

    @Test
    fun sendRequestTimesOutWithoutResponse() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(requestTimeoutMs = 100),
        )

        try {
            session.sendRequest("wmp.flow.action", null)
            throw AssertionError("Expected WmpTimeoutException")
        } catch (_: WmpTimeoutException) {
        }
    }

    @Test
    fun notificationsFlowEmitsServerNotification() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(requestTimeoutMs = 2_000),
        )

        val createJob = launch { session.create("token") }
        waitForSentCount(transport, 1)
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()

        val notificationDeferred = async { session.notifications().first() }
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"state":"processing"}}"""
                .toByteArray()
        )

        val notification = notificationDeferred.await()
        assertEquals("wmp.flow.progress", notification.method)

        session.close()
    }

    @Test
    fun disconnectTriggersResumeAndReturnsActive() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(
                requestTimeoutMs = 2_000,
                maxReconnectAttempts = 2,
                reconnectBaseMs = 1,
                reconnectMaxMs = 5,
            ),
        )

        val createJob = launch { session.create("token") }
        waitForSentCount(transport, 1)
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()
        assertEquals(WmpSessionState.ACTIVE, session.state.value)

        transport.simulateDisconnect()

        waitForRequestMethod(transport, "wmp.session.resume")
        val resumeReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"${resumeReq.id}","result":{"wmp":{"version":"0.1","session_id":"session-123"},"resumed":true}}"""
                .toByteArray()
        )

        withTimeout(2_000) {
            while (session.state.value != WmpSessionState.ACTIVE) {
                delay(10)
            }
        }

        session.close()
    }

    @Test
    fun failedReconnectAttemptsTransitionToFailed() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(
                requestTimeoutMs = 1_000,
                maxReconnectAttempts = 2,
                reconnectBaseMs = 1,
                reconnectMaxMs = 5,
            ),
        )

        val createJob = launch { session.create("token") }
        waitForSentCount(transport, 1)
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()

        transport.simulateFailure()

        repeat(2) {
            waitForRequestMethod(transport, "wmp.session.resume")
            val resumeReq = codec.decodeRequest(transport.sentMessages.last())
            transport.receiveFromServer(
                """{"jsonrpc":"2.0","id":"${resumeReq.id}","error":{"code":-31001,"message":"resume failed"}}"""
                    .toByteArray()
            )
        }

        withTimeout(3_000) {
            while (session.state.value != WmpSessionState.FAILED) {
                delay(10)
            }
        }

        assertEquals(WmpSessionState.FAILED, session.state.value)
    }

    private suspend fun waitForSentCount(transport: FakeTransport, expected: Int) {
        withTimeout(2_000) {
            while (transport.sentMessages.size < expected) {
                delay(10)
            }
        }
    }

    private suspend fun waitForRequestMethod(transport: FakeTransport, method: String) {
        withTimeout(2_000) {
            while (true) {
                val matches = transport.sentMessages
                    .map { codec.decodeRequest(it) }
                    .any { it.method == method }
                if (matches) return@withTimeout
                delay(10)
            }
        }

        assertTrue(
            transport.sentMessages
                .map { codec.decodeRequest(it) }
                .any { it.method == method }
        )
    }

    private fun createSuccessResponse(requestId: String): String {
        return """{"jsonrpc":"2.0","id":"$requestId","result":{"wmp":{"version":"0.1","session_id":"session-123"},"resumption_token":"resume-abc"}}"""
    }

    @Test
    fun createOffersCapabilitiesOnlyWhenGiven() = runBlocking {
        suspend fun sentCreate(offered: kotlinx.serialization.json.JsonObject?): String {
            val transport = FakeTransport()
            val session = WmpSession(transport = transport, config = WmpSessionConfig(requestTimeoutMs = 2_000))
            val job = launch { session.create("tok", capabilitiesOffered = offered) }
            waitForSentCount(transport, 1)
            val req = codec.decodeRequest(transport.sentMessages.last())
            val text = transport.sentMessages.last().toString(Charsets.UTF_8)
            transport.receiveFromServer(createSuccessResponse(req.id!!).toByteArray())
            job.join()
            session.close()
            return text
        }

        val withCaps = sentCreate(
            kotlinx.serialization.json.buildJsonObject {
                put(
                    "transaction_data",
                    kotlinx.serialization.json.buildJsonObject {
                        put("versions", kotlinx.serialization.json.JsonArray(listOf(kotlinx.serialization.json.JsonPrimitive(1))))
                    },
                )
            },
        )
        val without = sentCreate(null)

        assertTrue(withCaps, withCaps.contains("\"capabilities_offered\":{\"transaction_data\":{\"versions\":[1]}}"))
        assertTrue(without, !without.contains("transaction_data"))
    }
}
