package org.siros.sdk.transport.wmp

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import org.siros.sdk.transport.Transport
import org.siros.sdk.transport.TransportState
import timber.log.Timber
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min

/**
 * WMP session client managing a single session over a [Transport].
 *
 * Handles session lifecycle (create/resume/close), request-response correlation,
 * and automatic reconnection with session resumption.
 */
class WmpSession(
    private val transport: Transport,
    internal val codec: WmpCodec = WmpCodec(),
    private val config: WmpSessionConfig = WmpSessionConfig(),
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val _state = MutableStateFlow(WmpSessionState.CLOSED)
    val state: StateFlow<WmpSessionState> = _state

    private var sessionId: String? = null
    private var resumptionToken: String? = null
    private var lastReceivedId: String? = null

    private val pendingRequests = ConcurrentHashMap<String, CompletableDeferred<JsonRpcResponse>>()
    private val incomingNotifications = Channel<JsonRpcRequest>(Channel.BUFFERED)
    private val sendMutex = Mutex()

    /** Notifications from the server (flow.progress, flow.complete, etc.). */
    fun notifications(): Flow<JsonRpcRequest> = incomingNotifications.receiveAsFlow()

    /**
     * Create a new WMP session with the given auth token.
     *
     * @param capabilitiesOffered the capabilities this wallet offers
     *   (`capabilities_offered`), by name. Capabilities are offered per
     *   session: changing what a wallet supports takes effect only on a new
     *   session. `null` offers none.
     */
    suspend fun create(
        authToken: String,
        sender: String? = null,
        capabilitiesOffered: JsonObject? = null,
    ) {
        _state.value = WmpSessionState.CONNECTING
        transport.connect()
        startMessageLoop()

        val params = codec.encodeParams(
            SessionCreateParams(
                wmp = WmpMeta(sender = sender),
                capabilitiesOffered = capabilitiesOffered,
                auth = SessionAuth(type = "bearer", token = authToken),
                ttl = config.sessionTtlSeconds,
            )
        )

        val response = sendRequest("wmp.session.create", params)
        if (response.error != null) {
            _state.value = WmpSessionState.FAILED
            throw WmpSessionException("Session creation failed: ${response.error.message}")
        }

        val result = response.result
            ?: throw WmpSessionException("Session creation response missing result")
        val parsed = codec.json.decodeFromJsonElement(
            SessionCreateResult.serializer(),
            result,
        )

        sessionId = parsed.wmp.sessionId
        resumptionToken = parsed.resumptionToken

        _state.value = WmpSessionState.ACTIVE
        Timber.i("WMP session created: $sessionId")
    }

    /** Resume an existing session after reconnection. */
    suspend fun resume() {
        val sid = sessionId ?: throw WmpSessionException("No session to resume")
        val token = resumptionToken ?: throw WmpSessionException("No resumption token")

        _state.value = WmpSessionState.RESUMING
        transport.connect()
        startMessageLoop()

        val params = codec.encodeParams(
            SessionResumeParams(
                wmp = WmpMeta(sessionId = sid),
                sessionId = sid,
                resumptionToken = token,
                lastReceivedId = lastReceivedId,
            )
        )

        val response = sendRequest("wmp.session.resume", params)
        if (response.error != null) {
            _state.value = WmpSessionState.FAILED
            throw WmpSessionException("Session resume failed: ${response.error.message}")
        }

        _state.value = WmpSessionState.ACTIVE
        Timber.i("WMP session resumed: $sessionId")
    }

    /** Close the session gracefully. */
    suspend fun close(reason: String = "complete") {
        val sid = sessionId ?: return

        val params = codec.encodeParams(
            SessionCloseParams(
                wmp = WmpMeta(sessionId = sid),
                reason = reason,
            )
        )

        sendNotification("wmp.session.close", params)
        transport.disconnect()
        _state.value = WmpSessionState.CLOSED
        sessionId = null
        resumptionToken = null
        scope.cancel()
        Timber.i("WMP session closed: $sid")
    }

    /**
     * Send a JSON-RPC request and wait for the correlated response.
     * Throws [WmpTimeoutException] if the response is not received within the timeout.
     */
    suspend fun sendRequest(
        method: String,
        params: kotlinx.serialization.json.JsonObject?,
        timeoutMs: Long = config.requestTimeoutMs,
    ): JsonRpcResponse {
        val id = UUID.randomUUID().toString()
        val deferred = CompletableDeferred<JsonRpcResponse>()
        pendingRequests[id] = deferred

        try {
            val message = codec.encodeRequest(method, params, id)
            sendMutex.withLock {
                transport.send(message)
            }
            return withTimeout(timeoutMs) { deferred.await() }
        } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
            pendingRequests.remove(id)
            throw WmpTimeoutException("Request $method timed out after ${timeoutMs}ms")
        }
    }

    /** Send a JSON-RPC notification (no response expected). */
    suspend fun sendNotification(method: String, params: kotlinx.serialization.json.JsonObject?) {
        val message = codec.encodeNotification(method, params)
        sendMutex.withLock {
            transport.send(message)
        }
    }

    /**
     * Send a JSON-RPC 2.0 response for a server-initiated request.
     * Used when the peer acts as the responder for inbound requests.
     */
    internal suspend fun sendResponse(id: String, result: kotlinx.serialization.json.JsonObject?) {
        val response = JsonRpcResponse(id = id, result = result)
        val message = codec.json.encodeToString(JsonRpcResponse.serializer(), response).toByteArray(Charsets.UTF_8)
        sendMutex.withLock {
            transport.send(message)
        }
    }

    /**
     * Send a JSON-RPC 2.0 error response for a server-initiated request.
     * Used when the peer cannot handle an inbound request.
     *
     * @param id The JSON-RPC request id to correlate the error with.
     * @param code A JSON-RPC / WMP error code (see [WmpErrorCodes]).
     * @param message A human-readable description of the error.
     */
    internal suspend fun sendErrorResponse(id: String, code: Int, message: String) {
        val response = JsonRpcResponse(id = id, error = JsonRpcError(code = code, message = message))
        val msg = codec.json.encodeToString(JsonRpcResponse.serializer(), response).toByteArray(Charsets.UTF_8)
        sendMutex.withLock {
            transport.send(msg)
        }
    }

    private fun startMessageLoop() {
        scope.launch {
            transport.incoming().collect { data ->
                try {
                    handleIncoming(data)
                } catch (e: Exception) {
                    Timber.e(e, "Error handling incoming WMP message")
                }
            }
        }

        scope.launch {
            transport.state.collect { transportState ->
                when (transportState) {
                    TransportState.DISCONNECTED, TransportState.FAILED -> {
                        if (_state.value == WmpSessionState.ACTIVE) {
                            handleDisconnect()
                        }
                    }
                    else -> {} // no-op
                }
            }
        }
    }

    private suspend fun handleIncoming(data: ByteArray) {
        when (val message = codec.decodeMessage(data)) {
            is WmpMessage.Response -> {
                val id = message.response.id
                if (id != null) {
                    pendingRequests.remove(id)?.complete(message.response)
                        ?: Timber.w("Received response for unknown request: $id")
                }
            }
            is WmpMessage.Notification -> {
                message.notification.id?.let { lastReceivedId = it }
                incomingNotifications.send(message.notification)
            }
            is WmpMessage.Request -> {
                message.request.id?.let { lastReceivedId = it }
                incomingNotifications.send(message.request)
            }
        }
    }

    private suspend fun handleDisconnect() {
        if (resumptionToken == null) return
        _state.value = WmpSessionState.RESUMING

        var attempt = 0
        while (attempt < config.maxReconnectAttempts) {
            attempt++
            val backoffMs = min(config.reconnectBaseMs * (1L shl attempt), config.reconnectMaxMs)
            Timber.i("WMP reconnect attempt $attempt in ${backoffMs}ms")
            delay(backoffMs)

            try {
                resume()
                return
            } catch (e: Exception) {
                Timber.w(e, "Reconnect attempt $attempt failed")
            }
        }

        _state.value = WmpSessionState.FAILED
        pendingRequests.values.forEach { it.cancel() }
        pendingRequests.clear()
    }
}

enum class WmpSessionState {
    CLOSED,
    CONNECTING,
    ACTIVE,
    RESUMING,
    FAILED,
}

data class WmpSessionConfig(
    val sessionTtlSeconds: Int = 3600,
    val requestTimeoutMs: Long = 30_000,
    val maxReconnectAttempts: Int = 10,
    val reconnectBaseMs: Long = 1_000,
    val reconnectMaxMs: Long = 30_000,
)

class WmpSessionException(message: String, cause: Throwable? = null) : org.siros.sdk.credentials.SirosException(message, cause)
class WmpTimeoutException(message: String) : org.siros.sdk.credentials.SirosException(message)
