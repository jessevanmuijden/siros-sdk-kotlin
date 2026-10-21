// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.transport.engine

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.siros.sdk.credentials.interop.AuthorizationDetail
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.siros.sdk.credentials.AuthException
import org.siros.sdk.transport.CredentialNotifier
import timber.log.Timber
import java.util.concurrent.TimeUnit

/**
 * WebSocket session client for the wallet backend engine protocol.
 *
 * This implements the wallet backend's custom type-based WebSocket protocol
 * (handshake → flow_start → sign_request/match_request → flow_complete).
 *
 * Connection sequence:
 * 1. Open WebSocket to `/api/v2/wallet?tenant_id=<tenantId>`
 * 2. Send `{"type":"handshake","app_token":"<jwt>"}`
 * 3. Receive `{"type":"handshake_complete","session_id":"...","capabilities":[...]}`
 * 4. Exchange flow messages until disconnect
 */
class WalletEngineSession(
    private val baseUrl: String,
    private val tenantId: String = "default",
    private val client: OkHttpClient = defaultClient(),
) : CredentialNotifier {
    /**
     * [REAUTH_REQUIRED] is distinct from [FAILED]: it means a reconnect
     * attempt's [tokenProvider] call itself failed (the access-token/session
     * refresh mechanism was rejected), not merely that the socket couldn't
     * connect - see [scheduleReconnect]/[forceReconnect]. [FAILED] is reserved
     * for exhausting reconnect attempts on a transient network-level failure.
     */
    enum class State { DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, REAUTH_REQUIRED, FAILED }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private val _state = MutableStateFlow(State.DISCONNECTED)
    val state: StateFlow<State> = _state

    // @Volatile: these are written from the caller's thread (connect/disconnect),
    // OkHttp's own WebSocketListener callback thread, and this class's own
    // scope.launch coroutines (which can run on different Dispatchers.IO
    // threads) - without this, a write on one thread isn't guaranteed to be
    // visible to a read on another.
    @Volatile
    private var webSocket: WebSocket? = null
    @Volatile
    private var sessionId: String? = null
    @Volatile
    private var lastAppToken: String? = null
    /**
     * Mints a fresh handshake token on demand - called before every
     * reconnect attempt (automatic backoff or [forceReconnect]) instead of
     * replaying [lastAppToken], which is otherwise never updated after the
     * initial [connect] and goes stale within minutes (the AS's default
     * access-token TTL is 2 minutes) since the WS path had no refresh logic
     * at all. Typically wraps `authTokens.ensureBackendToken()`/
     * `ensureAnonymousToken()`, which already handles expiry-aware caching -
     * this class only needs to call it, not duplicate that logic. Null
     * preserves the old (non-refreshing) behavior for callers that haven't
     * opted in.
     */
    @Volatile
    private var tokenProvider: (suspend () -> String)? = null
    /**
     * Invoked whenever [refreshTokenOrSignalReauth] sees an explicit 401/403
     * auth rejection from the AS before a reconnect - lets the caller (e.g.
     * [org.siros.sdk.wallet.SirosWallet], which owns the `AuthTokens`
     * instance this class has no dependency on) feed the rejection into its
     * own rejection-counting/auto-logout mechanism, the same way a REST 401
     * does via `AuthTokens.registerTokenRejection`. This class only reports
     * the rejection; it doesn't decide what "too many" means.
     */
    @Volatile
    private var onAuthRejected: (() -> Unit)? = null
    @Volatile
    private var reconnectAttempts = 0
    private val maxReconnectAttempts = 5
    private val baseReconnectDelayMs = 1000L

    /**
     * This session's own WebSocket ping cadence, in milliseconds - starts at
     * [DEFAULT_PING_INTERVAL_MS] and is updated (for the *next* connection
     * attempt, not the current one - see [handleMessage]'s
     * `HANDSHAKE_COMPLETE` case) whenever the server reports a different
     * value via [HandshakeCompleteMessage.config]. In-memory only: a fresh
     * process restart falls back to the hardcoded default and re-learns the
     * server's value on its very first handshake, which is fine since that
     * default is itself already safe (see [DEFAULT_PING_INTERVAL_MS]'s doc
     * comment) - this isn't a value that ever needs to survive a restart to
     * avoid a broken connection, only to avoid an unnecessary mid-life
     * disagreement between client and server.
     */
    @Volatile
    private var pingIntervalMs: Long = DEFAULT_PING_INTERVAL_MS

    /**
     * Raw incoming WS text frames, processed strictly one at a time by a
     * single consumer coroutine (started in [init]) - `onMessage` previously
     * did `scope.launch { handleMessage(text) }` per frame, an unstructured
     * launch onto the shared [scope] (backed by [Dispatchers.IO], a real
     * thread pool). Two frames arriving close together (e.g. a flow_progress
     * immediately followed by flow_complete) could then have their
     * [handleMessage] bodies run concurrently on different threads while
     * both read/write [sessionId] and friends. Routing through this channel
     * preserves OkHttp's own delivery order while guaranteeing at most one
     * [handleMessage] call is ever in flight at a time.
     */
    /** A received frame, or - with a null [text] - the marker [forceReconnect] queues to purge stale flow traffic. */
    private class RawFrame(val generation: Int, val text: String?)

    private val rawMessageChannel = Channel<RawFrame>(Channel.UNLIMITED)

    /**
     * Incremented for every socket this session opens (first connect,
     * [forceReconnect], automatic reconnect). Every flow frame carries the
     * generation of the socket that delivered it, so a consumer can tell a
     * reply to something it sent on an earlier connection from one on the
     * current connection, even after both were buffered together.
     */
    private val generationCounter = java.util.concurrent.atomic.AtomicInteger(0)

    /** The generation allowed to act (its callbacks count); [NO_LIVE_SOCKET] while a replacement is being made. */
    private val liveGeneration = java.util.concurrent.atomic.AtomicInteger(NO_LIVE_SOCKET)

    /** Generation of the most recently opened socket. */
    val connectionGeneration: Int get() = generationCounter.get()

    /** Orders overlapping [forceReconnect] calls; only the latest may replace the socket. */
    private val reconnectRequests = java.util.concurrent.atomic.AtomicInteger(0)

    init {
        scope.launch {
            for (frame in rawMessageChannel) {
                val text = frame.text
                if (text == null) purgeStaleFlowTraffic() else handleMessage(text, frame.generation)
            }
        }
    }

    /** Issuer trust reports awaiting their flow's completion; see [FlowCompleteMessage.issuerTrust]. */
    private val issuerTrustByFlow = java.util.concurrent.ConcurrentHashMap<String, IssuerTrustReport>()

    private fun recordIssuerTrustReport(msg: FlowProgressMessage) {
        if (msg.step != "trust_evaluated") return
        val payload = msg.payload as? kotlinx.serialization.json.JsonObject ?: return
        fun str(name: String) = (payload[name] as? kotlinx.serialization.json.JsonPrimitive)?.content
        if (str("issuer_trust_evaluated") != "true") return
        issuerTrustByFlow[msg.flowId] = IssuerTrustReport(
            issuer = str("issuer"),
            trusted = str("trusted") == "true",
            framework = str("framework"),
            reason = str("reason"),
        )
    }

    private val incomingMessages = Channel<EngineMessage>(Channel.BUFFERED)
    private val flowProgressChannel = Channel<FlowProgressMessage>(Channel.BUFFERED)
    private val flowCompleteChannel = Channel<FlowCompleteMessage>(Channel.BUFFERED)
    private val flowErrorChannel = Channel<FlowErrorMessage>(Channel.BUFFERED)
    private val signRequestChannel = Channel<SignRequestMessage>(Channel.BUFFERED)
    private val matchRequestChannel = Channel<MatchRequestMessage>(Channel.BUFFERED)
    private val pushChannel = Channel<PushMessage>(Channel.BUFFERED)
    private val notificationAckChannel = Channel<NotificationAckMessage>(Channel.BUFFERED)

    /** All incoming messages as raw [EngineMessage] (for type-based dispatch). */
    fun messages(): Flow<EngineMessage> = incomingMessages.receiveAsFlow()

    /** Server flow progress updates. */
    fun flowProgress(): Flow<FlowProgressMessage> = flowProgressChannel.receiveAsFlow()

    /** Server flow completion events. */
    fun flowComplete(): Flow<FlowCompleteMessage> = flowCompleteChannel.receiveAsFlow()

    /** Server flow error events. */
    fun flowErrors(): Flow<FlowErrorMessage> = flowErrorChannel.receiveAsFlow()

    /** Server signing requests. */
    fun signRequests(): Flow<SignRequestMessage> = signRequestChannel.receiveAsFlow()

    /** Server credential matching requests. */
    fun matchRequests(): Flow<MatchRequestMessage> = matchRequestChannel.receiveAsFlow()

    /** Server push notifications. */
    fun pushMessages(): Flow<PushMessage> = pushChannel.receiveAsFlow()

    /**
     * Acknowledgements for OID4VCI §10 credential notifications sent via
     * [sendCredentialNotification]. Each value reports whether the backend
     * forwarded the notification to the issuer (`status == "forwarded"`) or
     * rejected it, including any `error` detail.
     */
    fun notificationAcks(): Flow<NotificationAckMessage> = notificationAckChannel.receiveAsFlow()

    /** Whether the underlying WebSocket is currently connected. */
    val isConnected: Boolean get() = webSocket != null

    /**
     * Connect to the engine WebSocket and perform the handshake.
     * @param appToken JWT obtained from login/register, used for this initial
     *   handshake (avoids an extra round trip re-minting a token we were
     *   just handed).
     * @param tokenProvider mints a fresh token before each subsequent
     *   reconnect attempt - see [tokenProvider]'s doc comment. Omit only if
     *   the caller genuinely has no refresh mechanism to offer; every real
     *   [SirosWallet] call site should pass one.
     * @param onAuthRejected called on an explicit 401/403 auth rejection
     *   before a reconnect - see [onAuthRejected]'s doc comment.
     */
    fun connect(
        appToken: String,
        tokenProvider: (suspend () -> String)? = null,
        onAuthRejected: (() -> Unit)? = null,
    ) {
        if (_state.value == State.CONNECTED) return
        _state.value = State.CONNECTING
        lastAppToken = appToken
        this.tokenProvider = tokenProvider
        this.onAuthRejected = onAuthRejected
        reconnectAttempts = 0
        doConnect(appToken)
    }

    /**
     * Guards every change of which socket is current: the generation check, publishing the socket, cancelling the previous one
     * and the pending backoff, and scheduling a backoff are one atomic step, so a stale automatic attempt cannot publish an older
     * socket after [forceReconnect] installed a newer one, and a late callback of an old socket cannot schedule a retry that
     * would replace the new socket's.
     */
    private val connLock = Any()

    /** [onlyIfLive]: connect only while that generation is still the live one (an automatic attempt superseded meanwhile does nothing). */
    private fun doConnect(appToken: String, onlyIfLive: Int? = null) {
        val wsUrl = baseUrl
            .replace("https://", "wss://")
            .replace("http://", "ws://")
            .trimEnd('/') + "/api/v2/wallet?tenant_id=$tenantId"

        val request = Request.Builder()
            .url(wsUrl)
            .header("Sec-WebSocket-Protocol", "wmp.v1")
            .build()

        // Derived per-connection rather than baked into [client] itself:
        // OkHttp's automatic ping/pong keepalive is fixed for the lifetime
        // of whatever OkHttpClient a WebSocket is opened on, so a value
        // learned from the server (see [pingIntervalMs]'s doc comment)
        // between connections can only take effect on the NEXT one -
        // `newBuilder()` reuses [client]'s connection pool/dispatcher/etc.
        // and overrides only the interval, rather than constructing an
        // unrelated OkHttpClient from scratch.
        val connectionClient = client.newBuilder()
            .pingInterval(livenessIntervalMs(pingIntervalMs), TimeUnit.MILLISECONDS)
            .build()

        // Single-flight: at most one socket is ever live. Opening a new one supersedes (and cancels) the previous, and a
        // callback from a superseded socket (the failure its own cancel() raises, a late ping timeout) is ignored: it must
        // not schedule yet another connection, which is how two sockets ended up killing each other in a reconnect storm.
        synchronized(connLock) {
            if (onlyIfLive != null && liveGeneration.get() != onlyIfLive) {
                Timber.d("Engine WebSocket: a superseded reconnect attempt did nothing")
                return
            }
            val generation = generationCounter.incrementAndGet()
            liveGeneration.set(generation)
            pendingReconnect?.cancel()
            pendingReconnect = null
            val previous = webSocket
            webSocket = null
            previous?.cancel()
            webSocket = connectionClient.newWebSocket(request, object : WebSocketListener() {
                private fun stale() = liveGeneration.get() != generation

                override fun onOpen(ws: WebSocket, response: Response) {
                    if (stale()) { ws.cancel(); return }
                    Timber.d("Engine WebSocket connected, sending handshake")
                    reconnectAttempts = 0
                    val handshake = json.encodeToString(
                        HandshakeMessage.serializer(),
                        HandshakeMessage(appToken = appToken),
                    )
                    ws.send(handshake)
                }

                override fun onMessage(ws: WebSocket, text: String) {
                    if (stale()) return
                    rawMessageChannel.trySend(RawFrame(generation, text))
                }

                override fun onClosing(ws: WebSocket, code: Int, reason: String) {
                    Timber.d("Engine WebSocket closing: $code $reason")
                    ws.close(1000, null)
                    socketEnded(generation, ws)
                }

                override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                    synchronized(connLock) {
                        if (stale()) {
                            Timber.d("Engine WebSocket: failure of a superseded socket ignored (${t.javaClass.simpleName})")
                            return
                        }
                        Timber.e(t, "Engine WebSocket failure")
                    }
                    socketEnded(generation, ws)
                }
            })
        }
    }

    /** The current socket ended: it is no longer a usable socket, and one backoff attempt is scheduled; a stale socket does nothing. */
    private fun socketEnded(generation: Int, ws: WebSocket) {
        synchronized(connLock) {
            if (liveGeneration.get() != generation) return
            if (webSocket === ws) webSocket = null // isConnected/send() must not claim a dead socket during the backoff
            scheduleReconnect()
        }
    }

    /** The one pending backoff-then-connect attempt, if any; a new schedule or any connect replaces it. */
    @Volatile
    private var pendingReconnect: kotlinx.coroutines.Job? = null

    private fun scheduleReconnect() {
        if (lastAppToken == null) {
            // disconnect() already nulled this and set State.DISCONNECTED itself -
            // this is OkHttp delivering a stale onClosing/onFailure for the socket
            // we just closed on purpose. Don't clobber that with FAILED.
            return
        }
        if (reconnectAttempts >= maxReconnectAttempts) {
            Timber.w("WebSocket reconnection exhausted ($reconnectAttempts attempts)")
            _state.value = State.FAILED
            return
        }
        // One attempt in flight: a second failure/closing of the same socket must not queue another (or inflate the backoff).
        if (pendingReconnect?.isActive == true) return
        _state.value = State.RECONNECTING
        reconnectAttempts++
        val delayMs = baseReconnectDelayMs * (1L shl (reconnectAttempts - 1).coerceAtMost(4))
        Timber.i("Reconnecting in ${delayMs}ms (attempt $reconnectAttempts/$maxReconnectAttempts)")
        val scheduledFor = liveGeneration.get()
        pendingReconnect = scope.launch {
            kotlinx.coroutines.delay(delayMs)
            if (_state.value != State.RECONNECTING) return@launch
            val token = refreshTokenOrSignalReauth() ?: return@launch
            if (_state.value == State.RECONNECTING) {
                doConnect(token, onlyIfLive = scheduledFor)
            }
        }
    }

    /**
     * Mints a fresh token via [tokenProvider] (falling back to [lastAppToken]
     * if no provider was supplied) for a reconnect attempt. Only an explicit
     * auth/session rejection (401/403 from the AS - see [AuthException.code])
     * means the refresh mechanism itself was rejected, so only that
     * short-circuits straight to [State.REAUTH_REQUIRED] rather than
     * consuming the remaining backoff budget on a broken session. Any other
     * failure (network blip, AS 5xx, etc.) is transient like a socket-connect
     * failure, so it falls back to [lastAppToken] and lets the normal
     * reconnect/backoff loop keep retrying. Cancellation is always rethrown,
     * never treated as a token-refresh failure.
     * @return the token to reconnect with, or null if reconnecting should
     *   stop (state has already been updated to reflect why).
     */
    private suspend fun refreshTokenOrSignalReauth(request: Int? = null): String? {
        val provider = tokenProvider ?: return lastAppToken
        // A refresh whose caller was superseded (see [forceReconnect]) must not
        // publish anything: no token, no reauth signal, no state change.
        fun superseded() = request != null && reconnectRequests.get() != request
        return try {
            provider().also { if (!superseded()) lastAppToken = it }
        } catch (e: CancellationException) {
            throw e
        } catch (e: AuthException) {
            if (superseded()) return null
            if (e.code == 401 || e.code == 403) {
                Timber.w(e, "Token refresh rejected (${e.code}) before reconnect - session invalid")
                onAuthRejected?.invoke()
                _state.value = State.REAUTH_REQUIRED
                null
            } else {
                Timber.w(e, "Token refresh failed before reconnect (AS error ${e.code}) - retrying with existing token")
                lastAppToken
            }
        } catch (e: Exception) {
            if (superseded()) return null
            Timber.w(e, "Token refresh failed before reconnect (transient) - retrying with existing token")
            lastAppToken
        }
    }

    private suspend fun handleMessage(text: String, generation: Int) {
        try {
            val element = json.parseToJsonElement(text).jsonObject
            val type = element["type"]?.jsonPrimitive?.content ?: return

            when (type) {
                MessageTypes.HANDSHAKE_COMPLETE -> {
                    val msg = json.decodeFromString(HandshakeCompleteMessage.serializer(), text)
                    sessionId = msg.sessionId
                    _state.value = State.CONNECTED
                    Timber.i("Engine session established: ${msg.sessionId}")
                    msg.config?.pingIntervalMs
                        ?.takeIf { it > 0 && it != pingIntervalMs }
                        ?.let { serverPingIntervalMs ->
                            Timber.i(
                                "Server ping interval (${serverPingIntervalMs}ms) differs " +
                                    "from ours (${pingIntervalMs}ms) - adopting it for the next connection"
                            )
                            pingIntervalMs = serverPingIntervalMs
                        }
                }
                MessageTypes.FLOW_PROGRESS -> {
                    val msg = json.decodeFromString(FlowProgressMessage.serializer(), text)
                        .also { it.connectionGeneration = generation }
                    recordIssuerTrustReport(msg)
                    flowProgressChannel.trySend(msg)
                }
                MessageTypes.FLOW_COMPLETE -> {
                    val decoded = json.decodeFromString(FlowCompleteMessage.serializer(), text)
                    // copy() builds a new instance, so stamp the generation on the copy.
                    val msg = decoded.copy(issuerTrust = issuerTrustByFlow.remove(decoded.flowId))
                        .also { it.connectionGeneration = generation }
                    flowCompleteChannel.trySend(msg)
                }
                MessageTypes.FLOW_ERROR -> {
                    val msg = json.decodeFromString(FlowErrorMessage.serializer(), text)
                        .also { it.connectionGeneration = generation }
                    msg.flowId?.let { issuerTrustByFlow.remove(it) }
                    flowErrorChannel.trySend(msg)
                }
                MessageTypes.SIGN_REQUEST -> {
                    val msg = json.decodeFromString(SignRequestMessage.serializer(), text)
                        .also { it.connectionGeneration = generation }
                    signRequestChannel.trySend(msg)
                }
                MessageTypes.MATCH_REQUEST -> {
                    val msg = json.decodeFromString(MatchRequestMessage.serializer(), text)
                    matchRequestChannel.trySend(msg)
                }
                MessageTypes.PUSH -> {
                    val msg = json.decodeFromString(PushMessage.serializer(), text)
                    pushChannel.trySend(msg)
                }
                MessageTypes.NOTIFICATION_ACK -> {
                    val msg = json.decodeFromString(NotificationAckMessage.serializer(), text)
                    notificationAckChannel.trySend(msg)
                }
                MessageTypes.ERROR -> {
                    val msg = json.decodeFromString(ErrorMessage.serializer(), text)
                    Timber.e("Engine error: ${msg.code} — ${msg.details}")
                    _state.value = State.FAILED
                }
                else -> Timber.w("Unknown engine message type: $type")
            }

            // Also send to the raw messages channel
            val envelope = json.decodeFromString(EngineMessage.serializer(), text)
            incomingMessages.trySend(envelope)
        } catch (e: Exception) {
            Timber.e(e, "Failed to parse engine message")
        }
    }

    // ── Client → Server messages ────────────────────────────────────

    /**
     * Start an OID4VCI credential issuance flow.
     *
     * @param clientAttestation DEPRECATED - leave null. go-wallet-backend now
     *   requests the Wallet Instance Attestation itself via a
     *   `request_attestation` sign request once it has resolved the issuer's
     *   authorization server (see [SignResponseMessage.clientAttestation]);
     *   supplying one up front only bypasses that and requires the caller to
     *   have discovered the PoP audience on its own. Still honoured on the
     *   wire for callers that have - see [FlowStartMessage.clientAttestation].
     * @param clientAttestationPoP DEPRECATED - the matching per-flow PoP JWT,
     *   required whenever [clientAttestation] is set.
     * @param authorizationDetails the OID4VCI `authorization_details` to ask
     *   with - see [FlowStartMessage.authorizationDetails]. Null or empty
     *   omits the field, leaving the `scope` path unchanged.
     */
    fun startIssuance(
        offer: String? = null,
        credentialOfferUri: String? = null,
        redirectUri: String? = null,
        clientAttestation: String? = null,
        clientAttestationPoP: String? = null,
        authorizationDetails: List<AuthorizationDetail>? = null,
    ) {
        send(FlowStartMessage.serializer(), FlowStartMessage(
            protocol = "oid4vci",
            offer = offer,
            credentialOfferUri = credentialOfferUri,
            redirectUri = redirectUri,
            clientAttestation = clientAttestation,
            clientAttestationPoP = clientAttestationPoP,
            authorizationDetails = authorizationDetails?.takeIf { it.isNotEmpty() },
        ))
    }

    /**
     * Resume an OID4VCI issuance flow after an OAuth browser redirect returns to the app,
     * on a fresh flow_start rather than a flow_action on the original flow_id.
     *
     * The backend's `resumeWithAuthCode` path is fully stateless: it re-derives issuer
     * metadata/trust from [offer]/[credentialOfferUri] and completes the token exchange
     * with [authCode]/[codeVerifier], so this works even if the original flow_id's session
     * no longer exists server-side (the common case - see [WalletEngineSession] backoff
     * reconnect logic, and SirosWallet.completeAuthorization for why that happens).
     *
     * @param clientAttestation/[clientAttestationPoP] DEPRECATED - leave null;
     *   the engine requests attestation itself on the resumed flow exactly as
     *   on a fresh one (`Execute()` runs its attestation setup before
     *   branching on `msg.AuthCode`) - see [startIssuance]'s note.
     */
    fun resumeIssuance(
        offer: String? = null,
        credentialOfferUri: String? = null,
        redirectUri: String,
        authCode: String,
        codeVerifier: String?,
        clientAttestation: String? = null,
        clientAttestationPoP: String? = null,
    ) {
        send(FlowStartMessage.serializer(), FlowStartMessage(
            protocol = "oid4vci",
            offer = offer,
            credentialOfferUri = credentialOfferUri,
            redirectUri = redirectUri,
            authCode = authCode,
            codeVerifier = codeVerifier,
            clientAttestation = clientAttestation,
            clientAttestationPoP = clientAttestationPoP,
        ))
    }

    /**
     * Start a credential renewal flow (credential re-issuance/renewal plan,
     * Phase 1 Slice 2 - go-wallet-backend's `Execute` synthesizes a
     * single-config offer from [credentialIssuer]/[selectedCredentialConfigurationId]
     * rather than parsing a fresh one). [reissuanceKid], if provided, asks
     * the server to request the client sign the renewal's holder-binding
     * proof with that existing key instead of a fresh one - see
     * [FlowStartMessage.reissuanceKid].
     *
     * Debug/test-only entry point for now - no SDK-level API wraps this yet
     * (Phase 2, not built), and callers are responsible for having captured
     * [refreshToken] from a prior [FlowCompleteMessage.refreshToken]
     * themselves.
     */
    fun startRenewal(
        refreshToken: String,
        credentialIssuer: String,
        selectedCredentialConfigurationId: String,
        reissuanceKid: String? = null,
        dpopJwk: String? = null,
        dpopKeyId: String? = null,
    ) {
        send(FlowStartMessage.serializer(), FlowStartMessage(
            protocol = "oid4vci",
            refreshToken = refreshToken,
            credentialIssuer = credentialIssuer,
            selectedCredentialConfigurationId = selectedCredentialConfigurationId,
            reissuanceKid = reissuanceKid,
            dpopJwk = dpopJwk,
            dpopKeyId = dpopKeyId,
        ))
    }

    /**
     * Start an OID4VP credential presentation flow.
     *
     * @param features optional protocol features to declare (see
     *   [FlowStartMessage.features]); `null` declares nothing, which is what
     *   every caller did before `transaction_data` support existed.
     */
    fun startPresentation(
        requestUri: String? = null,
        requestUriRef: String? = null,
        features: List<String>? = null,
    ) {
        send(FlowStartMessage.serializer(), FlowStartMessage(
            protocol = "oid4vp",
            requestUri = requestUri,
            requestUriRef = requestUriRef,
            features = features,
        ))
    }

    /** Cancel an in-progress flow by sending a decline action. */
    fun cancelFlow(flowId: String) {
        sendFlowAction(flowId, "decline", kotlinx.serialization.json.buildJsonObject {
            put("reason", kotlinx.serialization.json.JsonPrimitive("user_cancelled"))
        })
    }

    /** Send a flow action (consent, select_credential, etc.). */
    fun sendFlowAction(flowId: String, action: String, payload: JsonObject? = null) {
        send(FlowActionMessage.serializer(), FlowActionMessage(
            flowId = flowId,
            action = action,
            payload = payload,
            timestamp = java.time.Instant.now().toString(),
        ))
    }

    /**
     * Send a signing response back to the server.
     *
     * @param credentialRequestExtras extra members for the credential
     *   request the backend will send - see
     *   [SignResponseMessage.credentialRequestExtras]. Null for every flow
     *   that does not need them.
     */
    fun sendSignResponse(
        flowId: String,
        proofJwt: String? = null,
        vpToken: String? = null,
        proofs: List<ProofObject>? = null,
        messageId: String? = null,
        credentialRequestExtras: kotlinx.serialization.json.JsonObject? = null,
        clientAttestation: String? = null,
        clientAttestationPoP: String? = null,
        dpopKeyId: String? = null,
        dpopProof: String? = null,
    ) {
        send(SignResponseMessage.serializer(), SignResponseMessage(
            flowId = flowId,
            messageId = messageId,
            proofJwt = proofJwt,
            vpToken = vpToken,
            proofs = proofs,
            credentialRequestExtras = credentialRequestExtras,
            clientAttestation = clientAttestation,
            clientAttestationPoP = clientAttestationPoP,
            dpopKeyId = dpopKeyId,
            dpopProof = dpopProof,
        ))
    }

    /**
     * Send a credential matching response back to the server.
     *
     * [noMatchReason] is the wallet's own account of why [matches] is empty.
     * [MatchResponseMessage] has always declared the field and nothing ever
     * populated it, so the reason never left the device.
     */
    fun sendMatchResponse(
        flowId: String,
        matches: List<CredentialMatch>,
        noMatchReason: String? = null,
    ) {
        send(MatchResponseMessage.serializer(), MatchResponseMessage(
            flowId = flowId,
            matches = matches,
            noMatchReason = noMatchReason,
        ))
    }

    /**
     * Report the outcome of this wallet's own DCQL matching for a
     * presentation the engine asked it to answer (go-wallet-backend#336).
     *
     * An empty [matches] ends the flow immediately with
     * `NO_MATCHING_CREDENTIAL`, naming the credential types the query asked
     * for. That is the answer a wallet holding nothing the verifier wants
     * never had: `decline` reports `access_denied` / "User declined the
     * request" to the verifier though the user was never asked, and saying
     * nothing stalls the flow until the engine's five-minute
     * user-interaction timeout - which is what a wallet missing the PID an
     * issuer demands used to hit.
     *
     * A non-empty [matches] is informational: the engine goes on waiting for
     * `consent`/`decline` exactly as before, so sending this before the
     * consent UI has an answer changes nothing for that case.
     */
    fun sendCredentialsMatched(
        flowId: String,
        matches: List<CredentialMatch>,
        noMatchReason: String? = null,
    ) {
        val payload = kotlinx.serialization.json.buildJsonObject {
            put("matches", json.encodeToJsonElement(
                kotlinx.serialization.builtins.ListSerializer(CredentialMatch.serializer()),
                matches,
            ))
            noMatchReason?.let { put("no_match_reason", kotlinx.serialization.json.JsonPrimitive(it)) }
        }
        sendFlowAction(flowId = flowId, action = "credentials_matched", payload = payload)
    }

    /** Send a trust evaluation result back to the server. */
    fun sendTrustResult(flowId: String, trusted: Boolean, reason: String? = null) {
        val payload = kotlinx.serialization.json.buildJsonObject {
            put("trusted", kotlinx.serialization.json.JsonPrimitive(trusted))
            reason?.let { put("reason", kotlinx.serialization.json.JsonPrimitive(it)) }
        }
        sendFlowAction(
            flowId = flowId,
            action = "trust_result",
            payload = payload,
        )
    }

    /**
     * Send an OID4VCI §10 credential lifecycle notification to the backend,
     * which forwards it to the issuer's notification_endpoint using the
     * ephemeral issuance token. The client supplies the notification_id it
     * received at issuance.
     *
     * This is a no-op when the session is not connected: the notification is
     * triggered automatically after a credential is stored, which may race with
     * a concurrent disconnect (e.g. logout). Dropping it in that case is safe
     * because §10 notifications are optional and best-effort.
     */
    override fun sendCredentialNotification(
        flowId: String,
        notificationId: String,
        event: String,
        eventDescription: String?,
    ) {
        if (!isConnected) return
        // Best effort: a notification the socket refuses must not interrupt the credential processing that sent it.
        try {
            send(CredentialNotificationMessage.serializer(), CredentialNotificationMessage(
                flowId = flowId,
                notificationId = notificationId,
                event = event,
                eventDescription = eventDescription,
                timestamp = java.time.Instant.now().toString(),
            ))
        } catch (e: IllegalStateException) {
            Timber.w("Credential notification not sent (${e.message})")
        }
    }

    /**
     * Suspend until the engine WebSocket handshake completes or fails.
     * Call this after [connect] to ensure the session is ready before sending messages.
     */
    suspend fun awaitConnected(timeoutMs: Long = 10_000) {
        withTimeout(timeoutMs) {
            state.first { it == State.CONNECTED || it == State.FAILED || it == State.REAUTH_REQUIRED }
        }
        when (_state.value) {
            State.REAUTH_REQUIRED -> throw AuthException(
                "Session expired and could not be refreshed - user must log in again",
                errorCode = "reauth_required",
            )
            State.FAILED -> throw IllegalStateException("Engine WebSocket connection failed")
            else -> {}
        }
    }

    /**
     * Force a fresh WebSocket connection, without waiting for OkHttp to notice the
     * current one is dead.
     *
     * Unlike [disconnect], this does NOT close the flow/message channels or cancel
     * [scope] - existing flowProgress()/flowErrors()/etc. collectors keep working
     * across the reconnect, exactly like the automatic onFailure->scheduleReconnect
     * path already does.
     *
     * Needed because a WebSocket can end up in a "zombie" state where OkHttp's
     * onClosing/onFailure callbacks never fire (the OS can silently stop delivering
     * data to a backgrounded app's socket without a clean close - e.g. while an
     * external OAuth browser has foreground focus for a login redirect), so the
     * automatic reconnect logic never kicks in even though nothing sent over the
     * socket actually reaches the server anymore. Call this before anything
     * time-sensitive right after the app regains foreground from such a background
     * gap, rather than trusting the existing connection is still good.
     */
    suspend fun forceReconnect() {
        if (lastAppToken == null) {
            Timber.w("Engine WebSocket: forced reconnect skipped (no session to reconnect)")
            return
        }
        Timber.i("Engine WebSocket: forced reconnect (was ${_state.value}); the old socket is dropped, it may be a zombie after the browser gap")
        val request = reconnectRequests.incrementAndGet()
        // The pending backoff attempt is NOT cancelled yet: this caller may be cancelled while the token refresh is suspended, and
        // recovery is the session's, not the caller's. The attempt is replaced below, atomically with installing the new socket.
        val token = refreshTokenOrSignalReauth(request)
        // A newer forceReconnect began while this one was refreshing its token
        // (the caller moved on - e.g. a cancelled start that was retried). It
        // owns the socket now; replacing it again would close the newer
        // caller's connection and drop its replies.
        if (reconnectRequests.get() != request) return
        synchronized(connLock) {
            if (reconnectRequests.get() != request) return
            // Clear the (possibly zombie) socket unconditionally, even if refresh was rejected below - otherwise isConnected
            // stays true and send() would keep appearing usable on a session that's actually no longer valid. The old socket is
            // superseded BEFORE it is cancelled, so the failure its cancel() raises is recognised as stale.
            liveGeneration.set(NO_LIVE_SOCKET)
            pendingReconnect?.cancel()
            pendingReconnect = null
            webSocket?.cancel() // ungraceful - the connection may already be dead
            webSocket = null
            sessionId = null
            rawMessageChannel.trySend(RawFrame(0, null))
            if (token == null) return // refreshTokenOrSignalReauth already set State.REAUTH_REQUIRED
            _state.value = State.CONNECTING
            reconnectAttempts = 0
            doConnect(token)
        }
        Timber.i("Engine WebSocket: new connection requested")
    }

    /**
     * Drop flow traffic the replaced connection delivered that no collector has
     * consumed yet. Server-side flow state died with that socket, so such a
     * reply is stale; left queued it would reach whatever flow the caller
     * starts next. Runs in the single reader, at the point in the frame order
     * where [forceReconnect] queued its marker: every earlier frame has been
     * processed (so a `trust_evaluated` report still reaches its
     * `flow_complete`, and a credential-bearing `flow_complete`, push and
     * notification ack are all kept) and no later frame has. Best effort: a
     * message a collector already took cannot be recalled.
     */
    private fun purgeStaleFlowTraffic() {
        while (flowProgressChannel.tryReceive().isSuccess) { /* drop */ }
        while (flowErrorChannel.tryReceive().isSuccess) { /* drop */ }
        while (signRequestChannel.tryReceive().isSuccess) { /* drop */ }
        while (matchRequestChannel.tryReceive().isSuccess) { /* drop */ }
    }

    /** Disconnect the WebSocket session. */
    fun disconnect() {
        lastAppToken = null  // prevent reconnection
        tokenProvider = null
        onAuthRejected = null
        synchronized(connLock) {
            liveGeneration.set(NO_LIVE_SOCKET)
            pendingReconnect?.cancel()
            pendingReconnect = null
            webSocket?.close(1000, "client disconnect")
            webSocket = null
        }
        sessionId = null
        _state.value = State.DISCONNECTED
        // Close all channels to release consumers
        incomingMessages.close()
        flowProgressChannel.close()
        flowCompleteChannel.close()
        flowErrorChannel.close()
        signRequestChannel.close()
        matchRequestChannel.close()
        pushChannel.close()
        notificationAckChannel.close()
        scope.cancel()
    }

    private fun <T> send(serializer: kotlinx.serialization.KSerializer<T>, message: T) {
        val ws = webSocket ?: throw IllegalStateException("Not connected")
        val text = json.encodeToString(serializer, message)
        // A frame the socket refuses (closed or cancelled) must not vanish: the flow would wait for a reply forever.
        if (!ws.send(text)) throw IllegalStateException("Not connected (the engine socket refused the message)")
    }

    companion object {
        private const val NO_LIVE_SOCKET = -1

        /**
         * Used until (and unless) the server tells us otherwise via
         * [HandshakeCompleteMessage.config] - see [pingIntervalMs]'s doc
         * comment. 3s, not the 30s this used to be hardcoded to: found
         * empirically (raw idle-TLS-connection tests against production
         * Fly.io apps, not documentation - Fly's own docs don't state a
         * number) that Fly.io's edge closes a connection with no traffic on
         * it after ~5-6s, which is why every engine WebSocket in production
         * was silently reconnecting every few seconds. Matches
         * go-wallet-backend's own default (config.ServerConfig.EngineWSPingInterval).
         */
        const val DEFAULT_PING_INTERVAL_MS = 3000L

        /**
         * Floor of the client's own liveness ping (OkHttp fails the socket when a pong does not arrive within one interval, so
         * this is also the pong wait). The engine pings every 3 s itself, which keeps Fly's edge from dropping the idle
         * connection and which OkHttp answers automatically; the client's ping is only a dead-peer detector, and 3 s was so tight
         * that a flaky mobile network, or a socket the engine closed as superseded, produced a 1-2 s reconnect loop.
         */
        private const val MIN_LIVENESS_INTERVAL_MS = 10_000L

        internal fun livenessIntervalMs(configured: Long): Long = maxOf(configured, MIN_LIVENESS_INTERVAL_MS)

        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .pingInterval(DEFAULT_PING_INTERVAL_MS, TimeUnit.MILLISECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .build()
    }
}
