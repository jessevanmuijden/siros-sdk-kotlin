// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.auth

import org.siros.sdk.credentials.BackendApiException
import org.siros.sdk.credentials.NetworkException
import org.siros.sdk.credentials.CertificationInfo
import org.siros.sdk.credentials.SignerSecurityProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import timber.log.Timber


private val JSON_MEDIA_TYPE = "application/json".toMediaType()

/**
 * Authenticated HTTP client for the wallet backend REST API.
 *
 * Supports two auth modes:
 * 1. Legacy: set a static `appToken` via [setAppToken].
 * 2. New AS: provide an [AuthTokens] instance via [setAuthTokens] — tokens
 *    are automatically requested/refreshed per request, and 401 rejections
 *    trigger automatic retry with a fresh token.
 */
class BackendApiClient(
    private val baseUrl: String,
    private val tenantId: String = "default",
    private val httpClient: OkHttpClient = OkHttpClient(),
    private val json: Json = Json { ignoreUnknownKeys = true },
) {
    /**
     * Waits between the attempts of a `409 ERASURE_INCOMPLETE` retry (see
     * [revokeAllWalletInstances]). One more attempt is made than there are
     * entries here, so the default is five attempts over about 15 s - long
     * enough for a transient backend failure to clear, short enough that the
     * OS will not suspend the app mid-loop.
     *
     * Deliberately a property rather than a constructor parameter: adding one
     * would change this class's JVM constructor signature and break already
     * compiled consumers, for something only the tests (which lower it to
     * zeros) ever set.
     */
    internal var erasureRetryDelaysMs: List<Long> = listOf(1_000, 2_000, 4_000, 8_000)

    private var appToken: String? = null
    private var authTokens: AuthTokens? = null

    fun setAppToken(token: String) {
        Timber.d("setAppToken: token set")
        appToken = token
    }

    /**
     * Configure this client to use [AuthTokens] for automatic token management.
     * When set, [setAppToken] is ignored and tokens are obtained from the AS.
     */
    fun setAuthTokens(tokens: AuthTokens) {
        authTokens = tokens
    }

    /** GET /user/session/account-info */
    suspend fun getAccountInfo(): JsonObject = get("/user/session/account-info")

    /** GET /storage/vc — list all credentials */
    suspend fun getCredentials(): JsonObject = get("/storage/vc")

    /** POST /storage/vc — store a credential */
    suspend fun storeCredential(credential: JsonObject): JsonObject =
        post("/storage/vc", credential)

    /** GET /storage/vc/:id */
    suspend fun getCredential(id: String): JsonObject = get("/storage/vc/$id")

    /** DELETE /storage/vc/:id */
    suspend fun deleteCredential(id: String): JsonObject = delete("/storage/vc/$id")

    /** GET /issuer/all — list registered issuers */
    suspend fun getIssuers(): JsonElement = getElement("/issuer/all")

    /** GET /issuer/:id/metadata — get cached issuer metadata via the backend proxy */
    suspend fun getIssuerMetadata(id: Long): JsonObject = get("/issuer/$id/metadata")

    /** GET /verifier/all — list registered verifiers */
    suspend fun getVerifiers(): JsonObject = get("/verifier/all")

    /** GET /user/session/private-data */
    suspend fun getPrivateData(): JsonObject = get("/user/session/private-data")

    /** POST /user/session/private-data */
    suspend fun updatePrivateData(data: JsonObject): JsonObject =
        post("/user/session/private-data", data)

    /** GET /health */
    suspend fun healthCheck(): JsonObject = get("/health")

    /** GET /api/v1/tenants/:id/config */
    suspend fun getTenantConfig(): JsonObject = get("/api/v1/tenants/$tenantId/config")

    /** POST /v1/evaluate — AuthZEN trust evaluation via backend proxy */
    suspend fun evaluateTrust(requestBody: JsonObject): JsonObject =
        post("/v1/evaluate", requestBody)

    /**
     * POST /v1/resolve — resolve credential issuer metadata through the backend.
     *
     * Unlike fetching the well-known document directly, this returns metadata
     * the backend has already authenticated: it verifies the signed_metadata
     * JWS, evaluates the signer against the trust registry, and (per ARF
     * section 6.6.2.3) reports whether the provider is registered to issue the
     * requested credential types.
     *
     * [credentialTypes] are credential configuration ids from the offer. They
     * are what lets the backend answer "may this provider issue *this*", rather
     * than only "is this provider trusted at all".
     */
    suspend fun resolveIssuer(issuerUrl: String, credentialTypes: List<String> = emptyList()): JsonObject {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("subject_id", kotlinx.serialization.json.JsonPrimitive(issuerUrl))
            put("subject_type", kotlinx.serialization.json.JsonPrimitive("url"))
            put("resource_type", kotlinx.serialization.json.JsonPrimitive("credential_issuer"))
            if (credentialTypes.isNotEmpty()) {
                put(
                    "credential_types",
                    kotlinx.serialization.json.JsonArray(
                        credentialTypes.map { kotlinx.serialization.json.JsonPrimitive(it) },
                    ),
                )
            }
        }
        return post("/v1/resolve", body)
    }

    /**
     * POST /v1/resolve — resolve a "key" subject (a `did:` identifier) to
     * its verification key material, proxied by the backend directly to
     * the PDP (see go-wallet-backend's `AuthZENProxyHandler.Resolve`).
     *
     * Distinct from [resolveIssuer], which always sends
     * `subject_type: "url"` for OpenID4VCI issuer metadata resolution -
     * this is the counterpart for a DID-scheme verifier's
     * `TrustEvaluationRequest.requires_resolution`
     * (go-wallet-backend#396/#401): when the engine cannot resolve the DID
     * itself (no verifier PDP configured), it defers to the frontend/SDK,
     * which must call this before `evaluateTrust`.
     *
     * The response's `context.trust_metadata` is the resolved DID
     * Document - the caller is responsible for extracting a
     * `verificationMethod` entry's `publicKeyJwk` and verifying the
     * accompanying `request_jwt` against it (see
     * [org.siros.sdk.wallet.SirosWallet]'s `resolveDidKeyMaterial`).
     */
    suspend fun resolveKey(subjectId: String): JsonObject {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("subject_id", kotlinx.serialization.json.JsonPrimitive(subjectId))
            put("subject_type", kotlinx.serialization.json.JsonPrimitive("key"))
        }
        return post("/v1/resolve", body)
    }

    /** POST /user/session/refresh — refresh appToken using refreshToken */
    suspend fun refreshSession(refreshToken: String): JsonObject = withContext(Dispatchers.IO) {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("refreshToken", kotlinx.serialization.json.JsonPrimitive(refreshToken))
        }
        val builder = Request.Builder()
            .url("$baseUrl/user/session/refresh")
            .post(body.toString().toRequestBody(JSON_MEDIA_TYPE))
        addCommonHeaders(builder)
        execute(builder.build())
    }

    // ── Wallet Provider endpoints ───────────────────────────────────

    /**
     * POST /wallet-provider/key-attestation/generate — request a key attestation JWT.
     * @param jwks list of JWK objects for the keys to attest
     * @param nonce OpenID4VCI nonce from the issuer
     * @param securityProperties optional WSCD security properties for KA claims (CS-04 §7.1.3)
     * @param walletInstanceId optional WIA JWK Thumbprint (`cnf.jkt`) identifying this wallet
     *   instance, sent as `wallet_instance_id` - lets the backend's KA trust gate look up this
     *   instance's recorded `attestation_source` and lift its `security_properties` clamp when
     *   it's genuinely native-attested. Omitted when null/blank.
     * @return key attestation JWT string
     */
    suspend fun requestKeyAttestation(
        jwks: List<JsonObject>,
        nonce: String,
        securityProperties: SignerSecurityProperties? = null,
        credentialIssuer: String? = null,
        walletInstanceId: String? = null,
    ): String {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("jwks", kotlinx.serialization.json.JsonArray(jwks))
            put("openid4vci", kotlinx.serialization.json.buildJsonObject {
                put("nonce", kotlinx.serialization.json.JsonPrimitive(nonce))
                // Binds the KA's `aud` claim to the target issuer, preventing
                // a KA minted for one issuer from being replayed against
                // another - omitted (server leaves `aud` unset) when unknown.
                if (!credentialIssuer.isNullOrBlank()) {
                    put("credential_issuer", kotlinx.serialization.json.JsonPrimitive(credentialIssuer))
                }
            })
            // The WIA's JWK-thumbprint identity (`cnf.jkt`) - lets the backend's
            // KA trust gate look up this wallet instance's own recorded
            // attestation_source and lift the K3 clamp when it's genuinely
            // native-attested. Omitted whenever the caller has no such WIA.
            if (!walletInstanceId.isNullOrBlank()) {
                put("wallet_instance_id", kotlinx.serialization.json.JsonPrimitive(walletInstanceId))
            }
            if (securityProperties != null) {
                put("security_properties", kotlinx.serialization.json.buildJsonObject {
                    put("key_storage", kotlinx.serialization.json.JsonArray(
                        securityProperties.keyStorage.map { kotlinx.serialization.json.JsonPrimitive(it) }
                    ))
                    put("user_authentication", kotlinx.serialization.json.JsonArray(
                        securityProperties.userAuthentication.map { kotlinx.serialization.json.JsonPrimitive(it) }
                    ))
                    when (val cert = securityProperties.certification) {
                        is CertificationInfo.None ->
                            put("certification", kotlinx.serialization.json.JsonPrimitive("none"))
                        is CertificationInfo.Certified ->
                            put("certification", kotlinx.serialization.json.buildJsonObject {
                                put("scheme", kotlinx.serialization.json.JsonPrimitive(cert.scheme))
                                put("assurance_level", kotlinx.serialization.json.JsonPrimitive(cert.assuranceLevel))
                            })
                    }
                })
            }
        }
        val result = post("/wallet-provider/key-attestation/generate", body)
        return result["key_attestation"]?.let {
            (it as? kotlinx.serialization.json.JsonPrimitive)?.content
        } ?: throw BackendApiException(0, "Missing key_attestation in response", "")
    }

    /** POST /wallet-provider/wia/challenge — request a WIA challenge nonce. */
    suspend fun requestWIAChallenge(): JsonObject =
        post("/wallet-provider/wia/challenge", JsonObject(emptyMap()))

    /**
     * POST /wallet-provider/wia/generate — generate a Wallet Instance Attestation.
     * @param pop WIA-PoP JWT (typ: oauth-client-attestation-pop+jwt)
     * @param challenge the challenge nonce from requestWIAChallenge()
     * @param clientId this wallet's OAuth client_id (e.g. its redirect_uri, per
     *   OID4VCI's unregistered-client convention) - embedded as the WIA JWT's
     *   `sub` claim. draft-ietf-oauth-attestation-based-client-auth-10 requires
     *   "the sub claim MUST specify client_id value of the OAuth Client";
     *   omitting this falls back to the instance identifier (jkt) server-side.
     * @param nativeAttestation optional platform attestation evidence
     * @param credentialId base64url WebAuthn credential id of the passkey this
     *   installation logs in with. The backend records it on the wallet
     *   instance so that suspending or revoking the instance also refuses
     *   login with that passkey (SID-AUTH-06, go-wallet-backend#319). Optional;
     *   older backends ignore it.
     * @return WIA JWT string
     */
    suspend fun generateWIA(
        pop: String,
        challenge: String,
        clientId: String? = null,
        nativeAttestation: JsonObject? = null,
        credentialId: String? = null,
    ): String {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("pop", kotlinx.serialization.json.JsonPrimitive(pop))
            put("challenge", kotlinx.serialization.json.JsonPrimitive(challenge))
            if (!clientId.isNullOrBlank()) {
                put("client_id", kotlinx.serialization.json.JsonPrimitive(clientId))
            }
            if (nativeAttestation != null) {
                put("native_attestation", nativeAttestation)
            }
            if (!credentialId.isNullOrBlank()) {
                put("credential_id", kotlinx.serialization.json.JsonPrimitive(credentialId))
            }
        }
        val result = post("/wallet-provider/wia/generate", body)
        return result["wallet_instance_attestation"]?.let {
            (it as? kotlinx.serialization.json.JsonPrimitive)?.content
        } ?: throw BackendApiException(0, "Missing wallet_instance_attestation in response", "")
    }

    // ---- Wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#319) ----

    /** GET /user/session/instances — this user's wallet instances in the current tenant. */
    suspend fun listWalletInstances(): List<WalletInstance> {
        val result = get("/user/session/instances")
        // The backend always sends the array (empty when the user has no
        // instances); its absence is a malformed response, not "no instances".
        val arr = result["instances"] as? kotlinx.serialization.json.JsonArray
            ?: throw BackendApiException(0, "Missing instances in response", "")
        return arr.map { json.decodeFromJsonElement(WalletInstance.serializer(), it) }
    }

    /**
     * PUT /user/session/instances/{id}/status — suspend, reactivate or revoke
     * one of this user's instances. Throws [BackendApiException] with code 404
     * for an instance that is not the caller's and 409 for an invalid
     * transition (e.g. reactivating a revoked instance).
     *
     * Revoking the caller's last instance deactivates the wallet, so this
     * request runs the same erasure cascade as [revokeAllWalletInstances] and
     * can answer `409 ERASURE_INCOMPLETE`; it is retried here on the same
     * budget. If the erasure is still unfinished when the budget runs out the
     * recorded status is returned anyway (it stands - only the cascade is
     * unfinished) and the residual is logged for an administrator.
     */
    suspend fun setWalletInstanceStatus(
        instanceId: String,
        status: WalletInstanceStatus,
        reason: String? = null,
    ): WalletInstance {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("status", kotlinx.serialization.json.JsonPrimitive(status.wire))
            if (!reason.isNullOrBlank()) put("reason", kotlinx.serialization.json.JsonPrimitive(reason))
        }
        val attempted = retryWhileErasureIncomplete("setWalletInstanceStatus($instanceId, ${status.wire})") {
            decodeInstance(put("/user/session/instances/$instanceId/status", body), instanceId)
        }
        // A 409 that outlived the retries, or a 401 that dropped the acting
        // token with the erased key material, both leave the recorded status
        // standing - report it rather than failing a change that took effect.
        return attempted.value ?: WalletInstance(id = instanceId, status = status.wire)
    }

    /**
     * Deprecated string form of [setWalletInstanceStatus]. Kept for one
     * release so callers built against SDK 0.16 keep compiling; an unknown
     * status is rejected locally instead of being sent to the backend.
     */
    @Deprecated(
        "Use the WalletInstanceStatus overload",
        ReplaceWith("setWalletInstanceStatus(instanceId, requireNotNull(WalletInstanceStatus.fromWire(status)), reason)"),
    )
    suspend fun setWalletInstanceStatus(instanceId: String, status: String, reason: String? = null): WalletInstance =
        setWalletInstanceStatus(
            instanceId,
            WalletInstanceStatus.fromWire(status)
                ?: throw IllegalArgumentException("Unknown wallet instance status: $status"),
            reason,
        )

    private fun decodeInstance(result: JsonObject, instanceId: String): WalletInstance =
        // Today the backend answers {id, status}; decode the whole object when
        // it sends more, so callers see every field it returns.
        runCatching { json.decodeFromJsonElement(WalletInstance.serializer(), result) }.getOrElse {
            WalletInstance(
                id = (result["id"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: instanceId,
                status = (result["status"] as? kotlinx.serialization.json.JsonPrimitive)?.content
                    ?: throw BackendApiException(0, "Missing status in response", ""),
            )
        }

    /**
     * POST /user/session/instances/revoke-all — deactivate the wallet: every
     * instance revoked, wallet data erased server-side, new enrollment required.
     *
     * The backend records the revocations before it erases, so it can answer
     * `409 ERASURE_INCOMPLETE`; repeating the identical request re-runs the
     * erasure. This does that on the documented budget (five attempts, 1 s →
     * 8 s) and reports what happened in [DeactivationOutcome.complete]. A
     * `401` after such a `409` means the acting token was dropped together
     * with the erased key material, which is the erasure having succeeded -
     * it counts as complete.
     */
    suspend fun revokeAllWalletInstances(reason: String? = null): DeactivationOutcome {
        val body = kotlinx.serialization.json.buildJsonObject {
            if (!reason.isNullOrBlank()) put("reason", kotlinx.serialization.json.JsonPrimitive(reason))
        }
        // The first attempt reports how many instances it revoked; a repeat
        // answers 0 because there is nothing left to revoke. Keep the largest
        // count seen (the 409 body carries it too) so the caller can tell the
        // user what actually happened.
        var revoked = 0
        val attempted = retryWhileErasureIncomplete(
            "revokeAllWalletInstances",
            onIncomplete = { e -> revoked = maxOf(revoked, revokedCount(e.body) ?: 0) },
        ) {
            val result = post("/user/session/instances/revoke-all", body)
            (result["revoked"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toIntOrNull()
                ?: throw BackendApiException(0, "Missing revoked count in response", "")
        }
        return DeactivationOutcome(
            revoked = maxOf(revoked, attempted.value ?: 0),
            complete = attempted.complete,
        )
    }

    private fun revokedCount(body: String?): Int? = runCatching {
        (json.parseToJsonElement(body ?: return null).jsonObject["revoked"] as? kotlinx.serialization.json.JsonPrimitive)
            ?.content?.toIntOrNull()
    }.getOrNull()

    private class Attempted<T>(val value: T?, val complete: Boolean)

    /**
     * Run [request], repeating it while the backend answers `409
     * ERASURE_INCOMPLETE` (SID-AUTH-06): the status change is already
     * recorded, only the erasure cascade needs re-running, and the protocol
     * says to repeat the identical request until it answers `200`.
     *
     * Ends with `complete = false` when the budget runs out, and with
     * `complete = true, value = null` on a `401` that follows such a `409` -
     * that is the acting token being dropped along with the erased key
     * material, i.e. the erasure got far enough that the wallet is gone. A
     * `401` on the very first attempt is an ordinary authentication failure
     * and is rethrown.
     */
    private suspend fun <T> retryWhileErasureIncomplete(
        what: String,
        onIncomplete: (BackendApiException) -> Unit = {},
        request: suspend () -> T,
    ): Attempted<T> {
        val attempts = erasureRetryDelaysMs.size + 1
        var lastIncomplete: BackendApiException? = null
        for (attempt in 0 until attempts) {
            if (attempt > 0) delay(erasureRetryDelaysMs[attempt - 1])
            try {
                return Attempted(request(), complete = true)
            } catch (e: BackendApiException) {
                when {
                    e.code == 409 && e.apiErrorCode() == ERROR_ERASURE_INCOMPLETE -> {
                        lastIncomplete = e
                        onIncomplete(e)
                        Timber.w("$what: ERASURE_INCOMPLETE (attempt ${attempt + 1}/$attempts) — repeating the request")
                    }
                    e.code == 401 && lastIncomplete != null -> {
                        Timber.i("$what: acting token dropped with the erased key material — erasure complete")
                        return Attempted(null, complete = true)
                    }
                    else -> throw e
                }
            }
        }
        Timber.e(
            "$what: still ERASURE_INCOMPLETE after $attempts attempts — the status change stands, " +
                "residual data must be cleaned up by an administrator: ${lastIncomplete?.body}"
        )
        return Attempted(null, complete = false)
    }

    /**
     * POST /wallet-provider/fido2-attestation/register — register a FIDO2/CTAP2
     * hardware-key attestation once, at key-creation time, so the backend can
     * durably mark the wallet instance as hardware-key-attested (see
     * `FIDO2AttestationService` in go-wallet-backend). Throws [BackendApiException]
     * if the backend rejects the attestation (e.g. untrusted AAGUID/chain) or the
     * feature isn't enabled.
     *
     * @param walletInstanceId the WIA JWK Thumbprint (`cnf.jkt`) this key belongs to
     * @param attestationObject the raw CTAP2 makeCredential attestation object
     *   (siros-wscd-manager's `AttestationChain.certificates[0]`)
     * @param clientDataHash the 32-byte hash the attestation signature was computed
     *   over (`AttestationChain.clientDataHash`)
     */
    suspend fun registerFido2Attestation(
        walletInstanceId: String,
        attestationObject: ByteArray,
        clientDataHash: ByteArray,
    ) {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("wallet_instance_id", kotlinx.serialization.json.JsonPrimitive(walletInstanceId))
            put(
                "attestation_object",
                kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(attestationObject)),
            )
            put(
                "client_data_hash",
                kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(clientDataHash)),
            )
        }
        post("/wallet-provider/fido2-attestation/register", body)
    }

    // ── HTTP primitives ─────────────────────────────────────────────

    private suspend fun get(path: String): JsonObject = withContext(Dispatchers.IO) {
        val builder = Request.Builder()
            .url("$baseUrl$path")
            .get()
        addCommonHeaders(builder)
        execute(builder.build())
    }

    private suspend fun getElement(path: String): JsonElement = withContext(Dispatchers.IO) {
        val builder = Request.Builder()
            .url("$baseUrl$path")
            .get()
        addCommonHeaders(builder)
        executeRaw(builder.build())
    }

    private suspend fun post(path: String, body: JsonObject): JsonObject = withContext(Dispatchers.IO) {
        val builder = Request.Builder()
            .url("$baseUrl$path")
            .post(body.toString().toRequestBody(JSON_MEDIA_TYPE))
        addCommonHeaders(builder)
        execute(builder.build())
    }

    private suspend fun put(path: String, body: JsonObject): JsonObject = withContext(Dispatchers.IO) {
        val builder = Request.Builder()
            .url("$baseUrl$path")
            .put(body.toString().toRequestBody(JSON_MEDIA_TYPE))
        addCommonHeaders(builder)
        execute(builder.build())
    }

    private suspend fun delete(path: String): JsonObject = withContext(Dispatchers.IO) {
        val builder = Request.Builder()
            .url("$baseUrl$path")
            .delete()
        addCommonHeaders(builder)
        execute(builder.build())
    }

    private suspend fun addCommonHeaders(builder: Request.Builder) {
        builder.header("X-Tenant-ID", tenantId)
        val tokens = authTokens
        if (tokens != null) {
            val token = tokens.ensureBackendToken()
            builder.header("Authorization", "Bearer ${token.raw}")
        } else if (appToken != null) {
            builder.header("Authorization", "Bearer $appToken")
        } else {
            Timber.w("addCommonHeaders: no token source — request will be unauthenticated!")
        }
    }

    private fun execute(request: Request): JsonObject {
        return executeRaw(request).jsonObject
    }

    private fun executeRaw(request: Request): JsonElement {
        val response = try {
            httpClient.newCall(request).execute()
        } catch (e: java.io.IOException) {
            throw NetworkException("Network error: ${request.url}", e)
        }
        val responseBody = response.body?.string() ?: "{}"

        if (!response.isSuccessful) {
            Timber.e("API request failed: ${request.method} ${request.url} -> ${response.code}")
            if (response.code == 401) {
                // Every request in this class authenticates via the backend
                // token (see addCommonHeaders/ensureBackendToken) - feed a 401
                // into AuthTokens' rejection counter so REJECTION_THRESHOLD
                // rejections within REJECTION_WINDOW_MS actually trigger
                // onSessionRejected/logout, instead of silently doing nothing
                // (registerTokenRejection was previously dead code - nothing
                // called it despite AuthTokens already tracking rejections).
                authTokens?.registerTokenRejection(AuthTokens.TOKEN_BACKEND)
            }
            throw BackendApiException(
                code = response.code,
                message = "API request failed: ${response.code}",
                body = responseBody,
            )
        }

        return if (responseBody.isBlank()) {
            JsonObject(emptyMap())
        } else {
            json.parseToJsonElement(responseBody)
        }
    }
}
