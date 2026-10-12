package org.siros.sdk.auth

import org.siros.sdk.credentials.AuthException
import org.siros.sdk.credentials.NetworkException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import timber.log.Timber

/**
 * Handles WebAuthn registration/login flows against the wallet backend REST API.
 * Coordinates between the backend challenge endpoints and the [AuthProvider] for
 * credential creation/assertion.
 */
class WebAuthnAuthClient(
    baseUrl: String,
    private val tenantId: String = "default",
    private val authProvider: AuthProvider,
    private val httpClient: OkHttpClient = OkHttpClient(),
    private val json: Json = Json { ignoreUnknownKeys = true },
) {
    private val baseUrl = baseUrl.trimEnd('/')

    /**
     * The `rpId` from the most recent [register]/[login] challenge. Lets a
     * caller (e.g. [org.siros.sdk.wallet.SirosWallet]'s legacy register/login
     * paths) make a follow-up [AuthProvider.getPrfOutput] call against the
     * right RP without this client needing to expose its own internals.
     */
    var lastRpId: String? = null
        private set

    /** Register a new user with WebAuthn. Returns an authenticated session. */
    suspend fun register(displayName: String, prfSalt: ByteArray? = null): AuthSession = withContext(Dispatchers.IO) {
        // Step 1: Get registration challenge from backend
        val challengeResponse = post(
            "/user/register-webauthn-begin",
            buildJsonObject { put("displayName", displayName) },
        )

        // Decode tagged binary objects ({"$b64u": "..."} → plain strings) in the response
        val options = TaggedBinary.decode(challengeResponse).jsonObject
        val challengeId = options["challengeId"]?.jsonPrimitive?.content
        val publicKey = (options["getOptions"] ?: options["createOptions"])?.jsonObject
            ?.get("publicKey")?.jsonObject
            ?: options["publicKey"]?.jsonObject
            ?: throw AuthException("Missing publicKey in registration challenge")

        val rpId = publicKey["rp"]?.jsonObject?.get("id")?.jsonPrimitive?.content
            ?: throw AuthException("Missing rp.id")
        lastRpId = rpId
        val rpName = publicKey["rp"]?.jsonObject?.get("name")?.jsonPrimitive?.content ?: rpId
        val challenge = decodeBase64Url(publicKey["challenge"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing challenge"))
        val user = publicKey["user"]?.jsonObject ?: throw AuthException("Missing user")
        val userId = decodeBase64Url(user["id"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing user.id"))
        val userName = user["name"]?.jsonPrimitive?.content ?: displayName

        // Step 2: Create credential via AuthProvider
        val result = authProvider.register(
            RegisterOptions(
                rpId = rpId,
                rpName = rpName,
                userId = userId,
                userName = userName,
                userDisplayName = displayName,
                challenge = challenge,
                prfSalt = prfSalt,
            )
        )

        // Step 3: Complete registration with backend
        val credential = buildJsonObject {
            put("id", encodeBase64Url(result.credentialId))
            put("rawId", encodeBase64Url(result.credentialId))
            put("type", "public-key")
            put("response", buildJsonObject {
                put("attestationObject", encodeBase64Url(result.attestationObject))
                put("clientDataJSON", encodeBase64Url(result.clientDataJSON))
            })
        }
        val finishBody = buildJsonObject {
            challengeId?.let { put("challengeId", it) }
            put("credential", credential)
            // The backend's FinishRegistrationRequest reads displayName from
            // THIS request, not from register-webauthn-begin's - it defaults
            // to the literal string "User" if absent (see go-wallet-backend's
            // WebAuthnService.FinishRegistration).
            put("displayName", displayName)
        }

        val sessionResponse = post("/user/register-webauthn-finish", finishBody)
        Timber.d("register finish response keys: ${sessionResponse.keys}")
        // privateData (per privatedata-spec §3.3) is tagged binary
        // ({"$b64u": "..."}), not a plain string - decode it to a plain
        // string first or AuthSession.privateData's deserialization throws.
        val session = json.decodeFromJsonElement(AuthSession.serializer(), TaggedBinary.decode(sessionResponse).jsonObject)
        Timber.d("register session: uuid=...${session.uuid.takeLast(4)}, tenantId=${session.tenantId}")
        session
    }

    /**
     * Authenticate an existing user with WebAuthn. Returns an authenticated session.
     *
     * @param prfSalt single shared PRF salt (legacy/single-account case).
     * @param prfSaltsByCredential per-credential PRF salts (credentialId to
     *   salt) for a discoverable-credential login where multiple accounts or
     *   passkeys are candidates - see [AuthenticateOptions.prfSaltsByCredential].
     *   Takes priority over [prfSalt] when non-empty.
     * @param onCredentialResolved invoked with the credential id the
     *   authenticator returned, as soon as the ceremony resolves and before
     *   the backend is asked. Lets a caller attribute a later refusal to the
     *   passkey that actually answered *this* attempt.
     */
    suspend fun login(
        prfSalt: ByteArray? = null,
        prfSaltsByCredential: List<Pair<ByteArray, ByteArray>>? = null,
        onCredentialResolved: ((ByteArray) -> Unit)? = null,
    ): AuthSession = withContext(Dispatchers.IO) {
        // Step 1: Get login challenge
        val challengeResponse = post("/user/login-webauthn-begin", buildJsonObject {})
        // Decode tagged binary objects
        val options = TaggedBinary.decode(challengeResponse).jsonObject
        val challengeId = options["challengeId"]?.jsonPrimitive?.content
        val publicKey = (options["getOptions"])?.jsonObject
            ?.get("publicKey")?.jsonObject
            ?: options["publicKey"]?.jsonObject
            ?: throw AuthException("Missing publicKey in login challenge")

        val rpId = publicKey["rpId"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing rpId")
        lastRpId = rpId
        val challenge = decodeBase64Url(publicKey["challenge"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing challenge"))

        // Step 2: Authenticate via AuthProvider
        val result = authProvider.authenticate(
            AuthenticateOptions(
                rpId = rpId,
                challenge = challenge,
                prfSalt = prfSalt,
                prfSaltsByCredential = prfSaltsByCredential,
            )
        )

        // Which passkey answered, reported before the backend is asked and so
        // before it can refuse. A caller that has to attribute a refusal to an
        // account cannot read it off this client afterwards: the provider's
        // last-credential field is shared, and a concurrent login would
        // overwrite it between this ceremony and its refusal.
        onCredentialResolved?.invoke(result.credentialId)

        // Step 3: Complete login with backend
        val credential = buildJsonObject {
            put("id", encodeBase64Url(result.credentialId))
            put("rawId", encodeBase64Url(result.credentialId))
            put("type", "public-key")
            put("response", buildJsonObject {
                put("authenticatorData", encodeBase64Url(result.authenticatorData))
                put("clientDataJSON", encodeBase64Url(result.clientDataJSON))
                put("signature", encodeBase64Url(result.signature))
                result.userHandle?.let { put("userHandle", encodeBase64Url(it)) }
            })
        }
        val finishBody = buildJsonObject {
            challengeId?.let { put("challengeId", it) }
            put("credential", credential)
        }

        val sessionResponse = post("/user/login-webauthn-finish", finishBody)
        Timber.d("login finish response keys: ${sessionResponse.keys}")
        // privateData (per privatedata-spec §3.3) is tagged binary
        // ({"$b64u": "..."}), not a plain string - decode it to a plain
        // string first or AuthSession.privateData's deserialization throws.
        // Only actually non-empty once a credential has been synced, which
        // is why this wasn't hit before WscdKeystoreAdapter's persistence
        // fix made that sync actually succeed for WSCD-backed accounts.
        val session = json.decodeFromJsonElement(AuthSession.serializer(), TaggedBinary.decode(sessionResponse).jsonObject)
        Timber.d("login session: uuid=...${session.uuid.takeLast(4)}, tenantId=${session.tenantId}")
        session
    }

    private fun post(path: String, body: JsonObject): JsonObject {
        val url = "$baseUrl$path"
        Timber.d("Auth request: POST $url (tenant=$tenantId)")
        val request = Request.Builder()
            .url(url)
            .header("X-Tenant-ID", tenantId)
            .header("Content-Type", "application/json")
            .post(body.toString().toRequestBody("application/json".toMediaType()))
            .build()

        val response = httpClient.newCall(request).execute()
        val responseBody = response.body?.string()
            ?: throw AuthException("Empty response from $url")

        if (!response.isSuccessful) {
            Timber.e("Auth request failed: ${response.code} — $url\nbody: $responseBody")
            // Carry the wallet API's stable error code, refusal scope and
            // user-facing message. The legacy login finishes here rather than
            // at the AS, so without these a SID-AUTH-06 refusal met on this
            // path is indistinguishable from any other 4xx and never reaches
            // WalletState.LifecycleBlocked. Same body shape as the AS sends:
            // {"error": ..., "scope": ..., "message": ...}.
            val errorBody = runCatching { json.parseToJsonElement(responseBody).jsonObject }.getOrNull()
            fun field(name: String): String? =
                (errorBody?.get(name) as? kotlinx.serialization.json.JsonPrimitive)
                    ?.content?.takeIf { it.isNotBlank() }
            throw AuthException(
                message = "Auth request failed: ${response.code} — $path\nbody: $responseBody",
                cause = null,
                errorCode = field("error") ?: "auth_failed",
                code = response.code,
                serverMessage = field("message"),
                serverScope = field("scope"),
            )
        }

        Timber.d("Auth response: ${response.code} — $path")
        return json.parseToJsonElement(responseBody).jsonObject
    }

    companion object {
        private val base64Url = java.util.Base64.getUrlEncoder().withoutPadding()
        private val base64UrlDecoder = java.util.Base64.getUrlDecoder()

        fun encodeBase64Url(data: ByteArray): String = base64Url.encodeToString(data)
        fun decodeBase64Url(data: String): ByteArray = base64UrlDecoder.decode(data)
    }
}
