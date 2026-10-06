// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv

import android.app.Activity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * Generic HTTP client for remote identity verification backends.
 *
 * Implements the common 3-step IDV flow:
 * 1. Session token acquisition
 * 2. Biometric (liveness) submission
 * 3. Document (ID scan) submission → credential offer URI
 *
 * This client is provider-agnostic — any backend that follows the
 * session-token → liveness → id-scan pattern can be used. The app
 * layer provides a [BiometricCaptureDelegate] for vendor-specific
 * UI capture (FaceTec, iProov, Regula, etc.).
 *
 * ## Usage
 *
 * ```kotlin
 * val client = RemoteIDVClient(
 *     config = RemoteIDVClient.Config(
 *         serverUrl = "https://idv.example.com",
 *         authToken = "Bearer <token>",
 *     )
 * )
 * val provider = RemoteIDVProvider(client, faceTecDelegate)
 * wallet.verifyIdentityAndIssue(provider, activity)
 * ```
 */
class RemoteIDVClient(private val config: Config) {

    data class Config(
        /** Base URL of the IDV server (e.g., "https://idv.example.com"). */
        val serverUrl: String,
        /** Authorization header value (e.g., "Bearer <token>"). */
        val authToken: String,
        /** Session token endpoint path (default: "/v1/session-token"). */
        val sessionTokenPath: String = "/v1/session-token",
        /** Liveness submission endpoint path (default: "/v1/liveness"). */
        val livenessPath: String = "/v1/liveness",
        /** ID scan submission endpoint path (default: "/v1/id-scan"). */
        val idScanPath: String = "/v1/id-scan",
        /** Connect timeout in ms (default: 30s). */
        val connectTimeoutMs: Int = 30_000,
        /** Read timeout in ms (default: 60s for large biometric payloads). */
        val readTimeoutMs: Int = 60_000,
    )

    private val baseUrl = config.serverUrl.trimEnd('/')

    /**
     * Get a session token from the IDV backend.
     * Used to initialize vendor SDKs that require server-issued tokens.
     */
    suspend fun getSessionToken(): String = withContext(Dispatchers.IO) {
        val json = postJson("$baseUrl${config.sessionTokenPath}", JSONObject())
        json.getString("sessionToken")
    }

    /**
     * Submit biometric data (e.g. FaceScan) for liveness verification.
     *
     * @param payload JSON object containing vendor-specific biometric data.
     *   The backend validates liveness and stores the biometric template
     *   in-memory for the subsequent document match.
     * @return An opaque session ID to pass to [submitDocument].
     * @throws IDVException.LivenessFailed if liveness check fails (HTTP 422).
     */
    suspend fun submitBiometric(payload: JSONObject): String = withContext(Dispatchers.IO) {
        val json = postJson("$baseUrl${config.livenessPath}", payload) { msg ->
            IDVException.LivenessFailed(msg)
        }
        json.getString("livenessSessionId")
    }

    /**
     * Submit document images for identity verification and credential issuance.
     *
     * @param payload JSON object containing document images and the liveness session ID.
     * @return [IDVResult] with the credential offer URI for OID4VCI issuance.
     * @throws IDVException.VerificationFailed if document verification fails (HTTP 422).
     */
    suspend fun submitDocument(payload: JSONObject): IDVResult = withContext(Dispatchers.IO) {
        val json = postJson("$baseUrl${config.idScanPath}", payload) { msg ->
            IDVException.VerificationFailed(msg)
        }
        IDVResult(
            credentialOfferURI = json.getString("credentialOfferURI"),
            transactionId = json.optString("transactionId", null),
        )
    }

    // ── HTTP helper ─────────────────────────────────────────────────

    private fun postJson(
        url: String,
        body: JSONObject,
        throwOn422: ((String) -> IDVException)? = null,
    ): JSONObject {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Authorization", config.authToken)
            conn.connectTimeout = config.connectTimeoutMs
            conn.readTimeout = config.readTimeoutMs
            conn.doOutput = true

            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use {
                it.write(body.toString())
            }

            val code = conn.responseCode
            val responseBody = if (code in 200..299) {
                conn.inputStream.bufferedReader().use { it.readText() }
            } else {
                conn.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
            }

            if (code == 422 && throwOn422 != null) {
                val error = runCatching { JSONObject(responseBody) }.getOrNull()
                throw idvExceptionFor422(
                    errorCode = error?.optString("error_code")?.takeIf { it.isNotEmpty() },
                    errorMessage = error?.optString("error")?.takeIf { it.isNotEmpty() },
                    responseBody = responseBody,
                    fallback = throwOn422,
                )
            }
            if (code !in 200..299) {
                throw IDVException.NetworkError(Exception("HTTP $code: $responseBody"))
            }

            return JSONObject(responseBody)
        } finally {
            conn.disconnect()
        }
    }
}

/**
 * Maps a 422 from the IDV backend to an [IDVException]. The backend's error body is
 * `{"error": "<message>", "error_code": "<code>"}`: an `nfc_*` code means the document's
 * chip was not read and authenticated ([IDVException.DocumentChipNotVerified]); anything
 * else goes to the step's own [fallback], with the raw body as before.
 */
internal fun idvExceptionFor422(
    errorCode: String?,
    errorMessage: String?,
    responseBody: String,
    fallback: (String) -> IDVException,
): IDVException =
    if (errorCode != null && errorCode.startsWith("nfc_")) {
        IDVException.DocumentChipNotVerified(errorCode, errorMessage ?: responseBody)
    } else {
        fallback(responseBody)
    }

/**
 * Delegate for vendor-specific biometric capture UI.
 *
 * The SDK's [RemoteIDVProvider] calls these methods to capture biometric
 * data from the user. The delegate presents the vendor's SDK UI
 * (FaceTec, iProov, Regula, etc.) and returns the captured data.
 *
 * ## Contract
 *
 * - Methods are called sequentially: [captureLiveness] first, then [captureDocument].
 * - Each method receives the session token from [RemoteIDVClient.getSessionToken].
 * - Return a JSON payload matching the IDV backend's expected format.
 * - Throw [IDVException.Cancelled] if the user dismisses the capture UI.
 */
interface BiometricCaptureDelegate {
    /** Human-readable name of the capture provider (e.g. "FaceTec"). */
    val name: String

    /** Whether the capture SDK is available on this device. */
    suspend fun isAvailable(): Boolean

    /**
     * Capture liveness biometric data (e.g. FaceScan).
     *
     * @param activity The hosting Activity for presenting capture UI.
     * @param sessionToken Server-issued session token.
     * @return JSON payload for [RemoteIDVClient.submitBiometric].
     */
    suspend fun captureLiveness(activity: Activity, sessionToken: String): JSONObject

    /**
     * Capture document images (e.g. photo ID front/back).
     *
     * @param activity The hosting Activity for presenting capture UI.
     * @param sessionToken Server-issued session token.
     * @return JSON payload for [RemoteIDVClient.submitDocument].
     *   Must include the `livenessSessionId` from the prior liveness step.
     */
    suspend fun captureDocument(activity: Activity, sessionToken: String, livenessSessionId: String): JSONObject
}

/**
 * Identity verification provider backed by a remote IDV server and
 * a pluggable [BiometricCaptureDelegate].
 *
 * This is the SDK-provided orchestrator. Apps configure it with a
 * [RemoteIDVClient] (pointing at their IDV backend) and a
 * [BiometricCaptureDelegate] (wrapping their chosen biometric SDK).
 *
 * ```kotlin
 * val client = RemoteIDVClient(RemoteIDVClient.Config(serverUrl = "...", authToken = "..."))
 * val delegate = FaceTecCaptureDelegate(context)  // app provides this
 * val provider = RemoteIDVProvider(client, delegate)
 * wallet.verifyIdentityAndIssue(provider, activity)
 * ```
 */
class RemoteIDVProvider(
    private val client: RemoteIDVClient,
    private val delegate: BiometricCaptureDelegate,
) : IdentityVerificationProvider {

    override val name: String get() = delegate.name

    override suspend fun isAvailable(): Boolean = delegate.isAvailable()

    override suspend fun startVerification(activity: Activity): IDVResult {
        // Step 1: Get session token
        val sessionToken = client.getSessionToken()

        // Step 2: Capture liveness (vendor UI) → submit to backend
        val livenessPayload = delegate.captureLiveness(activity, sessionToken)
        val livenessSessionId = client.submitBiometric(livenessPayload)

        // Step 3: Capture document (vendor UI) → submit to backend → credential offer
        val documentPayload = delegate.captureDocument(activity, sessionToken, livenessSessionId)
        return client.submitDocument(documentPayload)
    }
}
