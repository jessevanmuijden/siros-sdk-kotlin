// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv.facetec

import org.json.JSONObject
import java.io.IOException
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * facetec-api's answer to one `/process-request` call.
 *
 * @property responseBlob Opaque FaceTec Server response, handed back to the FaceTec SDK.
 * @property credentialOfferURI Set once facetec-api has issued a credential for the session.
 * @property transactionId facetec-api's transaction ID for the issued credential, if any.
 * @property credentialIssueErrorCode Set when the scan completed but facetec-api refused to
 *   issue, e.g. `nfc_skipped` or `policy_rejected` (see [refusalToException]).
 * @property credentialIssueError facetec-api's human-readable reason for the refusal, if any.
 */
internal data class ProcessRequestResponse(
    val responseBlob: String,
    val credentialOfferURI: String? = null,
    val transactionId: String? = null,
    val credentialIssueErrorCode: String? = null,
    val credentialIssueError: String? = null,
)

/**
 * Posts FaceTec 10 session request blobs to facetec-api's `/process-request`.
 *
 * Blocking: it is called from [FaceTecSessionRequestRelay.onSessionRequest], which the
 * FaceTec SDK already invokes off the main thread and expects to return only once the
 * response is known.
 */
internal class FaceTecProcessRequestClient(private val config: FaceTecIDVConfig) {
    /**
     * @throws IOException on a transport failure, a non-2xx status or a body without a
     *   `responseBlob`. The relay turns any of these into an aborted FaceTec session.
     */
    fun post(requestBlob: String, externalDatabaseRefID: String): ProcessRequestResponse {
        val conn = URL(config.processRequestUrl).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Authorization", config.authToken)
            conn.connectTimeout = config.connectTimeoutMs
            conn.readTimeout = config.readTimeoutMs
            conn.doOutput = true

            val payload = JSONObject()
                .put("requestBlob", requestBlob)
                .put("externalDatabaseRefID", externalDatabaseRefID)
            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(payload.toString()) }

            val code = conn.responseCode
            if (code !in 200..299) {
                // The body is not included: it may echo request data, and this message can
                // end up in an app's logs.
                throw IOException("process-request failed with HTTP $code")
            }
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val json = try {
                JSONObject(body)
            } catch (e: Exception) {
                throw IOException("process-request returned a body that is not JSON", e)
            }

            val responseBlob = json.optString("responseBlob")
            if (responseBlob.isEmpty()) throw IOException("process-request response has no responseBlob")

            return ProcessRequestResponse(
                responseBlob = responseBlob,
                credentialOfferURI = json.optNonBlank("credentialOfferURI"),
                transactionId = json.optNonBlank("transactionId"),
                credentialIssueErrorCode = json.optNonBlank("credentialIssueErrorCode"),
                credentialIssueError = json.optNonBlank("credentialIssueError"),
            )
        } finally {
            conn.disconnect()
        }
    }

    private fun JSONObject.optNonBlank(key: String): String? =
        if (isNull(key)) null else optString(key).takeIf { it.isNotBlank() }
}
