// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv.facetec

import java.util.UUID

/**
 * The logic behind one session's `FaceTecSessionRequestProcessor`, kept free of FaceTec types
 * so it can be tested without the FaceTec SDK. [FaceTecApi.newSessionRequestProcessor] wraps
 * it in the real interface.
 *
 * It relays each request blob to facetec-api and remembers what facetec-api said about
 * issuance, for [sessionOutcome] once the session has finished.
 */
internal class FaceTecSessionRequestRelay(
    private val post: (requestBlob: String, externalDatabaseRefID: String) -> ProcessRequestResponse,
) {
    /**
     * Identifies this session's Enrollment Record on FaceTec Server. It must stay the same for
     * every request of one session (the liveness step files the record under it and the ID
     * match step looks it up), and differ between sessions, since a key can only be enrolled
     * once. facetec-api cannot mint it: the requests of one session carry nothing that ties
     * them together. One relay per session gives exactly that.
     */
    val externalDatabaseRefID: String = "siros-sdk-android-" + UUID.randomUUID()

    @Volatile var credentialOfferURI: String? = null
        private set

    @Volatile var transactionId: String? = null
        private set

    @Volatile var credentialIssueErrorCode: String? = null
        private set

    @Volatile var credentialIssueError: String? = null
        private set

    /** The failure that made the relay abort the session, if any. */
    @Volatile var transportError: Throwable? = null
        private set

    /**
     * Relays one request. Returns the response blob for the FaceTec SDK, or `null` when the
     * session has to be aborted (`abortOnCatastrophicError`); the cause is in [transportError].
     */
    fun onSessionRequest(requestBlob: String): String? =
        try {
            val response = post(requestBlob, externalDatabaseRefID)
            response.credentialOfferURI?.let {
                credentialOfferURI = it
                transactionId = response.transactionId
            }
            response.credentialIssueErrorCode?.let {
                credentialIssueErrorCode = it
                credentialIssueError = response.credentialIssueError
            }
            response.responseBlob
        } catch (t: Throwable) {
            // Throwable, not Exception: the SDK waits on this request, and has to be told
            // whatever went wrong or the session hangs.
            transportError = t
            null
        }
}
