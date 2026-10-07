// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.idv

import android.app.Activity

/**
 * Result of an identity verification session.
 *
 * The primary output is a [credentialOfferURI] that can be passed directly to
 * `SirosWallet.startIssuance(offerUri)` to accept the issued credential.
 *
 * @property credentialOfferURI OID4VCI credential offer URI (e.g. `openid-credential-offer://...`).
 * @property transactionId Opaque transaction ID for audit/support purposes. Provider-specific.
 */
data class IDVResult(
    val credentialOfferURI: String,
    val transactionId: String? = null,
)

/**
 * Errors that can occur during identity verification.
 *
 * Each variant exposes a machine-readable [errorCode] for i18n mapping.
 */
sealed class IDVException(
    message: String,
    cause: Throwable? = null,
    /** Machine-readable error code for i18n mapping. */
    val errorCode: String = "idv_error",
) : Exception(message, cause) {
    /** The user cancelled the verification flow. */
    class Cancelled : IDVException("Identity verification cancelled by user", errorCode = "idv_cancelled")

    /** The provider is not available on this device (e.g. no camera). */
    class Unavailable(reason: String) : IDVException("IDV provider unavailable: $reason", errorCode = "idv_unavailable")

    /** Liveness check failed. */
    class LivenessFailed(message: String) : IDVException(message, errorCode = "idv_liveness_failed")

    /** Document scan or face-match failed. */
    class VerificationFailed(message: String) : IDVException(message, errorCode = "idv_verification_failed")

    /** Network or backend error. */
    class NetworkError(cause: Throwable) : IDVException("Network error during IDV", cause, errorCode = "idv_network_error")

    /**
     * The backend refused to issue because the document's NFC chip was not read and
     * authenticated, which facetec-api requires for every credential
     * (sirosfoundation/facetec-api#65). [reason] is the backend's `nfc_*` code and
     * [errorCode] is `idv_<reason>`.
     *
     * Through [RemoteIDVClient] (facetec-api's `/v1/id-scan`) the reason is always
     * `nfc_skipped`: that path only learns whether the chip was verified, not why it
     * was not. facetec-api's `/process-request` flow distinguishes
     * `nfc_not_requested`, `nfc_device_not_capable`, `nfc_chip_read_failed`
     * and `nfc_not_authenticated` as well, and any `nfc_*` code a backend sends maps here.
     */
    class DocumentChipNotVerified(val reason: String, message: String) : IDVException(message, errorCode = "idv_$reason")

    /**
     * The backend refused because the document's chip data could not be traced to a trusted
     * document signer (facetec-api's `chip_untrusted`, decided by its go-trust PDP). The chip was
     * read and authenticated, but trust could not be established. That is usually because the
     * document's signer is not trusted, so another document is needed; it can also be a temporary
     * outage of the trust service (facetec-api reports both as `chip_untrusted`), in which case a
     * new verification later with the same document may succeed. [errorCode] is `idv_chip_untrusted`.
     */
    class ChipUntrusted(message: String) : IDVException(message, errorCode = "idv_chip_untrusted")

    /**
     * The backend refused because the document's expiry date has passed (`document_expired`).
     * A document whose expiry date is missing or unreadable is [VerificationFailed] instead.
     * [errorCode] is `idv_document_expired`.
     */
    class DocumentExpired(message: String) : IDVException(message, errorCode = "idv_document_expired")

    /**
     * The backend no longer holds the liveness step this request relies on (`session_expired`):
     * it expired, or was already used. A liveness step is single-use, so it is never retried;
     * start a new verification from the face scan. [errorCode] is `idv_session_expired`.
     *
     * Through [RemoteIDVClient] this is the answer to a `/v1/id-scan` for a `livenessSessionId`
     * that is older than the backend's liveness TTL or was already submitted. facetec-api's
     * `/process-request` flow does not send it: there an expired or missing liveness proof is
     * reported as `liveness_failed` ([LivenessFailed]).
     */
    class SessionExpired(message: String) : IDVException(message, errorCode = "idv_session_expired")

    /** Provider-specific error with vendor-specific code. */
    class ProviderError(val providerCode: String, message: String) : IDVException("[$providerCode] $message", errorCode = "idv_provider_$providerCode")
}

/**
 * Plugin interface for identity verification (document + liveness).
 *
 * Implement this for any IDV vendor (FaceTec, iProov, Regula, Onfido, etc.).
 * The implementation manages its own capture UI and backend communication.
 *
 * ## Contract
 *
 * - [startVerification] must present vendor-specific UI (camera, document capture)
 *   and drive the full verification flow.
 * - On success, return an [IDVResult] containing the credential offer URI that
 *   the backend issued after successful identity proofing.
 * - On failure/cancellation, throw an appropriate [IDVException].
 *
 * ## Example
 *
 * ```kotlin
 * val provider = FaceTecIDVProvider(apiUrl = "https://ft.example.com", deviceKey = "...")
 * wallet.verifyIdentityAndIssue(provider, activity)
 * ```
 *
 * ## Thread Safety
 *
 * Implementations will be called from a coroutine context. UI operations
 * should be dispatched to the main thread internally.
 */
interface IdentityVerificationProvider {
    /** Human-readable name of the provider (e.g. "FaceTec", "iProov"). */
    val name: String

    /**
     * Whether this provider is available on the current device.
     *
     * Check for camera availability, SDK initialization status, etc.
     */
    suspend fun isAvailable(): Boolean

    /**
     * Start the identity verification flow.
     *
     * The implementation should:
     * 1. Present its own capture UI (face scan, document photos)
     * 2. Communicate with its backend to perform liveness/document checks
     * 3. Trigger credential issuance on the backend
     * 4. Return the resulting credential offer URI
     *
     * @param activity The hosting Activity for presenting IDV UI.
     * @return An [IDVResult] containing the credential offer URI.
     * @throws IDVException on failure or cancellation.
     */
    suspend fun startVerification(activity: Activity): IDVResult
}
