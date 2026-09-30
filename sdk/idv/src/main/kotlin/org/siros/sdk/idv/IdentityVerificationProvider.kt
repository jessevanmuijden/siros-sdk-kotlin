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
     * `nfc_not_supported_by_document`, `nfc_device_not_capable`, `nfc_chip_read_failed`
     * and `nfc_not_authenticated` as well, and any `nfc_*` code a backend sends maps here.
     */
    class DocumentChipNotVerified(val reason: String, message: String) : IDVException(message, errorCode = "idv_$reason")

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
