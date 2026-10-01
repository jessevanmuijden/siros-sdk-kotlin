// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv.facetec

/**
 * Configuration for [FaceTecIDVProvider].
 *
 * @property processRequestUrl Full URL of facetec-api's process-request endpoint,
 *   e.g. `https://idv.example.com/v1/process-request`.
 * @property authToken `Authorization` header value for facetec-api (e.g. `"Bearer <token>"`).
 * @property deviceKeyIdentifier FaceTec device key identifier for this app, issued by FaceTec.
 * @property requireNfc Refuse to start on a device without NFC, or with NFC switched off.
 *   facetec-api issues nothing without an authenticated read of the document's chip
 *   (sirosfoundation/facetec-api#65), so a scan on such a device can only end in a refusal.
 * @property connectTimeoutMs Connect timeout for each process-request call.
 * @property readTimeoutMs Read timeout for each process-request call. The calls carry
 *   biometric data and can take a while on FaceTec Server.
 */
data class FaceTecIDVConfig(
    val processRequestUrl: String,
    val authToken: String,
    val deviceKeyIdentifier: String,
    val requireNfc: Boolean = true,
    val connectTimeoutMs: Int = 30_000,
    val readTimeoutMs: Int = 60_000,
) {
    /** Leaves [authToken] out, so logging a config does not leak the token. */
    override fun toString(): String =
        "FaceTecIDVConfig(processRequestUrl=$processRequestUrl, authToken=<redacted>, " +
            "deviceKeyIdentifier=$deviceKeyIdentifier, requireNfc=$requireNfc, " +
            "connectTimeoutMs=$connectTimeoutMs, readTimeoutMs=$readTimeoutMs)"
}
