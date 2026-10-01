// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv.facetec

import android.app.Activity
import android.content.Intent
import android.nfc.NfcAdapter
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.siros.sdk.idv.IDVException
import org.siros.sdk.idv.IDVResult
import org.siros.sdk.idv.IdentityVerificationProvider

/**
 * Identity verification with the FaceTec **10** SDK and facetec-api.
 *
 * Runs FaceTec's 3D liveness → document scan (with NFC chip read) → 3D:2D photo match session.
 * Every request blob of the session goes to facetec-api's `/process-request`, which proxies it
 * to FaceTec Server and, once the match succeeds and the document's chip was authenticated,
 * issues a credential: the session's [IDVResult] carries that credential offer.
 *
 * ```kotlin
 * val provider = FaceTecIDVProvider(
 *     FaceTecIDVConfig(
 *         processRequestUrl = "https://idv.example.com/v1/process-request",
 *         authToken = "Bearer $token",
 *         deviceKeyIdentifier = "<from FaceTec>",
 *     )
 * )
 * wallet.verifyIdentityAndIssue(provider, activity)
 * ```
 *
 * ## App requirements
 *
 * - The FaceTec Android SDK 10 AAR (`com.facetec:facetec-sdk`) on the app's classpath. This SDK
 *   has no compile-time dependency on it; without it [isAvailable] is `false` and
 *   [startVerification] throws [IDVException.Unavailable].
 * - The `CAMERA` permission in the app's manifest (FaceTec's AAR declares it); the provider asks
 *   for it at runtime when needed.
 *
 * ## Errors
 *
 * - [IDVException.Cancelled]: the user left the face or ID scan.
 * - [IDVException.DocumentChipNotVerified]: facetec-api refused because the document's chip was
 *   not read and authenticated (`nfc_*` codes).
 * - [IDVException.LivenessFailed], [IDVException.VerificationFailed]: liveness, face match or
 *   policy refusals.
 * - [IDVException.ProviderError]: any other refusal code from facetec-api (e.g. `chip_untrusted`,
 *   `issuance_failed`) or FaceTec status, with the code in `providerCode`.
 * - [IDVException.NetworkError]: facetec-api could not be reached during the session.
 * - [IDVException.Unavailable]: no compatible FaceTec SDK, no device key identifier, no camera
 *   permission, or (with [FaceTecIDVConfig.requireNfc]) no NFC or NFC switched off.
 */
class FaceTecIDVProvider internal constructor(
    private val config: FaceTecIDVConfig,
    private val api: FaceTecApi,
) : IdentityVerificationProvider {

    constructor(config: FaceTecIDVConfig) : this(config, FaceTecApi())

    private val client = FaceTecProcessRequestClient(config)

    override val name: String = "FaceTec"

    /** Whether a FaceTec 10 SDK is on the classpath. */
    override suspend fun isAvailable(): Boolean = api.missingApi() == null

    override suspend fun startVerification(activity: Activity): IDVResult {
        api.missingApi()?.let { throw IDVException.Unavailable("FaceTec SDK 10 not found ($it)") }
        if (config.deviceKeyIdentifier.isBlank()) {
            throw IDVException.Unavailable("no FaceTec device key identifier configured")
        }
        if (config.requireNfc) {
            val nfc = NfcAdapter.getDefaultAdapter(activity)
                ?: throw IDVException.Unavailable("this device cannot read NFC, which reading the document's chip requires")
            if (!nfc.isEnabled) throw IDVException.Unavailable("NFC is switched off")
        }

        val result = CompletableDeferred<IDVResult>()
        val relay = FaceTecSessionRequestRelay(client::post)
        val sessionId = FaceTecSessionActivity.register(
            FaceTecSessionActivity.PendingSession(api, config.deviceKeyIdentifier, relay, result),
        )
        try {
            withContext(Dispatchers.Main) {
                activity.startActivity(
                    Intent(activity, FaceTecSessionActivity::class.java)
                        .putExtra(FaceTecSessionActivity.EXTRA_SESSION_ID, sessionId),
                )
            }
            return result.await()
        } finally {
            FaceTecSessionActivity.unregister(sessionId)
        }
    }
}
