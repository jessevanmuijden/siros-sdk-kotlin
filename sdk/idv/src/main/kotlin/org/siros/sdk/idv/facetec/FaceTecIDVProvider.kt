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
 * ## Sessions, retries and the liveness proof
 *
 * One [startVerification] call is one FaceTec session, with one `externalDatabaseRefID` that goes
 * on **every** `/process-request` of it. facetec-api (v0.16.0 and later) records FaceTec Server's
 * liveness verdict under that ID and refuses the final result with `liveness_failed` unless it
 * was proven; a request without the ID is refused the same way.
 *
 * - **Retries inside a session** (FaceTec's own retry screens for the face scan, the document
 *   photos or the chip read) need nothing from the app: they keep the session's ID, and a
 *   liveness retry passes if the latest liveness step passed.
 * - **The proof is single-use and short-lived.** The final result uses it up, and it expires 15
 *   minutes after the liveness step. After any failure, a cancel or a back-navigation the
 *   session is over: call [startVerification] again. That starts a new FaceTec session with a
 *   fresh ID and a fresh liveness step. Never reuse a session's ID for a second session, and do
 *   not offer "retry the document" after the liveness step: it cannot succeed.
 * - **Session affinity.** The liveness verdict is held in memory by the facetec-api instance that
 *   saw the liveness step, so every request of a session must reach the same instance. Point
 *   [FaceTecIDVConfig.processRequestUrl] at a host that routes by session (sticky routing) or at
 *   a single instance; a deployment that load-balances freely turns random sessions into
 *   `liveness_failed`.
 *
 * ## Errors
 *
 * - [IDVException.Cancelled]: the user left the face or ID scan.
 * - [IDVException.DocumentChipNotVerified]: facetec-api refused because the document's chip was
 *   not read and authenticated (`nfc_*` codes).
 * - [IDVException.ChipUntrusted]: the chip was read, but its data is not trusted by facetec-api's
 *   trust decision point (`chip_untrusted`). Usually another document is needed, but a temporary
 *   trust-service outage is reported the same way, so offer a retry later too.
 * - [IDVException.DocumentExpired]: the document has expired (`document_expired`).
 * - [IDVException.SessionExpired]: facetec-api reports the liveness step as expired or used
 *   (`session_expired`); start over.
 * - [IDVException.LivenessFailed], [IDVException.VerificationFailed]: liveness (including a
 *   missing, used or expired liveness proof), face match, unreadable document or policy
 *   refusals.
 * - [IDVException.ProviderError]: any other refusal code from facetec-api (e.g.
 *   `issuance_failed`, `internal_error`) or FaceTec status, with the code in `providerCode`.
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
