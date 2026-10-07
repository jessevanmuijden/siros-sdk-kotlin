// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.wallet.TransactionConsentHandler
import org.siros.sdk.credentials.WalletException
import org.siros.sdk.wallet.R
import timber.log.Timber

/**
 * Near-headless Activity that receives the OS's Digital Credentials API
 * `GET_CREDENTIAL` intent when the user picks one of the host app's entries
 * from a browser page's `navigator.credentials.get({digital: {...}})`
 * picker (the entries [SirosCredentialRegistry.refresh] registered).
 *
 * Declared in this library's manifest, so a host app gets DC API
 * presentation by depending on the SDK, calling [SirosCredentialRegistry.refresh]
 * when its wallet has credentials, and keeping [WalletSessionHolder] pointed
 * at its unlocked wallet. It declares no component of its own. The
 * translucent theme it runs under is the SDK's `Theme.SirosSdk.DcApiHost`;
 * a host app that wants a different look overrides that style.
 *
 * Not necessarily launched via the host app's own UI - the OS starts this
 * directly from the credential picker, so it must not assume any existing UI
 * state. It reuses the currently-unlocked wallet session via
 * [WalletSessionHolder] (see that class's doc comment for the cold-start
 * limitation) rather than performing its own login/unlock flow.
 *
 * All DC API protocol logic (request parsing, trust evaluation, DCQL
 * matching, signing, response encryption) runs in
 * [org.siros.sdk.wallet.SirosWallet.handleDCAPIRequest] - this Activity is
 * just the platform glue: extract the request + verified origin from the
 * Intent, call the SDK, and hand the result back via [PendingIntentHandler].
 *
 * Shows a bare spinner rather than being fully invisible:
 * [org.siros.sdk.wallet.SirosWallet.handleDCAPIRequest] does real network
 * work (trust evaluation, occasionally an engine reconnect) that can take
 * more than an instant, and a blank screen during that window reads as
 * frozen - a real test found a user swiping away what looked like a hung
 * screen, which tears down the whole host task (including the calling
 * browser, since this Activity runs in the caller's task). Built with plain
 * views on purpose: an SDK component must not decide the host app's UI
 * toolkit, and this is a spinner and two lines of text.
 */
@OptIn(ExperimentalDigitalCredentialApi::class)
class DCAPIGetCredentialActivity : Activity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        if (request == null) {
            finishWithError("No credential request found in intent")
            return
        }

        val digitalOption = request.credentialOptions
            .filterIsInstance<GetDigitalCredentialOption>()
            .firstOrNull()
        if (digitalOption == null) {
            finishWithError("No digital credential option in request")
            return
        }

        // Cheap, synchronous pre-check (no network/trust eval - see
        // CredentialMatcher.isZkRequest's own doc comment) so the loading UI
        // can immediately signal "this is a zero-knowledge proof, not a raw
        // disclosure" instead of a generic spinner, without waiting for
        // SirosWallet.handleDCAPIRequest's full async request handling below.
        val isZkProof = try {
            DCAPIRequestParser.parse(digitalOption.requestJson).dcqlQuery
                ?.let { CredentialMatcher.isZkRequest(it) } == true
        } catch (e: Exception) {
            false
        }
        setContentView(buildLoadingView(isZkProof))

        // The verified origin the OS/browser attests, NOT anything read from
        // the request body itself - resolved against Google Password
        // Manager's openly-published privileged browser allowlist
        // (https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json,
        // bundled at res/raw/siros_gpm_privileged_apps.json), the same
        // allowlist Chrome's own passkey/DC API origin verification is
        // checked against.
        val origin = try {
            request.callingAppInfo.getOrigin(loadPrivilegedAllowlist())
        } catch (e: Exception) {
            Timber.w(e, "Could not resolve verified origin for DC API request")
            null
        }
        if (origin == null) {
            finishWithError("Could not verify the calling origin")
            return
        }

        val wallet = WalletSessionHolder.wallet
        if (wallet == null) {
            finishWithError("Wallet is not unlocked - open the app once first")
            return
        }

        // A payment confirmation request (transaction_data) and its response (KB-JWT with the transaction
        // hashes) are private; their content is never logged.
        val carriesTransactionData = digitalOption.requestJson.contains("transaction_data")
        if (!carriesTransactionData) Timber.d("DCAPI raw request (origin=$origin): ${digitalOption.requestJson}")

        scope.launch {
            try {
                val result = wallet.handleDCAPIRequest(
                    digitalOption.requestJson,
                    origin,
                    // The app's own screens are not in front of the user during a DC API request,
                    // so a payment confirmation is shown in this activity.
                    consentHandler = TransactionConsentHandler { showTransactionConsentDialog(this@DCAPIGetCredentialActivity, it) },
                )
                if (!carriesTransactionData) Timber.d("DCAPI final response: ${result.responseJson}")
                val responseIntent = Intent()
                PendingIntentHandler.setGetCredentialResponse(
                    responseIntent,
                    GetCredentialResponse(DigitalCredential(result.responseJson)),
                )
                setResult(RESULT_OK, responseIntent)
                finish()
            } catch (e: TransactionDataError) {
                // A refused transaction_data request is answered with the
                // protocol error OpenID4VP defines for it, not a generic one.
                // Only the OpenID4VP error code goes to the verifier's page: free text would tell it
                // which credentials the wallet holds and why a request failed.
                Timber.w("DC API transaction_data refused (${e.reason.code})")
                finishWithProtocolError(null, e.verifierError)
            } catch (e: WalletException) {
                // A decline (untrusted verifier, no matching/eligible
                // credential, missing encryption key, ...) is a normal
                // OpenID4VP-protocol outcome, not a platform-level failure -
                // surfacing it via setGetCredentialException makes Chrome
                // reject navigator.credentials.get() with a generic
                // "error retrieving a token", discarding our specific reason
                // before the RP's own JS ever sees it. Returning it as a
                // real (successful) DC API response whose body is an
                // OpenID4VP error object lets the RP read and display the
                // actual reason instead.
                Timber.w(e, "DC API presentation declined")
                finishWithProtocolError(e.message ?: "Presentation declined")
            } catch (e: Exception) {
                Timber.e(e, "DC API presentation failed unexpectedly")
                finishWithError(e.message ?: "Presentation failed")
            }
        }
    }

    override fun onDestroy() {
        // The wallet call is not cancelled when the Activity goes away
        // mid-request: SirosWallet owns that work, and a presentation the
        // user backed out of is reported by the OS to the caller regardless.
        // Only this Activity's own continuation is dropped.
        scope.cancel()
        super.onDestroy()
    }

    private fun finishWithError(message: String) {
        val responseIntent = Intent()
        PendingIntentHandler.setGetCredentialException(responseIntent, GetCredentialUnknownException(message))
        setResult(RESULT_OK, responseIntent)
        finish()
    }

    /**
     * Finishes with a real DC API response carrying an OpenID4VP error
     * object (`{"error": "access_denied", "error_description": "..."}`) -
     * per OpenID4VP 1.0's DC API response mode, this is returned as plain
     * JSON regardless of whether the request asked for an encrypted
     * (`dc_api.jwt`) success response; there is no RP-supplied encryption
     * key to use here since trust evaluation (which is what most declines
     * happen during) runs before `client_metadata.jwks` is ever consulted.
     * `access_denied` covers every current decline reason (untrusted
     * verifier, no matching/eligible credential, missing encryption key) -
     * none of them are distinguished by [WalletException.errorCode] today,
     * and OpenID4VP doesn't define a more specific code for most of them
     * anyway.
     */
    private fun finishWithProtocolError(description: String?, error: String = "access_denied") {
        val errorJson = buildJsonObject {
            put("error", JsonPrimitive(error))
            if (description != null) put("error_description", JsonPrimitive(description))
        }.toString()
        Timber.d("DCAPI error response: $errorJson")
        val responseIntent = Intent()
        PendingIntentHandler.setGetCredentialResponse(
            responseIntent,
            GetCredentialResponse(DigitalCredential(errorJson)),
        )
        setResult(RESULT_OK, responseIntent)
        finish()
    }

    private fun loadPrivilegedAllowlist(): String =
        resources.openRawResource(R.raw.siros_gpm_privileged_apps).bufferedReader().use { it.readText() }

    /** A dimmed full-screen scrim with a spinner; for a ZK proof, a lock glyph and two lines of explanation. */
    private fun buildLoadingView(isZkProof: Boolean): FrameLayout {
        val scrim = FrameLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            setBackgroundColor(Color.argb(102, 0, 0, 0)) // 40% black, as before
        }
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            val pad = dp(24)
            setPadding(pad, pad, pad, pad)
        }
        if (isZkProof) {
            column.addView(
                TextView(this).apply {
                    // Plain-text lock glyph: no drawable dependency, and it is a
                    // status cue, not a decoration.
                    text = "🔒"
                    setTextSize(TypedValue.COMPLEX_UNIT_SP, 28f)
                    gravity = Gravity.CENTER
                    setPadding(0, 0, 0, dp(12))
                },
            )
        }
        column.addView(ProgressBar(this))
        if (isZkProof) {
            column.addView(statusText(R.string.siros_dcapi_zk_proof_status, 16f, alpha = 1f, topPadding = dp(16)))
            column.addView(statusText(R.string.siros_dcapi_zk_proof_detail, 13f, alpha = 0.8f, topPadding = dp(8)))
        }
        scrim.addView(column, FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.CENTER))
        return scrim
    }

    private fun statusText(resId: Int, sizeSp: Float, alpha: Float, topPadding: Int): TextView =
        TextView(this).apply {
            setText(resId)
            setTextColor(Color.WHITE)
            this.alpha = alpha
            setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
            gravity = Gravity.CENTER
            setPadding(0, topPadding, 0, 0)
        }

    private fun dp(value: Int): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()
}
