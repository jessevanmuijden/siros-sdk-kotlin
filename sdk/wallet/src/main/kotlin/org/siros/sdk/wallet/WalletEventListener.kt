// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.CredentialAttributeDiff
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.StoredCredential

/**
 * Context provided when a verifier requests credential presentation.
 *
 * Contains the matched credentials, requested claims, and optional
 * verifier identity so the app can render an informed consent screen.
 */
data class PresentationRequest(
    /** Verifier display name (from trust evaluation), null if unknown. */
    val verifierName: String?,
    /** Trust evaluation result with full metadata. Null if trust was not evaluated. */
    val trustResult: TrustResult? = null,
    /** Matched credentials grouped by DCQL query. */
    val matchResults: List<CredentialMatcher.MatchResult>,
    /** Flat list of candidate credentials (convenience). */
    val candidates: List<StoredCredential>,
    /** DCQL credential set constraints, null if no `credential_sets` in query. */
    val credentialSets: List<CredentialMatcher.CredentialSetQuery>? = null,
    /** Which credential set options are satisfiable with available credentials. */
    val satisfiableOptions: List<CredentialMatcher.SatisfiableOption> = emptyList(),
)

/**
 * Callback interface for wallet events that require user interaction.
 *
 * Implement this in your Activity or Fragment and pass it to
 * [SirosWallet.setEventListener]. All callbacks are invoked on the
 * main thread.
 */
interface WalletEventListener {

    /**
     * A verifier has requested credentials. The app should present a
     * consent UI showing the verifier name and requested claims,
     * then return the IDs the user has consented to share.
     *
     * The [request] parameter provides verifier identity and the
     * DCQL match results including which claims are requested.
     *
     * Return an empty list to cancel the presentation.
     */
    suspend fun onCredentialSelectionRequired(
        request: PresentationRequest,
    ): List<Long>

    /**
     * A new credential has been received from an issuer.
     * The SDK has already stored it — this callback is for
     * showing a confirmation / toast.
     */
    fun onCredentialReceived(credential: StoredCredential) {}

    /**
     * A credential batch was renewed (credential re-issuance/renewal plan,
     * Phase 2, `AttributeDiffService`-equivalent, ISSU_59) and at least one
     * claim differs from the batch it replaced. The renewal's own network
     * round-trip was silent (no user interaction), but ISSU_59 mandates
     * notifying the user of any claim change - the app should surface this
     * (e.g. wallet-frontend #73's consent/notification popup) even though
     * [onCredentialReceived] already fired for the new credential.
     *
     * Not called when a renewal completes with identical claims (the fully
     * silent case per plan §4.4) - only when [CredentialAttributeDiff.hasChanges]
     * is true.
     */
    fun onCredentialRenewedWithAttributeDiff(credential: StoredCredential, diff: CredentialAttributeDiff) {}

    /**
     * A credential batch's eligible (unused) instance count has dropped to
     * or below its renew threshold (credential re-issuance/renewal plan
     * §4.3/wallet-frontend #72 parity - EUDI ARF ISSU_50/54's proactive
     * renewal trigger). The app should surface this as a near-expiry
     * banner/nudge (Phase 3 UX, not yet built here) rather than waiting for
     * the reactive fully-exhausted case. Fires at most once per drop below
     * threshold per [SirosWallet.recordPresentation] call - not repeated on
     * every recomposition.
     */
    fun onCredentialNearExpiry(credential: StoredCredential, eligibleRemaining: Int, threshold: Int) {}

    /**
     * Called when a flow completes (issuance or presentation).
     *
     * @param redirectUri For an OID4VP `direct_post.jwt` presentation, some
     *   verifiers (e.g. verifier.multipaz.org) return a `redirect_uri` in
     *   their response so the user's browser/session can be returned to the
     *   verifier's own page to see the result. When present, the app should
     *   open it (Custom Tab or browser), matching [onAuthorizationRequired]'s
     *   pattern. Null when the verifier didn't return one (also true for
     *   every OID4VCI issuance completion).
     */
    fun onFlowComplete(flowId: String, redirectUri: String? = null) {}

    /**
     * Called when a flow fails.
     *
     * @param redirectUri Some verifiers return a `redirect_uri` even from
     *   their error-response endpoint (e.g. when the user declines an OID4VP
     *   presentation) - see [onFlowComplete]'s equivalent param. Null unless
     *   the verifier provided one.
     */
    fun onFlowError(flowId: String, errorMessage: String, redirectUri: String? = null) {}

    /**
     * A presentation request carrying OpenID4VP `transaction_data` (EC TS12)
     * was refused or declined, with nothing signed. The SDK reports the
     * machine-readable [reason]; the app words it for the user in its own
     * language ([org.siros.sdk.credentials.TransactionDataReason.code] is the
     * cross-SDK reason code). Called in addition to [onFlowError] where the
     * transport reports a flow error. Not called for the DC API, whose
     * refusal is thrown to the caller of [SirosWallet.handleDCAPIRequest].
     */
    fun onTransactionDataRefused(flowId: String, reason: org.siros.sdk.credentials.TransactionDataReason) {
        // Optional: apps that do not word refusals themselves ignore it.
    }

    /**
     * An issuer requires user authorization (OAuth consent).
     *
     * The app should open [authorizationUrl] in a Custom Tab or browser.
     * When the user approves and the browser redirects to [redirectUri],
     * call [SirosWallet.completeAuthorization] with the received `code`
     * and `state` query parameters.
     *
     * @param flowId The flow that requires authorization.
     * @param authorizationUrl The URL to open for user consent.
     * @param redirectUri The expected redirect URI (register as an app link).
     * @param state OAuth state parameter for CSRF validation.
     */
    fun onAuthorizationRequired(
        flowId: String,
        authorizationUrl: String,
        redirectUri: String,
        state: String,
    ) {}

    /**
     * An issuer requires a transaction code (PIN) for pre-authorized issuance.
     *
     * Return the PIN/tx_code value, or null to cancel the flow.
     *
     * @param flowId The flow that requires a tx_code.
     * @param description Human-readable description from the issuer (may contain the code for testing).
     */
    fun onTxCodeRequired(
        flowId: String,
        description: String?,
    ): String? = null

    /**
     * The current session could not be silently refreshed and is no longer
     * valid - e.g. the engine WebSocket's token refresh failed before a
     * reconnect, or repeated REST calls were rejected as unauthenticated.
     * [SirosWallet] fires this *before* logging out (logout is launched
     * asynchronously right after), so wallet state read during this callback
     * may still briefly reflect the old session. Unlike [onFlowError] (a
     * specific flow's failure, session otherwise fine), this means the whole
     * session is gone - route the user to the login screen rather than
     * surfacing a generic error message.
     *
     * Since SID-AUTH-06 the SDK attempts exactly one login itself right after
     * this fires: a lifecycle cut-off is indistinguishable from an expired
     * session until that login is refused with `WALLET_SUSPENDED` /
     * `WALLET_REVOKED`, which is what turns it into
     * [WalletState.LifecycleBlocked] rather than an endless reauth loop. So an
     * implementation should show its login/progress screen and wait for the
     * state to change - it must NOT call [SirosWallet.login] itself, or two
     * WebAuthn ceremonies race on the session store, the wallet state and the
     * engine session.
     */
    fun onReauthenticationRequired() {
        // Default: no-op. Host apps override to route to a login screen.
    }

    /**
     * The backend refuses this installation because of its wallet instance's
     * lifecycle (SID-AUTH-06): the instance was suspended or revoked, or the
     * whole wallet was deactivated and its data erased. Fired when
     * [SirosWallet] enters [WalletState.LifecycleBlocked] - from a login, a
     * keystore unlock, a session resume, or the SDK's own single re-login
     * after a token cut-off.
     *
     * Unlike [onReauthenticationRequired] this is not "prompt again": another
     * login attempt with the same passkey is refused the same way until
     * someone else acts. `SUSPENDED` is lifted by reactivating the instance
     * from another device; `REVOKED` is terminal *for this installation's
     * instance* and needs a fresh enrollment; `DEACTIVATED` is terminal for
     * the whole wallet.
     *
     * `REVOKED` does **not** imply the wallet was deactivated and erased - it
     * is the per-instance case, and the account's other passkeys and devices
     * keep working - so nothing local is discarded for it. `DEACTIVATED` is
     * the refusal that says the wallet itself is gone, and by the time this
     * fires the SDK has already forgotten the cached account it was about -
     * or, when nothing identified that account, has deliberately kept every
     * one rather than guess. Read
     * [WalletState.LifecycleBlocked.cachedAccounts] for what actually
     * remains; neither reason is licence for an app to drop further state of
     * its own. Apps that already render [WalletState.LifecycleBlocked] need
     * not implement this.
     */
    fun onWalletLifecycleBlocked(reason: org.siros.sdk.auth.WalletLifecycleRefusal, message: String?) {
        // Default: no-op. The state change is the primary signal.
    }
}
