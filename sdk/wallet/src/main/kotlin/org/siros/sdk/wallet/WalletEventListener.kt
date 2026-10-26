// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.CredentialAttributeDiff
import org.siros.sdk.credentials.CircuitZkRuleSet
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.CredentialUtils
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
) {
    /**
     * True when answering this request discloses NO credential data: every matched query is a circuit_zk / `zkp_req` query whose
     * PLAN consists only of the rulebook functions that return a derived value and never a claim (`pseudonym`, `age_check`). A consent
     * UI then has nothing to let the user select or confirm beyond choosing the credential and sharing or declining, so it can skip its
     * claim-selection and "confirm what is shared" steps.
     *
     * Derived from the plan, not from [CredentialMatcher.MatchResult.requestedClaims], which is empty for EVERY circuit_zk query: the
     * legacy `zk-claim-disclosure-v1` function (claims, `mso_mdoc_zk`-style age-over-18) discloses claims that live in the plan's functions.
     * Fail closed: any other function, an unknown one, an empty plan or a query without a plan keeps every step, as does any query in
     * another format (which may ask for the whole credential) and an empty request.
     */
    val disclosesNoClaims: Boolean
        get() = consentMatchResults.isNotEmpty() && consentMatchResults.all { r ->
            val plan = r.circuitZkPlan
            CredentialUtils.isCircuitZkFormat(r.format) && r.requestedClaims.flatten().isEmpty() && plan != null &&
                plan.functions.isNotEmpty() && plan.functions.all { it.id in NON_DISCLOSING_FUNCTIONS }
        }

    /**
     * The queries a consent UI shows: only those the wallet matched at least one credential for. A DCQL query without a candidate (one
     * alternative of a `credential_sets` option list the wallet cannot answer, with several alternatives each asking for the same
     * claims) has nothing to select or confirm, so it gets no claim-selection step and no card; an optional set with no match is skipped,
     * not an empty step. [matchResults] still lists every query (the matcher's full answer).
     */
    val consentMatchResults: List<CredentialMatcher.MatchResult>
        get() = matchResults.filter { it.candidates.isNotEmpty() }

    /**
     * How many steps a stepped consent UI needs: the overview with the credential choice, then (unless [disclosesNoClaims]) one
     * claim-selection step per [consentMatchResults] entry and a final "confirm what is shared" summary. Share and Decline are on the last step, so
     * a request that discloses nothing is one step.
     */
    val consentStepCount: Int
        get() = if (disclosesNoClaims) 1 else consentMatchResults.size + 2

    private companion object {
        /** Rulebook functions whose result is a derived value (a pseudonym, a boolean), never a disclosed claim. */
        val NON_DISCLOSING_FUNCTIONS = setOf(CircuitZkRuleSet.PSEUDONYM, CircuitZkRuleSet.AGE_CHECK)
    }
}

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
     * The issuer refused this wallet's pseudonym commitment: it holds a
     * different one for the user (flow error `PSC_CONFLICT`). Terminal for the
     * flow, with nothing issued or stored. Show
     * [PseudonymCommitmentConflictException.userMessageRes] and tell the user to
     * ask the issuer for a reset.
     *
     * The default forwards the issuer's text to [onFlowError], so a listener
     * that does not know this callback still sees the failure.
     */
    fun onPseudonymCommitmentConflict(flowId: String, error: PseudonymCommitmentConflictException) {
        onFlowError(flowId, error.issuerMessage)
    }

    /**
     * The issuer refused the auxiliary data the wallet sent because it holds a conflicting one (`AUXILIARY_DATA_CONFLICT`). Terminal
     * and NOT retryable ([AuxiliaryDataConflictException.retryable] is false): show [AuxiliaryDataConflictException.userMessageRes]
     * without a retry button. The default forwards the issuer's text to [onFlowError].
     */
    fun onAuxiliaryDataConflict(flowId: String, error: AuxiliaryDataConflictException) {
        onFlowError(flowId, error.issuerMessage)
    }

    /**
     * The issuer refused the auxiliary data of the key proofs (`invalid_proof`, `auxiliary_data: ...`). Terminal and NOT retryable
     * ([AuxiliaryDataRefusedException.retryable] is false); only the fixed [AuxiliaryDataRefusedException.reason] is carried, never the
     * issuer's text. The default calls [onFlowError] with a short fixed message.
     */
    fun onAuxiliaryDataRefused(flowId: String, error: AuxiliaryDataRefusedException) {
        onFlowError(flowId, "The issuer refused the wallet's auxiliary data (${error.reason.code}). Trying again will not help.")
    }

    /**
     * An issuance was refused because the issuer's trust could not be
     * established (remote evaluation negative or rejected, backend unreachable
     * with no positive local validation, or an unverifiable mdoc `issuerAuth`).
     * Nothing was stored. Called in addition to [onFlowError], which carries the
     * default English wording; apps wording it themselves use the string
     * resource `siros_issuer_not_trusted`. [reason] is for logs, not users.
     */
    fun onIssuerNotTrusted(flowId: String, issuer: String?, reason: String) {}

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
