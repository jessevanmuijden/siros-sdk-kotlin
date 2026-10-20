// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.auth.WalletLifecycleRefusal
import org.siros.sdk.credentials.StoredCredential

/**
 * Observable wallet state. Apps collect [SirosWallet.state] to drive their UI.
 */
sealed class WalletState {

    /** Not authenticated. The user must call [SirosWallet.login] or [SirosWallet.register]. */
    data class Disconnected(
        /** Cached accounts that can be logged into (have PRF keys). */
        val cachedAccounts: List<CachedAccount> = emptyList(),
    ) : WalletState()

    /** Authentication / keystore unlock in progress. Show a loading indicator. */
    data object Connecting : WalletState()

    /** Authenticated, keystore unlocked, engine connected. */
    data class Ready(
        val userId: String,
        val displayName: String?,
        val credentials: List<StoredCredential> = emptyList(),
        /** All cached accounts (for the account switcher in settings). */
        val cachedAccounts: List<CachedAccount> = emptyList(),
    ) : WalletState()

    /**
     * Session resumed but the keystore is still locked (requires PRF).
     *
     * The engine is connected and the session token is valid, but
     * credentials and signing are unavailable until [SirosWallet.unlockKeystore]
     * is called (which triggers a WebAuthn assertion to obtain the PRF output).
     */
    data class KeystoreLocked(
        val userId: String,
        val displayName: String?,
    ) : WalletState()

    /** An issuance or presentation flow is in progress. */
    data class FlowActive(
        val userId: String,
        val displayName: String?,
        val flowId: String,
        val flowType: String,
        val status: String,
        val credentials: List<StoredCredential> = emptyList(),
    ) : WalletState() {
        /**
         * True while the wallet is still doing the local work that precedes the
         * engine's first progress event (see [PENDING_FLOW_ID]). There is no
         * engine flow to cancel or correlate yet; [flowId] is a placeholder.
         */
        val isPending: Boolean get() = flowId == PENDING_FLOW_ID

        companion object {
            /** [flowId] of the synchronous pre-engine state; never a real engine flow id. */
            const val PENDING_FLOW_ID: String = ""

            /** [flowType] of an issuance flow. */
            const val FLOW_TYPE_ISSUANCE: String = "issuance"

            /**
             * Client-side [status] tokens emitted before the engine reports
             * its first progress step ("parsing_offer"), in order. The wallet
             * does this work itself, so it is not part of the engine's step
             * vocabulary. Steps that do not apply to a given start path are
             * skipped (an offer URI has no entitlement check).
             */
            const val STEP_INITIALIZING: String = "initializing"
            const val STEP_CONNECTING_ENGINE: String = "connecting_engine"
            const val STEP_ESTABLISHING_SESSION: String = "establishing_session"
            const val STEP_CHECKING_ENTITLEMENT: String = "checking_entitlement"
            const val STEP_PREPARING_ISSUANCE: String = "preparing_issuance"
            const val STEP_STARTING_FLOW: String = "starting_flow"
        }
    }

    /**
     * The backend refuses this installation because of its wallet instance's
     * lifecycle (SID-AUTH-06): the instance is suspended, or the wallet has
     * been deactivated and its data erased. Terminal for this session - it is
     * not an error to retry or dismiss, but a condition that only someone
     * else (another device, the provider) can lift.
     *
     * Entered from [SirosWallet.login], [SirosWallet.unlockKeystore],
     * [SirosWallet.resumeSession] and from the SDK's own re-login after a
     * token cut-off, whenever the authorization server answers `403` with
     * `WALLET_SUSPENDED` / `WALLET_REVOKED`.
     *
     * **How far it reaches is [reason], and only [reason].** `SUSPENDED` and
     * `REVOKED` are about this installation's wallet instance alone: nothing
     * local is forgotten and [cachedAccounts] still lists this account,
     * because revoking one wallet unit leaves the user's other devices,
     * passkeys and keys untouched. `DEACTIVATED` is the whole wallet - every
     * instance revoked and the server-side data erased - and is the one case
     * where a cached account may be dropped: the account the refused
     * operation was for, which [cachedAccounts] then no longer lists.
     *
     * When nothing identifies that account - a login can offer several
     * accounts' passkeys at once and be refused before this SDK learns which
     * one answered - every cached account is kept rather than guessed at. So
     * `DEACTIVATED` means at most one account was forgotten, never that one
     * certainly was; read [cachedAccounts] for what actually remains.
     *
     * A backend that does not send the refusal's `scope` yet never produces
     * `DEACTIVATED`; its `WALLET_REVOKED` reads as `REVOKED` and nothing
     * local is lost.
     *
     * What an app should offer: for `SUSPENDED`, a retry - a later
     * [SirosWallet.login] succeeds once the instance is reactivated from
     * another device. For `REVOKED` and `DEACTIVATED`, a fresh enrollment.
     * [message] is written for the user and says which device or wallet the
     * refusal was about; show it rather than composing your own.
     */
    data class LifecycleBlocked(
        val reason: WalletLifecycleRefusal,
        /** The backend's user-facing explanation, when it sent one. */
        val message: String?,
        /** Cached accounts that can still be logged into. */
        val cachedAccounts: List<CachedAccount> = emptyList(),
    ) : WalletState()

    /** An error occurred. The app should show the message and offer retry / logout. */
    data class Error(val message: String) : WalletState()
}
