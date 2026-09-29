// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import android.app.Activity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.putJsonObject
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import org.siros.sdk.auth.AuthSession
import org.siros.sdk.auth.AuthServerClient
import org.siros.sdk.auth.AuthTokens
import org.siros.sdk.auth.BackendApiClient
import org.siros.sdk.auth.AuthProvider
import org.siros.sdk.auth.CredentialManagerAuthProvider
import org.siros.sdk.auth.LocalAuthProvider
import org.siros.sdk.auth.PrfOutput
import org.siros.sdk.auth.DeactivationOutcome
import org.siros.sdk.auth.ERROR_CREDENTIAL_NOT_OWNED
import org.siros.sdk.auth.WalletInstance
import org.siros.sdk.auth.WalletInstanceStatus
import org.siros.sdk.auth.WalletLifecycleRefusal
import org.siros.sdk.auth.apiErrorCode
import org.siros.sdk.auth.apiRefusalMessage
import org.siros.sdk.auth.apiRefusalScope
import org.siros.sdk.auth.WebAuthnAuthClient
import org.siros.sdk.auth.WscdAutoEnrollHint
import org.siros.sdk.credentials.AuthException
import org.siros.sdk.credentials.Integrity
import org.siros.sdk.credentials.IssuerEntitlement
import org.siros.sdk.credentials.BackendApiException
import org.siros.sdk.credentials.KeystoreException
import org.siros.sdk.credentials.NetworkException
import org.siros.sdk.credentials.SirosException
import org.siros.sdk.credentials.WalletException
import org.siros.sdk.credentials.CredentialStore
import org.siros.sdk.credentials.InMemoryCredentialStore
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.CredentialOffer
import org.siros.sdk.credentials.CredentialMetadata
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.credentials.IssuerEntry
import org.siros.sdk.credentials.IssuerMetadata
import org.siros.sdk.credentials.CredentialConfiguration
import org.siros.sdk.credentials.CredentialConsumptionPolicy
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.Vctm
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.COSE_ALG_ES256
import org.siros.sdk.credentials.CredentialFormat
import org.siros.sdk.credentials.CredentialTypeRef
import org.siros.sdk.credentials.ZkProofSystemRegistry
import org.siros.sdk.credentials.VerifierIdentity
import com.upokecenter.cbor.CBORObject
import org.siros.sdk.credentials.mdoc.MdocCbor
import org.siros.sdk.keystore.mdoc.MdocCose
import org.siros.sdk.credentials.VctmFetcher
import org.siros.sdk.credentials.MddlSchema
import org.siros.sdk.credentials.MddlSchemaFetcher
import org.siros.sdk.keystore.BbsHolderStateVault
import org.siros.sdk.keystore.CredentialRefreshTokenEntry
import org.siros.sdk.keystore.DCAPIResponseEncryption
import org.siros.sdk.keystore.JweKeystore
import org.siros.sdk.keystore.KeypairInfo
import org.siros.sdk.keystore.KeystoreManager
import org.siros.sdk.keystore.LongfellowZkProofSystem
import org.siros.sdk.keystore.MdocDeviceResponseBuilder
import org.siros.sdk.keystore.ZkMdocPresentation
import org.siros.sdk.keystore.WscdKeystoreAdapter
import org.siros.sdk.keystore.WscdManager
import org.siros.sdk.wallet.dcapi.DCAPIRequest
import org.siros.sdk.wallet.dcapi.DCAPIRequestParser
import org.siros.sdk.transport.CredentialNotifier
import org.siros.sdk.transport.engine.CredentialMatch
import org.siros.sdk.transport.engine.CredentialNotificationEvent
import org.siros.sdk.transport.engine.FlowError
import org.siros.sdk.transport.engine.ProofObject
import org.siros.sdk.transport.engine.SignRequestMessage
import org.siros.sdk.transport.engine.WalletEngineSession
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import timber.log.Timber
import java.security.SecureRandom
import java.util.Base64

/**
 * Main entry point for the SIROS Wallet SDK.
 *
 * Provides a single, self-contained API for wallet apps:
 *
 * ```kotlin
 * val wallet = SirosWallet.create(activity, WalletConfig("https://wallet.sirosid.dev"))
 * wallet.login()               // WebAuthn + PRF + keystore + engine — all automatic
 * wallet.state.collect { ... }  // observe state to drive UI
 * ```
 *
 * The SDK handles WebAuthn authentication with PRF extension, HKDF key
 * derivation, JWE keystore unlock, encrypted private-data sync with the
 * backend, and the engine WebSocket session for issuance/presentation flows.
 *
 * The only things the host app is responsible for are:
 * 1. Providing an [Activity] context (for the passkey system UI).
 * 2. Observing [state] and rendering the appropriate screens.
 * 3. Implementing [WalletEventListener] for credential-selection UX.
 */

/**
 * Context saved from an `authorization_required` progress message, needed to resume
 * an OID4VCI flow after the OAuth browser redirects back to the app.
 *
 * The WebSocket session that started the flow very often will not survive the
 * redirect step - Android backgrounds/throttles the app while the external browser
 * (or Custom Tab) is in the foreground, and the engine session dies with it (see
 * [SirosWallet.completeAuthorization]). [offerJson] is the exact `credential_offer`
 * object the backend already parsed, round-tripped verbatim so resume never needs
 * to re-fetch a possibly single-use `credential_offer_uri`.
 */
private data class PendingAuthorization(
    val offerJson: String?,
    val redirectUri: String,
    val codeVerifier: String?,
    val state: String,
)

/** Facade methods that need a live backend session throw this when there is none. */
private const val NOT_LOGGED_IN = "Not logged in"

/**
 * The engine's error code for a presentation this wallet cannot satisfy
 * (go-wallet-backend `ErrCodeNoMatchingCredential`). Its `details` carry
 * `requested_types` (what the verifier asked for) and `no_match_reason` (what
 * this wallet reported).
 */
private const val ERROR_NO_MATCHING_CREDENTIAL = "NO_MATCHING_CREDENTIAL"

/**
 * A randomly-generated uint32-range identifier, matching wallet-frontend's
 * `WalletStateUtils.getRandomUint32()` exactly (CSPRNG, full 1..2^32-1 range,
 * 0 remapped to 1) - used for both [StoredCredential.id] (`credentialId`) and
 * [org.siros.sdk.credentials.PresentationRecord.id] (`presentationId`), so
 * either client can read the other's privatedata-spec container.
 */
// A single, reused instance - constructing a fresh SecureRandom() per call is
// a well-known anti-pattern (wasteful, and on some platforms rapid
// back-to-back instantiation can yield correlated or even duplicate output,
// which is exactly what previously caused two ids in the same batch-issuance
// loop to collide and silently overwrite each other in the credential store's
// id-keyed map).
private val idRandom = SecureRandom()

private fun randomUint32Id(): Long {
    val bytes = ByteArray(4)
    idRandom.nextBytes(bytes)
    val value = ((bytes[0].toLong() and 0xFF) shl 24) or
        ((bytes[1].toLong() and 0xFF) shl 16) or
        ((bytes[2].toLong() and 0xFF) shl 8) or
        (bytes[3].toLong() and 0xFF)
    return if (value == 0L) 1L else value
}

class SirosWallet private constructor(
    private val activity: Activity,
    private val config: WalletConfig,
) {
    // ── Public API ──────────────────────────────────────────────────

    private val _state = MutableStateFlow<WalletState>(WalletState.Disconnected())

    /** Observable wallet state. Collect this from your UI layer. */
    val state: StateFlow<WalletState> = _state.asStateFlow()

    /** Helper: build Disconnected with current cached accounts. */
    private fun disconnectedState() = WalletState.Disconnected(
        cachedAccounts = accountRegistry.listLoginableAccounts(),
    )

    /** Helper: build Ready with current cached accounts. */
    private fun readyState(userId: String, displayName: String?, credentials: List<org.siros.sdk.credentials.StoredCredential>) =
        WalletState.Ready(userId = userId, displayName = displayName, credentials = credentials,
            cachedAccounts = accountRegistry.listAccounts())

    /** All known accounts across all tenants. Survives logout. */
    fun listAccounts(): List<CachedAccount> = accountRegistry.listAccounts()

    /** Accounts that have passkeys and can log in. */
    fun listLoginableAccounts(): List<CachedAccount> = accountRegistry.listLoginableAccounts()

    /**
     * Get a valid access token for authenticated API calls (e.g., IDV backend).
     * Returns the raw JWT string. Throws if no session is active.
     */
    suspend fun getAccessToken(): String {
        return authTokens.ensureBackendToken().raw
    }

    /** Remove a cached account (forgets it from the login screen). */
    fun forgetAccount(accountId: String) {
        accountRegistry.removeAccount(accountId)
        if (accountRegistry.activeAccountId == accountId) {
            logout()
        } else {
            // Re-emit state so UI reflects the removed account
            _state.value = disconnectedState()
        }
    }

    /**
     * Delete the currently active account: removes it from the local account
     * registry (so it no longer lingers as a cached "Welcome back" entry on
     * the login screen) and logs out. There's no server-side account
     * deletion endpoint - this is [forgetAccount] scoped to whichever
     * account is currently active, which is what "delete" is expected to do
     * from the logged-in Settings screen.
     */
    fun deleteAccount() {
        val activeId = accountRegistry.activeAccountId
        if (activeId != null) {
            forgetAccount(activeId)
        } else {
            logout()
        }
    }

    // ── Passkey Management ──────────────────────────────────────────

    /**
     * Passkeys registered for the active account.
     * Returns from the local AccountRegistry cache (not the backend).
     */
    fun listPasskeys(): List<CachedPasskey> {
        val active = accountRegistry.activeAccountId ?: return emptyList()
        return accountRegistry.findAccount(active)?.passkeys ?: emptyList()
    }

    /**
     * Rename a passkey (local only — updates the AccountRegistry).
     */
    fun renamePasskey(credentialId: String, nickname: String) {
        val active = accountRegistry.activeAccountId ?: return
        val account = accountRegistry.findAccount(active) ?: return
        val updated = account.copy(
            passkeys = account.passkeys.map {
                if (it.credentialId == credentialId) it.copy(nickname = nickname) else it
            }
        )
        accountRegistry.upsertAccount(updated)
    }

    // ── Wallet instance lifecycle (SID-AUTH-06) ─────────────────────

    /**
     * This user's wallet instances in the current tenant, from the backend
     * (`GET /user/session/instances`). One instance per installation; match an
     * instance to a passkey via [WalletInstance.credentialId] when present.
     * Requires a backend with go-wallet-backend#319; older backends answer 404,
     * surfaced as [org.siros.sdk.auth.BackendApiException].
     */
    suspend fun listWalletInstances(): List<WalletInstance> {
        val client = apiClient ?: throw AuthException(NOT_LOGGED_IN)
        // Best-effort: [thisInstanceId] reads the WIA this session already
        // holds, so fetch one when there is none yet rather than returning a
        // list in which no row can be marked "this device". A failure here
        // must not fail the listing - ensureWalletInstanceAttestation()
        // already swallows its own errors and returns null.
        if (thisInstanceId == null) ensureWalletInstanceAttestation()
        val self = thisInstanceId
        return client.listWalletInstances().map {
            it.copy(isThisDevice = self != null && it.id == self)
        }
    }

    /**
     * This installation's wallet instance id: the JWK thumbprint of its
     * instance key, which is what the backend registers an instance under and
     * what this SDK already sends as `wallet_instance_id`. Null until this
     * session has obtained a Wallet Instance Attestation (the value is read
     * from its `cnf.jkt`); [listWalletInstances] fetches one if needed, so
     * reading this right after it is the reliable order.
     */
    val thisInstanceId: String? get() = instanceKeyThumbprint()

    /**
     * Suspend, reactivate or revoke one of this user's wallet instances
     * (`PUT /user/session/instances/{id}/status`). Suspension is reversible and
     * only blocks that installation (login, attestation, sessions); revocation
     * is terminal. Revoking the last non-revoked instance deactivates the
     * wallet - prefer [deactivateWallet] for that, which also clears local state.
     *
     * Any change away from `active` cuts off every bearer token issued before
     * it, including this session's (the acting token survives only for the
     * request that made the change, and may not mint new ones), so this
     * re-logs in once afterwards - see [WalletState.LifecycleBlocked].
     * Suspending *this* device's own instance therefore ends in
     * `LifecycleBlocked(SUSPENDED)`, which is the truthful state; confirm
     * with the user before calling it for [WalletInstance.isThisDevice].
     */
    suspend fun setWalletInstanceStatus(
        instanceId: String,
        status: WalletInstanceStatus,
        reason: String? = null,
    ): WalletInstance {
        val client = apiClient ?: throw AuthException(NOT_LOGGED_IN)
        val updated = client.setWalletInstanceStatus(instanceId, status, reason)
        // Every status write records a cut-off, and the acting token's
        // exemption from it does not reach POST /auth/token or an engine flow
        // start - so this session is done either way. Re-login once instead of
        // letting the next issuance or presentation discover it as a 401.
        reloginAfterLifecycleChange()
        return updated
    }

    /**
     * Deprecated string form of [setWalletInstanceStatus]. Kept for one
     * release so callers built against SDK 0.16 keep compiling.
     */
    @Deprecated(
        "Use the WalletInstanceStatus overload",
        ReplaceWith("setWalletInstanceStatus(instanceId, requireNotNull(WalletInstanceStatus.fromWire(status)), reason)"),
    )
    suspend fun setWalletInstanceStatus(instanceId: String, status: String, reason: String? = null): WalletInstance =
        setWalletInstanceStatus(
            instanceId,
            WalletInstanceStatus.fromWire(status)
                ?: throw IllegalArgumentException("Unknown wallet instance status: $status"),
            reason,
        )

    /**
     * Deactivate this wallet: revoke every wallet instance of the user
     * (`POST /user/session/instances/revoke-all`). The backend erases the
     * wallet's private data and server-side credentials, and refuses every
     * passkey of the user at login with `WALLET_REVOKED`; a new enrollment is
     * required afterwards. The local cached account is forgotten and the
     * wallet logged out, since the vault it decrypts no longer exists - in
     * both outcomes, since the revocations stand even when the erasure
     * cascade did not finish.
     *
     * Unlike [setWalletInstanceStatus] this does not re-login: there is
     * nothing left to log in to.
     *
     * @return how many instances the backend revoked and whether it confirmed
     *   the erasure ([DeactivationOutcome.complete]); an incomplete erasure
     *   leaves residual server-side data for an administrator to clean up.
     */
    suspend fun deactivateWallet(reason: String? = null): DeactivationOutcome {
        val client = apiClient ?: throw AuthException(NOT_LOGGED_IN)
        val outcome = client.revokeAllWalletInstances(reason)
        if (outcome.complete) {
            Timber.i("Wallet deactivated: ${outcome.revoked} instance(s) revoked; forgetting local account")
        } else {
            Timber.w(
                "Wallet deactivated with an unfinished erasure: ${outcome.revoked} instance(s) revoked, " +
                    "residual server-side data must be cleaned up by an administrator; forgetting local account anyway"
            )
        }
        deleteAccount()
        return outcome
    }

    // ── Lifecycle refusals and the cut-off re-login (SID-AUTH-06) ───

    /**
     * True while the SDK's own single re-login (after a token cut-off or a
     * lifecycle write) is running - the guard that makes it happen exactly
     * once, so the 401s that re-login itself may provoke cannot start another.
     */
    @Volatile
    private var reloginInProgress: Boolean = false

    /**
     * The cached account whose passkey answered one login's WebAuthn ceremony,
     * once that is known.
     *
     * A lifecycle refusal has to name the account it is about before anything
     * local may be forgotten, and the account active before a login is not it:
     * a login offers every account's passkeys at once (see [loginCandidates]),
     * so which wallet was refused is decided by the credential the
     * authenticator returns, not by whoever was signed in before.
     *
     * One instance per [login] call, never a field on the wallet: two logins
     * running at once would otherwise overwrite each other's answer, and the
     * loser could forget an account the refusal was never about. Null means
     * the refusal names no account, and then nothing is forgotten.
     */
    private class RefusedAccount {
        @Volatile
        var id: String? = null
    }

    /**
     * Which session this wallet currently holds. Bumped whenever one ends
     * ([logout], [destroy]) or a new one is established (a successful
     * [login]/[register]).
     *
     * It is what makes the self-driven re-login *once per session* rather than
     * once per call: requests issued before a cut-off complete long after it,
     * still holding the same [AuthTokens], and each of their 401s re-enters
     * [handleReauthenticationRequired]. Without a generation, every one of
     * those arriving after [endSelfDrivenRelogin] would start another
     * re-login. It also lets [reloginAfterCutOff] notice that the caller
     * logged out or destroyed the wallet while it was tearing the old session
     * down, instead of resurrecting a session the user ended.
     */
    @Volatile
    private var sessionGeneration: Int = 0

    /**
     * Whether a self-driven re-login has already been run for the current
     * [sessionGeneration]. Cleared by [bumpSessionGeneration].
     *
     * A boolean rather than "the generation it was last run for": the tests
     * build this class with `Unsafe.allocateInstance`, which skips field
     * initializers, so a sentinel like `-1` would come up equal to a
     * zero-valued generation and refuse every re-login.
     */
    @Volatile
    private var reloginDoneForGeneration: Boolean = false

    /**
     * Set by [destroy]. The state is left untouched there (a destroyed wallet
     * is not a logged-out one), so without this a re-authentication signal
     * from a coroutine still unwinding could pass the guard and log back in
     * after the host tore the wallet down.
     */
    @Volatile
    private var isDestroyed: Boolean = false

    /**
     * Claims the right to run the SDK's own re-login, at most once per
     * session. Refuses when one is already running, when one has already been
     * run for this session generation (late 401s from requests issued before
     * the cut-off), or when the wallet no longer believes it has a session to
     * replace - after a logout, an error or a lifecycle block, a silent
     * WebAuthn prompt is never the right answer.
     *
     * @return the session generation the re-login is replacing, or null when
     *   it must not run.
     */
    @Synchronized
    private fun beginSelfDrivenRelogin(): Int? {
        if (isDestroyed) return null
        if (reloginInProgress) return null
        if (reloginDoneForGeneration) return null
        if (!hasReplaceableSession()) return null
        reloginDoneForGeneration = true
        reloginInProgress = true
        return sessionGeneration
    }

    /** Whether the current state describes a session worth replacing. */
    private fun hasReplaceableSession(): Boolean = when (_state.value) {
        is WalletState.Ready,
        is WalletState.FlowActive,
        is WalletState.KeystoreLocked -> true
        // Deliberately NOT Connecting: that is also where the initial [login]
        // and [resumeSession] sit before their own session setup finishes, and
        // a 401 from /auth/token fires onSessionRejected immediately. Treating
        // it as replaceable would let a second WebAuthn ceremony start
        // underneath the first and race its state, its API client and its
        // keystore. There is no session to replace until one is established.
        is WalletState.Connecting,
        is WalletState.Disconnected,
        is WalletState.Error,
        is WalletState.LifecycleBlocked -> false
    }

    /**
     * Ends the current session generation. Call whenever a session ends or is
     * replaced.
     */
    @Synchronized
    private fun bumpSessionGeneration() {
        sessionGeneration += 1
        reloginDoneForGeneration = false
    }

    @Synchronized
    private fun endSelfDrivenRelogin() {
        reloginInProgress = false
    }

    /**
     * Drop everything the backend's lifecycle cut-off just invalidated - the
     * cached tokens, the API client built on them and the engine WebSocket,
     * which the backend re-checks at every flow start - and log in once.
     * [login] itself routes the outcome: a lifecycle `403` to
     * [WalletState.LifecycleBlocked], a success to [WalletState.Ready], and
     * anything else to [WalletState.Error].
     */
    private suspend fun reloginAfterCutOff(generation: Int) {
        engineStateJob?.cancel()
        engineStateJob = null
        engineSession?.disconnect()
        engineSession = null
        // The WMP transport holds its own live WebSocket, and the backend
        // re-checks the cut-off at every flow start - leaving it connected
        // would keep a socket authenticated by a token the backend has already
        // stopped accepting, and the next connect would overwrite the
        // reference without ever closing it.
        wmpPeer?.close()
        wmpPeer = null
        credentialNotifier = null
        apiClient = null
        authTokens.clear()
        // AuthServerClient caches access tokens independently of AuthTokens,
        // and a token minted before the cut-off is refused with 401 however
        // fresh it looks. Clear it explicitly - logout() would clear it too
        // but ends the session first, which is the opposite of what a
        // re-login needs.
        authServerClient.clearTokenCache()
        // Lock the key material too, the way logout() does. The session is
        // already gone server-side; if the replacement login then fails (a
        // cancelled passkey ceremony, no network, or a lifecycle refusal) the
        // wallet must not be left holding an unlocked keystore whose
        // credentials are still signable. A successful login() unlocks it
        // again as part of its normal path.
        keystore.lock()
        // The teardown above suspends (the WMP peer's close, the token-cache
        // clears), and the caller may have logged out or destroyed the wallet
        // in the meantime. Logging back in then would resurrect a session the
        // user explicitly ended - and race the asynchronous AS logout.
        if (sessionGeneration != generation) {
            Timber.i("Self-driven re-login abandoned: the session it was replacing is already gone")
            return
        }
        login(accountRegistry.activeAccountId ?: sessionStore.activeAccountId)
        // The check above cannot be atomic with the call - [login] is a long
        // suspending operation and [logout]/[destroy] are synchronous and can
        // land anywhere inside it. So undo rather than prevent: a session
        // established after the user ended the one it was replacing is torn
        // down again here, which is the outcome they asked for.
        if ((sessionGeneration != generation + 1 || isDestroyed) && _state.value is WalletState.Ready) {
            Timber.i("Self-driven re-login undone: the session it replaced was ended while it ran")
            endSessionLocally()
            _state.value = disconnectedState()
        }
    }

    /** [reloginAfterCutOff] under the once-only guard, never throwing at the caller. */
    private suspend fun reloginAfterLifecycleChange() {
        val generation = beginSelfDrivenRelogin()
        if (generation == null) {
            Timber.d("Re-login not started: one already ran for this session, or there is none to replace")
            return
        }
        try {
            reloginAfterCutOff(generation)
        } catch (e: Exception) {
            // login() has already put the failure in the state; this call
            // must not turn a lifecycle write that succeeded into a throw.
            Timber.w(e, "Re-login after a wallet lifecycle change failed")
        } finally {
            endSelfDrivenRelogin()
        }
    }

    /**
     * The lifecycle refusal [error] (or one of its causes) reports, or null
     * when it is not one. The AS carries the code as
     * [AuthException.errorCode] and how far it reaches as
     * [AuthException.serverScope]; the causes are walked because login paths
     * wrap failures in [WalletException].
     *
     * Both are read from the *same* exception, so a refusal never borrows the
     * scope of an unrelated one further down the chain.
     */
    private fun lifecycleRefusalOf(error: Throwable?): WalletLifecycleRefusal? {
        var current = error
        var depth = 0
        while (current != null && depth++ < 8) {
            val refusal = when (val e = current) {
                is AuthException -> WalletLifecycleRefusal.fromRefusal(e.errorCode, e.serverScope)
                // The backend emits the same refusal body from the wallet API
                // (`internal/api/handlers.go`) as from the AS passkey endpoint,
                // and a wallet-API failure surfaces as a BackendApiException
                // carrying the raw body. Reading only one of the two emitters
                // would let a refusal met on a wallet-API call fall through to a
                // generic error instead of the blocked state.
                is BackendApiException ->
                    WalletLifecycleRefusal.fromRefusal(e.apiErrorCode(), e.apiRefusalScope())
                else -> null
            }
            if (refusal != null) return refusal
            current = current.cause
        }
        return null
    }

    /** The server's user-facing explanation carried by [error], if any. */
    private fun lifecycleMessageOf(error: Throwable?): String? {
        var current = error
        var depth = 0
        while (current != null && depth++ < 8) {
            when (val e = current) {
                is AuthException -> e.serverMessage?.let { return it }
                is BackendApiException -> e.apiRefusalMessage()?.let { return it }
                else -> Unit
            }
            current = current.cause
        }
        return null
    }

    /**
     * Enter [WalletState.LifecycleBlocked].
     *
     * What survives depends on how far the refusal reaches, which the backend
     * says in the `scope` field and nowhere else - `WALLET_REVOKED` answers
     * both a single revoked instance and a deactivated wallet.
     *
     * [WalletLifecycleRefusal.SUSPENDED] and [WalletLifecycleRefusal.REVOKED]
     * are about **this installation's instance only**. Under the EUDI
     * specifications revoking one wallet unit ends that unit and nothing else,
     * so the user's other devices, passkeys and keys must be left alone: the
     * SDK ends the session, keeps the cached account, shows the backend's own
     * explanation and leaves re-enrollment to the user.
     *
     * [WalletLifecycleRefusal.DEACTIVATED] is the one refusal that reaches the
     * whole wallet: every instance has been revoked and the server-side data
     * erased, so there is nothing left to log in to and the cached account is
     * forgotten as well. A backend that sends no scope never produces it - the
     * refusal degrades to [WalletLifecycleRefusal.REVOKED] and nothing local is
     * lost.
     *
     * [deactivateWallet] forgets the account too, but there the caller asked
     * for it.
     */
    private suspend fun enterLifecycleBlocked(
        reason: WalletLifecycleRefusal,
        message: String?,
        refusedAccountId: String?,
    ) {
        Timber.w("Wallet lifecycle refusal: $reason — ${message ?: "(no message from the backend)"}")
        val deactivatedAccountId =
            if (reason == WalletLifecycleRefusal.DEACTIVATED) refusedAccountId else null
        if (reason == WalletLifecycleRefusal.DEACTIVATED && deactivatedAccountId == null) {
            // A deactivation whose account the caller could not name. It happens
            // when a login offered every account's passkeys and was refused
            // before this SDK could tell which one answered: the ceremony's
            // credential is what says whose wallet it was, and without it
            // forgetting anything would be a guess at the user's expense.
            Timber.w("Wallet deactivated but the account could not be identified: keeping every cached account")
        }
        // End the session either way - nothing this installation holds can be
        // used until someone else acts - but keep the account (see this
        // function's doc comment for why REVOKED is not licence to forget it),
        // and do not schedule the remote DELETE: a retry after the instance is
        // reactivated reuses the same AS session cookie, and the DELETE could
        // land after its loginFinish. See [endSessionLocally].
        endSessionLocally()
        // [endSessionLocally] clears [AuthTokens], but [AuthServerClient] keeps
        // its own cache: a backend token minted just before the 403 arrived
        // (during the private-data fetch or the engine connect) would otherwise
        // be served straight back to the retry without the AS ever being asked,
        // and it is already cut off. Awaited here, so it cannot race the retry
        // the app may make the moment this state is published.
        try {
            authServerClient.clearTokenCache()
        } catch (e: Exception) {
            Timber.w(e, "Clearing the AS token cache failed (non-fatal)")
        }
        // The wallet is gone server-side: its private data is erased, so the
        // vault this account's passkey decrypts no longer exists and offering
        // it on the login screen would only produce the same refusal. Removed
        // directly rather than through [forgetAccount], which logs out and
        // would schedule the remote session DELETE this path deliberately
        // avoids (see [endSessionLocally]).
        deactivatedAccountId?.let {
            Timber.i("Wallet deactivated server-side: forgetting cached account")
            accountRegistry.removeAccount(it)
        }
        _state.value = WalletState.LifecycleBlocked(
            reason = reason,
            message = message,
            cachedAccounts = accountRegistry.listLoginableAccounts(),
        )
        scope.launch { eventListener?.onWalletLifecycleBlocked(reason, message) }
    }

    /**
     * Route [error] into [WalletState.LifecycleBlocked] when it is a
     * SID-AUTH-06 refusal. Returns true when it handled the error, so callers
     * can leave their own error handling untouched for everything else.
     *
     * [refusedAccountId] is the account the refused operation was for, and the
     * caller must capture it when that operation *starts* rather than leaving
     * this to read whichever account happens to be active when the refusal
     * lands. The two differ exactly where it is most costly: a login offers
     * every account's passkeys at once, so the account signed in beforehand
     * is not necessarily the one being refused, and a deactivation is the one
     * refusal that throws local state away. Null when the caller cannot say,
     * and then nothing is forgotten.
     */
    private suspend fun handleLifecycleRefusal(error: Throwable?, refusedAccountId: String?): Boolean {
        val reason = lifecycleRefusalOf(error) ?: return false
        enterLifecycleBlocked(reason, lifecycleMessageOf(error), refusedAccountId)
        return true
    }

    /** Set a listener for events that require user interaction (credential picker, etc.). */
    fun setEventListener(listener: WalletEventListener) {
        eventListener = listener
    }

    /**
     * Governs whether a successful presentation exhausts the credential
     * instance it used (see [CredentialUtils.eligibleInstances]). Defaults
     * to [CredentialConsumptionPolicy.NEVER_CONSUME] so existing behavior
     * doesn't change until a host app opts in. This is core wallet policy,
     * not a UI-only preference - the host app is responsible for persisting
     * the user's choice across restarts and setting it here on startup.
     */
    var credentialConsumptionPolicy: CredentialConsumptionPolicy = CredentialConsumptionPolicy.NEVER_CONSUME

    /**
     * Register a new user with a passkey.
     *
     * This single call:
     * 1. Gets a registration challenge from the backend.
     * 2. Creates a passkey via the system UI (with PRF extension).
     * 3. Derives an encryption key from the PRF output.
     * 4. Initialises an empty encrypted keystore.
     * 5. Sends the encrypted keystore to the backend as `privateData`.
     * 6. Opens the engine WebSocket.
     *
     * @param displayName the user's display name for the passkey.
     * @throws WalletException if registration fails.
     * @throws IllegalArgumentException if displayName is blank or too long.
     */
    suspend fun register(displayName: String) {
        require(displayName.isNotBlank() && displayName.length <= 256) {
            "displayName must be 1-256 characters"
        }
        _state.value = WalletState.Connecting
        // See logout()'s identical reset: this enrollment gets its own
        // instance key, so any WIA still cached from an earlier account must
        // not be what identifies this device afterwards.
        cachedWia = null
        cachedWiaExpiresAt = 0
        try {
            ensureAuthMode()
            when (authMode) {
                AuthMode.LEGACY_AS -> legacyRegister(displayName)
                else -> newAsRegister(displayName)
            }
        } catch (e: SirosException) {
            Timber.e(e, "Registration failed")
            rollbackLocalCredential()
            _state.value = WalletState.Error(e.message ?: "Registration failed")
        } catch (e: Exception) {
            Timber.e(e, "Registration failed")
            rollbackLocalCredential()
            _state.value = WalletState.Error(e.message ?: "Registration failed")
            throw WalletException("Registration failed", e)
        }
    }

    private suspend fun newAsRegister(displayName: String) {
        // Generate a fresh PRF salt for this registration
        val prfSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val hkdfSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val hkdfInfo = HKDF_INFO.toByteArray(Charsets.UTF_8)

        // Step 1: Get challenge from AS
        val challengeResponse = authServerClient.registerBegin()
        val challengeId = challengeResponse["challengeId"]?.jsonPrimitive?.contentOrNull
            ?: throw WalletException("Missing challengeId in register begin response")
        val createOptions = challengeResponse["createOptions"]?.jsonObject
            ?: throw WalletException("Missing createOptions")
        val publicKey = createOptions["publicKey"]?.jsonObject
            ?: throw WalletException("Missing publicKey in createOptions")

        val rpObj = publicKey["rp"]?.jsonObject
            ?: throw WalletException("Missing rp in publicKey")
        val rpId = rpObj["id"]?.jsonPrimitive?.contentOrNull ?: throw WalletException("Missing rp.id")
        val rpName = rpObj["name"]?.jsonPrimitive?.contentOrNull ?: rpId
        val challenge = WebAuthnAuthClient.decodeBase64Url(publicKey["challenge"]?.jsonPrimitive?.contentOrNull
            ?: throw WalletException(MISSING_CHALLENGE))
        val userObj = publicKey["user"]?.jsonObject
            ?: throw WalletException("Missing user in publicKey")
        val userId = WebAuthnAuthClient.decodeBase64Url(userObj["id"]?.jsonPrimitive?.contentOrNull
            ?: throw WalletException("Missing user.id"))
        val userName = userObj["name"]?.jsonPrimitive?.contentOrNull ?: displayName

        // Step 2: Create credential via platform AuthProvider
        val result = authProvider.register(
            org.siros.sdk.auth.RegisterOptions(
                rpId = rpId,
                rpName = rpName,
                userId = userId,
                userName = userName,
                userDisplayName = displayName,
                challenge = challenge,
                prfSalt = prfSalt,
            )
        )

        // Step 3: Complete registration with AS
        val credentialJson = kotlinx.serialization.json.buildJsonObject {
            put("id", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.credentialId)))
            put("rawId", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.credentialId)))
            put("type", kotlinx.serialization.json.JsonPrimitive("public-key"))
            put("response", kotlinx.serialization.json.buildJsonObject {
                put("attestationObject", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.attestationObject)))
                put("clientDataJSON", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.clientDataJSON)))
            })
        }
        val session = authServerClient.registerFinish(
            challengeId = challengeId,
            credential = credentialJson,
            displayName = displayName,
        )
        Timber.i("Registration successful: ${session.uuid}")

        val credId = extractLastCredentialId()
            ?: throw WalletException("No credential ID after registration")
        val prfOutput = extractLastPrfOutput()
            ?: throw WalletException("PRF not supported by authenticator — cannot encrypt wallet data")

        finishRegistration(
            userId = session.uuid,
            displayName = session.displayName,
            givenDisplayName = displayName,
            credId = credId,
            prfOutput = prfOutput,
            prfSalt = prfSalt,
            hkdfSalt = hkdfSalt,
            hkdfInfo = hkdfInfo,
            appToken = null,
        )
    }

    private suspend fun legacyRegister(displayName: String) {
        // Generate a fresh PRF salt for this registration
        val prfSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val hkdfSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val hkdfInfo = HKDF_INFO.toByteArray(Charsets.UTF_8)

        val session = legacyAuthClient.register(displayName = displayName, prfSalt = prfSalt)
        Timber.i("Legacy registration successful: ${session.uuid}")

        val credId = extractLastCredentialId()
            ?: throw WalletException("No credential ID after registration")
        val prfOutput = extractLastPrfOutput()
            ?: throw WalletException("PRF not supported by authenticator — cannot encrypt wallet data")

        finishRegistration(
            userId = session.uuid,
            displayName = session.displayName,
            givenDisplayName = displayName,
            credId = credId,
            prfOutput = prfOutput,
            prfSalt = prfSalt,
            hkdfSalt = hkdfSalt,
            hkdfInfo = hkdfInfo,
            appToken = session.appToken,
        )
    }

    private suspend fun finishRegistration(
        userId: String,
        displayName: String?,
        givenDisplayName: String,
        credId: ByteArray,
        prfOutput: PrfOutput,
        prfSalt: ByteArray,
        hkdfSalt: ByteArray,
        hkdfInfo: ByteArray,
        appToken: String?,
    ) {
        // Derive key and initialise empty keystore
        keystore.unlock(prfOutput.first, ByteArray(0), hkdfSalt, hkdfInfo)
        unlockAvailableKeystores(prfOutput.first, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore.setCredentialId(credId)
        val encryptedContainer = try {
            keystore.exportEncryptedContainer()
        } catch (_: UnsupportedOperationException) { null }

        // Register account in the persistent registry (survives logout)
        val accountId = "${config.tenantId}:${userId}"
        accountRegistry.upsertAccount(CachedAccount(
            userId = userId,
            tenantId = config.tenantId,
            displayName = givenDisplayName,
            backendUrl = config.backendUrl,
            passkeys = listOf(CachedPasskey(
                credentialId = b64UrlEncode(credId),
                prfSalt = b64Encode(prfSalt),
            )),
            hkdfSalt = b64Encode(hkdfSalt),
            hkdfInfo = b64Encode(hkdfInfo),
        ))
        accountRegistry.activeAccountId = accountId

        // Scope session store to this account
        sessionStore.activeAccountId = accountId
        sessionStore.userId = userId
        sessionStore.displayName = displayName ?: givenDisplayName
        sessionStore.tenantId = config.tenantId
        sessionStore.credentialId = b64UrlEncode(credId)
        sessionStore.prfSalt = b64Encode(prfSalt)
        sessionStore.hkdfSalt = b64Encode(hkdfSalt)
        sessionStore.hkdfInfo = b64Encode(hkdfInfo)
        encryptedContainer?.let {
            sessionStore.privateDataJwe = String(it, Charsets.UTF_8)
        }

        if (appToken != null) {
            setupApiClient(AuthSession(appToken = appToken, uuid = userId, displayName = displayName))
            legacyAppToken = appToken
            sessionStore.appToken = appToken
        } else {
            setupApiClientWithTokens()
        }
        syncPrivateDataToBackend()

        // Connect engine with anonymous token (new AS) or app token (legacy AS)
        connectEngineWithToken()

        // A new session: see [sessionGeneration].
        bumpSessionGeneration()
        _state.value = WalletState.Ready(
            userId = userId,
            displayName = displayName ?: givenDisplayName,
            credentials = credentialStore.getAll(),
        )
    }

    /**
     * Login with an existing passkey.
     *
     * This single call:
     * 1. Gets a login challenge from the backend.
     * 2. Authenticates via the system passkey UI (with PRF extension).
     * 3. Derives the encryption key from the PRF output.
     * 4. Downloads the encrypted keystore (`privateData`) from the backend.
     * 5. Unlocks the keystore.
     * 6. Opens the engine WebSocket.
     */
    /**
     * @param accountId if given, log in as this specific cached account
     *   (e.g. the user tapped "Welcome back, <name>") - the WebAuthn ceremony
     *   is scoped to just that account's own passkey(s). If null, every
     *   loginable account's passkeys are offered as candidates via WebAuthn's
     *   `prf.evalByCredential` extension (see [loginCandidates]), since which
     *   one the user actually authenticates with is only known once the
     *   discoverable-credential ceremony completes.
     */
    suspend fun login(accountId: String? = null) {
        // Scoped to this attempt so concurrent logins cannot answer for one
        // another; see [RefusedAccount].
        val refused = RefusedAccount()
        _state.value = WalletState.Connecting
        // See logout()'s identical reset: a WIA still cached from another
        // account (or from before a re-enrollment) must not be what identifies
        // this device once this login resolves.
        cachedWia = null
        cachedWiaExpiresAt = 0
        try {
            ensureAuthMode()
            if (accountId != null) {
                sessionStore.activeAccountId = accountId
            } else {
                restoreActiveAccountForLogin()
            }
            when (authMode) {
                AuthMode.LEGACY_AS -> legacyLogin(accountId, refused)
                else -> newAsLogin(accountId, refused)
            }
        } catch (e: SirosException) {
            // A SID-AUTH-06 refusal is a state, not an error: this passkey's
            // wallet instance is suspended or revoked, or the wallet was
            // deactivated, and retrying the same login changes nothing until
            // someone else acts.
            if (handleLifecycleRefusal(e, refused.id)) return
            Timber.e(e, "Login failed")
            _state.value = WalletState.Error(e.message ?: "Login failed")
        } catch (e: Exception) {
            if (handleLifecycleRefusal(e, refused.id)) return
            Timber.e(e, "Login failed")
            _state.value = WalletState.Error(e.message ?: "Login failed")
            throw WalletException("Login failed", e)
        }
    }

    /**
     * Ensure [sessionStore] has *some* account scoped before login, purely so
     * reads made before the WebAuthn ceremony resolves (e.g. UI state) have
     * something sensible to show - [scopeSessionStoreToCredential] is what
     * actually matters for correctness, since it re-scopes to whichever
     * account the ceremony resolves to. Falls back to the single loginable
     * account when there's exactly one, since [logout] clears
     * [AccountRegistry.activeAccountId] and there's nothing else to restore
     * from at that point.
     */
    private fun restoreActiveAccountForLogin() {
        if (sessionStore.activeAccountId != null) return
        accountRegistry.activeAccountId?.let {
            sessionStore.activeAccountId = it
            return
        }
        accountRegistry.listLoginableAccounts().singleOrNull()?.let {
            sessionStore.activeAccountId = it.accountId
        }
    }

    /**
     * Build (credentialId, prfSalt) pairs for every passkey login should
     * offer as a candidate - mirrors WebAuthn's `prf.evalByCredential`
     * extension (see [org.siros.sdk.auth.AuthenticateOptions.prfSaltsByCredential],
     * and wallet-frontend's `makeAssertionPrfExtensionInputs`). Scoped to
     * just [accountId]'s own passkeys when given; otherwise every loginable
     * account's passkeys are offered, so the platform authenticator can
     * evaluate PRF with the right salt no matter which credential the user
     * picks, all within one ceremony - no fixed/shared salt, no guessing the
     * account in advance, no second prompt.
     */
    private fun loginCandidates(accountId: String?): List<Pair<ByteArray, ByteArray>> {
        val accounts = accountId?.let { listOfNotNull(accountRegistry.findAccount(it)) }
            ?: accountRegistry.listLoginableAccounts()
        return accounts.flatMap { account ->
            account.passkeys.mapNotNull { passkey ->
                if (passkey.prfSalt.isBlank()) return@mapNotNull null
                b64UrlDecode(passkey.credentialId) to b64Decode(passkey.prfSalt)
            }
        }
    }

    /**
     * Scope [sessionStore] to whichever cached account owns [credId], now
     * that the login ceremony has resolved which credential was actually
     * used. [finishLogin] reads sessionStore.hkdfSalt/hkdfInfo before it
     * derives an accountId from the server's confirmed userId, so this must
     * run before that call, or the wrong (or a freshly-generated, WRONG)
     * salt gets used to derive the decryption key and the correctly-resolved
     * PRF output from [loginCandidates] ends up wasted.
     */
    private fun scopeSessionStoreToCredential(credId: ByteArray) {
        accountForCredential(credId)?.let { sessionStore.activeAccountId = it }
    }

    /** The cached account whose passkey list contains [credId], if any. */
    private fun accountForCredential(credId: ByteArray): String? {
        val credIdB64url = b64UrlEncode(credId)
        return accountRegistry.listAccounts()
            .find { acc -> acc.passkeys.any { it.credentialId == credIdB64url } }
            ?.accountId
    }

    private suspend fun newAsLogin(accountId: String?, refused: RefusedAccount) {
        val prfCandidates = loginCandidates(accountId)

        // Step 1: Get challenge from AS
        val challengeResponse = authServerClient.loginBegin()
        val challengeId = challengeResponse["challengeId"]?.jsonPrimitive?.contentOrNull
            ?: throw WalletException("Missing challengeId in login begin response")
        val getOptions = challengeResponse["getOptions"]?.jsonObject
            ?: throw WalletException("Missing getOptions")
        val publicKey = getOptions["publicKey"]?.jsonObject
            ?: throw WalletException("Missing publicKey in getOptions")

        val rpId = publicKey["rpId"]?.jsonPrimitive?.contentOrNull
            ?: throw WalletException("Missing rpId")
        val challenge = WebAuthnAuthClient.decodeBase64Url(publicKey["challenge"]?.jsonPrimitive?.contentOrNull
            ?: throw WalletException(MISSING_CHALLENGE))

        // Step 2: Authenticate via platform AuthProvider
        val result = authProvider.authenticate(
            org.siros.sdk.auth.AuthenticateOptions(
                rpId = rpId,
                challenge = challenge,
                prfSaltsByCredential = prfCandidates.ifEmpty { null },
            )
        )

        // Which cached account just answered. Recorded before the AS is asked,
        // because the AS's answer may be a lifecycle refusal that has to say
        // whose wallet it was about. Nothing sets it if the ceremony never
        // ran, and then a refusal names no account. See [RefusedAccount].
        refused.id = accountForCredential(result.credentialId)

        // Step 3: Complete login with AS
        val credentialJson = kotlinx.serialization.json.buildJsonObject {
            put("id", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.credentialId)))
            put("rawId", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.credentialId)))
            put("type", kotlinx.serialization.json.JsonPrimitive("public-key"))
            put("response", kotlinx.serialization.json.buildJsonObject {
                put("authenticatorData", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.authenticatorData)))
                put("clientDataJSON", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.clientDataJSON)))
                put("signature", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.signature)))
                result.userHandle?.let { put("userHandle", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(it))) }
            })
        }
        val session = authServerClient.loginFinish(
            challengeId = challengeId,
            credential = credentialJson,
        )
        Timber.i("Login successful: ${session.uuid}")

        val credId = extractLastCredentialId()
            ?: throw WalletException("No credential ID after login")
        scopeSessionStoreToCredential(credId)
        val prfOutput = extractLastPrfOutput()
            ?: throw WalletException("PRF not supported by authenticator — cannot decrypt wallet data")

        // Set up API client with AuthTokens and fetch private data
        setupApiClientWithTokens()
        finishLogin(session.uuid, session.displayName, credId, prfOutput)
    }

    private suspend fun legacyLogin(accountId: String?, refused: RefusedAccount) {
        val prfCandidates = loginCandidates(accountId)
        // The legacy client performs the ceremony and the finish inside one
        // call, so it reports the credential itself the moment the ceremony
        // resolves. Reading the provider's last-credential field afterwards
        // would not do: it is shared mutable state, so a concurrent login
        // could overwrite it between this ceremony and this refusal, and the
        // account this names is the one a deactivation deletes.
        val session = legacyAuthClient.login(
            prfSaltsByCredential = prfCandidates.ifEmpty { null },
            onCredentialResolved = { credId -> refused.id = accountForCredential(credId) },
        )
        Timber.i("Legacy login successful: ${session.uuid}")

        val credId = extractLastCredentialId()
            ?: throw WalletException("No credential ID after login")
        scopeSessionStoreToCredential(credId)
        val prfOutput = extractLastPrfOutput()
            ?: throw WalletException("PRF not supported by authenticator — cannot decrypt wallet data")

        setupApiClient(session)
        legacyAppToken = session.appToken
        sessionStore.appToken = session.appToken
        finishLogin(session.uuid, session.displayName, credId, prfOutput)
    }

    private suspend fun finishLogin(
        userId: String,
        displayName: String?,
        credId: ByteArray,
        prfOutput: PrfOutput,
    ) {
        val privateData = fetchPrivateData()

        val hkdfSalt = sessionStore.hkdfSalt?.let { b64Decode(it) }
            ?: ByteArray(32).also { SecureRandom().nextBytes(it) }
        val hkdfInfo = sessionStore.hkdfInfo?.let { b64Decode(it) }
            ?: HKDF_INFO.toByteArray(Charsets.UTF_8)
        val prfSaltBytes = sessionStore.prfSalt?.let { b64Decode(it) }
            ?: ByteArray(32).also { SecureRandom().nextBytes(it) }

        keystore.unlock(prfOutput.first, privateData, hkdfSalt, hkdfInfo)
        unlockAvailableKeystores(prfOutput.first, privateData, hkdfSalt, hkdfInfo)

        // Scope session store to this account
        val accountId = "${config.tenantId}:${userId}"
        sessionStore.activeAccountId = accountId
        accountRegistry.activeAccountId = accountId
        sessionStore.userId = userId
        sessionStore.displayName = displayName
        sessionStore.tenantId = config.tenantId
        sessionStore.credentialId = b64UrlEncode(credId)
        sessionStore.prfSalt = b64Encode(prfSaltBytes)
        sessionStore.hkdfSalt = b64Encode(hkdfSalt)
        sessionStore.hkdfInfo = b64Encode(hkdfInfo)

        // Connect engine with anonymous token (new AS) or app token (legacy AS)
        connectEngineWithToken()

        // A new session: a cut-off met on THIS one deserves its own
        // self-driven re-login, and the 401s of the session it replaced no
        // longer do. See [sessionGeneration].
        bumpSessionGeneration()
        _state.value = WalletState.Ready(
            userId = userId,
            displayName = displayName,
            credentials = credentialStore.getAll(),
        )
        hydrateReloadedCredentials()
        reloadPresentationHistory()
    }

    /**
     * After loading credentials from a reimported private-data container
     * (fresh login here, or [unlockKeystore] after [resumeSession]), re-fetch
     * VCTM/MDDL display metadata and re-derive issuedAt/expiresAt for any
     * credential that's missing them.
     *
     * privatedata-spec's container format doesn't persist `metadata`/
     * `issuedAt`/`expiresAt` at all - wallet-frontend's own schema
     * (`WalletSessionEventNewCredential`) has no such fields either, since it
     * re-fetches/derives this live rather than snapshotting it into the
     * encrypted container. Without this, a freshly-reimported credential
     * would display with no VCTM styling/claim labels or expiry indefinitely
     * (metadata is never null for a credential saved earlier in the same
     * session, only for one just reconstructed from a container).
     *
     * ### Never a spinner for nothing
     *
     * Because this runs on every login, a type whose document can't be
     * fetched used to cost the user a network round-trip and a loading
     * indicator on its card on every launch. Two things fix that:
     *
     * 1. The fetchers share [displayMetadataCache], which remembers misses
     *    with backoff. While a retry isn't due, `fetch` returns null at once
     *    with no network.
     * 2. When no document is available, a synthesised
     *    [CredentialUtils.buildFallbackMetadata] is persisted on the
     *    credential (marked [CredentialMetadata.HYDRATION_FALLBACK]) so the
     *    UI has non-null metadata to render the flat layout from
     *    immediately. A fallback still counts as "needs hydration": it is
     *    replaced by real metadata the moment a later fetch succeeds.
     *
     * Credentials are hydrated concurrently (capped at
     * [HYDRATION_PARALLELISM]) so one slow issuer doesn't hold up the rest,
     * but [WalletState.Ready] is re-emitted exactly once at the end, as
     * before. Fire-and-forget: never blocks login/unlock.
     */
    private fun hydrateReloadedCredentials() {
        scope.launch {
            val candidates = credentialStore.getAll().filter { it.metadata?.isFallback != false }
            if (candidates.isEmpty()) return@launch
            val gate = Semaphore(HYDRATION_PARALLELISM)
            val updates = candidates
                .map { cred -> async { gate.withPermit { hydrateOne(cred) } } }
                .awaitAll()
                .filterNotNull()
            if (updates.isEmpty()) return@launch
            updates.forEach { credentialStore.save(it) }
            val fallbacks = updates.count { it.metadata?.isFallback == true }
            Timber.i(
                "Hydrated ${updates.size}/${candidates.size} reloaded credentials " +
                    "(${updates.size - fallbacks} from issuer documents, $fallbacks fallback)",
            )
            val current = _state.value
            if (current is WalletState.Ready) {
                _state.value = current.copy(credentials = credentialStore.getAll())
            }
        }
    }

    /**
     * One credential's share of [hydrateReloadedCredentials]: the credential
     * with whatever could be (re)derived applied, or null when nothing
     * changed - so an existing fallback whose retry isn't due yet is not
     * re-saved on every launch.
     */
    private suspend fun hydrateOne(cred: StoredCredential): StoredCredential? {
        val issuerIdent = cred.credentialIssuerIdentifier
        val configId = cred.credentialConfigurationId
        val canFetch = !issuerIdent.isNullOrBlank() && !configId.isNullOrBlank()
        // Only synthesise a fallback when there is no metadata at all; an
        // existing fallback stays as it is until a real document replaces it.
        fun fallbackIfNone(): CredentialMetadata? =
            if (cred.metadata == null) CredentialUtils.buildFallbackMetadata(cred) else null

        if (cred.format == "mso_mdoc") {
            // mdoc has no JWT iat/exp claims to re-derive here (ISO 18013-5
            // validity lives in the MSO's validityInfo, inside issuerAuth -
            // deliberately not parsed by this wallet, see MdocCbor's doc
            // comment: MSO parsing is a verifier-side concern this holder
            // doesn't need). Only metadata (via MDDLSchema) is re-hydrated.
            val mddlSchema = if (canFetch) {
                try {
                    mddlSchemaFetcher.fetch(
                        issuerUrl = issuerIdent!!,
                        scope = configId!!,
                        // The docType is parseable from the credential's own
                        // MSO, so the registry-first strategy can run - and
                        // the cache key then matches what issuance wrote.
                        vct = CredentialUtils.parseMdocDocument(cred)?.docType,
                        registryUrl = registryUrl,
                    )
                } catch (e: Exception) {
                    Timber.w(e, "Failed to re-fetch MDDL schema for reloaded credential ${cred.id}")
                    null
                }
            } else {
                null
            }
            val metadata = mddlSchema?.let {
                CredentialUtils.buildMdocMetadata(
                    offer = CredentialOffer(
                        credentialConfigurationId = configId!!,
                        credentialIssuerIdentifier = issuerIdent!!,
                        credentialName = cred.format,
                        issuerName = issuerIdent,
                        format = cred.format,
                    ),
                    mddlSchema = it,
                )
            } ?: fallbackIfNone()
            return metadata?.let { cred.copy(metadata = it) }
        }

        // A JWP (or anything else that isn't `<jwt>~...`) has no parseable
        // payload here; it still gets a VCTM attempt and a fallback rather
        // than being skipped and left spinning.
        val payload = CredentialUtils.parseJwtPayload(cred.raw)
        val issuedAt = payload?.get("iat")?.jsonPrimitive?.longOrNull
        val expiresAt = payload?.get("exp")?.jsonPrimitive?.longOrNull
        val vct = payload?.get("vct")?.jsonPrimitive?.contentOrNull
        val vctm = if (canFetch) {
            try {
                vctmFetcher.fetch(
                    issuerUrl = issuerIdent!!,
                    scope = configId!!,
                    vct = vct,
                    registryUrl = registryUrl,
                )
            } catch (e: Exception) {
                Timber.w(e, "Failed to re-fetch VCTM for reloaded credential ${cred.id}")
                null
            }
        } else {
            null
        }
        val metadata = vctm?.let {
            CredentialUtils.buildMetadata(
                offer = CredentialOffer(
                    credentialConfigurationId = configId ?: "",
                    credentialIssuerIdentifier = issuerIdent ?: "",
                    credentialName = cred.format,
                    issuerName = issuerIdent ?: "",
                    format = cred.format,
                ),
                vctm = it,
                rawCredential = cred.raw,
            )
        } ?: fallbackIfNone()
        val newIssuedAt = issuedAt ?: cred.issuedAt
        val newExpiresAt = expiresAt ?: cred.expiresAt
        if (metadata == null && newIssuedAt == cred.issuedAt && newExpiresAt == cred.expiresAt) return null
        return cred.copy(
            metadata = metadata ?: cred.metadata,
            issuedAt = newIssuedAt,
            expiresAt = newExpiresAt,
        )
    }

    /**
     * Detect whether the backend uses the new standalone AS or the legacy
     * wallet-backend-integrated auth endpoints.
     *
     * Probes `/auth/passkey/login/begin`. A 404 means the backend predates
     * the new AS and we should fall back to `/user/login-webauthn-*`.
     */
    private suspend fun detectAuthMode(): AuthMode {
        Timber.i("Detecting auth mode for ${config.backendUrl} (tenant=${config.tenantId})")
        return try {
            authServerClient.loginBegin()
            Timber.i("Detected new AS at ${config.backendUrl}")
            AuthMode.NEW_AS
        } catch (e: AuthException) {
            if (e.code == 404) {
                Timber.i("Detected legacy AS at ${config.backendUrl} (404 on /auth/passkey/login/begin)")
                AuthMode.LEGACY_AS
            } else {
                Timber.e(e, "Auth mode probe failed with HTTP ${e.code} at ${config.backendUrl}; surfacing error")
                throw e
            }
        } catch (e: Exception) {
            Timber.e(e, "Auth mode detection failed at ${config.backendUrl}; surfacing error")
            throw e
        }
    }

    private suspend fun ensureAuthMode() {
        if (authMode == AuthMode.UNKNOWN) {
            authMode = detectAuthMode()
        }
    }

    /**
     * Disconnect from the wallet backend, lock the keystore,
     * and clear session data.
     */
    fun logout() {
        endSessionLocally()
        // Ending the server session too is what makes this a logout rather
        // than a local teardown. Fire-and-forget is safe *here* because the
        // wallet then sits on the login screen: any login that follows is a
        // deliberate user action far removed from this DELETE. It is NOT safe
        // on the lifecycle-blocked path, where the app may retry within
        // milliseconds - see [endSessionLocally].
        scope.launch {
            try {
                authServerClient.logout()
            } catch (e: Exception) {
                Timber.w(e, "AS logout failed (non-fatal)")
            }
        }
        _state.value = disconnectedState()
        Timber.i("Logged out")
    }

    /**
     * Everything [logout] does except ending the server session: drop the
     * engine, the WMP peer, the API client, the cached tokens, the keystore
     * and the account-scoped session, and end this session's generation.
     *
     * The lifecycle-blocked path uses this rather than [logout]. A suspended
     * instance is reactivated from another device and the app then retries
     * [login], which reuses the same AS session cookie - an unawaited
     * `DELETE /auth/session` from the block could land *after* that
     * `loginFinish` and invalidate the session the retry had just
     * established. There is also nothing to end: the backend has already
     * refused this installation.
     */
    private fun endSessionLocally() {
        engineStateJob?.cancel()
        engineStateJob = null
        engineSession?.disconnect()
        engineSession = null
        scope.launch { wmpPeer?.close() }
        wmpPeer = null
        credentialNotifier = null
        keystore.lock()
        sessionStore.clear()  // clears active account's session only
        accountRegistry.activeAccountId = null
        apiClient = null
        legacyAppToken = null
        // The WIA cache is wallet-wide but the instance key it attests is
        // account-scoped, so a WIA kept across a logout would answer
        // [thisInstanceId] (and `wallet_instance_id`) with the PREVIOUS
        // account's thumbprint for the next one. It is cheap to reissue.
        cachedWia = null
        cachedWiaExpiresAt = 0
        // This session is over: a 401 still in flight from it must not be
        // taken for a cut-off worth re-logging in from, and a self-driven
        // re-login suspended in the old session's teardown must abandon
        // rather than resurrect what the user just ended.
        bumpSessionGeneration()
        scope.launch {
            try {
                authTokens.clear()
            } catch (e: Exception) {
                Timber.w(e, "Clearing cached tokens failed (non-fatal)")
            }
        }
    }

    /**
     * Resume a previous session without requiring a new WebAuthn assertion.
     *
     * Uses stored `appToken` + `refreshToken` from the previous login.
     * If the stored token is expired, it will be refreshed automatically.
     * Falls back to [WalletState.Disconnected] if no session is stored.
     *
     * Call this on app startup before showing the login screen.
     */
    suspend fun resumeSession() {
        // Restore the active account ID so the session store reads the right data
        val activeId = accountRegistry.activeAccountId
        if (activeId != null) {
            sessionStore.activeAccountId = activeId
        }
        val userId = sessionStore.userId
        if (userId == null) {
            Timber.d("No stored session to resume")
            return
        }
        _state.value = WalletState.Connecting
        try {
            ensureAuthMode()
            val displayName = sessionStore.displayName

            if (authMode == AuthMode.LEGACY_AS) {
                // Legacy mode: verify the stored appToken is still valid by fetching account info
                val storedAppToken = sessionStore.appToken
                if (storedAppToken.isNullOrBlank()) {
                    Timber.i("No stored legacy appToken, need re-login")
                    sessionStore.clear()
                    _state.value = disconnectedState()
                    return
                }
                legacyAppToken = storedAppToken
                setupApiClient(AuthSession(appToken = storedAppToken, uuid = userId, displayName = displayName))
                try {
                    apiClient?.getAccountInfo()
                } catch (e: Exception) {
                    Timber.i("Legacy session invalid, need re-login")
                    sessionStore.clear()
                    apiClient = null
                    legacyAppToken = null
                    _state.value = disconnectedState()
                    return
                }
            } else {
                // Set up the API client using AuthTokens (session cookie handles auth)
                setupApiClientWithTokens()

                // Verify the session is still valid by requesting a backend token
                try {
                    authTokens.ensureBackendToken()
                } catch (e: AuthException) {
                    if (handleLifecycleRefusal(e, activeId)) return
                    Timber.i("Session cookie expired, need re-login")
                    sessionStore.clear()
                    apiClient = null
                    _state.value = disconnectedState()
                    return
                }
            }

            // Unlock keystore from stored private data if available
            val storedJwe = sessionStore.privateDataJwe
            val hkdfSalt = sessionStore.hkdfSalt?.let { b64Decode(it) }
            val hkdfInfo = sessionStore.hkdfInfo?.let { b64Decode(it) }

            // Connect the engine with the appropriate token
            connectEngineWithToken()

            if (storedJwe != null && hkdfSalt != null && hkdfInfo != null) {
                _state.value = WalletState.KeystoreLocked(
                    userId = userId,
                    displayName = displayName,
                )
                Timber.i("Session resumed for user $userId (keystore locked — call unlockKeystore())")
            } else {
                _state.value = WalletState.Ready(
                    userId = userId,
                    displayName = displayName,
                    credentials = emptyList(),
                )
                Timber.i("Session resumed for user $userId (no private data)")
            }
        } catch (e: SirosException) {
            if (handleLifecycleRefusal(e, activeId)) return
            Timber.e(e, "Session resume failed")
            _state.value = disconnectedState()
        } catch (e: Exception) {
            if (handleLifecycleRefusal(e, activeId)) return
            Timber.e(e, "Session resume failed")
            _state.value = disconnectedState()
        }
    }

    /**
     * Unlock the keystore after a session resume.
     *
     * Call this when the wallet is in [WalletState.KeystoreLocked].
     * Triggers a WebAuthn assertion (biometric prompt) to obtain the PRF
     * output needed to decrypt the keystore and credentials.
     *
     * After a successful unlock the state transitions to [WalletState.Ready].
     */
    suspend fun unlockKeystore() {
        val current = _state.value
        if (current !is WalletState.KeystoreLocked) {
            Timber.w("unlockKeystore called but state is $current")
            return
        }
        // The session this unlock belongs to, captured before anything can end
        // it, so a lifecycle refusal met here names the right account.
        val refusedAccountId = accountRegistry.activeAccountId
        try {
            val storedPrfSalt = sessionStore.prfSalt?.let { b64Decode(it) }
            val prfOutput = if (authMode == AuthMode.LEGACY_AS) {
                // Legacy backend: re-authenticate via the wallet-backend endpoint
                val session = legacyAuthClient.login(prfSalt = storedPrfSalt)
                legacyAppToken = session.appToken
                sessionStore.appToken = session.appToken
                extractLastPrfOutput()
                    ?: throw WalletException("PRF not available from authenticator")
            } else {
                // New AS: use AS login flow to get PRF output via biometric assertion
                val challengeResponse = authServerClient.loginBegin()
                val challengeId = challengeResponse["challengeId"]?.jsonPrimitive?.contentOrNull
                    ?: throw WalletException("Missing challengeId")
                val getOptions = challengeResponse["getOptions"]?.jsonObject
                    ?: throw WalletException("Missing getOptions")
                val publicKey = getOptions["publicKey"]?.jsonObject
                    ?: throw WalletException("Missing publicKey")
                val rpId = publicKey["rpId"]?.jsonPrimitive?.contentOrNull
                    ?: throw WalletException("Missing rpId")
                val challenge = WebAuthnAuthClient.decodeBase64Url(publicKey["challenge"]?.jsonPrimitive?.contentOrNull
                    ?: throw WalletException(MISSING_CHALLENGE))

                val result = authProvider.authenticate(
                    org.siros.sdk.auth.AuthenticateOptions(
                        rpId = rpId,
                        challenge = challenge,
                        prfSalt = storedPrfSalt,
                    )
                )

                // Complete login with AS (also refreshes the session cookie)
                val credentialJson = kotlinx.serialization.json.buildJsonObject {
                    put("id", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.credentialId)))
                    put("rawId", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.credentialId)))
                    put("type", kotlinx.serialization.json.JsonPrimitive("public-key"))
                    put("response", kotlinx.serialization.json.buildJsonObject {
                        put("authenticatorData", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.authenticatorData)))
                        put("clientDataJSON", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.clientDataJSON)))
                        put("signature", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.signature)))
                        result.userHandle?.let { put("userHandle", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(it))) }
                    })
                }
                authServerClient.loginFinish(challengeId = challengeId, credential = credentialJson)

                // Same reason as finishLogin's identical assignment: this is
                // also a completed passkey ceremony, and a session resumed
                // from an older SDK (or one whose stored id went stale) would
                // otherwise reach WIA generation with no `credential_id` to
                // bind the instance to. The store is already scoped to the
                // resumed account here.
                sessionStore.credentialId = b64UrlEncode(result.credentialId)

                extractLastPrfOutput()
                    ?: throw WalletException("PRF not available from authenticator")
            }

            val storedJwe = sessionStore.privateDataJwe
            val hkdfSalt = sessionStore.hkdfSalt?.let { b64Decode(it) }
                ?: throw WalletException("Missing HKDF salt")
            val hkdfInfo = sessionStore.hkdfInfo?.let { b64Decode(it) }
                ?: HKDF_INFO.toByteArray(Charsets.UTF_8)

            val privateData = storedJwe?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)
            keystore.unlock(prfOutput.first, privateData, hkdfSalt, hkdfInfo)
            unlockAvailableKeystores(prfOutput.first, privateData, hkdfSalt, hkdfInfo)

            _state.value = WalletState.Ready(
                userId = current.userId,
                displayName = current.displayName,
                credentials = credentialStore.getAll(),
            )
            hydrateReloadedCredentials()
            reloadPresentationHistory()
            Timber.i("Keystore unlocked after session resume")
        } catch (e: KeystoreException) {
            Timber.e(e, "Keystore unlock failed: corrupt container")
            _state.value = WalletState.Error(e.message ?: "Keystore unlock failed")
        } catch (e: AuthException) {
            if (handleLifecycleRefusal(e, refusedAccountId)) return
            Timber.e(e, "Keystore unlock failed: authentication error")
            _state.value = WalletState.Error(e.message ?: "Authentication failed")
        } catch (e: SirosException) {
            if (handleLifecycleRefusal(e, refusedAccountId)) return
            Timber.e(e, "Keystore unlock failed")
            _state.value = WalletState.Error(e.message ?: "Keystore unlock failed")
        } catch (e: Exception) {
            if (handleLifecycleRefusal(e, refusedAccountId)) return
            Timber.e(e, "Keystore unlock failed")
            _state.value = WalletState.Error(e.message ?: "Keystore unlock failed")
        }
    }

    /**
     * Release all resources held by this wallet instance.
     *
     * Call this when the host Activity is destroyed or the wallet is
     * no longer needed. After calling [destroy], this instance must
     * not be used again — create a new one with [create].
     */
    fun destroy() {
        // Same reason as logout()'s: a self-driven re-login still suspended in
        // the old session's teardown must not log back in after the host has
        // torn this wallet down. The flag is what stops a *later* signal - the
        // state is deliberately left as it was (a destroyed wallet is not a
        // logged-out one), so it would otherwise still look replaceable.
        isDestroyed = true
        bumpSessionGeneration()
        activity.applicationContext.unregisterComponentCallbacks(memoryPressureCallbacks)
        zkPresentation.releaseProvers()
        engineSession?.disconnect()
        engineSession = null
        scope.launch { wmpPeer?.close() }
        wmpPeer = null
        credentialNotifier = null
        keystore.lock()
        apiClient = null
        supervisorJob.cancel()
        Timber.i("Wallet instance destroyed")
    }

    /**
     * Get credentials, excluding expired ones.
     *
     * @param includeExpired when true, returns all credentials including expired.
     */
    suspend fun getCredentials(includeExpired: Boolean = false): List<StoredCredential> {
        val all = credentialStore.getAll()
        if (includeExpired) return all
        val now = System.currentTimeMillis() / 1000
        return all.filter { cred ->
            val exp = cred.expiresAt
            exp == null || exp > now
        }
    }

    /**
     * Sign an mDoc DeviceResponse for an ISO 18013-5 proximity (BLE)
     * presentation - the local, engine-free counterpart to the redirect/
     * DC-API presentation paths (`handleSignRequest`/`handleWmpSignRequest`),
     * since proximity presentation has no wallet-backend/engine round trip
     * at all: the reader IS the counterpart, connected directly over BLE.
     *
     * @param credentialId the [StoredCredential.id] of the mdoc credential to present.
     * @param disclosedClaims element identifiers to disclose (see [DeviceRequestParser.DocRequest.disclosedClaims]).
     * @param sessionTranscriptBytes the proximity `SessionTranscript` bytes, from `ProximitySessionTranscript.build`.
     * @return CBOR-encoded DeviceResponse bytes.
     */
    suspend fun signMdocPresentationForProximity(
        credentialId: Long,
        disclosedClaims: List<String>?,
        sessionTranscriptBytes: ByteArray,
    ): ByteArray {
        val credential = credentialStore.getById(credentialId)
            ?: throw WalletException("Credential not found: $credentialId")
        val allInstances = credentialStore.getAll().filter { it.batchId == credential.batchId }
        if (eligibleInstances(allInstances).none { it.id == credentialId }) {
            throw WalletException("No eligible copies of this credential remain - renew it to get more")
        }
        val response = keystore.signMdocPresentationForProximity(
            credentialBytes = CredentialUtils.decodeMdocRawBytes(credential),
            disclosedClaims = disclosedClaims,
            sessionTranscriptBytes = sessionTranscriptBytes,
            kid = credential.kid,
        )
        recordPresentation(PresentationRecord(
            id = randomUint32Id(),
            flowId = "proximity-${java.util.UUID.randomUUID()}",
            credentialIds = listOf(credentialId),
            credentialNames = listOfNotNull(credential.metadata?.name),
            requestedClaims = disclosedClaims ?: emptyList(),
            timestamp = System.currentTimeMillis(),
        ))
        return response
    }

    /**
     * Fetch the list of available credential issuers from the backend.
     *
     * Requires an active session (call after [login] or [register]).
     * Each [IssuerEntry] contains the issuer URL; call [getAvailableCredentials]
     * to discover what credentials each issuer offers.
     */
    suspend fun getIssuers(): List<IssuerEntry> = withContext(Dispatchers.IO) {
        val client = apiClient ?: throw WalletException(NOT_CONNECTED)
        val response = client.getIssuers()
        // Backend user API returns a plain JSON array, admin API wraps in {"issuers": [...]}
        val arr = when (response) {
            is kotlinx.serialization.json.JsonArray -> response
            is kotlinx.serialization.json.JsonObject ->
                response["issuers"]?.jsonArray
                    ?: response["data"]?.jsonArray
                    ?: throw WalletException("Unexpected issuer list format")
            else -> throw WalletException("Unexpected issuer response type")
        }
        arr.map { json.decodeFromJsonElement(IssuerEntry.serializer(), it) }
            .filter { it.visible }
    }

    /**
     * Fetch OpenID4VCI credential issuer metadata for a given issuer URL.
     *
     * Prefers the backend proxy (which caches metadata and handles
     * internal network access). Falls back to a direct HTTP call if
     * no authenticated session is available.
     */
    suspend fun getIssuerMetadata(
        issuerUrl: String,
        credentialTypes: List<String> = emptyList(),
    ): IssuerMetadata = resolveIssuerMetadata(issuerUrl, credentialTypes).metadata

    /**
     * Issuer metadata together with what the backend concluded about it.
     *
     * [entitlement] is null when the backend was not consulted - see
     * [resolveIssuerMetadata] - and a null entitlement means "not checked",
     * never "checked and fine".
     */
    data class ResolvedIssuerMetadata(
        val metadata: IssuerMetadata,
        val entitlement: IssuerEntitlement? = null,
        val trusted: Boolean? = null,
    )

    /**
     * Resolve issuer metadata, preferring the backend so the document arrives
     * authenticated rather than merely fetched.
     *
     * The backend verifies the signed_metadata JWS, evaluates the signer
     * against the trust registry, and reports whether the provider is
     * registered to issue [credentialTypes] (ARF section 6.6.2.3). Doing this
     * wallet-side would mean a second certificate-handling implementation in
     * every SDK language, kept in sync by hand.
     *
     * Falls back to fetching the well-known document directly when there is no
     * authenticated session. That path returns metadata that is parsed but not
     * authenticated, so [ResolvedIssuerMetadata.entitlement] is left null and
     * callers must not read the absence of findings as a pass.
     */
    suspend fun resolveIssuerMetadata(
        issuerUrl: String,
        credentialTypes: List<String> = emptyList(),
    ): ResolvedIssuerMetadata = withContext(Dispatchers.IO) {
        val client = apiClient
        if (client != null) {
            try {
                val resolved = client.resolveIssuer(issuerUrl, credentialTypes)
                val metadataJson = resolved["context"]?.jsonObject?.get("trust_metadata")?.jsonObject
                if (metadataJson != null) {
                    return@withContext ResolvedIssuerMetadata(
                        metadata = json.decodeFromJsonElement(IssuerMetadata.serializer(), metadataJson),
                        entitlement = resolved["issuer_entitlement"]?.let {
                            json.decodeFromJsonElement(IssuerEntitlement.serializer(), it)
                        },
                        trusted = resolved["decision"]?.jsonPrimitive?.booleanOrNull,
                    )
                }
                Timber.w("Backend resolve returned no metadata for $issuerUrl; falling back to a direct fetch")
            } catch (e: Exception) {
                // A backend that is unreachable must not make issuance
                // impossible, but the caller has to be able to tell that the
                // checks did not run - hence a null entitlement below.
                Timber.w(e, "Backend resolve failed for $issuerUrl; falling back to a direct fetch")
            }
        }

        val url = issuerUrl.trimEnd('/') + "/.well-known/openid-credential-issuer"
        val request = Request.Builder().url(url).get().build()
        val response = httpClient.newCall(request).execute()
        val body = response.body?.string()
            ?: throw WalletException("Empty metadata response from $issuerUrl")
        if (!response.isSuccessful) {
            throw WalletException("Metadata fetch failed: ${response.code}")
        }
        ResolvedIssuerMetadata(json.decodeFromString(IssuerMetadata.serializer(), body))
    }

    /**
     * The backend's entitlement decision for one credential configuration, or
     * null if it could not be obtained.
     *
     * Null means "not checked", and a check that could not run must not block
     * issuance - the same distinction the backend draws between "revoked" and
     * "could not determine". Making issuance depend on this round-trip
     * succeeding would turn a backend outage into an outage for every issuer.
     */
    private suspend fun issuerEntitlementFor(issuerUrl: String, configurationId: String): IssuerEntitlement? =
        try {
            resolveIssuerMetadata(issuerUrl, listOf(configurationId)).entitlement
        } catch (e: Exception) {
            Timber.w(e, "Could not obtain an entitlement decision for $issuerUrl; proceeding unchecked")
            null
        }

    /**
     * Refuse issuance when the backend says the provider is not registered to
     * issue what it is offering.
     *
     * Mirrors the guard the DC API verifier path already applies: a decision is
     * computed and then acted on, rather than computed and ignored. Warn mode
     * reports findings while leaving [IssuerEntitlement.allowed] true, so this
     * only throws when the deployment has asked it to.
     */
    private fun enforceIssuerEntitlement(issuerUrl: String, entitlement: IssuerEntitlement?) {
        if (entitlement == null || entitlement.allowed) {
            if (entitlement != null && entitlement.findings.isNotEmpty()) {
                Timber.w(
                    "Issuer $issuerUrl has entitlement findings (mode=${entitlement.mode}): " +
                        entitlement.findings.joinToString { "${it.code}: ${it.message}" },
                )
            }
            return
        }
        val reasons = entitlement.findings.joinToString { "${it.code}: ${it.message}" }
        throw WalletException("Issuer '$issuerUrl' is not registered to issue this credential: $reasons")
    }

    /**
     * The credential type this flow was authorised to receive, or null if the
     * wallet never resolved one.
     *
     * This is the type whose metadata was fetched, whose WSCD requirement was
     * applied, and which the issuer's registration was checked against - the
     * same chain [resolveEffectiveKeystoreForIssuance] keys on. The credential
     * configuration ID is deliberately NOT a fallback here: it is an
     * OID4VCI-internal identifier, not a credential type, so comparing a `vct`
     * against it would fail every time and refuse legitimate issuance.
     */
    private fun authorisedCredentialType(format: String): String? =
        if (format == "mso_mdoc") {
            // The offer first: it is what the entitlement check was run
            // against, and unlike the resolved schema it is present even when
            // metadata resolution failed. Taking only the resolved metadata
            // would make this check a no-op in exactly the situation where the
            // wallet knows least about the credential.
            activeOffer?.doctype ?: activeMddlSchema?.doctype
        } else {
            activeOffer?.vct ?: activeVctm?.vct
        }

    /**
     * Refuse a credential whose issuer pinned its type metadata to something
     * other than what the wallet resolved.
     *
     * SD-JWT VC Type Metadata lets the credential carry `vct#integrity`, a
     * digest over the type metadata document. It exists so the *issuer* decides
     * what a credential type means. Without checking it, whoever serves the
     * registry decides how the credential is displayed and which claims it is
     * understood to carry - independently of the issuer who vouched for it, and
     * even for a type the issuer is legitimately registered to issue.
     *
     * Only checked when the credential asks for it. A credential with no
     * `vct#integrity` is not making a claim about its metadata, so there is
     * nothing to disagree with.
     */
    private suspend fun verifyVctIntegrity(
        format: String,
        payload: JsonObject,
        offer: org.siros.sdk.credentials.CredentialOffer?,
        document: org.siros.sdk.credentials.VctmDocument?,
    ): VctIntegrityCheck {
        if (format == "mso_mdoc") return VctIntegrityCheck.ACCEPTED
        val expected = payload["vct#integrity"]?.jsonPrimitive?.contentOrNull
            ?: return VctIntegrityCheck.ACCEPTED

        if (document != null && Integrity.matches(document.raw.toByteArray(Charsets.UTF_8), expected)) {
            return VctIntegrityCheck.ACCEPTED
        }

        // What was resolved before issuance is not what the issuer signed over
        // - or nothing was resolved at all. Both are ordinary: the document may
        // have been cached before the issuer changed it, or fetched from a
        // source serving a different copy, and a cached failure can outlive the
        // fix for it. So resolve again, this time directed by the pin, and let
        // the credential through if the issuer's own document can still be
        // found. Only a wallet that cannot find it anywhere refuses.
        val resolved = try {
            offer?.let { offer ->
                vctmFetcher.fetchDocument(
                    issuerUrl = offer.credentialIssuerIdentifier,
                    scope = offer.credentialConfigurationId,
                    vct = offer.vct,
                    registryUrl = registryUrl,
                    expectedIntegrity = expected,
                )
            }
        } catch (e: Exception) {
            Timber.w(e, "Re-resolving type metadata against the issuer's vct#integrity failed")
            null
        }

        if (resolved != null) {
            Timber.i("Type metadata re-resolved to the document the issuer pinned")
            return VctIntegrityCheck(refreshed = resolved)
        }

        if (document == null) {
            // Nothing was applied, so nothing was tampered with - but say so,
            // because a credential asking to be checked and not being checked
            // is exactly the state this method exists to make visible.
            Timber.w("Credential pinned vct#integrity but no type metadata could be resolved to check it against")
            return VctIntegrityCheck.ACCEPTED
        }

        Timber.e("Type metadata for '${document.vctm.vct}' does not match the issuer's vct#integrity")
        return VctIntegrityCheck(reason = "The issuer's type metadata does not match what it published")
    }

    /**
     * What [verifyVctIntegrity] decided: a refusal [reason], or the document a
     * re-resolution settled on when one happened.
     *
     * The refreshed document is handed back rather than written into
     * [activeVctm]/[activeVctmDocument] on the way past. [verifyVctIntegrity]
     * suspends on the network, and [resetIssuanceGuards] - which a cancelled
     * flow or a logout calls - clears those fields and lets a new issuance
     * populate them in the meantime. A write there would then be the *old*
     * flow overwriting the new flow's metadata with its own pinned document.
     * The caller applies it to the one credential it is storing, which is the
     * only thing the re-resolution was ever about: it answers "is THIS
     * credential's pinned document findable", not "what should the wallet now
     * believe about the flow".
     */
    private data class VctIntegrityCheck(
        val reason: String? = null,
        val refreshed: org.siros.sdk.credentials.VctmDocument? = null,
    ) {
        companion object {
            val ACCEPTED = VctIntegrityCheck()
        }
    }

    /**
     * Refuse a credential whose declared type is not the one this flow was
     * authorised to receive.
     *
     * Every earlier decision in the issuance path - the issuer's entitlement
     * under ARF section 6.6.2.3, which type metadata to apply, which WSCD to
     * use - was made about the type the issuer *advertised*. None of them
     * looked at what actually arrived. Without this, an issuer entitled to one
     * attestation type could deliver another and have every one of those
     * decisions stand, made about the wrong credential.
     *
     * Returns a failure reason, or null when the credential is acceptable.
     * A type that could not be determined on either side is not a mismatch:
     * as everywhere else in this path, a check that could not run must not
     * become a refusal.
     */
    private fun verifyIssuedType(format: String, raw: String): String? {
        val authorised = authorisedCredentialType(format) ?: return null
        val declared = CredentialUtils.declaredType(format, raw) ?: return null
        if (declared == authorised) return null
        Timber.e("Issuer delivered type '$declared' for an offer authorised as '$authorised'")
        return "Issuer delivered a '$declared' credential, but this offer was for '$authorised'"
    }

    /**
     * In-memory cache for this session's Wallet Instance Attestation (WIA) -
     * refetched when missing or close to expiry (see
     * [ensureWalletInstanceAttestation]). Not persisted across app restarts:
     * cheap to reissue given a challenge round trip, unlike the instance KEY
     * itself ([SessionStore.instanceKeyId]), which must stay stable.
     */
    private var cachedWia: String? = null
    private var cachedWiaExpiresAt: Long = 0

    /**
     * Get (creating once, on first use) this wallet installation's persistent
     * OAuth Client Attestation instance key ID - see [SessionStore.instanceKeyId].
     */
    private suspend fun ensureInstanceKeyId(): String {
        sessionStore.instanceKeyId?.let { return it }
        // First use has to be serialised. Two callers arriving together - an
        // engine `request_attestation` and a Devices listing, say - would
        // otherwise each generate an ES256 key and each persist it, and
        // whichever lost the race would already have published a WIA for a key
        // the store no longer names. The instance id the backend knows would
        // then disagree with the one this wallet proves, breaking later PoPs
        // and [WalletInstance.isThisDevice].
        // The account it is for is captured first: [SessionStore.instanceKeyId]
        // is account-scoped, so a logout/login that switches accounts while a
        // generation is in flight must not let it persist the old account's
        // key into the new account's scope - that would attest the new account
        // under the wrong lifecycle identity.
        val account = sessionStore.activeAccountId
        return instanceKeyMutex.withLock {
            // Re-check: a caller that was waiting here may have persisted one.
            sessionStore.instanceKeyId ?: run {
                val keyId = keystore.generateKey("ES256")
                if (sessionStore.activeAccountId != account) {
                    throw WalletException("Account changed while generating the wallet instance key")
                }
                sessionStore.instanceKeyId = keyId
                keyId
            }
        }
    }

    /** Serialises first-use instance-key creation; see [ensureInstanceKeyId]. */
    private val instanceKeyMutex = Mutex()

    /**
     * Obtain (fetching + caching, refreshing before expiry) a Wallet Instance
     * Attestation for this wallet instance from this wallet's own backend
     * (draft-ietf-oauth-attestation-based-client-auth-10 §3.1 / CS-04 §7.1.2):
     * request a single-use challenge, sign a PoP JWT over it with the
     * instance key, and exchange both for a WIA JWT.
     *
     * Best-effort: returns null on any failure (network, backend not
     * configured for WIA, etc.) rather than throwing - a missing/unavailable
     * client attestation must never block issuance, since not every backend
     * deployment enables this feature.
     */
    private suspend fun ensureWalletInstanceAttestation(): String? {
        val now = System.currentTimeMillis() / 1000
        cachedWia?.let { wia -> if (cachedWiaExpiresAt - now > 60) return wia }
        return try {
            val client = apiClient ?: return null
            // The session this attestation is being fetched for; see where it
            // is published below.
            val generation = sessionGeneration
            val keyId = ensureInstanceKeyId()
            val challengeResponse = client.requestWIAChallenge()
            val challenge = challengeResponse["challenge"]?.jsonPrimitive?.contentOrNull
                ?: return null
            val pop = keystore.generateKeyProof(
                keyId = keyId,
                typ = "oauth-client-attestation-pop+jwt",
                // iss doesn't need to equal client_id for THIS PoP - it's
                // validated by our own backend (WIAService.validatePop only
                // checks iss is non-empty), unlike the per-issuer PoP built in
                // buildClientAttestationPoP. clientAttestationClientId() is
                // still a reasonable choice: consistent, and non-empty.
                issuer = clientAttestationClientId(),
                // Must match the backend's configured wallet_provider_uri, if
                // it enforces one (WIAService.validatePop only checks aud
                // when that's non-empty) - the base backend URL is the only
                // value discoverable client-side without a dedicated endpoint.
                audience = config.backendUrl,
                extraClaims = mapOf("nonce" to challenge),
            )
            // Best-effort, on its OWN try/catch (not the outer one): a
            // native-attestation failure must degrade to a plain
            // backend-attested WIA, not abort issuance entirely.
            val nativeAttestation = config.nativeAttestationProvider?.let { provider ->
                try {
                    val evidence = provider.generateEvidence(challenge, keyId)
                    buildJsonObject {
                        put("type", kotlinx.serialization.json.JsonPrimitive(evidence.type))
                        put("token", kotlinx.serialization.json.JsonPrimitive(evidence.token))
                        put("key_id", kotlinx.serialization.json.JsonPrimitive(evidence.keyId))
                        put("challenge", kotlinx.serialization.json.JsonPrimitive(evidence.challenge))
                    }
                } catch (e: kotlinx.coroutines.CancellationException) {
                    // Must propagate, not degrade to null - swallowing this
                    // breaks structured concurrency (e.g. the parent scope
                    // being cancelled during issuance would silently fail to
                    // stop this coroutine).
                    throw e
                } catch (e: Exception) {
                    Timber.w(e, "Native attestation evidence generation failed, continuing without it")
                    null
                }
            }
            // draft-ietf-oauth-attestation-based-client-auth-10: "the sub
            // claim MUST specify client_id value of the OAuth Client" -
            // confirmed via a real geneva2026.mdoc.online conformance run
            // that flagged sub=<instance jkt> as a FAIL.
            val clientId = clientAttestationClientId()
            // Links this instance to the passkey it logs in with, so
            // suspending or revoking the instance also refuses login with
            // that passkey (SID-AUTH-06, go-wallet-backend#319).
            val linkedCredentialId = sessionStore.credentialId?.takeIf { it.isNotBlank() }
            val wia = try {
                client.generateWIA(
                    pop = pop,
                    challenge = challenge,
                    clientId = clientId,
                    nativeAttestation = nativeAttestation,
                    credentialId = linkedCredentialId,
                )
            } catch (e: BackendApiException) {
                // The passkey this session recorded is not one of the
                // caller's own (a session store carried over from another
                // account, a passkey deleted server-side). The first link
                // recorded for an instance wins, so never guess a different
                // id - drop the stale one and let the instance be attested
                // without a passkey link rather than losing the attestation.
                if (e.code != 403 || e.apiErrorCode() != ERROR_CREDENTIAL_NOT_OWNED || linkedCredentialId == null) throw e
                Timber.w(
                    "Backend refused the recorded passkey link (CREDENTIAL_NOT_OWNED) — " +
                        "clearing it and retrying the attestation without it"
                )
                sessionStore.credentialId = null
                client.generateWIA(
                    pop = pop,
                    challenge = challenge,
                    clientId = clientId,
                    nativeAttestation = nativeAttestation,
                    credentialId = null,
                )
            }
            // Only publish a WIA that still belongs to the session that asked
            // for it. This function suspends several times, and a logout,
            // account switch or new login landing in that window resets the
            // cache; storing afterwards would make [thisInstanceId] and
            // currentWalletInstanceId() answer with the PREVIOUS account's
            // thumbprint for the new session. The caller still gets its own
            // result - it is only the cache that is refused.
            if (sessionGeneration == generation) {
                cachedWia = wia
                cachedWiaExpiresAt = CredentialUtils.parseJwtPayload(wia)
                    ?.get("exp")?.jsonPrimitive?.longOrNull ?: (now + 300)
            }
            wia
        } catch (e: Exception) {
            Timber.w(e, "Failed to obtain Wallet Instance Attestation")
            null
        }
    }

    /**
     * The wallet_instance_id to send with a Key Attestation request: the
     * JWK Thumbprint (`cnf.jkt`) of the current session's WIA-issued
     * instance key, but only when that WIA's `attestation_source` is a
     * verified native platform attestation (ios_app_attest /
     * android_play_integrity) - go-wallet-backend's KA trust gate clamps to
     * K3 for anything else anyway, so there's no value in sending an ID that
     * won't lift the clamp, and every other failure mode (no WIA, WIA
     * disabled, non-native tier) must resolve to omitting the field exactly
     * like today's pre-this-change behavior.
     *
     * Peeks the existing WIA cache only - deliberately does NOT call
     * [ensureWalletInstanceAttestation] (real Copilot-review finding: that
     * would trigger a challenge+generateWIA network round trip, and retry it
     * on every backend key-attestation attempt in deployments where WIA is
     * unsupported/misconfigured, adding latency and log spam for a field
     * that's optional in the first place). A WIA obtained earlier this
     * session (e.g. during issuance) is still picked up; one that was never
     * fetched simply omits the field, exactly like today's behavior.
     */
    private fun currentWalletInstanceId(): String? {
        val now = System.currentTimeMillis() / 1000
        val wia = cachedWia?.takeIf { cachedWiaExpiresAt - now > 60 } ?: return null
        val nativeAttestationSources = setOf("ios_app_attest", "android_play_integrity")
        val payload = CredentialUtils.parseJwtPayload(wia) ?: return null
        val source = payload["attestation_source"]?.jsonPrimitive?.contentOrNull
        if (source !in nativeAttestationSources) return null
        return instanceKeyThumbprint()
    }

    /**
     * The JWK thumbprint of this installation's instance key - the id the
     * backend registers this wallet instance under, and the value
     * [currentWalletInstanceId] sends as `wallet_instance_id`. Read from the
     * `cnf.jkt` of the WIA this session already holds rather than recomputed,
     * so it is exactly the id the backend knows. Null when no unexpired WIA
     * has been obtained yet. Exposed as [thisInstanceId].
     */
    private fun instanceKeyThumbprint(): String? {
        val now = System.currentTimeMillis() / 1000
        val wia = cachedWia?.takeIf { cachedWiaExpiresAt - now > 60 } ?: return null
        return CredentialUtils.parseJwtPayload(wia)
            ?.get("cnf")?.jsonObject?.get("jkt")?.jsonPrimitive?.contentOrNull
    }

    /**
     * The OAuth `client_id` this wallet uses in OID4VCI/OID4VP flows.
     * Mirrors go-wallet-backend's `OID4VCIHandler.clientID` default
     * (`h.clientID = h.redirectURI`, OID4VCI §7.1's unregistered-client
     * convention). Used as the WIA's `sub`, and as the per-flow PoP `iss`
     * fallback only: the engine's `request_attestation` sign request carries
     * the flow's *effective* client_id (including any registered per-issuer
     * override the client can't otherwise see), which
     * [handleRequestAttestation] prefers.
     */
    private fun clientAttestationClientId(): String = config.redirectUri

    /**
     * Sign a per-flow OAuth Client Attestation PoP
     * (`oauth-client-attestation-pop+jwt`, draft-ietf-oauth-attestation-based-client-auth-10
     * §4.2) with this instance's key: `aud` = [asUrl] (the authorization
     * server the PAR/token request is sent to), `iss` = [clientId] (must equal
     * the WIA's `sub`), plus the AS's `challenge` when it publishes a
     * `challenge_endpoint` - see [fetchAttestationChallenge].
     *
     * Driven by the engine-requested `request_attestation` sign action, where
     * go-wallet-backend supplies [asUrl]/[clientId] itself after resolving the
     * issuer's metadata (its `SignActionRequestAttestation`) - see
     * [handleRequestAttestation].
     *
     * Best-effort: returns null on any failure rather than throwing.
     */
    private suspend fun buildClientAttestationPoP(asUrl: String, clientId: String): String? {
        return try {
            val challenge = fetchAttestationChallenge(asUrl)
            val keyId = ensureInstanceKeyId()
            keystore.generateKeyProof(
                keyId = keyId,
                typ = "oauth-client-attestation-pop+jwt",
                issuer = clientId,
                audience = asUrl,
                extraClaims = challenge?.let { mapOf("challenge" to it) } ?: emptyMap(),
            )
        } catch (e: Exception) {
            Timber.w(e, "Failed to generate client attestation PoP")
            null
        }
    }

    /**
     * Answer the engine's `request_attestation` sign request
     * (go-wallet-backend `SignActionRequestAttestation`): the backend sends it
     * from `OID4VCIHandler.Execute` once it has resolved the issuer's
     * authorization server, whenever the flow_start carried no attestation,
     * with `params.audience` = that AS (the PoP `aud`) and `params.issuer` =
     * the flow's effective OAuth client_id (the PoP `iss`).
     *
     * ALWAYS sends exactly one sign_response: the WIA + PoP when available,
     * otherwise an empty one so the backend proceeds without wallet
     * attestation immediately - its `RequestSign` otherwise blocks the whole
     * issuance for its 30 s `ErrSignTimeout` waiting on us. Never throws.
     */
    private suspend fun handleRequestAttestation(engine: WalletEngineSession, msg: SignRequestMessage) {
        val audience = msg.params.audience?.takeIf { it.isNotBlank() }
        val clientId = msg.params.issuer?.takeIf { it.isNotBlank() } ?: clientAttestationClientId()
        var wia: String? = null
        var pop: String? = null
        try {
            if (audience == null) {
                Timber.w("request_attestation for flow ${msg.flowId} carried no audience; declining")
            } else {
                wia = ensureWalletInstanceAttestation()
                if (wia == null) {
                    Timber.d("No Wallet Instance Attestation available for flow ${msg.flowId}; declining")
                } else {
                    pop = buildClientAttestationPoP(audience, clientId)
                }
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.w(e, "Failed to resolve client attestation for flow ${msg.flowId}; declining")
        }
        val attested = wia != null && pop != null
        Timber.d("Sending request_attestation response for flow ${msg.flowId} (attested=$attested, aud=$audience, iss=$clientId)")
        engine.sendSignResponse(
            flowId = msg.flowId,
            messageId = msg.messageId,
            clientAttestation = if (attested) wia else null,
            clientAttestationPoP = if (attested) pop else null,
        )
    }

    /**
     * What one `sign_client_auth` request produced - see [buildClientAuth].
     * [keyId] is null only when even naming the key failed, which the engine
     * reads as "action unsupported" and falls back to its own DPoP key.
     */
    private data class ClientAuthMaterial(
        val keyId: String?,
        val dpopProof: String?,
        val wia: String?,
        val pop: String?,
    )

    /**
     * What the engine asked for in one `sign_client_auth` (or legacy
     * `request_attestation`) sign request, transport-agnostic - the legacy
     * `SignRequestParams` and the WMP `SignSubFlowParams` both map onto it.
     * Null/blank members mean "not asked for".
     */
    private data class ClientAuthRequest(
        val keyIdHint: String? = null,
        val audience: String? = null,
        val issuer: String? = null,
        val htm: String? = null,
        val htu: String? = null,
        val dpopNonce: String? = null,
        val ath: String? = null,
    )

    /**
     * Produce the client authentication material the engine asked for in one
     * `sign_client_auth` sign request (go-wallet-backend#317), transport-
     * agnostic: [handleSignClientAuth] (legacy engine transport) and
     * [handleWmpSignRequest] (WMP) both call this.
     *
     * The key is this wallet's instance key ([ensureInstanceKeyId]) - the
     * same key [ensureWalletInstanceAttestation] binds as the WIA `cnf`, so
     * the DPoP-bound token and the attestation are bound to one key (EC TS03
     * §2.2.1.1). On a renewal the engine names the key it must be
     * ([keyIdHint], the `dpop_key_id` this wallet returned at issuance) and
     * that is used instead. A DPoP proof is produced when [htm]/[htu] are
     * given; a WIA and a **fresh** PoP (new `jti`, `aud` = [audience]) when
     * [audience] is given. Never throws: whatever could not be produced is
     * simply absent, and the engine decides what that means for the request
     * it was building (a missing DPoP proof fails it; missing attestation
     * proceeds unattested).
     */
    private suspend fun buildClientAuth(flowId: String, req: ClientAuthRequest): ClientAuthMaterial {
        val (keyIdHint, audience, issuer, htm, htu, dpopNonce, ath) = req
        val clientId = issuer?.takeIf { it.isNotBlank() } ?: clientAttestationClientId()
        var keyId: String? = null
        var dpopProof: String? = null
        var wia: String? = null
        var pop: String? = null
        try {
            keyId = keyIdHint?.takeIf { it.isNotBlank() } ?: ensureInstanceKeyId()
            if (!htm.isNullOrBlank() && !htu.isNullOrBlank()) {
                dpopProof = keystore.generateDPoPProof(
                    keyId = keyId,
                    htm = htm,
                    htu = htu,
                    nonce = dpopNonce?.takeIf { it.isNotBlank() },
                    accessTokenHash = ath?.takeIf { it.isNotBlank() },
                )
            }
            if (!audience.isNullOrBlank()) {
                wia = ensureWalletInstanceAttestation()
                if (wia == null) {
                    Timber.d("No Wallet Instance Attestation available for flow $flowId; answering sign_client_auth unattested")
                } else {
                    pop = buildClientAttestationPoP(audience, clientId)
                }
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.w(e, "sign_client_auth for flow $flowId failed part-way; answering with what was produced")
        }
        val attested = wia != null && pop != null
        Timber.d(
            "sign_client_auth for flow $flowId: key=$keyId dpop=${dpopProof != null} attested=$attested aud=$audience htm=$htm"
        )
        return ClientAuthMaterial(
            keyId = keyId,
            dpopProof = dpopProof,
            wia = if (attested) wia else null,
            pop = if (attested) pop else null,
        )
    }

    /**
     * Answer the engine's `sign_client_auth` sign request on the legacy engine
     * transport - see [buildClientAuth]. ALWAYS sends exactly one
     * sign_response, like [handleRequestAttestation].
     */
    private suspend fun handleSignClientAuth(engine: WalletEngineSession, msg: SignRequestMessage) {
        val p = msg.params
        val m = buildClientAuth(
            msg.flowId,
            ClientAuthRequest(
                keyIdHint = p.keyId,
                audience = p.audience,
                issuer = p.issuer,
                htm = p.htm,
                htu = p.htu,
                dpopNonce = p.dpopNonce,
                ath = p.ath,
            ),
        )
        engine.sendSignResponse(
            flowId = msg.flowId,
            messageId = msg.messageId,
            clientAttestation = m.wia,
            clientAttestationPoP = m.pop,
            dpopKeyId = m.keyId,
            dpopProof = m.dpopProof,
        )
    }

    /**
     * Fetch a fresh attestation challenge from [asUrl]'s own metadata-published
     * `challenge_endpoint` (draft-ietf-oauth-attestation-based-client-auth-10
     * §"Challenge Endpoint"), if it publishes one. Tries the OAuth 2.0
     * Authorization Server Metadata well-known path (RFC 8414) first, falling
     * back to the OIDC discovery path for ASes that only publish there.
     *
     * Returns null (never throws) if the AS doesn't publish a challenge
     * endpoint, or on any fetch failure - the `challenge` claim is optional
     * per spec, so its absence must never block attestation entirely.
     */
    private suspend fun fetchAttestationChallenge(asUrl: String): String? {
        val metadata = fetchOAuthServerMetadata(asUrl) ?: return null
        val challengeEndpoint = metadata["challenge_endpoint"]?.jsonPrimitive?.contentOrNull ?: return null
        return try {
            withContext(Dispatchers.IO) {
                val request = Request.Builder()
                    .url(challengeEndpoint)
                    .post("{}".toRequestBody("application/json".toMediaType()))
                    .build()
                httpClient.newCall(request).execute().use { response ->
                    val body = response.body?.string()
                    if (!response.isSuccessful || body == null) return@withContext null
                    json.parseToJsonElement(body).jsonObject["attestation_challenge"]
                        ?.jsonPrimitive?.contentOrNull
                }
            }
        } catch (e: Exception) {
            Timber.d(e, "No attestation challenge available from $challengeEndpoint")
            null
        }
    }

    private suspend fun fetchOAuthServerMetadata(asUrl: String): JsonObject? = withContext(Dispatchers.IO) {
        val base = asUrl.trimEnd('/')
        for (path in listOf("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration")) {
            try {
                val request = Request.Builder().url(base + path).get().build()
                httpClient.newCall(request).execute().use { response ->
                    val body = response.body?.string()
                    if (response.isSuccessful && body != null) {
                        return@withContext json.parseToJsonElement(body).jsonObject
                    }
                }
            } catch (e: Exception) {
                // Try the next well-known path.
            }
        }
        null
    }

    /**
     * Discover all available credentials across all visible issuers.
     *
     * Returns a flat list of [CredentialOffer] items ready for display in a
     * picker UI. Each item can be passed to [startIssuanceByOffer].
     */
    suspend fun getAvailableCredentials(): List<CredentialOffer> = withContext(Dispatchers.IO) {
        val issuers = getIssuers()
        Timber.d("getAvailableCredentials: ${issuers.size} issuers")
        val client = apiClient ?: throw WalletException(NOT_CONNECTED)
        val offers = mutableListOf<CredentialOffer>()

        for (issuer in issuers) {
            try {
                val metadataJson = client.getIssuerMetadata(issuer.id)
                val metadata = json.decodeFromJsonElement(IssuerMetadata.serializer(), metadataJson)
                for (configId in metadata.credentialConfigurationsSupported.keys) {
                    buildCredentialOfferFromMetadata(issuer.credentialIssuerIdentifier, configId, metadata)
                        ?.let { offers.add(it) }
                }
            } catch (e: Exception) {
                Timber.w(e, "Failed to fetch metadata for ${issuer.credentialIssuerIdentifier}")
            }
        }
        offers
    }

    /**
     * Build a [CredentialOffer] (display name/logo/colors) for one credential
     * configuration from an issuer's already-fetched [IssuerMetadata], reading
     * the standard OID4VCI `credential_metadata.display` field (falling back to
     * the issuer's own top-level `display`). Shared by [getAvailableCredentials]
     * (lists every configuration a registered issuer supports) and
     * [startIssuance] (resolves display metadata for the single configuration
     * named in a scanned/deep-linked offer, including from issuers - e.g.
     * interop test issuers - never registered with this wallet).
     *
     * Returns null if `configId` isn't actually offered by this issuer.
     */
    private fun buildCredentialOfferFromMetadata(
        issuerUrl: String,
        configId: String,
        metadata: IssuerMetadata,
    ): CredentialOffer? {
        metadata.credentialConfigurationsSupported[configId] ?: return null
        val config = metadata.credentialConfigurationsSupported.getValue(configId)
        val issuerDisplay = metadata.display?.firstOrNull()
        val issuerName = issuerDisplay?.name
            ?: java.net.URI(issuerUrl).host
            ?: issuerUrl
        val credDisplay = config.credentialMetadata?.display?.firstOrNull()
        val credName = credDisplay?.name ?: configId
        return CredentialOffer(
            credentialConfigurationId = configId,
            credentialIssuerIdentifier = issuerUrl,
            credentialName = credName,
            credentialDescription = credDisplay?.description,
            issuerName = issuerName,
            format = config.format,
            vct = config.vct,
            doctype = config.doctype,
            backgroundColor = credDisplay?.backgroundColor
                ?: issuerDisplay?.backgroundColor,
            textColor = credDisplay?.textColor
                ?: issuerDisplay?.textColor,
            logoUri = credDisplay?.logo?.uri,
            issuerLogoUri = issuerDisplay?.logo?.uri,
        )
    }

    /**
     * Start an issuance flow for a specific credential offer.
     *
     * Constructs the OID4VCI credential_offer and sends it to the engine.
     *
     * @param replacesBatchId when set, this flow's completion supersedes an
     * existing batch (e.g. [renewCredential]'s fallback to full re-issuance
     * when no refresh_token is available) - the same batch-replacement/
     * attribute-diff logic in flow_complete that a silent [renewCredential]
     * triggers via `pendingRenewalSourceBatchId` applies here too, so the
     * old batch's credentials are deleted instead of left duplicated
     * alongside the newly-issued one.
     * @param zkInput what the holder contributes when the credential type
     * cannot be issued by the issuer alone - see [ZkIssuanceInput]. Null for
     * every ordinary credential.
     */
    suspend fun startIssuanceByOffer(
        offer: CredentialOffer,
        replacesBatchId: Long? = null,
        zkInput: ZkIssuanceInput? = null,
    ) {
        val engine = engineSession ?: throw WalletException(NOT_CONNECTED)
        ensureEngineConnected(engine)
        if (issuanceInFlight) {
            throw WalletException("Another issuance is already in progress")
        }
        issuanceInFlight = true
        pendingRenewalSourceBatchId = replacesBatchId
        activeZkIssuanceInput = zkInput
        try {
            // ARF section 6.6.2.3: before requesting issuance, check that the
            // provider registered for this credential type. Done here rather
            // than on the display paths, which deliberately swallow failures so
            // a missing card image cannot block issuance - a place that
            // swallows exceptions cannot also be where a refusal is decided.
            enforceIssuerEntitlement(
                offer.credentialIssuerIdentifier,
                issuerEntitlementFor(
                    offer.credentialIssuerIdentifier,
                    offer.credentialConfigurationId,
                ),
            )

            activeOffer = offer
            activeVctmDocument = try {
                vctmFetcher.fetchDocument(
                    issuerUrl = offer.credentialIssuerIdentifier,
                    scope = offer.credentialConfigurationId,
                    // The offer names the type, and the registry strategy needs
                    // it: without a vct the fetcher can only ask the issuer's
                    // own endpoint, so an issuer that resolves its types from a
                    // registry and does not republish them resolved to nothing.
                    vct = offer.vct,
                    registryUrl = registryUrl,
                )
            } catch (e: Exception) {
                Timber.w(e, "Failed to fetch VCTM for ${offer.credentialConfigurationId}")
                null
            }
            activeVctm = activeVctmDocument?.vctm
            // The mdoc half of the same lookup. Previously fetched on demand in
            // resolveEffectiveKeystoreForIssuance and thrown away; kept now
            // because verifyIssuedType needs the authorised doctype at
            // flow_complete, and because the fetcher is cached this is the same
            // request that path already makes rather than an extra one.
            activeMddlSchema = try {
                mddlSchemaFetcher.fetch(
                    issuerUrl = offer.credentialIssuerIdentifier,
                    scope = offer.credentialConfigurationId,
                    registryUrl = registryUrl,
                )
            } catch (e: Exception) {
                Timber.w(e, "Failed to fetch MDDL schema for ${offer.credentialConfigurationId}")
                null
            }
            val credentialOffer = kotlinx.serialization.json.buildJsonObject {
                put("credential_issuer", kotlinx.serialization.json.JsonPrimitive(
                    offer.credentialIssuerIdentifier
                ))
                put("credential_configuration_ids", kotlinx.serialization.json.buildJsonArray {
                    add(kotlinx.serialization.json.JsonPrimitive(offer.credentialConfigurationId))
                })
                put("grants", kotlinx.serialization.json.buildJsonObject {
                    if (offer.preAuthorizedCode != null) {
                        put("urn:ietf:params:oauth:grant-type:pre-authorized_code",
                            kotlinx.serialization.json.buildJsonObject {
                                put("pre-authorized_code", kotlinx.serialization.json.JsonPrimitive(
                                    offer.preAuthorizedCode
                                ))
                                if (offer.txCode != null) {
                                    put("tx_code", kotlinx.serialization.json.buildJsonObject {
                                        put("input_mode", kotlinx.serialization.json.JsonPrimitive("text"))
                                    })
                                }
                            })
                    } else {
                        put("authorization_code", kotlinx.serialization.json.buildJsonObject {})
                    }
                })
            }
            engine.startIssuance(
                offer = credentialOffer.toString(),
                redirectUri = config.redirectUri.ifBlank { null },
            )
        } catch (e: Exception) {
            // The flow was never registered server-side (no flow ID was ever
            // assigned), so nothing will ever arrive to clear
            // issuanceInFlight via the normal flow_complete/flow_error path -
            // clear it here instead, or a failed start would permanently
            // lock out every future issuance attempt for the rest of the
            // session.
            issuanceInFlight = false
            activeOffer = null
            activeVctm = null
            activeZkIssuanceInput = null
            throw e
        }
    }

    /**
     * Renew a credential batch via OID4VCI's `refresh_token` grant
     * (credential re-issuance/renewal plan, Phase 2), using the
     * refresh_token/DPoP key durably captured for it in `privatedata`
     * (`S.credentialRefreshTokens` - see [exportCredentialRefreshTokens])
     * at the time it (or its most recent prior renewal) was issued.
     *
     * Throws [WalletException] if no renewal candidate is stored for
     * [batchId] - either it was never captured (the issuer didn't return a
     * refresh_token), or it's already been consumed/superseded.
     * `reissuanceKid` is left unset for now - the server-side
     * same-wallet-unit continuity mechanism (re-signing `generate_proof`
     * with the original credential's key) is tracked separately and not yet
     * wired into this call site.
     *
     * A renewal's flow_complete is handled by the exact same code path as a
     * fresh issuance's, which reads display metadata (logo/issuer
     * name/friendly credential name) off [activeOffer] - but a renewal
     * never parses a fresh credential_offer, so activeOffer would otherwise
     * be left null/stale from whatever the *previous* flow reset it to.
     * Re-fetch and rebuild it here from the stored issuer/config id so the
     * renewed card displays correctly rather than falling back to raw wire
     * values (e.g. the bare "mso_mdoc" format string instead of "mDL").
     */
    suspend fun renewCredential(batchId: Long) {
        val engine = engineSession ?: throw WalletException(NOT_CONNECTED)
        ensureEngineConnected(engine)
        val candidate = exportCredentialRefreshTokens()[batchId]
            ?: throw WalletException("No refresh_token stored for batch $batchId - it may not be renewable, or was already renewed")
        Timber.d("Starting renewal for batch=$batchId issuer=${candidate.credentialIssuerIdentifier}")
        try {
            val metadata = getIssuerMetadata(candidate.credentialIssuerIdentifier)
            activeOffer = buildCredentialOfferFromMetadata(
                candidate.credentialIssuerIdentifier,
                candidate.credentialConfigurationId,
                metadata,
            )
        } catch (e: Exception) {
            Timber.w(e, "Failed to refresh issuer metadata for renewal display; card will show raw format")
        }
        pendingRenewalSourceBatchId = batchId
        engine.startRenewal(
            refreshToken = candidate.refreshToken,
            credentialIssuer = candidate.credentialIssuerIdentifier,
            selectedCredentialConfigurationId = candidate.credentialConfigurationId,
            dpopJwk = candidate.dpopJwk,
            dpopKeyId = candidate.dpopKeyId,
        )
    }

    /**
     * Start a credential issuance flow with a raw offer or URI.
     *
     * @param offerUri a credential_offer_uri or raw JSON credential_offer string.
     * @param zkInput what the holder contributes when the credential type
     * cannot be issued by the issuer alone - see [ZkIssuanceInput]. Null for
     * every ordinary credential.
     */
    suspend fun startIssuance(offerUri: String, zkInput: ZkIssuanceInput? = null) {
        val engine = engineSession ?: throw WalletException(NOT_CONNECTED)
        ensureEngineConnected(engine)
        if (issuanceInFlight) {
            throw WalletException("Another issuance is already in progress")
        }
        activeZkIssuanceInput = zkInput
        // Set unconditionally, before display-metadata resolution: every
        // branch below calls engine.startIssuance() regardless of whether
        // resolveOfferForDisplay() succeeds, so gating this on that result
        // would leave some real issuance flows unguarded.
        issuanceInFlight = true
        try {
            val redirectUri = config.redirectUri.ifBlank { null }
            resolveOfferForDisplay(offerUri)?.let { offer ->
                activeOffer = offer
                activeVctm = try {
                    vctmFetcher.fetch(
                        issuerUrl = offer.credentialIssuerIdentifier,
                        scope = offer.credentialConfigurationId,
                        registryUrl = registryUrl,
                    )
                } catch (e: Exception) {
                    Timber.w(e, "Failed to fetch VCTM for ${offer.credentialConfigurationId}")
                    null
                }
            }
            // OAuth Client Attestation is no longer resolved here: the engine
            // asks for it via a `request_attestation` sign request once it has
            // resolved the issuer's authorization server itself - see
            // handleRequestAttestation. That spares this side a second fetch
            // of a possibly single-use credential_offer_uri and a duplicate
            // authorization_servers/client_id discovery.
            when (val start = resolveIssuanceStart(offerUri)) {
                is IssuanceStart.Offer -> engine.startIssuance(
                    offer = start.offer,
                    redirectUri = redirectUri,
                )
                is IssuanceStart.CredentialOfferUri -> engine.startIssuance(
                    credentialOfferUri = start.uri,
                    redirectUri = redirectUri,
                )
            }
        } catch (e: Exception) {
            // See startIssuanceByOffer's matching catch block: the flow was
            // never registered server-side, so nothing will ever clear
            // issuanceInFlight via the normal flow_complete/flow_error path.
            issuanceInFlight = false
            activeOffer = null
            activeVctm = null
            activeZkIssuanceInput = null
            throw e
        }
    }

    /**
     * Resolve display metadata (name/logo/colors) for a scanned/deep-linked
     * credential offer, ahead of forwarding it to the engine.
     *
     * [activeOffer] was previously only ever set by [startIssuanceByOffer]
     * (the picker-driven path from [getAvailableCredentials]) - the QR/
     * deep-link entry point here never populated it, so every credential
     * issued that way (mdoc or SD-JWT, ours or a third-party issuer's) was
     * stored with no display metadata AND no recorded issuer/config
     * identifiers at all (both derive from [activeOffer] at storage time),
     * confirmed against a real geneva2026.mdoc.online mDL credential offer.
     *
     * Best-effort: returns null on any failure (unparseable offer, unreachable
     * issuer, issuer doesn't support the offered configuration) rather than
     * throwing - a missing display must never block issuance itself.
     */
    private suspend fun resolveOfferForDisplay(offerUri: String): CredentialOffer? {
        return try {
            val offerJson = extractOfferJson(offerUri) ?: return null
            val issuerUrl = offerJson["credential_issuer"]?.jsonPrimitive?.contentOrNull ?: return null
            val configId = offerJson["credential_configuration_ids"]?.jsonArray
                ?.firstOrNull()?.jsonPrimitive?.contentOrNull ?: return null
            val metadata = getIssuerMetadata(issuerUrl)
            buildCredentialOfferFromMetadata(issuerUrl, configId, metadata)
        } catch (e: Exception) {
            Timber.w(e, "Failed to resolve display metadata for offer")
            null
        }
    }

    /** Extract the raw `credential_offer` JSON object from any of the shapes [startIssuance] accepts. */
    private suspend fun extractOfferJson(offerUri: String): JsonObject? =
        when (val start = resolveIssuanceStart(offerUri)) {
            // Inline offer JSON (unpacked from a query parameter, or the raw
            // object itself). A URI the engine is left to interpret is not
            // JSON and yields nothing to display.
            is IssuanceStart.Offer -> try {
                json.parseToJsonElement(start.offer).jsonObject
            } catch (_: Exception) {
                null
            }
            is IssuanceStart.CredentialOfferUri -> fetchOfferJson(start.uri)
        }

    private suspend fun fetchOfferJson(uri: String): JsonObject? = withContext(Dispatchers.IO) {
        val request = Request.Builder().url(uri).get().build()
        httpClient.newCall(request).execute().use { response ->
            val body = response.body?.string()
            if (!response.isSuccessful || body == null) null else json.parseToJsonElement(body).jsonObject
        }
    }

    /**
     * Start a credential presentation flow.
     *
     * @param requestUri the OID4VP request URI.
     */
    suspend fun startPresentation(requestUri: String) {
        val engine = engineSession ?: throw WalletException(NOT_CONNECTED)
        ensureEngineConnected(engine)
        engine.startPresentation(requestUri = requestUri)
    }

    /**
     * The final payload to hand back to the OS/browser for a W3C Digital
     * Credentials API presentation - Android's `PendingIntentHandler` (or
     * the equivalent on other platforms) wraps [responseJson] as the
     * `DigitalCredential`'s response data.
     *
     * For `response_mode=dc_api` (unencrypted): `{"vp_token": {...}}`.
     * For `response_mode=dc_api.jwt`: `{"response": "<jwe-compact>"}` per
     * OpenID4VP 1.0 Appendix A.3.2.
     */
    data class DCAPIPresentationResult(
        val responseJson: String,
        val credentialIds: List<Long>,
    )

    /**
     * Process an incoming W3C Digital Credentials API (DC API) OpenID4VP
     * presentation request entirely client-side - mirrors wallet-frontend's
     * proven architecture rather than the [startPresentation]/engine-relay
     * pattern: there is no `WalletEngineSession` involvement and no
     * DC-API-specific backend call. The only backend calls made are the SAME
     * generic trust-evaluation ([evaluateTrustDirect]) and presentation-history
     * persistence the redirect flow already uses (see task #74's revised
     * finding - go-wallet-backend needs no `origin:`/`dc_api.jwt`/
     * `OpenID4VPDCAPIHandover` support under this architecture).
     *
     * @param rawRequestJson the raw request data string from the OS/browser -
     *   either a raw OpenID4VP request JSON object (unsigned protocol
     *   variant) or `{"request": "<JWT>"}` (signed/multisigned JAR variant).
     * @param origin the browser/page origin that made the
     *   `navigator.credentials.get()` call, as verified by the platform
     *   (e.g. Android's Credential Manager) - NOT read from the request body,
     *   which is untrusted until the platform attests it.
     * @throws WalletException if the user declines, or if not connected.
     */
    suspend fun handleDCAPIRequest(rawRequestJson: String, origin: String): DCAPIPresentationResult {
        val request = DCAPIRequestParser.parse(rawRequestJson)

        // request.clientId is only cryptographically bound to anything when
        // the request is signed (keyMaterial != null, verified against the
        // JWS header's own key in DCAPIRequestParser) - for the unsigned
        // variant it's just a caller-supplied field in the untrusted request
        // body. Using it there let a malicious page set client_id to some
        // other, possibly-whitelisted verifier's identity and have trust
        // evaluated (and this presentation's history recorded) against that
        // spoofed identity instead of the platform-attested origin.
        val subjectId = if (request.keyMaterial != null) (request.clientId ?: origin) else origin
        val trustResult = try {
            evaluateTrustDirect(
                subjectId = subjectId,
                subjectType = "credential_verifier",
                keyMaterialType = when {
                    request.keyMaterial?.x5c != null -> "x5c"
                    request.keyMaterial?.jwk != null -> "jwk"
                    else -> null
                },
                x5c = request.keyMaterial?.x5c?.let { chain ->
                    kotlinx.serialization.json.buildJsonArray {
                        chain.forEach { add(kotlinx.serialization.json.JsonPrimitive(it)) }
                    }
                },
                jwk = request.keyMaterial?.jwk,
                context = null,
            )
        } catch (e: TrustEvaluationFailedClosedException) {
            // Deliberately ahead of the cache: a refusal, or REMOTE_ONLY with
            // an unreachable backend, must not be answered by a stale positive.
            Timber.e(e, "DC API trust evaluation failed closed for $subjectId - not consulting the trust cache")
            TrustResult(trusted = false, identifier = subjectId, reason = e.message)
        } catch (e: Exception) {
            Timber.w(e, "DC API trust evaluation failed for $subjectId")
            trustCache.get(subjectId) ?: TrustResult(trusted = false, identifier = subjectId, reason = e.message)
        }

        // Unlike the QR/redirect flow, there is no engine round-trip here to
        // gate on (trust is evaluated and enforced entirely wallet-side) - a
        // request from an untrusted or trust-eval-failed verifier must be
        // rejected before any credential is matched or signed, not merely
        // have its trust result computed and ignored.
        if (!trustResult.trusted) {
            throw WalletException("Verifier '$subjectId' is not trusted: ${trustResult.reason ?: "no reason given"}")
        }

        val allCreds = credentialStore.getAll()
        val dcqlOutput = if (request.dcqlQuery != null) {
            CredentialMatcher.matchDcql(request.dcqlQuery, allCreds)
        } else {
            CredentialMatcher.DcqlMatchOutput(
                queryResults = listOf(CredentialMatcher.MatchResult(
                    queryId = "_default", format = null, candidates = allCreds, requestedClaims = emptyList(),
                )),
                credentialSets = null,
                satisfiableOptions = emptyList(),
            )
        }
        val matchResults = dcqlOutput.queryResults
        val candidates = matchResults.flatMap { it.candidates }.distinctBy { it.id }

        // Which query result actually governs each candidate - same
        // first-match selection used below when building tokens (a
        // credential id can appear as a candidate under more than one query,
        // e.g. one plain and one "mso_mdoc_zk", so this must be resolved
        // once and reused everywhere rather than re-derived with different
        // semantics in different places).
        val matchResultByCredentialId = candidates.associate { c ->
            c.id to matchResults.firstOrNull { r -> r.candidates.any { it.id == c.id } }
        }

        // Which candidates will actually be presented as a ZK proof (vs a
        // raw disclosure) for THIS request - a credential's stored format is
        // always plain "mso_mdoc" even under a ZK query (see
        // CredentialMatcher.matchesFormat), so this must come from the
        // MATCHED query's format, not the candidate's own. Derived from
        // [matchResultByCredentialId]'s first-match query per id, not from
        // "is this id a candidate under ANY zk query" - a credential that
        // also matches some other, non-zk query first would otherwise be
        // wrongly marked zk here even though the token-building loop below
        // (which also uses first-match) will actually raw-disclose it.
        // Feeds eligibleInstances below so
        // CredentialConsumptionPolicy.CONSUME_NON_ZKP actually distinguishes
        // the two, per that policy's own doc comment.
        val zkRequestedIds = matchResultByCredentialId
            .filterValues { it?.format?.equals("mso_mdoc_zk", ignoreCase = true) == true }
            .keys

        // Unlike the QR/redirect flow, credential selection and consent
        // already happened natively - the OS's own credential picker (see
        // DCAPIProviderRegistration/DCAPIGetCredentialActivity) showed the
        // matching registered entries and the user picked one before this
        // Activity was ever launched. Routing through eventListener's
        // interactive onCredentialSelectionRequired here would suspend
        // waiting for an in-app consent screen that this headless flow
        // never shows - and since that listener is registered globally on
        // the shared wallet instance (by MainActivity's WalletViewModel, for
        // the unrelated in-app flow) and stays registered even once
        // MainActivity is backgrounded, that wait would hang forever.
        val selectedIds = eligibleInstances(candidates) { it.id in zkRequestedIds }.map { it.id }

        if (selectedIds.isEmpty()) {
            throw WalletException(
                if (candidates.isEmpty()) {
                    "No credential in the wallet matches the request"
                } else {
                    "No eligible copies of the requested credential remain - renew it to get more"
                },
            )
        }

        // "origin:<value>" per OpenID4VP 1.0 Appendix A is only used for the
        // VP token audience claim at signing time - trust evaluation above
        // uses the bare origin, matching wallet-frontend's useOID4VPFlow.ts.
        val audience = "origin:$origin"
        val encryptionJwk = if (request.responseMode == "dc_api.jwt") {
            findEncryptionJwk(request.clientMetadata)
                ?: throw WalletException("dc_api.jwt response_mode requires client_metadata.jwks with an encryption key")
        } else {
            null
        }
        val encryptionThumbprint = encryptionJwk?.computeThumbprint()?.toString()

        // Per OpenID4VP 1.0 (#response_parameters), vp_token's value for each
        // DCQL query id MUST be a JSON array of one or more Presentations -
        // even when `multiple` is omitted/false, the array MUST still
        // contain exactly one Presentation, never a bare string. A real bug,
        // confirmed via Multipaz's own server source
        // (multipaz-verifier-server's handleDcGetDataOpenID4VP does
        // `value.jsonArray.map{...}` for the openid4vp-v1-signed/-unsigned
        // protocol versions): putting a bare JsonPrimitive here threw inside
        // their server and surfaced as an opaque HTTP 500, with our own
        // wallet-side exchange having completed successfully - nothing on
        // our side ever saw an error.
        val tokensByQueryId = linkedMapOf<String, MutableList<String>>()
        for (id in selectedIds) {
            val cred = allCreds.find { it.id == id } ?: continue
            val matchResult = matchResultByCredentialId[id]
            val queryId = matchResult?.queryId ?: "_default"
            val disclosedClaims = matchResult?.requestedClaims?.mapNotNull { it.lastOrNull() }

            val token = if (matchResult?.format?.equals("mso_mdoc_zk", ignoreCase = true) == true) {
                val credBytes = android.util.Base64.decode(
                    cred.raw, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP
                )
                // cred.kid is commonly null for a softkey-issued credential
                // with no explicit per-credential key binding (the plain,
                // non-ZK signMdocPresentation/-ForDCAPI paths tolerate this
                // via selectSigningKey's null-kid fallback to the only
                // available key) - keystore.sign() below needs an explicit
                // key id, so resolve the same default here rather than
                // treating a null kid as "no key exists". Resolved lazily
                // (checked only inside the signer lambda, not eagerly here):
                // a ZK system without a device-binding concept (Vega, unlike
                // Longfellow's real-witness-DeviceResponse construction)
                // never calls signer at all, so requiring a key up front
                // would spuriously fail a Vega presentation whenever no
                // signing key happens to be resolvable, even though nothing
                // in that flow ever needs one.
                val kid = cred.kid ?: keystore.listKeys().firstOrNull()?.keyId
                // Only bind a pseudonym when the verifier actually asked for
                // one - passing a non-null VerifierIdentity unconditionally
                // would make generateProof auto-add and disclose
                // "pairwise_pseudonym" even for requests that never asked
                // for it (see ZkProofSystem.generateProof's own doc comment).
                val wantsPseudonym = disclosedClaims?.contains(LongfellowZkProofSystem.PSEUDONYM_CLAIM) == true
                val verifierIdentity = if (wantsPseudonym) {
                    VerifierIdentity(clientId = subjectId, ppidContext = matchResult.ppidContext)
                } else {
                    null
                }
                val sessionTranscript = MdocDeviceResponseBuilder.buildDCAPISessionTranscript(
                    origin = origin,
                    nonce = request.nonce,
                    encryptionPublicJwkThumbprint = encryptionThumbprint,
                )
                val presented = try {
                    zkPresentation.present(
                        ZkMdocPresentation.Request(
                            credentialBytes = credBytes,
                            requestedSystems = matchResult.zkSystemTypes.orEmpty(),
                            sessionTranscript = sessionTranscript,
                            requestedClaims = disclosedClaims ?: emptyList(),
                            verifierIdentity = verifierIdentity,
                        ),
                        signer = { algorithm, data ->
                            require(algorithm == COSE_ALG_ES256) {
                                "This keystore signs ES256 only, proof system asked for COSE alg $algorithm"
                            }
                            keystore.sign(
                                requireNotNull(kid) { "No signing key available for credential $id - cannot generate a ZK proof for it" },
                                data,
                            )
                        },
                    )
                } catch (e: ZkMdocPresentation.NoMatchingProofSystem) {
                    throw WalletException(e.message ?: "No registered ZK proof system satisfies the request")
                }
                android.util.Base64.encodeToString(
                    presented.deviceResponse, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP
                )
            } else if (cred.format == "mso_mdoc") {
                val credBytes = android.util.Base64.decode(
                    cred.raw, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP
                )
                val deviceResponse = keystore.signMdocPresentationForDCAPI(
                    credentialBytes = credBytes,
                    disclosedClaims = disclosedClaims,
                    nonce = request.nonce,
                    origin = origin,
                    encryptionPublicJwkThumbprint = encryptionThumbprint,
                    kid = cred.kid,
                )
                android.util.Base64.encodeToString(
                    deviceResponse, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP
                )
            } else {
                keystore.signVpToken(
                    credential = cred.raw,
                    disclosedClaims = disclosedClaims,
                    nonce = request.nonce,
                    audience = audience,
                    kid = cred.kid,
                )
            }
            tokensByQueryId.getOrPut(queryId) { mutableListOf() }.add(token)
        }

        val vpTokenObj = kotlinx.serialization.json.buildJsonObject {
            for ((queryId, tokens) in tokensByQueryId) {
                put(queryId, kotlinx.serialization.json.buildJsonArray {
                    tokens.forEach { add(kotlinx.serialization.json.JsonPrimitive(it)) }
                })
            }
        }

        val responseBody = kotlinx.serialization.json.buildJsonObject {
            put("vp_token", vpTokenObj)
            // The verifier's only means of correlating this response back to
            // the right authorization session - the response arrives via the
            // DC API callback, a wholly separate channel from the original
            // request, with no other correlator available. Omitting this
            // (a real bug: request.state was parsed but never echoed back)
            // left the verifier decrypting a JWE it had no way to attribute
            // to any session.
            request.state?.let { put("state", kotlinx.serialization.json.JsonPrimitive(it)) }
        }.toString()

        val responseData = if (request.responseMode == "dc_api.jwt") {
            // The verifier's declared alg/enc preference MUST be honored, not
            // silently overridden by our own defaults (OpenID4VP 1.0 #8.3) -
            // mirrors wallet-frontend's DCAPISession#encryptResponse
            // priority: the encryption key's own "alg" JWK member first,
            // then client_metadata's authorization_encrypted_response_alg/
            // _enc, falling back to ECDH-ES/A128GCM only if the verifier
            // declared neither.
            val alg = encryptionJwk!!.algorithm?.let { com.nimbusds.jose.JWEAlgorithm.parse(it.name) }
                ?: request.clientMetadata?.get("authorization_encrypted_response_alg")
                    ?.jsonPrimitive?.contentOrNull?.let { com.nimbusds.jose.JWEAlgorithm.parse(it) }
                ?: com.nimbusds.jose.JWEAlgorithm.ECDH_ES
            val enc = request.clientMetadata?.get("authorization_encrypted_response_enc")
                ?.jsonPrimitive?.contentOrNull?.let { com.nimbusds.jose.EncryptionMethod.parse(it) }
                ?: com.nimbusds.jose.EncryptionMethod.A128GCM
            val jwe = DCAPIResponseEncryption.encryptResponse(responseBody, encryptionJwk, alg, enc)
            kotlinx.serialization.json.buildJsonObject {
                put("response", kotlinx.serialization.json.JsonPrimitive(jwe))
            }
        } else {
            kotlinx.serialization.json.Json.parseToJsonElement(responseBody).jsonObject
        }

        // The platform's own reference wallet
        // (https://github.com/digitalcredentialsdev/CMWallet) wraps its
        // response in this exact {"protocol": ..., "data": {...}} envelope
        // before handing it to DigitalCredential() - the mirror image of the
        // {"requests": [{"protocol", "data"}]} envelope the request itself
        // arrives in (see DCAPIRequestParser). Returning the bare `data`
        // object on its own, as this code did before, leaves the platform
        // with no declared protocol to associate the response with; it
        // fails the exchange with a generic, non-diagnostic error rather
        // than a parse error.
        val finalResponseJson = kotlinx.serialization.json.buildJsonObject {
            put("protocol", kotlinx.serialization.json.JsonPrimitive(request.protocol))
            put("data", responseData)
        }.toString()

        recordPresentation(PresentationRecord(
            id = randomUint32Id(),
            flowId = "dc-api-${java.util.UUID.randomUUID()}",
            verifierName = trustResult.entityName,
            credentialIds = selectedIds,
            credentialNames = selectedIds.mapNotNull { id -> allCreds.find { it.id == id }?.metadata?.name },
            requestedClaims = matchResults.flatMap { result ->
                result.requestedClaims.mapNotNull { path -> path.lastOrNull() }
            }.distinct(),
            zkProof = selectedIds.any { it in zkRequestedIds },
            timestamp = System.currentTimeMillis(),
        ))

        return DCAPIPresentationResult(responseJson = finalResponseJson, credentialIds = selectedIds)
    }

    /** Find the verifier's response-encryption key (`use: "enc"`) from DC API `client_metadata.jwks`. */
    private fun findEncryptionJwk(clientMetadata: kotlinx.serialization.json.JsonObject?): com.nimbusds.jose.jwk.JWK? {
        val keys = clientMetadata
            ?.get("jwks")?.jsonObject
            ?.get("keys")?.let { it as? kotlinx.serialization.json.JsonArray }
            ?: return null
        val jwkObj = keys.map { it.jsonObject }
            .firstOrNull { it["use"]?.jsonPrimitive?.contentOrNull == "enc" }
            ?: keys.map { it.jsonObject }.firstOrNull()
            ?: return null
        return com.nimbusds.jose.jwk.JWK.parse(jwkObj.toString())
    }

    /**
     * Force a fresh engine WebSocket connection before starting a new flow,
     * rather than trusting a connection that may have gone idle since the last
     * one. Mirrors [completeAuthorization]'s existing zombie-connection handling
     * (see [WalletEngineSession.forceReconnect]'s doc comment) - the same failure
     * mode isn't unique to the post-OAuth-redirect gap: a connection left open
     * across a backend restart or any other silent network drop can look
     * connected (no onClosing/onFailure fired yet) while actually discarding
     * every send. Confirmed live: [startIssuanceByOffer] sent a flow_start over
     * such a connection with no exception, no engine-side log, and no trace of
     * the message ever reaching the backend.
     */
    private suspend fun ensureEngineConnected(engine: WalletEngineSession) {
        engine.forceReconnect()
        engine.awaitConnected()
    }

    /**
     * Perform identity verification via a plugin provider and automatically start
     * credential issuance with the resulting offer.
     *
     * This is the primary integration point for IDV flows (FaceTec, iProov, etc.).
     * The provider handles all capture UI and backend communication; this method
     * bridges the IDV result into the standard OID4VCI issuance flow.
     *
     * @param provider An [IdentityVerificationProvider] implementation.
     * @param activity The hosting Activity for presenting the IDV UI.
     * @throws IDVException if verification fails.
     * @throws WalletException if issuance fails.
     */
    suspend fun verifyIdentityAndIssue(
        provider: org.siros.sdk.idv.IdentityVerificationProvider,
        activity: android.app.Activity,
    ) {
        if (!provider.isAvailable()) {
            throw org.siros.sdk.idv.IDVException.Unavailable(
                "${provider.name} is not available on this device"
            )
        }
        val result = provider.startVerification(activity)
        startIssuance(result.credentialOfferURI)
    }

    /**
     * Cancel an in-progress flow and return the wallet to the Ready state.
     *
     * If there is an active flow, sends a decline message to the backend.
     * If no flow is active, simply resets to Ready state.
     *
     * [resetIssuanceGuards] is called unconditionally, not just inside the
     * [WalletState.FlowActive] branch - a slow/unresponsive issuer (real
     * case: an interop test issuer that timed out) leaves the wallet in
     * [WalletState.Ready] the whole time [startIssuance]/[startIssuanceByOffer]
     * is awaiting the engine's first progress message, since the engine
     * doesn't assign (and report) a flow ID until then. The old
     * FlowActive-only guard meant cancelling during exactly that window did
     * nothing at all - not even a local reset - permanently stranding
     * [issuanceInFlight] at `true` and blocking every subsequent issuance
     * attempt until the app process was killed. This call is a no-op if no
     * issuance was ever in flight, so it's always safe to call from here.
     */
    fun cancelCurrentFlow() {
        val current = _state.value
        if (current is WalletState.FlowActive) {
            try {
                engineSession?.cancelFlow(current.flowId)
            } catch (e: Exception) {
                Timber.w(e, "Failed to send cancel to backend")
            }
            // A cancelled issuance produces no credential, so anything the
            // holder committed for it is unusable from here on.
            discardZkIssuancePreparation(current.flowId)
            _state.value = readyState(current.userId, current.displayName, current.credentials)
        }
        resetIssuanceGuards()
    }

    /**
     * Complete an OAuth authorization flow after the user has approved in the browser.
     *
     * Call this from your app's deep link handler when the browser redirects
     * back with `code` and `state` query parameters.
     *
     * The original flow's WebSocket session very often will not still be alive at this
     * point - Android backgrounds/throttles the app for however long the user spends in
     * the external browser/Custom Tab completing the OAuth login, and the engine's
     * WebSocket session (and with it, all server-side flow state) commonly dies within
     * seconds of the browser taking over. This resumes on a brand-new, stateless
     * flow_start (auth_code + code_verifier + the original credential_offer) instead of
     * a flow_action on the possibly-gone original flow_id - the same resume contract the
     * web client and native-android-wrapper already rely on (see go-wallet-backend's
     * `resumeWithAuthCode`, which re-derives everything else from what's supplied here).
     *
     * Also forces a fresh engine WebSocket connection first (see
     * [WalletEngineSession.forceReconnect]) rather than trusting the existing one:
     * confirmed live that a connection left idle across the background/browser gap
     * can become a "zombie" that still accepts local sends but never actually
     * delivers them, silently losing the resumed flow's trust-evaluation reply (the
     * backend then fails the flow 2 minutes later with a wait timeout that never
     * reaches the app either, since the same dead connection can't deliver that
     * error back either - see [WalletEventListener.onFlowError] for how a genuine
     * failure here gets surfaced instead).
     *
     * @param flowId The flow ID from [WalletEventListener.onAuthorizationRequired].
     * @param code The authorization code from the redirect.
     * @param state The state parameter from the redirect (for CSRF validation).
     */
    fun completeAuthorization(flowId: String, code: String, state: String) {
        val engine = engineSession ?: throw WalletException(NOT_CONNECTED)
        // Peek, don't remove yet - removing before the CSRF check below meant
        // a mismatched (attacker-supplied) state consumed the real, still-
        // pending context, so any later, legitimate completion attempt for
        // the same flowId would fall through to the no-context branch below,
        // which sends the flow action straight through with no CSRF check
        // at all. Only remove once the check actually passes.
        val pending = pendingAuthorizations[flowId]
        if (pending == null) {
            Timber.w("No saved resume context for flow $flowId; falling back to same-session completion")
            val payload = buildJsonObject {
                put("code", kotlinx.serialization.json.JsonPrimitive(code))
                put("state", kotlinx.serialization.json.JsonPrimitive(state))
            }
            engine.sendFlowAction(flowId, "authorization_complete", payload)
            return
        }
        if (pending.state != state) {
            throw WalletException("Authorization state mismatch for flow $flowId (possible CSRF)")
        }
        pendingAuthorizations.remove(flowId)
        scope.launch {
            try {
                engine.forceReconnect()
                engine.awaitConnected()
                // Client attestation for the resumed flow arrives the same way
                // as for a fresh one: go-wallet-backend's Execute() runs its
                // attestation setup before branching on msg.AuthCode, so it
                // sends us a `request_attestation` sign request on this resume
                // too (the token request - the one that actually needs it for
                // redirect-based authorization_code issuers - only ever happens
                // via this path). See handleRequestAttestation.
                engine.resumeIssuance(
                    offer = pending.offerJson,
                    redirectUri = pending.redirectUri,
                    authCode = code,
                    codeVerifier = pending.codeVerifier,
                )
            } catch (e: Exception) {
                Timber.e(e, "Failed to resume authorization for flow $flowId")
                eventListener?.onFlowError(flowId, e.message ?: "Failed to resume authorization")
            }
        }
    }

    /**
     * Delete a credential by ID.
     * Also syncs the updated keystore to the backend.
     */
    suspend fun deleteCredential(credentialId: Long) {
        val deletedBatchId = credentialStore.getAll().find { it.id == credentialId }?.batchId
        credentialStore.delete(credentialId)
        // privatedata-spec §6.1.2: deleting the entity an extension entry
        // names must delete the entry. Left behind, BBS holder state is a
        // long-lived secret belonging to a credential that no longer exists
        // - and it is a secret worth deleting, since it is exactly what
        // would undo the blinding.
        bbsHolderStateVault?.remove(credentialId.toString())
        // If that was the last instance of its batch, its refresh_token
        // entry (if any) is now orphaned - privatedata-spec §6.2 requires
        // it not linger pointing at a batch that no longer exists.
        deletedBatchId?.let { batchId ->
            if (credentialStore.getAll().none { it.batchId == batchId }) {
                removeCredentialRefreshToken(batchId)
            }
        }
        val current = _state.value
        if (current is WalletState.Ready) {
            _state.value = current.copy(credentials = credentialStore.getAll())
        }
        persistAndSyncKeystore()
    }

    // ── Internal wiring ─────────────────────────────────────────────

    private val supervisorJob = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.Main + supervisorJob)
    private val sessionStore = SessionStore(activity)
    private val accountRegistry = AccountRegistry(activity)
    private val authProvider = createAuthProvider(activity, config)
    private val keystore: KeystoreManager = config.keystore ?: JweKeystore()

    /**
     * WSCD hardware-key lifecycle (enroll/rotate/destroy) and
     * additional-plugin registration (FIDO2 rawSign, R2PS remote HSM) -
     * `null` unless [keystore] is WSCD-backed (see [WscdKeystoreAdapter]).
     * The default JWE-encrypted keystore has no such concept.
     */
    val wscdManager: WscdManager? get() = keystore as? WscdManager

    /**
     * Static feature availability - lets a consumer gate its own UI
     * without probing by side effect (e.g. attempting a WSCD plugin
     * registration and catching the resulting exception). Reflects what's
     * *configured*, not runtime plugin-registration state the app already
     * controls itself (e.g. whether FIDO2 specifically has been
     * registered on [wscdManager]).
     */
    val capabilities: WalletCapabilities
        get() = WalletCapabilities(
            nativeAttestation = config.nativeAttestationProvider != null,
            wscd = wscdManager != null,
        )

    private val credentialStore: CredentialStore =
        config.credentialStore ?: KeystoreBackedCredentialStore(keystore)
    private val json = Json { ignoreUnknownKeys = true }
    private val httpClient = config.httpClient ?: OkHttpClient()

    /**
     * Client for the go-zk-circuits catalog service (see
     * [WalletConfig.zkCircuitUrls]'s doc comment) - discovers/downloads the
     * ZK-proof circuit artifacts [zkProofSystemRegistry]'s systems consume.
     * Exposed publicly (unlike most of this class's internal clients) so a
     * consumer can inspect/prefetch circuits directly if it wants to.
     */
    val zkCircuitClient: ZkCircuitClient = ZkCircuitClient(
        sources = config.zkCircuitUrls,
        httpClient = httpClient,
        // Circuits are immutable and tens of megabytes: fetched and verified
        // once per device, then served from disk - including with no
        // network, which a proximity presentation has to survive. Under
        // cacheDir rather than files: nothing here is user data, the OS may
        // evict it under pressure, and re-downloading is the only cost.
        cacheDir = java.io.File(activity.applicationContext.cacheDir, "siros-zk-circuits"),
    )

    /**
     * The container-backed store [BbsHolderStateVault] writes, or `null`
     * when this wallet's keystore does not own a container.
     *
     * `null` is not a degraded mode to work around: BBS holder state cannot
     * be reconstructed, so a wallet that cannot persist it must not issue a
     * BBS credential in the first place. [zkIssuanceExtras] refuses rather
     * than committing to messages it will be unable to present.
     */
    private val bbsHolderStateVault: BbsHolderStateVault? =
        (keystore as? org.siros.sdk.keystore.ExtensionStore)?.let { BbsHolderStateVault(it) }

    /**
     * Resolves a stored credential's BBS state for [BbsProofSystem].
     *
     * The proof system keys on the JWP itself, since that is all it has at
     * presentation time; the container keys on credential id, since §6.1.1
     * requires an entry key to name an entity the wallet tracks. This is the
     * join between the two.
     */
    private val bbsHolderStateStore = object : org.siros.sdk.credentials.BbsHolderStateStore {
        override suspend fun stateFor(issuedJwp: String): org.siros.sdk.credentials.BbsHolderState? {
            val vault = bbsHolderStateVault ?: return null
            val credential = credentialStore.getAll().firstOrNull { it.raw == issuedJwp } ?: return null
            return vault.get(credential.id.toString())
        }
    }

    /**
     * ZK presentation of mdoc credentials - every proof system this wallet
     * can satisfy a verifier's `"mso_mdoc_zk"` DCQL request with, assembled
     * once here and usable without this wallet: see [ZkMdocPresentation] for
     * why the assembly is a public type of its own. The registry tries each
     * system in order via [ZkProofSystem.matchingSpec] until one claims the
     * request, so ordering only matters when two systems could both match
     * the same spec (not the case today - Vega and Longfellow declare
     * disjoint `system` ids). BBS is registered alongside because its
     * holder state lives in this wallet's keystore - only when the
     * deployment declares BBS credential types (see
     * [WalletConfig.bbsCredentialTypes]); the set is a constructor argument
     * rather than something derived from what is stored because the
     * issuance half needs it before any credential of that type exists.
     */
    val zkPresentation: ZkMdocPresentation = ZkMdocPresentation.standard(
        circuitClient = zkCircuitClient,
        extra = buildList {
            if (config.bbsCredentialTypes.isNotEmpty()) {
                add(
                    org.siros.sdk.credentials.BbsProofSystem(
                        holderState = bbsHolderStateStore,
                        supportedVcts = config.bbsCredentialTypes,
                    ),
                )
            }
        },
    )

    private val zkProofSystemRegistry: ZkProofSystemRegistry get() = zkPresentation.registry

    /**
     * Drops the resident ZK prover (100+ MB of native memory) the moment the
     * app's UI is no longer visible, and under any memory pressure at all.
     * TRIM_MEMORY_UI_HIDDEN is the closest Android signal to "left the
     * foreground" that needs no lifecycle dependency; the prover is
     * reloaded from the on-device circuit cache on the next proof. A proof
     * in flight finishes first (see [ZkProverResidency.release]).
     */
    private val memoryPressureCallbacks = object : android.content.ComponentCallbacks2 {
        override fun onTrimMemory(level: Int) {
            if (level >= android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN) {
                zkPresentation.releaseProvers()
            }
        }

        override fun onConfigurationChanged(newConfig: android.content.res.Configuration) = Unit

        @Deprecated("Deprecated in Java")
        override fun onLowMemory() {
            zkPresentation.releaseProvers()
        }
    }.also { activity.applicationContext.registerComponentCallbacks(it) }

    /**
     * The zero-knowledge systems this wallet can prove with.
     *
     * Exposed because registration with the OS credential picker happens
     * before any request exists: a wallet declaring what it can do has nothing
     * to be asked about yet, so the registry's request-shaped `resolve` cannot
     * answer it. Identifiers only - see [ZkProofSystemRegistry.systemIds] for
     * why specific circuits are deliberately not claimed here.
     */
    val zkSystemIds: List<String> get() = zkProofSystemRegistry.systemIds

    /**
     * What the holder contributes to the issuance currently in flight, set
     * by whichever [startIssuance]/[startIssuanceByOffer] began it.
     *
     * Scoped the same way [activeOffer] is - one issuance runs at a time
     * (`issuanceInFlight` enforces it), so a single slot is the whole state.
     */
    private var activeZkIssuanceInput: ZkIssuanceInput? = null

    /**
     * Preparations produced during a sign request, by flow id.
     *
     * Kept past the request because the wallet is not finished with them:
     * `accept()` on the preparation is the only place a mis-issued
     * credential is caught, and the state it returns is what makes the
     * credential presentable at all. Keyed by flow rather than held in one
     * slot so a completion arriving for a superseded flow cannot consume
     * another flow's blinding factor.
     */
    private val zkPreparationsByFlow =
        java.util.concurrent.ConcurrentHashMap<String, org.siros.sdk.credentials.ZkIssuancePreparation>()

    /**
     * Drop [flowId]'s preparation, unconsumed, because the flow it belongs
     * to has ended.
     *
     * A preparation holds material that must not outlive its flow - for BBS
     * the secret prover blind behind the commitment. This is the only place
     * one is removed: [acceptZkIssuedCredential] deliberately leaves it,
     * because the credential loop enters that path at all only while the
     * flow still has a preparation, and dropping it mid-batch would send
     * every later credential down the ordinary validation branch. Left in
     * the map past the flow, though, it would sit in memory for the life of
     * the process and gain one entry per issuance, so every terminal path
     * calls this the way every one of them already calls
     * [resetIssuanceGuards].
     *
     * Not folded into [resetIssuanceGuards] itself because this is
     * flow-scoped and that is not: `flow_complete` calls the reset *before*
     * the credential loop's results are reported, and the preparation has
     * to survive that far.
     */
    private fun discardZkIssuancePreparation(flowId: String?) {
        if (flowId == null) return
        if (zkPreparationsByFlow.remove(flowId) != null) {
            Timber.d("Discarded unconsumed ZK issuance preparation for flow $flowId")
        }
    }

    /**
     * Runs the holder's half of issuance and returns what the credential
     * request must carry, or `null` when this flow needs nothing.
     *
     * `null` is the answer for almost every issuance: it means no registered
     * proof system claims the credential type being issued, or the caller
     * supplied no [ZkIssuanceInput]. Both transports call this at the same
     * point - the `generate_proof` sign request, the wallet's one turn to
     * speak before the credential request goes out - so a flow behaves the
     * same whichever transport carries it.
     */
    private suspend fun zkIssuanceExtras(flowId: String): kotlinx.serialization.json.JsonObject? {
        val input = activeZkIssuanceInput ?: return null
        val offer = activeOffer ?: return null
        val credentialType = org.siros.sdk.credentials.CredentialTypeRef(
            format = org.siros.sdk.credentials.CredentialFormat.JWP,
            typeId = activeVctm?.vct ?: offer.credentialConfigurationId,
        )
        val participant = zkProofSystemRegistry.issuanceParticipant(credentialType) ?: run {
            Timber.i("No ZK issuance participant for $credentialType - issuing without a holder commitment")
            return null
        }
        // Refuse rather than commit to messages whose blinding factor has
        // nowhere durable to live. Presenting needs that factor and it
        // cannot be recomputed, so proceeding here would produce a
        // credential that is issued, stored, and permanently unusable.
        if (bbsHolderStateVault == null) {
            throw WalletException(
                "Cannot issue a ${credentialType.typeId} credential: this wallet's keystore does not own " +
                    "a private-data container, so the holder state it requires could not be persisted",
            )
        }
        // Same reasoning, one step later in the flow: without the issuer's
        // key the credential that comes back cannot be checked against what
        // was committed, and checking it is the wallet's only chance to
        // notice the issuer signed something else. Refusing here costs an
        // argument; refusing after issuance costs a credential.
        if (input.issuerPublicKey == null) {
            throw WalletException(
                "Cannot issue a ${credentialType.typeId} credential: ZkIssuanceInput carries no " +
                    "issuerPublicKey, so what the issuer returns could not be verified against the commitment",
            )
        }
        val preparation = participant.prepare(
            holderClaimsJson = input.holderClaimsJson,
            keybindPublicKeys = input.keybindPublicKeys,
            signer = input.signer ?: NoKeybindSigner,
        )
        val extras = kotlinx.serialization.json.buildJsonObject {
            preparation.credentialRequestFields.forEach { (member, encodedValue) ->
                // Already-encoded JSON, parsed rather than re-encoded: these
                // values are covered by the commitment proof, and a
                // round trip through a second encoder is how the two ends
                // stop agreeing about what was signed.
                put(member, json.parseToJsonElement(encodedValue))
            }
        }
        // Registered only once the request members it belongs to exist. A
        // participant returning something `parseToJsonElement` rejects
        // means no sign response goes out and no credential ever arrives
        // for this flow - and the throw leaves the sign request before any
        // of the terminal paths that call [discardZkIssuancePreparation],
        // so a preparation stored ahead of this point would hold its
        // commitment secret with nothing left to consume or drop it.
        zkPreparationsByFlow[flowId] = preparation
        Timber.i(
            "Prepared ${participant.systemId} issuance for flow $flowId " +
                "(${input.keybindPublicKeys.size} key binding key(s))",
        )
        return extras
    }

    /**
     * Checks an issued JWP against what was committed and persists the state
     * that makes it presentable, returning the id to store it under.
     *
     * `null` means do not store this credential. That is deliberate and the
     * whole point of the method: a blind BBS credential that fails this
     * check is not a credential with a problem, it is bytes the issuer
     * signed over something other than what the wallet committed to. Storing
     * it would hide a mis-issuance until the first presentation failed, with
     * nothing left pointing at the cause.
     *
     * @param index this credential's position in the issued batch. One
     *   commitment authorises exactly one credential, so anything past the
     *   first is refused rather than accepted against a preparation that
     *   does not describe it.
     */
    private suspend fun acceptZkIssuedCredential(
        flowId: String,
        issuedJwp: String,
        index: Int,
    ): Long? {
        // Peeked rather than taken: the same preparation has to be visible
        // for every entry in the batch, so the refusal below can tell a
        // second credential apart from a first one.
        val preparation = zkPreparationsByFlow[flowId] ?: return null
        val issuerPublicKey = activeZkIssuanceInput?.issuerPublicKey ?: run {
            Timber.e("Flow $flowId has a ZK preparation but no issuer public key to check the result against")
            return null
        }
        if (index > 0) {
            Timber.e(
                "Flow $flowId returned more than one credential for a single commitment - " +
                    "refusing credential $index, which no commitment authorised",
            )
            return null
        }
        // The cast names BBS, unlike the issuance half, because what happens
        // next is BBS-specific all the way down: the state is typed, and the
        // namespace it lands in is `org.siros.bbs`. Generalising this is
        // worth doing when there is a second participant to generalise over,
        // not before.
        val bbs = preparation as? org.siros.sdk.credentials.BbsIssuancePreparation ?: run {
            Timber.e("Flow $flowId prepared a ${preparation.javaClass.simpleName} this wallet cannot accept")
            return null
        }
        val vault = bbsHolderStateVault ?: run {
            Timber.e("Flow $flowId has no container to persist holder state into")
            return null
        }
        val state = try {
            bbs.accept(issuedJwp, issuerPublicKey)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.e(e, "Issued credential for flow $flowId does not match what this wallet committed to")
            return null
        }
        val credentialId = randomUint32Id()
        vault.put(credentialId.toString(), state)
        // Deliberately still in the map. The caller enters this method at all
        // only while the flow has a preparation, so removing it here would
        // send every later entry in the same batch down the ordinary
        // JWT-validation branch instead - which is exactly the "no commitment
        // authorised this" case the `index > 0` refusal above exists to catch,
        // and it would be stored rather than refused. The preparation is
        // dropped once the whole flow is done, by
        // [discardZkIssuancePreparation] on the flow's terminal path.
        Timber.i("Accepted BBS credential $credentialId for flow $flowId and persisted its holder state")
        return credentialId
    }

    /**
     * Stands in for a signer on an unbound issuance, where there are no key
     * binding keys and so nothing is ever signed.
     *
     * Throwing rather than returning empty bytes: reaching this would mean a
     * key binding key slipped through without a signer, and a credential
     * bound to a key with a bogus proof is worse than a failed issuance.
     * [ZkIssuanceInput]'s own `init` already rejects that combination, so
     * this is the second of two guards, not the only one.
     */
    private object NoKeybindSigner : org.siros.sdk.credentials.ZkWitnessSigner {
        override suspend fun sign(algorithm: Long, data: ByteArray): ByteArray =
            throw IllegalStateException(
                "a key binding key was committed without a signer to prove possession of it",
            )
    }

    /** Stores trust evaluation results keyed by flow ID for use in credential selection UI. */
    private val lastTrustResults = mutableMapOf<String, TrustResult>()

    /**
     * DCQL [CredentialMatcher.MatchResult]s from this flow's match_request,
     * keyed by flow ID - populated in the `matchRequests()` collector below,
     * consumed by the `sign_presentation` handler so it can tell whether a
     * matched credential's originating query requested `"mso_mdoc_zk"` (and
     * if so, which [CredentialMatcher.MatchResult.zkSystemTypes]/
     * [CredentialMatcher.MatchResult.ppidContext] to use) - the stored
     * credential's own format is always plain `"mso_mdoc"`, so that alone
     * can never signal this. Mirrors [handleDCAPIRequest]'s in-scope
     * `matchResults` local, just persisted across the match/sign round trip
     * since the WS-engine protocol has no wire field to carry it instead.
     * Removed once consumed or once the flow reaches a terminal state.
     */
    private val pendingMatchResultsByFlow = mutableMapOf<String, List<CredentialMatcher.MatchResult>>()

    /** Resume context for in-progress OAuth authorizations, keyed by flow ID - see [PendingAuthorization]. */
    private val pendingAuthorizations = mutableMapOf<String, PendingAuthorization>()

    /** Persistent trust cache for degraded-mode operation. */
    private val trustCache = TrustCache()

    /**
     * Flow IDs that have already reached a terminal state (error or complete).
     *
     * The engine delivers flowProgress()/flowErrors()/flowComplete() as separate
     * Flow collectors, so a trailing informational progress message (e.g.
     * "trust_evaluated", sent right after the error that already failed the
     * flow) can arrive just after the error and would otherwise flip [_state]
     * back to [WalletState.FlowActive] with no further messages ever coming to
     * move it back to Ready - a permanently stuck spinner. Guards against that
     * without depending on specific step names.
     */
    private val terminatedFlowIds = mutableSetOf<String>()

    /**
     * Report a flow-terminating failure immediately (e.g. a keystore/WSCD
     * exception raised while handling a sign request) instead of leaving
     * the flow to die silently until the engine's own reply timeout fires.
     *
     * Confirmed necessary via live hardware testing: a real FIDO2
     * `CTAP2_ERR_PIN_INVALID` thrown from [generateProofsForRequest] was
     * only ever logged (`Timber.e`) by the sign-request collector's catch
     * block - nothing told the engine or [eventListener] the operation had
     * failed, so the UI stayed on "Access token received" for the ~20
     * seconds it took the engine's own timeout to notice no response ever
     * arrived and report a generic "Signing failed" itself. This reports
     * the real error the moment it's caught instead.
     */
    private suspend fun reportSignFailure(flowId: String, message: String) {
        terminatedFlowIds.add(flowId)
        pendingMatchResultsByFlow.remove(flowId)
        eventListener?.onFlowError(flowId, message)
        // A sign-request failure during issuance (e.g. the FIDO2 PIN_INVALID
        // this was written for) is a client-side termination of that
        // issuance flow - the engine's own flow_complete/flow_error will
        // never arrive for it, so this must clear issuanceInFlight itself or
        // every future issuance attempt would be permanently blocked. A
        // no-op for a presentation sign-request failure, which never sets
        // these fields.
        resetIssuanceGuards()
        discardZkIssuancePreparation(flowId)
        val current = _state.value
        val userId = (current as? WalletState.FlowActive)?.userId
            ?: (current as? WalletState.Ready)?.userId ?: ""
        val displayName = (current as? WalletState.FlowActive)?.displayName
            ?: (current as? WalletState.Ready)?.displayName
        _state.value = WalletState.Ready(
            userId = userId,
            displayName = displayName,
            credentials = credentialStore.getAll(),
        )
    }
    /**
     * On-device, cross-launch cache of VCTM/MDDL documents AND of the fact
     * that a document could not be fetched (see [FileFetchCache] and
     * [org.siros.sdk.credentials.FetchBackoff]). Without it, every login
     * re-ran every failed type-metadata fetch - [hydrateReloadedCredentials]
     * runs on each login because the private-data container never persists
     * `metadata` - and each failure was a visible spinner on the card.
     * Application context: this outlives any one Activity.
     */
    private val displayMetadataCache: org.siros.sdk.credentials.FetchCache =
        FileFetchCache(activity.applicationContext)

    private val vctmFetcher = VctmFetcher(
        httpGet = ::fetchTypeMetadataUrl,
        persistentCache = displayMetadataCache,
        revalidateScope = scope,
    )
    private val mddlSchemaFetcher = MddlSchemaFetcher(
        httpGet = ::fetchTypeMetadataUrl,
        persistentCache = displayMetadataCache,
        revalidateScope = scope,
    )

    /**
     * Base URL for go-wallet-backend's credential-type registry service (see
     * [WalletConfig.registryUrl]'s doc comment), passed to every
     * [vctmFetcher]/[mddlSchemaFetcher] call so the registry-first resolution
     * strategy can run. Uses [config]'s explicit override when set, otherwise
     * derives it from [WalletConfig.backendUrl] - the common case, since the
     * registry route is mounted under `/registry` on the same host as the
     * rest of go-wallet-backend's public API.
     */
    private val registryUrl: String
        get() = config.registryUrl ?: "${config.backendUrl.trimEnd('/')}/registry"

    /**
     * Shared `httpGet` for [vctmFetcher]/[mddlSchemaFetcher]'s strategies.
     *
     * Registry-service requests (URL targeting [registryUrl]) carry the same
     * `X-Tenant-ID`/`Authorization` headers as every other authenticated
     * go-wallet-backend call (see [BackendApiClient.addCommonHeaders]) - the
     * registry's `RequireAuth` gate is deployment-dependent (the test
     * environment happens to have it off; production might not), and it
     * should carry the same tenant-routing header every other backend call
     * does regardless.
     *
     * Issuer-direct (`<issuerUrl>/type-metadata/<scope>`) and well-known
     * (`.well-known/vct/...`) fallback requests hit arbitrary third-party
     * issuer domains and must NEVER receive these headers - leaking the
     * wallet's own bearer token / tenant ID to an external issuer would be a
     * real security bug. That's why the headers are attached here, gated on
     * the target URL actually being [registryUrl], rather than unconditionally
     * in the shared closure both fetchers use for every strategy.
     */
    private suspend fun fetchTypeMetadataUrl(url: String): String? {
        val request = Request.Builder().url(url).get()
        val registryBase = registryUrl.trimEnd('/')
        if (url.startsWith(registryBase)) {
            request.header("X-Tenant-ID", config.tenantId)
            val token = try {
                legacyAppToken ?: authTokens.ensureBackendToken().raw
            } catch (e: Exception) {
                Timber.w(e, "fetchTypeMetadataUrl: no token source for registry request — sending unauthenticated")
                null
            }
            if (token != null) {
                request.header("Authorization", "Bearer $token")
            }
        }
        val response = httpClient.newCall(request.build()).execute()
        return if (response.isSuccessful) response.body?.string() else null
    }

    /**
     * Resolves which [config].availableKeystores entry (if any) should back
     * a given credential-issuance key batch - see [WscdSelectionPolicy]'s
     * doc comment for the full resolution order. Constructing this
     * unconditionally is harmless: it's only ever consulted (in
     * [resolveEffectiveKeystoreForIssuance]) when [config].availableKeystores
     * is non-empty, so a caller that never sets that field never triggers
     * any TOFU read/write or prompting.
     */
    private val wscdSelectionPolicy = WscdSelectionPolicy(
        tofuStore = SessionStoreWscdTofuStore(sessionStore),
        defaultMapping = config.defaultWscdMapping,
        requestChoice = config.requestWscdChoice,
        userOverrideStore = SessionStoreWscdUserOverrideStore(sessionStore),
    )

    /**
     * The active account's persisted WSCD TOFU mapping (see
     * [WscdSelectionPolicy]'s doc comment), keyed by
     * `"issuer|credentialType"` -> plugin ID - exposed read-only so a
     * host-app settings screen can display it without reaching into SDK
     * internals ([SessionStore] is `internal`). Empty when no active
     * account or no choices have been persisted yet.
     */
    fun wscdTofuMapping(): Map<String, String> = wscdSelectionPolicy.tofuMapping()

    /**
     * Forget one persisted WSCD TOFU choice - a "forget this choice"
     * settings-screen affordance. The next credential-issuance batch for
     * that (issuer, credentialType) pair re-resolves from scratch (see
     * [WscdSelectionPolicy.resolve]'s doc comment).
     */
    fun clearWscdTofuMapping(issuer: String, credentialType: String) =
        wscdSelectionPolicy.clearTofuMapping(issuer, credentialType)

    /** Forget every persisted WSCD TOFU choice for the active account. */
    fun clearAllWscdTofuMappings() = wscdSelectionPolicy.clearAllTofuMappings()

    /**
     * Explicitly set a per-(issuer, credentialType) user override, e.g. "for
     * this issuer, always use my YubiKey even though a software key would
     * suffice" - a deliberate preference, distinct from [wscdTofuMapping]'s
     * auto-remembered ambiguous-choice outcome (see
     * [WscdSelectionPolicy.setUserOverride]'s doc comment). Only ever
     * RAISES the effective tier used: [WscdSelectionPolicy.resolve] still
     * requires the overridden plugin to meet the credential type's declared
     * requirement, falling through to the rest of its resolution order
     * otherwise (e.g. if the requirement was later raised past what this
     * plugin provides, or the plugin was unregistered).
     */
    fun setUserOverride(issuer: String, credentialType: String, pluginId: String) =
        wscdSelectionPolicy.setUserOverride(issuer, credentialType, pluginId)

    /** Forget one persisted per-(issuer, credentialType) user override. */
    fun clearUserOverride(issuer: String, credentialType: String) =
        wscdSelectionPolicy.clearUserOverride(issuer, credentialType)

    /**
     * Every persisted per-(issuer, credentialType) user override, keyed by
     * `"issuer|credentialType"` -> plugin ID - for a host-app settings
     * screen, kept separate from [wscdTofuMapping] so the UI can distinguish
     * "what I was asked and picked" from "what I've explicitly locked in".
     */
    fun currentUserOverrides(): Map<String, String> = wscdSelectionPolicy.currentUserOverrides()

    /**
     * Explicitly set the single global user override - "always use this
     * plugin for every issuer/credential type", unless a more specific
     * [setUserOverride] entry also applies (which wins first).
     */
    fun setGlobalUserOverride(pluginId: String) = wscdSelectionPolicy.setGlobalUserOverride(pluginId)

    /** Forget the persisted global user override, if any. */
    fun clearGlobalUserOverride() = wscdSelectionPolicy.clearGlobalUserOverride()

    /** The persisted global user override, or `null` if none set. */
    fun currentGlobalUserOverride(): String? = wscdSelectionPolicy.currentGlobalUserOverride()

    /**
     * A hardware-backed WSCD plugin's persisted key metadata, synced via
     * privatedata (see [WscdKeystoreAdapter.exportWscdCredentialsState]'s
     * doc comment) - `null` before any key has ever been exported for this
     * plugin. The host app should pass this to
     * [WscdManager.registerFido2PluginWithState] instead of
     * [WscdManager.registerFido2Plugin] whenever it's non-null, so a key
     * enrolled on ANY device sharing this account - not just the one that
     * originally enrolled it - stays addressable. Deliberately NOT backed by
     * device-local storage: CTAP2 roaming authenticators (e.g. a YubiKey)
     * are enrolled once but usable from any device.
     */
    suspend fun wscdCredentials(pluginId: String): String? =
        (keystore as? WscdKeystoreAdapter)?.exportWscdCredentialsState()?.get(pluginId)

    /**
     * Record a WSCD plugin's freshly-exported key metadata (see
     * [WscdManager.exportFido2State]) and sync it to the backend, so it
     * survives to the next [wscdCredentials] call on any device sharing
     * this account. Call after every enrollment/key-generation that could
     * have changed the plugin's state.
     */
    suspend fun saveWscdCredentials(pluginId: String, state: String) {
        (keystore as? WscdKeystoreAdapter)?.setWscdCredentialsState(pluginId, state)
        persistAndSyncKeystore()
    }

    /**
     * Every credential batch's durable OID4VCI renewal candidate
     * (`S.credentialRefreshTokens` - privatedata-spec §6.2), unlike
     * [wscdCredentials] this applies regardless of which concrete
     * [KeystoreManager] backs [keystore] - both the default [JweKeystore]
     * and [WscdKeystoreAdapter] (which internally delegates to its own
     * [JweKeystore] for credential/privatedata storage, separately from
     * whatever WSCD backs key signing) expose it.
     */
    private suspend fun exportCredentialRefreshTokens(): Map<Long, CredentialRefreshTokenEntry> =
        (keystore as? JweKeystore)?.exportCredentialRefreshTokens()
            ?: (keystore as? WscdKeystoreAdapter)?.exportCredentialRefreshTokens()
            ?: emptyMap()

    private suspend fun setCredentialRefreshToken(batchId: Long, entry: CredentialRefreshTokenEntry) {
        (keystore as? JweKeystore)?.setCredentialRefreshToken(batchId, entry)
        (keystore as? WscdKeystoreAdapter)?.setCredentialRefreshToken(batchId, entry)
    }

    private suspend fun removeCredentialRefreshToken(batchId: Long) {
        (keystore as? JweKeystore)?.removeCredentialRefreshToken(batchId)
        (keystore as? WscdKeystoreAdapter)?.removeCredentialRefreshToken(batchId)
    }

    /**
     * Exposes [authProvider] as a [WscdAutoEnrollHint] when it implements
     * one - `null` otherwise (e.g. a host-supplied [AuthProvider] that
     * doesn't). Intended use: right after a successful [login], the host
     * app checks `wscdAutoEnrollHint()?.suggestsWscdCapableDevice()` to
     * decide whether to offer enrolling the just-used login credential as a
     * WSCD signing device - see that interface's doc comment for why this
     * is a hint requiring a real (offered, not automatic) enrollment
     * attempt to confirm, not a guarantee.
     */
    fun wscdAutoEnrollHint(): WscdAutoEnrollHint? = authProvider as? WscdAutoEnrollHint

    // New AS-based auth
    private val authServerClient = AuthServerClient(
        context = activity,
        baseUrl = config.backendUrl,
        tenantId = config.tenantId,
    )
    private val legacyAuthClient = WebAuthnAuthClient(
        baseUrl = config.backendUrl,
        tenantId = config.tenantId,
        authProvider = authProvider,
        httpClient = httpClient,
        json = json,
    )

    private enum class AuthMode { UNKNOWN, NEW_AS, LEGACY_AS }
    private var authMode: AuthMode = AuthMode.UNKNOWN
    private var legacyAppToken: String? = null

    private val authTokens = AuthTokens(authServerClient, config.tenantId).apply {
        onSessionRejected = { handleReauthenticationRequired() }
    }

    /**
     * Fires whenever ANY code path determines the current session is no
     * longer valid and can't be silently refreshed - repeated REST 401s
     * ([AuthTokens.onSessionRejected]) or the engine WebSocket's token
     * refresh failing before a reconnect ([WalletEngineSession.State.REAUTH_REQUIRED],
     * observed via [engineStateJob]). Notifies the host app via
     * [WalletEventListener.onReauthenticationRequired] - distinct from
     * [WalletEventListener.onFlowError] - so it can route straight to a
     * login screen instead of surfacing a generic error message, then logs
     * out to put the SDK's own state in sync with that.
     *
     * Dispatches onto [scope] (Main) rather than calling the listener inline:
     * [AuthTokens.onSessionRejected] can fire this from whatever thread detected
     * the rejection (e.g. a background REST call), and [WalletEventListener]'s
     * contract promises every callback runs on the main thread.
     */
    private fun handleReauthenticationRequired() {
        Timber.w("Re-authentication required — session/token refresh failed")
        val generation = beginSelfDrivenRelogin()
        if (generation == null) {
            Timber.d("Ignoring re-authentication signal: one re-login already ran for this session, or there is none to replace")
            return
        }
        scope.launch {
            try {
                // The host hook stays: apps that drive their own prompt still
                // get told, and it fires before the SDK's attempt so a host
                // that routes to its login screen sees the same ordering as
                // before this change.
                eventListener?.onReauthenticationRequired()
                // A cut-off (SID-AUTH-06) looks exactly like an expired
                // session from here; the difference only shows in the login
                // that follows, which is refused with WALLET_SUSPENDED /
                // WALLET_REVOKED. Attempt it once - never in a loop - so the
                // state machine converges without host code.
                reloginAfterCutOff(generation)
            } catch (e: Exception) {
                Timber.e(e, "Self-driven re-login after a session cut-off failed")
                if (_state.value !is WalletState.LifecycleBlocked) logout()
            } finally {
                endSelfDrivenRelogin()
            }
        }
    }

    private val _presentationHistory = mutableListOf<PresentationRecord>()

    /** Presentation history — most recent first. */
    val presentationHistory: List<PresentationRecord> get() = _presentationHistory.toList()

    /**
     * Filters [instances] down to the ones this wallet's own
     * [credentialConsumptionPolicy] and [presentationHistory] currently
     * consider eligible (i.e. not yet consumed), AND whose bound signing
     * key still actually exists in [keystore] - the same computation this
     * class performs internally before every presentation, exposed as a
     * convenience so consent/selection UI doesn't need to thread policy,
     * history, and live key availability through
     * [CredentialUtils.eligibleInstances] itself.
     *
     * The key-availability half of this check exists because a real,
     * recurring bug (found via live proximity-presentation testing) let a
     * credential whose signing key was silently lost (e.g. a sync that
     * never folded a software key into the persisted container - see
     * privatedata-spec#1/siros-wscd-manager#68 for the deeper architectural
     * fix) keep reporting "available" under
     * [CredentialConsumptionPolicy.NEVER_CONSUME] forever, right up until a
     * live presentation attempt failed deep inside key selection with no
     * user-facing signal at all.
     *
     * @param isZkPresentation Per-candidate: will THIS presentation be a ZK
     * proof? Callers that know the matched query's format (the DC API path)
     * pass it so [CredentialConsumptionPolicy.CONSUME_NON_ZKP] can tell ZK
     * from raw; the default falls back to the stored format, which is never
     * ZK - see [CredentialUtils.eligibleInstances].
     */
    suspend fun eligibleInstances(
        instances: List<StoredCredential>,
        isZkPresentation: ((StoredCredential) -> Boolean)? = null,
    ): List<StoredCredential> {
        val keyIds = availableKeyIds()
        return if (isZkPresentation == null) {
            CredentialUtils.eligibleInstances(instances, credentialConsumptionPolicy, presentationHistory, keyIds)
        } else {
            CredentialUtils.eligibleInstances(
                instances,
                credentialConsumptionPolicy,
                presentationHistory,
                keyIds,
                isZkPresentation,
            )
        }
    }

    /**
     * The `kid`s this wallet's keystore can currently sign with - exposed so
     * consent/selection UI (e.g. `PresentationConsentScreen`'s exhausted-
     * query precheck) can compute eligibility ahead of time, in a
     * `LaunchedEffect`/`produceState`, without needing a full
     * [eligibleInstances] round trip per candidate list.
     */
    suspend fun availableKeyIds(): Set<String> = keystore.listKeys().map { it.keyId }.toSet()

    /**
     * Record a new presentation: adds it to the in-memory history and
     * persists it into the encrypted container (privatedata-spec's
     * `S.presentations[]`) so [CredentialUtils.groupForDisplay]'s
     * remaining-copies count survives an app restart instead of resetting
     * to the full batch size every time - mirrors [deleteCredential]'s
     * persist-after-mutation pattern.
     */
    private suspend fun recordPresentation(record: PresentationRecord) {
        _presentationHistory.add(0, record)
        if (keystore.isUnlocked) {
            keystore.savePresentationRecord(record.id, json.encodeToString(PresentationRecord.serializer(), record))
            persistAndSyncKeystore()
        }
        checkRenewThresholds(record.credentialIds)
    }

    /**
     * Per-credential-configuration-id override for [CredentialUtils.RENEW_THRESHOLD]
     * (plan §4.3: "near-expiry threshold is a per-credential user
     * preference," not a global constant). Not durably persisted in this
     * pass - callers wanting persistence across restarts should re-set this
     * on wallet construction from their own settings store, matching how
     * [credentialConsumptionPolicy] itself is currently handled.
     */
    var renewThresholds: MutableMap<String, Int> = mutableMapOf()

    private fun renewThresholdFor(credentialConfigurationId: String?): Int =
        credentialConfigurationId?.let { renewThresholds[it] } ?: CredentialUtils.RENEW_THRESHOLD

    /**
     * After [consumedCredentialIds] were just presented (see
     * [recordPresentation]), check whether any of their batches dropped to
     * or below its renew threshold and fire [WalletEventListener.onCredentialNearExpiry]
     * if so - the proactive-renewal trigger (plan §4.3).
     */
    private suspend fun checkRenewThresholds(consumedCredentialIds: List<Long>) {
        val allCredentials = credentialStore.getAll()
        val affectedBatchIds = consumedCredentialIds
            .mapNotNull { id -> allCredentials.find { it.id == id }?.batchId }
            .distinct()
        for (batchId in affectedBatchIds) {
            val batchInstances = allCredentials.filter { it.batchId == batchId }
            val representative = batchInstances.find { it.instanceId == 0 } ?: batchInstances.firstOrNull() ?: continue
            val threshold = renewThresholdFor(representative.credentialConfigurationId)
            val eligible = eligibleInstances(batchInstances)
            if (eligible.size <= threshold) {
                eventListener?.onCredentialNearExpiry(representative, eligible.size, threshold)
            }
        }
    }

    /** Reload presentation history from the encrypted container after unlock. */
    private suspend fun reloadPresentationHistory() {
        _presentationHistory.clear()
        _presentationHistory.addAll(
            keystore.getAllPresentationRecords().values.mapNotNull { raw ->
                try {
                    json.decodeFromString(PresentationRecord.serializer(), raw)
                } catch (e: Exception) {
                    Timber.w(e, "Failed to deserialize presentation record")
                    null
                }
            }.sortedByDescending { it.timestamp }
        )
    }

    private var apiClient: BackendApiClient? = null
    private var engineSession: WalletEngineSession? = null
    /** Collects [engineSession]'s state to catch [WalletEngineSession.State.REAUTH_REQUIRED]
     *  transitions from the automatic background reconnect loop, which never
     *  goes through [WalletEngineSession.awaitConnected] - cancelled/replaced
     *  whenever a new engine session is created (see [connectEngine]) or on
     *  [logout], since a raw StateFlow collector doesn't complete on its own
     *  just because the engine's internal scope was cancelled. */
    private var engineStateJob: kotlinx.coroutines.Job? = null
    /** Transport-independent notifier for OID4VCI §10 events. */
    private var credentialNotifier: CredentialNotifier? = null
    private var eventListener: WalletEventListener? = null
    private var activeOffer: CredentialOffer? = null
    private var activeVctm: Vctm? = null

    /**
     * The bytes [activeVctm] was parsed from, kept so `vct#integrity` can be
     * checked against the document as served rather than a re-serialisation.
     */
    private var activeVctmDocument: org.siros.sdk.credentials.VctmDocument? = null
    private var activeMddlSchema: org.siros.sdk.credentials.MddlSchema? = null
    /**
     * Set by [renewCredential] right before firing the renewal flow_start,
     * so the next flow_complete knows to replace this batchId's entries
     * instead of appending a new batch alongside them. Assumes a single
     * in-flight renewal at a time - real per-flow lineage tracking would
     * need to key this by flow ID for correctness under concurrent flows
     * (see task tracking this as a known simplification).
     */
    private var pendingRenewalSourceBatchId: Long? = null
    /**
     * True while an issuance flow is in flight (from [startIssuanceByOffer]/
     * [startIssuance] until its flow_complete/flow_error arrives).
     *
     * [activeOffer]/[activeVctm]/[activeAttestedKeyIds] are ambient fields,
     * not keyed by flow ID - the engine's [WalletEngineSession.startIssuance]
     * doesn't return a flow ID synchronously (the server only assigns one,
     * reported back asynchronously in the flow's first progress message), so
     * there's no ID available at the moment these fields are written to key
     * them by. Starting a second issuance before the first one's
     * flow_complete/flow_error arrives would silently read/write the wrong
     * flow's offer/VCTM/attested-key-IDs (real bug found via code review:
     * this data ends up in [StoredCredential.kid], so a race here binds the
     * wrong signing key to the wrong credential type). Guarding against a
     * second concurrent issuance turns that into a loud, catchable error
     * instead of silent cross-contamination.
     */
    private var issuanceInFlight = false
    /**
     * Key IDs generated for the current batch's Key Attestation proof, in the
     * SAME order they were submitted as `attested_keys` - an OID4VCI issuer
     * mints credential N in the response bound to `attested_keys[N]`'s public
     * key (per the batch-issuance convention this attestation flow already
     * follows, see [requestBackendKeyAttestation]'s doc comment), so
     * `StoredCredential.kid` for the credential at [StoredCredential.instanceId]
     * `i` must be `activeAttestedKeyIds[i]` - without this, every signing
     * operation had no way to know which of the N generated keys a given
     * batch credential was actually bound to, and silently used an arbitrary
     * one (see [WscdKeystoreAdapter.selectSigningKey]'s doc comment).
     */
    private var activeAttestedKeyIds: List<String>? = null

    /**
     * Clear the ambient issuance-in-progress guard fields, unconditionally.
     *
     * Every terminal path for an issuance attempt must call this - a
     * flow_complete/flow_error from the engine, a client-side termination
     * (e.g. [reportSignFailure]), a synchronous start failure, or the user
     * cancelling before the engine ever assigned a flow ID at all (see
     * [cancelCurrentFlow]'s doc comment for why that last case is real and
     * not just defensive: without it, cancelling a slow/unresponsive
     * issuer - before any [WalletState.FlowActive] state is ever reached -
     * left [issuanceInFlight] stuck `true` forever, since nothing else was
     * left running to clear it, permanently blocking every future issuance
     * attempt until the app process was killed).
     *
     * Also clears [pendingRenewalSourceBatchId]: a renewal attempt (silent
     * or the full-reissuance fallback) that fails or is cancelled before its
     * own flow_complete arrives must not leave this set - otherwise the
     * NEXT, unrelated successful issuance's flow_complete would find it
     * still set and incorrectly delete that stale batch's credentials.
     */
    private fun resetIssuanceGuards() {
        activeOffer = null
        activeVctm = null
        activeVctmDocument = null
        activeMddlSchema = null
        activeAttestedKeyIds = null
        issuanceInFlight = false
        pendingRenewalSourceBatchId = null
        // The holder's contribution belongs to the flow that carried it. A
        // later issuance that supplies none must not silently inherit this
        // one's claims and commit to them.
        activeZkIssuanceInput = null
    }

    /**
     * Extract the last credential ID from the auth provider, regardless of type.
     */
    private fun extractLastCredentialId(): ByteArray? = when (authProvider) {
        is LocalAuthProvider -> authProvider.lastCredentialId
        is CredentialManagerAuthProvider -> authProvider.lastCredentialId
        else -> null
    }

    /**
     * Roll back a locally-stored credential after a failed registration.
     * Prevents orphaned passkeys from appearing in the "Welcome back" picker.
     */
    private fun rollbackLocalCredential() {
        if (authProvider is LocalAuthProvider) {
            authProvider.rollbackLastRegistration()
        }
    }

    /**
     * Extract the last PRF output from the auth provider, regardless of type.
     */
    private fun extractLastPrfOutput(): PrfOutput? = when (authProvider) {
        is LocalAuthProvider -> authProvider.lastPrfOutput
        is CredentialManagerAuthProvider -> authProvider.lastPrfOutput
        else -> null
    }

    private fun setupApiClient(session: AuthSession) {
        Timber.d("setupApiClient: legacy authenticated session established")
        apiClient = BackendApiClient(config.backendUrl, config.tenantId, httpClient = httpClient).apply {
            setAppToken(session.appToken)
        }
    }

    private fun setupApiClientWithTokens() {
        Timber.d("setupApiClient: using AuthTokens for automatic token management")
        apiClient = BackendApiClient(config.backendUrl, config.tenantId, httpClient = httpClient).apply {
            setAuthTokens(authTokens)
        }
    }

    /**
     * Fetch this account's encrypted private-data container from the
     * backend. An empty result means the backend explicitly reported no
     * `privateData` field - a genuinely new account with nothing stored yet
     * - and callers (see [finishLogin]) treat that as license to initialize
     * a brand-new, empty keystore.
     *
     * A transient failure (network blip, backend 5xx) must NOT be folded
     * into that same empty-result case: a returning user hitting a
     * momentary outage would otherwise look identical to a new user, get
     * unlocked against a freshly-generated empty container, and then have
     * that empty container synced BACK to the backend on the very next
     * mutation - silently overwriting their real data with nothing.
     * Confirmed as a real gap via code review, not yet an observed
     * incident. Network/API errors are re-thrown instead so login fails
     * loudly and the user can retry once the backend is reachable again.
     */
    private suspend fun fetchPrivateData(): ByteArray {
        val client = apiClient ?: throw WalletException("Not authenticated")
        try {
            val response = client.getPrivateData()
            val pdElement = response["privateData"]
            if (pdElement != null) {
                // Backend returns {"privateData": {"$b64u": "base64url-encoded-container"}}
                val containerBytes = when (pdElement) {
                    is kotlinx.serialization.json.JsonObject -> {
                        val b64u = pdElement["\$b64u"]?.jsonPrimitive?.content
                        if (b64u != null) {
                            b64UrlDecode(b64u)
                        } else {
                            // Container is inline JSON
                            pdElement.toString().toByteArray(Charsets.UTF_8)
                        }
                    }
                    is kotlinx.serialization.json.JsonPrimitive -> {
                        // Plain string (legacy or direct JWE)
                        pdElement.content.toByteArray(Charsets.UTF_8)
                    }
                    else -> ByteArray(0)
                }
                if (containerBytes.isNotEmpty()) {
                    sessionStore.privateDataJwe = String(containerBytes, Charsets.UTF_8)
                }
                return containerBytes
            }
            return ByteArray(0)
        } catch (e: NetworkException) {
            throw WalletException("Could not fetch private data (network): ${e.message}", e)
        } catch (e: BackendApiException) {
            throw WalletException("Could not fetch private data (HTTP ${e.code}): ${e.message}", e)
        }
    }

    private suspend fun syncPrivateDataToBackend() {
        val client = apiClient ?: return
        val containerJson = sessionStore.privateDataJwe ?: return
        try {
            // Send the full container JSON as the POST body,
            // matching the wallet-frontend's format.
            val body = Json.parseToJsonElement(containerJson).jsonObject
            client.updatePrivateData(body)
            Timber.d("Private data synced to backend")
        } catch (e: Exception) {
            Timber.e(e, "Failed to sync private data to backend")
            eventListener?.onFlowError("sync", "Private data sync failed: ${e.message}")
        }
    }

    /**
     * Persist the current keystore state to local storage and sync to backend.
     *
     * Called after any credential mutation to minimise the data-loss window.
     */
    private suspend fun persistAndSyncKeystore() {
        if (!keystore.isUnlocked) return
        try {
            val container = keystore.exportEncryptedContainer()
            sessionStore.privateDataJwe = String(container, Charsets.UTF_8)
            syncPrivateDataToBackend()
        } catch (e: Exception) {
            // Unlike syncPrivateDataToBackend's own catch, this previously
            // only logged - a credential saved just before this failed would
            // silently never reach local storage or the backend, vanishing
            // on the next app restart/lock with no signal anywhere that it
            // happened.
            Timber.e(e, "Failed to persist keystore")
            eventListener?.onFlowError("sync", "Failed to persist keystore: ${e.message}")
        }
    }

    /**
     * Connect the engine using a backend token from the AS (new AS) or the
     * authenticated app token (legacy AS). The anonymous token is scoped to
     * `tac="rl"` for registry-style reads only - the engine session needs
     * `insert` for OID4VCI issuance, so it must use the fully-scoped backend
     * token, not the anonymous one (go-wallet-backend#264 made the missing
     * `insert` scope a hard server-side rejection for `oid4vci` flow_start,
     * not just a documentation note).
     */
    private suspend fun connectEngineWithToken() {
        val token = legacyAppToken ?: authTokens.ensureBackendToken().raw
        if (config.useWmpProtocol) {
            connectViaWmp(token)
        } else {
            connectEngine(token)
        }
    }

    // ── WMP Protocol Path ─────────────────────────────────────────────

    private var wmpPeer: org.siros.sdk.transport.wmp.WmpPeer? = null

    private suspend fun connectViaWmp(appToken: String) {
        // Same leaked-connection hazard as connectEngine's engineSession -
        // tear down any prior live peer before replacing the reference.
        wmpPeer?.close()

        // Resolve engine URL: explicit config > discovery > same as backend
        val engineBaseUrl = (config.engineUrl
            ?: WalletConfig.discoverEngineUrl(config.backendUrl)
            ?: config.backendUrl).trimEnd('/')
        val wsUrl = engineBaseUrl.replace("http://", "ws://").replace("https://", "wss://") +
            "/api/v2/wallet?tenant_id=${config.tenantId}"

        val transport = org.siros.sdk.transport.wmp.WmpWebSocketTransport(wsUrl)
        val session = org.siros.sdk.transport.wmp.WmpSession(transport)
        val peer = org.siros.sdk.transport.wmp.WmpPeer(session)

        val profile = org.siros.sdk.transport.wmp.openid4x.OpenID4xProfile(
            org.siros.sdk.transport.wmp.openid4x.OpenID4xConfig(
                onSignRequest = { flowId, params -> handleWmpSignRequest(flowId, params) },
                onMatchRequest = { flowId, payload -> handleWmpMatchRequest(flowId, payload) },
                onTrustEvaluation = { flowId, payload -> handleWmpTrustEvaluation(flowId, payload) },
                onComplete = { flowId, _ ->
                    Timber.i("WMP flow $flowId complete")
                    eventListener?.onFlowComplete(flowId)
                },
                onError = { flowId, code, message ->
                    Timber.e("WMP flow $flowId error: $code — $message")
                    eventListener?.onFlowError(flowId, "$code: $message")
                },
            )
        )
        peer.use(profile)
        peer.connect(appToken)
        wmpPeer = peer
        // WMP peer handles credential notifications via the profile
        credentialNotifier = null // Notifications go through WmpPeer.sendCredentialNotification()

        Timber.i("Connected via WMP protocol to $wsUrl")
    }

    /** Transport-agnostic description of one generated OID4VCI proof. */
    private data class GeneratedProofData(
        val proofType: String,
        val jwt: String? = null,
        val attestation: String? = null,
        /**
         * Key IDs backing `attestation`'s `attested_keys`, in submission
         * order - null when unavailable. See [SirosWallet.activeAttestedKeyIds]'s
         * doc comment for why this ordering matters for per-credential key
         * selection at signing time.
         */
        val attestedKeyIds: List<String>? = null,
    )

    /**
     * Recover the signing key's `kid` from a `jwt`-proof-type proof-of-possession
     * JWT's embedded `jwk` header claim, since [KeystoreManager.generateProof]
     * doesn't return it directly. Without this, [activeAttestedKeyIds] stayed
     * null for every credential issued via the (preferred, common) `jwt` proof
     * path - a real bug found via live proximity-presentation testing: with
     * `credential.kid` null, [WscdKeystoreAdapter.selectSigningKey] falls back
     * to "first available key" among ALL WSCD keys, which is only correct by
     * chance whenever more than one key exists - `deviceSignature` verification
     * then fails unpredictably depending on `signer.listKeys()`'s ordering.
     */
    private fun extractProofKeyId(jwt: String): String? {
        return try {
            val headerPart = jwt.substringBefore(".")
            val padded = headerPart + "=".repeat((4 - headerPart.length % 4) % 4)
            val headerJson = String(java.util.Base64.getUrlDecoder().decode(padded), Charsets.UTF_8)
            Json.parseToJsonElement(headerJson).jsonObject["jwk"]?.jsonObject?.get("kid")?.jsonPrimitive?.contentOrNull
        } catch (e: Exception) {
            Timber.w(e, "Failed to extract kid from proof JWT header")
            null
        }
    }

    /**
     * Decide which OID4VCI proof type to produce and generate it - shared by
     * both the legacy WebSocket engine and the WMP transport, since both
     * ultimately talk to the same wallet-backend engine (internal/engine/oid4vci.go's
     * requestProofs), which advertises the issuer's proof_types_supported the
     * same way regardless of which transport carried the request.
     *
     * Prefers `jwt` (simple, one proof-of-possession JWT per credential,
     * per [org.siros.sdk.transport.wmp.openid4x.ProofType.JWT]) when the
     * issuer supports it - unchanged from prior behavior. Falls back to
     * `attestation` (OID4VCI Appendix F.3: a single Key Attestation JWT
     * covering the whole batch via `attested_keys`) only when `jwt` isn't
     * listed - e.g. a real-world mdoc issuer that requires the wallet to
     * assert the key storage/user-authentication security properties of the
     * credential-binding keys instead of a plain signed proof.
     *
     * [proofTypesSupported] (from the issuer's metadata, relayed by the
     * backend) takes precedence when present; [proofTypeHint] is a fallback
     * for a transport that only forwards a single pre-decided type.
     *
     * Both branches resolve [resolveEffectiveKeystoreForIssuance] before
     * signing - a real bug found via live testing: the `jwt` branch used to
     * sign directly on [keystore] (the wallet's single unconditional
     * default), never consulting [WscdSelectionPolicy] at all. Since `jwt`
     * is the PREFERRED branch whenever an issuer supports it, this meant
     * every WSCD override (per-issuer, global, TOFU, host-app default
     * mapping) was silently unreachable for any such issuer - only an
     * issuer that specifically required `attestation` ever exercised
     * plugin selection. `jwt`'s simplicity (no backend session, no
     * attestation semantics) doesn't change which physical key/plugin
     * should sign it, so it must resolve the same way `attestation` does.
     */
    private suspend fun generateProofsForRequest(
        audience: String,
        nonce: String,
        count: Int,
        proofTypesSupported: Set<String>?,
        proofTypeHint: String?,
    ): List<GeneratedProofData> {
        val chosen = when {
            !proofTypesSupported.isNullOrEmpty() ->
                if ("jwt" in proofTypesSupported) "jwt"
                else proofTypesSupported.firstOrNull { it == "attestation" } ?: proofTypesSupported.first()
            !proofTypeHint.isNullOrBlank() -> proofTypeHint
            else -> "jwt"
        }
        return if (chosen == "attestation") {
            val backendResult = requestBackendKeyAttestation(audience, nonce, count)
            listOf(GeneratedProofData(
                proofType = "attestation",
                attestation = backendResult.jwt,
                attestedKeyIds = backendResult.keyIds,
            ))
        } else {
            val effectiveKeystore = resolveEffectiveKeystoreForIssuance()
            try {
                (1..count).map {
                    val proofJwt = effectiveKeystore.generateProof(
                        audience = audience,
                        nonce = nonce,
                        freshKey = count > 1,
                    )
                    val keyId = extractProofKeyId(proofJwt)
                    GeneratedProofData(proofType = "jwt", jwt = proofJwt, attestedKeyIds = keyId?.let { listOf(it) })
                }
            } finally {
                config.onWscdOperationEnd?.invoke()
            }
        }
    }

    /**
     * Ask go-wallet-backend's real, x5c-chained Key Attestation endpoint
     * (`POST /wallet-provider/key-attestation/generate`) to attest freshly
     * generated keys, instead of [KeystoreManager.generateKeyAttestation]'s
     * self-signed fallback (a bare `jwk` header - cryptographically valid
     * but no trust anchor a real issuer can validate against).
     *
     * Private keys never leave the device: only the public JWKs (from
     * [KeystoreManager.generateKeypairs]) and security properties are sent:
     * the backend signs an attestation *over* them with its own,
     * operator-provisioned x5c-chained key.
     *
     * Falls back to [KeystoreManager.generateKeyAttestation] (self-signed) on
     * [effectiveKeystore] - NEVER on [keystore], the wallet's unconditional
     * default - when there's no backend session, the keystore can't produce
     * raw keypairs (e.g. a non-WSCD backend that only overrides
     * [KeystoreManager.generateKeyAttestation] directly), or the backend
     * doesn't support/expose the endpoint (older backend version, or
     * `wallet_provider` not configured there): [effectiveKeystore] is
     * [resolveEffectiveKeystoreForIssuance]'s result, which may be a
     * different, higher-tier plugin than [keystore] - falling back to
     * [keystore] instead would silently downgrade to a lower-tier self-signed
     * attestation despite [WscdSelectionPolicy] having already resolved a
     * sufficient plugin for this call, defeating the entire point of that
     * resolution. Matches the same "degrade gracefully" behavior as the rest
     * of this SDK's backend-optional flows, just anchored to the right
     * keystore instance.
     *
     * [resolveEffectiveKeystoreForIssuance] is called unconditionally, before
     * checking for a backend session, so [NoEligibleWscdPluginException] /
     * [AmbiguousWscdPluginException] always propagate to the caller instead
     * of being caught below - those signal "issuance must not proceed at
     * all", not "the backend attestation call specifically failed".
     */
    private suspend fun requestBackendKeyAttestation(audience: String, nonce: String, count: Int): BackendAttestationResult {
        val effectiveKeystore = resolveEffectiveKeystoreForIssuance()
        try {
            val client = apiClient
                ?: return BackendAttestationResult(
                    jwt = effectiveKeystore.generateKeyAttestation(nonce = nonce, count = count),
                    keyIds = null,
                )
            return try {
                val keypairs = effectiveKeystore.generateKeypairs(count)
                registerFido2AttestationsForBatch(keypairs, client, effectiveKeystore)
                val securityProps = keypairs.firstOrNull()?.let { effectiveKeystore.securityProperties(it.keyId) }
                val jwt = client.requestKeyAttestation(
                    jwks = keypairs.map { it.publicKeyJWK },
                    nonce = nonce,
                    securityProperties = securityProps,
                    credentialIssuer = audience,
                    walletInstanceId = currentWalletInstanceId(),
                )
                // keypairs[i]'s key is exactly attested_keys[i] in the JWT just
                // built (jwks preserves list order) - the issuer is expected to
                // mint credential i in the eventual batch response bound to
                // attested_keys[i], so this ordering IS the instanceId -> kid
                // mapping the credential-storage handler needs later.
                BackendAttestationResult(jwt = jwt, keyIds = keypairs.map { it.keyId })
            } catch (e: UnsupportedOperationException) {
                Timber.d("Keystore doesn't support raw keypair generation, using self-signed key attestation")
                BackendAttestationResult(jwt = effectiveKeystore.generateKeyAttestation(nonce = nonce, count = count), keyIds = null)
            } catch (e: Exception) {
                Timber.w(e, "Backend key attestation request failed, falling back to self-signed attestation")
                BackendAttestationResult(jwt = effectiveKeystore.generateKeyAttestation(nonce = nonce, count = count), keyIds = null)
            }
        } finally {
            config.onWscdOperationEnd?.invoke()
        }
    }

    private data class BackendAttestationResult(val jwt: String, val keyIds: List<String>?)

    /**
     * Picks which [KeystoreManager] should back this issuance batch's key
     * generation - one of `config.availableKeystores`'s entries, chosen by
     * [wscdSelectionPolicy], or [keystore] (today's unconditional default)
     * when `config.availableKeystores` is unset/empty, the credential
     * type in scope declared no `Vctm.requiredKeyStorage` /
     * `MddlSchema.requiredKeyStorage` requirement, or [wscdSelectionPolicy]
     * otherwise resolves to "no change needed".
     *
     * The credential type in scope is read from [activeOffer] (issuer +
     * credential configuration ID) and [activeVctm] (SD-JWT VC requirement).
     * For mdoc credentials, [activeVctm] is always null (the VCTM endpoint's
     * response can't parse as a [Vctm] - it's missing the required `vct`
     * field), so the mdoc doctype's requirement is fetched here via
     * [mddlSchemaFetcher] using the same issuer/scope [activeOffer] already
     * carries - the wallet doesn't otherwise keep an "active MDDL schema"
     * field the way it keeps [activeVctm], since nothing needed one before
     * this feature.
     *
     * The `credentialType` identifier passed into [wscdSelectionPolicy] -
     * and therefore used for [WalletConfig.defaultWscdMapping]/TOFU/
     * user-override lookup keys - is the actual `Vctm.vct` / `MddlSchema.doctype`
     * the credential type carries, NOT `offer.credentialConfigurationId`
     * (an OID4VCI-internal configuration ID, which the public docs/config
     * examples never use as the key): `activeVctm?.vct ?: mddlSchema?.doctype
     * ?: offer.credentialConfigurationId` - falling back to the
     * configuration ID only covers the edge case where the offer carries
     * neither (empty/unavailable type metadata). Mirrors
     * `siros-sdk-swift`'s equivalent function's identical fallback chain, so
     * both SDKs key WSCD resolution the same way for a host app integrating
     * either one.
     *
     * Throws [NoEligibleWscdPluginException] when the credential type
     * declared a requirement but zero registered plugins meet it - this is
     * NOT caught here, so it propagates to [requestBackendKeyAttestation]'s
     * caller as a clear, distinct failure rather than silently falling back
     * to an insufficient plugin.
     */
    /**
     * Propagates unlock to every distinct [KeystoreManager] in
     * [WalletConfig.availableKeystores], not just [keystore].
     *
     * Found via live hardware testing: [resolveEffectiveKeystoreForIssuance]
     * can hand back an `availableKeystores` entry (e.g. "fido2") that is a
     * SEPARATE [KeystoreManager] instance from [keystore] - only [keystore]
     * itself was ever unlocked (at each of this class's `keystore.unlock(...)`
     * call sites), so the first real signing attempt through a resolved
     * non-default plugin threw `IllegalStateException("Keystore is locked")`
     * before ever reaching a PIN prompt. A plugin whose unlock fails here is
     * logged and skipped rather than failing the whole login/registration -
     * it simply won't be eligible for [WscdSelectionPolicy] resolution until
     * it can be unlocked (e.g. on a later retry).
     */
    private suspend fun unlockAvailableKeystores(
        prfOutput: ByteArray,
        encryptedContainer: ByteArray,
        hkdfSalt: ByteArray,
        hkdfInfo: ByteArray,
    ) {
        val seen = mutableSetOf<KeystoreManager>(keystore)
        config.availableKeystores?.values?.forEach { manager ->
            if (seen.add(manager)) {
                try {
                    manager.unlock(prfOutput, encryptedContainer, hkdfSalt, hkdfInfo)
                } catch (e: Exception) {
                    Timber.w(e, "unlockAvailableKeystores: failed to unlock an availableKeystores entry")
                }
            }
        }
    }

    private suspend fun resolveEffectiveKeystoreForIssuance(): KeystoreManager {
        val available = config.availableKeystores
        if (available.isNullOrEmpty()) {
            Timber.i("resolveEffectiveKeystoreForIssuance: no availableKeystores configured, using default keystore")
            return keystore
        }
        val offer = activeOffer ?: run {
            Timber.i("resolveEffectiveKeystoreForIssuance: no activeOffer, using default keystore")
            return keystore
        }
        val issuer = offer.credentialIssuerIdentifier

        val mddlSchema: MddlSchema? = if (activeVctm == null) {
            try {
                mddlSchemaFetcher.fetch(
                    issuerUrl = issuer,
                    scope = offer.credentialConfigurationId,
                    registryUrl = registryUrl,
                )
            } catch (e: Exception) {
                Timber.w(
                    e,
                    "Failed to fetch MDDL schema while resolving required key-storage tier for " +
                        "$issuer/${offer.credentialConfigurationId}",
                )
                null
            }
        } else {
            null
        }
        val requiredTier = activeVctm?.requiredKeyStorage ?: mddlSchema?.requiredKeyStorage
        val credentialType = activeVctm?.vct ?: mddlSchema?.doctype ?: offer.credentialConfigurationId

        // Identify which registered plugin (if any) is already the active
        // default, so WscdSelectionPolicy can prefer it over switching
        // unnecessarily when it's already sufficient.
        val currentDefaultPluginId = available.entries.firstOrNull { it.value === keystore }?.key

        Timber.i(
            "resolveEffectiveKeystoreForIssuance: issuer=$issuer credentialType=$credentialType " +
                "requiredTier=$requiredTier available=${available.keys} currentDefault=$currentDefaultPluginId " +
                "globalOverride=${wscdSelectionPolicy.currentGlobalUserOverride()} " +
                "userOverrides=${wscdSelectionPolicy.currentUserOverrides()}",
        )
        val pluginId = wscdSelectionPolicy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = requiredTier,
            availablePluginIds = available.keys,
            currentDefaultPluginId = currentDefaultPluginId,
        )
        Timber.i("resolveEffectiveKeystoreForIssuance: resolve() returned pluginId=$pluginId")
        if (pluginId == null) return keystore

        val resolved = available[pluginId] ?: keystore
        config.onWscdOperationStart?.invoke(pluginId)
        return resolved
    }

    /**
     * Register each freshly-generated credential key's FIDO2/CTAP2 hardware
     * attestation with the backend, keyed by that specific key - NOT the
     * wallet's own identity key (see go-wallet-backend's `KeyAttestationStore`
     * doc for why this must be per-credential-key: the identity key and
     * credential-issuance keys are separate keys, not guaranteed to share a
     * WSCD plugin, so registering only the identity key's attestation would
     * incorrectly leave the actual credential keys - the ones a KA request's
     * `attested_keys`/`security_properties` claim is really about -
     * unattested).
     *
     * A no-op per key when the effective keystore's active plugin isn't
     * hardware-backed ([WscdKeystoreAdapter.attestationChain] returns null
     * for those - most commonly the whole batch, since
     * `KeystoreManager.generateKeypairs` uses whichever single plugin is
     * currently active for every key in one call). Best-effort per key: a
     * registration failure for one key must never block the others, or the
     * overall KA request that follows - it's simply retried the next time a
     * fresh batch happens to reuse the same plugin (there's no "already
     * registered" dedup here, unlike the old identity-key path: these keys
     * are one-shot, used once for this batch, so there's nothing to dedupe
     * against).
     *
     * Requires a cached WIA to supply `wallet_instance_id` for the
     * registration record's auditing/scoping - peeks [cachedWia] directly
     * (any `attestation_source`, not gated to native platform attestation
     * like [currentWalletInstanceId] - that gate is specifically about the
     * KA security_properties clamp-lift, unrelated to this). No cached WIA
     * means nothing to register against, so this is a no-op entirely.
     *
     * @param effectiveKeystore the [KeystoreManager] the keys in [keypairs]
     *   were actually generated with - [resolveEffectiveKeystoreForIssuance]'s
     *   result, NOT unconditionally [keystore] (a chosen non-default WSCD
     *   plugin's attestation chain must be queried on that plugin's own
     *   keystore instance, not the wallet's default one).
     */
    private suspend fun registerFido2AttestationsForBatch(
        keypairs: List<KeypairInfo>,
        client: BackendApiClient,
        effectiveKeystore: KeystoreManager = keystore,
    ) {
        val now = System.currentTimeMillis() / 1000
        val wia = cachedWia?.takeIf { cachedWiaExpiresAt - now > 60 } ?: return
        val walletInstanceId = CredentialUtils.parseJwtPayload(wia)
            ?.get("cnf")?.jsonObject?.get("jkt")?.jsonPrimitive?.contentOrNull
            ?: return
        for (kp in keypairs) {
            try {
                val chain = effectiveKeystore.attestationChain(kp.keyId) ?: continue
                val attestationObject = chain.certificates.firstOrNull() ?: continue
                client.registerFido2Attestation(
                    walletInstanceId = walletInstanceId,
                    attestationObject = attestationObject,
                    clientDataHash = chain.clientDataHash,
                )
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                Timber.w(e, "FIDO2 attestation registration failed for key ${kp.keyId}, continuing")
            }
        }
    }

    private suspend fun handleWmpSignRequest(
        flowId: String,
        params: org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams,
    ): org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult {
        return when (params.action) {
            "generate_proof" -> {
                val count = params.count ?: 1
                val generated = generateProofsForRequest(
                    audience = params.audience,
                    nonce = params.nonce,
                    count = count,
                    proofTypesSupported = params.proofTypesSupported?.keys,
                    proofTypeHint = params.proofType,
                )
                // The "attestation" proof type returns a single GeneratedProofData
                // whose attestedKeyIds already covers the whole batch in order; the
                // "jwt" proof type returns one GeneratedProofData PER credential,
                // each carrying its own single-element attestedKeyIds - flatMap
                // concatenates either shape into one batch-order list. Taking only
                // the first entry's list (as this used to) silently dropped every
                // index past 0 for a "jwt" batch of more than one credential.
                activeAttestedKeyIds = generated.flatMap { it.attestedKeyIds.orEmpty() }.ifEmpty { null }
                val proofs = generated.map {
                    org.siros.sdk.transport.wmp.openid4x.ProofObject(
                        proofType = it.proofType, jwt = it.jwt, attestation = it.attestation,
                    )
                }
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult(
                    proofs = proofs,
                    credentialRequestExtras = zkIssuanceExtras(flowId),
                )
            }
            "sign_presentation" -> {
                // Same defense-in-depth audience check as the legacy engine
                // transport's handleSignRequest - this transport previously
                // skipped it entirely, so a WMP-relayed sign_presentation was
                // never checked against the trust result computed for this flow.
                validateAudience(flowId, params.audience)
                val vpToken = keystore.signPresentation(
                    nonce = params.nonce,
                    audience = params.audience,
                    credentialIds = emptyList(),
                )
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult(vpToken = vpToken)
            }
            // Client authentication, same semantics as the legacy transport's
            // handleRequestAttestation / handleSignClientAuth: the WMP sign
            // sub-flow carries the same params and the result goes back under
            // the same member names.
            "request_attestation" -> {
                val m = buildClientAuth(flowId, ClientAuthRequest(audience = params.audience, issuer = params.issuer))
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult(
                    clientAttestation = m.wia,
                    clientAttestationPoP = m.pop,
                )
            }
            "sign_client_auth" -> {
                val m = buildClientAuth(
                    flowId,
                    ClientAuthRequest(
                        keyIdHint = params.keyId,
                        audience = params.audience,
                        issuer = params.issuer,
                        htm = params.htm,
                        htu = params.htu,
                        dpopNonce = params.dpopNonce,
                        ath = params.ath,
                    ),
                )
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult(
                    clientAttestation = m.wia,
                    clientAttestationPoP = m.pop,
                    dpopKeyId = m.keyId,
                    dpopProof = m.dpopProof,
                )
            }
            else -> throw IllegalArgumentException("Unknown sign action: ${params.action}")
        }
    }

    /**
     * Answer the engine's credential-matching request on the WMP transport.
     *
     * This used to ignore `dcql_query` entirely and report every stored
     * credential as a match, so a wallet holding an mDL and no PID claimed a
     * full match set for a PID request - and any decision the engine keyed on
     * that answer would have been wrong for every wallet holding at least one
     * credential of any type. It now runs the same [CredentialMatcher] the
     * legacy transport and the DC API path use.
     *
     * An empty result carries [org.siros.sdk.transport.wmp.openid4x.MatchResult.noMatchReason],
     * which the profile relays as `credentials_matched` so the engine can end
     * the flow at once (go-wallet-backend#336) rather than let it sit at
     * credential selection until the five-minute user-interaction timeout.
     */
    private suspend fun handleWmpMatchRequest(
        flowId: String,
        payload: kotlinx.serialization.json.JsonObject?,
    ): org.siros.sdk.transport.wmp.openid4x.MatchResult {
        val allCreds = credentialStore.getAll()
        // `as? JsonObject`, not `.jsonObject`: a non-DCQL request shape has
        // this key relayed as JSON `null` rather than omitted, and
        // `.jsonObject` throws on that - the same crash #150 fixed in the
        // legacy transport's credential_selection handler.
        val dcqlQuery = payload?.get("dcql_query") as? JsonObject
        if (dcqlQuery == null) {
            // No query to match against: every credential is still a
            // candidate, which is what this handler always answered. The bug
            // was answering that for a real query too.
            Timber.w("WMP match request for flow $flowId carries no dcql_query; offering every stored credential")
            return org.siros.sdk.transport.wmp.openid4x.MatchResult(
                matches = allCreds.map { cred ->
                    org.siros.sdk.transport.wmp.openid4x.CredentialMatch(
                        // WMP wire protocol keeps credential_id as a string -
                        // see the other CredentialMatch construction site's
                        // comment.
                        credentialId = cred.id.toString(),
                        credentialQueryId = null,
                        disclosedClaims = null,
                    )
                },
            )
        }

        val matchResults = CredentialMatcher.match(dcqlQuery, allCreds)
        // The query each candidate is answered under - first match wins, the
        // same rule the other two transports apply.
        val matchResultByCredentialId = buildMap {
            for (r in matchResults) for (c in r.candidates) putIfAbsent(c.id, r)
        }
        val matches = matchResultByCredentialId.map { (credentialId, result) ->
            org.siros.sdk.transport.wmp.openid4x.CredentialMatch(
                credentialId = credentialId.toString(),
                credentialQueryId = result.queryId,
                // Each requestedClaims entry is a full DCQL claim path; only
                // its last segment is the disclosable element id (see the
                // legacy consent payload's identical mapNotNull).
                disclosedClaims = result.requestedClaims.mapNotNull { it.lastOrNull() }.distinct()
                    .takeIf { it.isNotEmpty() },
            )
        }
        if (matches.isNotEmpty()) {
            return org.siros.sdk.transport.wmp.openid4x.MatchResult(matches = matches)
        }
        val reason = noMatchReason(dcqlQuery, allCreds.size)
        Timber.i("WMP match request for flow $flowId matched nothing: $reason")
        return org.siros.sdk.transport.wmp.openid4x.MatchResult(
            matches = emptyList(),
            noMatchReason = reason,
        )
    }

    /**
     * This wallet's own account of why local DCQL matching came up empty,
     * sent alongside an empty match set and surfaced to the app in the
     * engine's `NO_MATCHING_CREDENTIAL` error details.
     *
     * The engine's message already names the credential types the verifier
     * asked for; this says what the wallet had to compare them against, which
     * is the part only the wallet knows.
     *
     * @param exhaustedOnly true when credentials of the requested type are
     *   held but every copy has already been presented - a different problem
     *   from holding none at all, and a different thing to tell the user.
     */
    private fun noMatchReason(
        dcqlQuery: JsonObject?,
        storedCredentialCount: Int,
        exhaustedOnly: Boolean = false,
    ): String {
        val requested = dcqlQuery?.let { CredentialMatcher.requestedCredentialTypes(it) }.orEmpty()
        val asked = if (requested.isEmpty()) "" else " (requested: ${requested.joinToString(", ")})"
        return if (exhaustedOnly) {
            "Every stored credential matching this request$asked has already been presented - " +
                "it must be renewed before it can be presented again"
        } else {
            "This wallet holds no credential matching the request$asked; " +
                "$storedCredentialCount credential(s) stored"
        }
    }

    private suspend fun handleWmpTrustEvaluation(
        flowId: String,
        payload: kotlinx.serialization.json.JsonObject?,
    ): org.siros.sdk.transport.wmp.openid4x.TrustResult {
        // Delegate to the existing trust evaluation logic via BackendApiClient
        val subjectId = payload?.get("request")?.jsonObject
            ?.get("subject_id")?.jsonPrimitive?.contentOrNull

        if (subjectId.isNullOrBlank()) {
            return org.siros.sdk.transport.wmp.openid4x.TrustResult(
                trusted = false, reason = "Missing subject_id"
            )
        }

        return try {
            val request = payload?.get("request")?.jsonObject
            val keyMaterial = request?.get("key_material")?.jsonObject
            // WMP carries both issuance (generate_proof) and presentation
            // (sign_presentation) sign requests over the same profile - the
            // action name must follow subject_type like the legacy engine
            // path does, not be hardcoded to "credential-issuer" for every
            // subject (a real bug: a verifier evaluated over WMP was being
            // checked against the issuer trust policy instead of the
            // verifier one).
            val subjectType = request?.get("subject_type")?.jsonPrimitive?.contentOrNull
            val actionName = if (subjectType == "credential_verifier") "credential-verifier" else "credential-issuer"

            // requires_resolution/request_jwt/resolution_subject_id
            // (go-wallet-backend#396/#401, this SDK's #219) - the same
            // did:-scheme frontend-fallback support the legacy engine
            // path's handleTrustEvaluation has, shared via
            // resolveDidKeyMaterial/resolveIssuerDidKeyMaterial. Without
            // this, a did:-scheme subject's trust evaluation routed over
            // WMP (WalletConfig.useWmpProtocol) silently ignored these
            // fields and evaluated with no key material at all (review
            // finding).
            val requiresResolution = request?.get("requires_resolution")?.jsonPrimitive?.booleanOrNull == true
            val resolvedJwk: kotlinx.serialization.json.JsonElement? = if (requiresResolution) {
                val resolutionSubjectId = request?.get("resolution_subject_id")?.jsonPrimitive?.contentOrNull
                if (resolutionSubjectId.isNullOrBlank()) {
                    return org.siros.sdk.transport.wmp.openid4x.TrustResult(
                        trusted = false, reason = "Trust evaluation requires resolution but no resolution_subject_id was supplied"
                    )
                }
                if (subjectType == "credential_verifier") {
                    val requestJwt = request?.get("request_jwt")?.jsonPrimitive?.contentOrNull
                    if (requestJwt.isNullOrBlank()) {
                        return org.siros.sdk.transport.wmp.openid4x.TrustResult(
                            trusted = false, reason = "Trust evaluation requires resolution but no request_jwt was supplied"
                        )
                    }
                    resolveDidKeyMaterial(resolutionSubjectId, requestJwt)
                } else {
                    resolveIssuerDidKeyMaterial(resolutionSubjectId)
                }
            } else {
                null
            }

            val evaluationRequest = kotlinx.serialization.json.buildJsonObject {
                putJsonObject("subject") {
                    put("type", kotlinx.serialization.json.JsonPrimitive("key"))
                    put("id", kotlinx.serialization.json.JsonPrimitive(subjectId))
                }
                putJsonObject("resource") {
                    val kmType = if (resolvedJwk != null) "jwk" else (keyMaterial?.get("type")?.jsonPrimitive?.contentOrNull ?: "x5c")
                    put("type", kotlinx.serialization.json.JsonPrimitive(kmType))
                    put("id", kotlinx.serialization.json.JsonPrimitive(subjectId))
                    val x5c = if (resolvedJwk != null) null else keyMaterial?.get("x5c")
                    val jwk = resolvedJwk ?: keyMaterial?.get("jwk")
                    if (x5c != null) {
                        put("key", x5c)
                    } else if (jwk is JsonArray) {
                        put("key", jwk)
                    } else if (jwk != null) {
                        put("key", kotlinx.serialization.json.buildJsonArray { add(jwk) })
                    }
                }
                putJsonObject("action") {
                    put("name", kotlinx.serialization.json.JsonPrimitive(actionName))
                }
                request?.get("context")?.let { put("context", it) }
            }
            val response = apiClient!!.evaluateTrust(evaluationRequest)
            val decision = response["decision"]?.jsonPrimitive?.boolean ?: false
            val context = response["context"]?.jsonObject

            // Store for the later sign_presentation step's validateAudience
            // check, mirroring the legacy engine path's trust-evaluation
            // handler - without this, WMP presentations had no
            // audience-binding defense-in-depth at all.
            lastTrustResults[flowId] = TrustResult(
                trusted = decision,
                framework = context?.get("framework")?.jsonPrimitive?.contentOrNull,
                reason = context?.get("reason")?.jsonPrimitive?.contentOrNull
                    ?: context?.get("message")?.jsonPrimitive?.contentOrNull,
                entityName = context?.get("entity_name")?.jsonPrimitive?.contentOrNull,
                entityLogo = context?.get("logo_uri")?.jsonPrimitive?.contentOrNull,
                identifier = subjectId,
            )

            org.siros.sdk.transport.wmp.openid4x.TrustResult(trusted = decision)
        } catch (e: Exception) {
            Timber.e(e, "WMP trust evaluation failed")
            org.siros.sdk.transport.wmp.openid4x.TrustResult(
                trusted = false, reason = e.message
            )
        }
    }

    // ── Legacy Engine Path ────────────────────────────────────────────

    private suspend fun connectEngine(appToken: String) {
        // connectEngineWithToken can run more than once on the same wallet
        // instance (initial login, session restore on startup, re-auth) -
        // without tearing down a prior live session first, its WebSocket
        // was leaked (never disconnected) while a brand new one took over
        // engineSession, leaving the backend with multiple concurrent
        // connections for the same user that kept evicting each other.
        engineStateJob?.cancel()
        engineSession?.disconnect()

        // Resolve engine URL: explicit config > discovery > same as backend
        val engineBaseUrl = config.engineUrl
            ?: WalletConfig.discoverEngineUrl(config.backendUrl)
            ?: config.backendUrl
        val engine = createEngineSession(engineBaseUrl, config.tenantId)
        engineSession = engine
        credentialNotifier = engine
        engineStateJob?.cancel()
        engineStateJob = scope.launch {
            engine.state.collect { s ->
                if (s == WalletEngineSession.State.REAUTH_REQUIRED) {
                    handleReauthenticationRequired()
                }
            }
        }
        engine.connect(
            appToken,
            tokenProvider = { legacyAppToken ?: authTokens.ensureBackendToken().raw },
            // The engine WS always authenticates with the backend token (see
            // the tokenProvider above) - an explicit 401/403 here is a real
            // auth rejection just like a REST 401, so feed it into the same
            // AuthTokens rejection counter rather than only flipping this
            // session's own State.REAUTH_REQUIRED.
            onAuthRejected = { authTokens.registerTokenRejection(AuthTokens.TOKEN_BACKEND) },
        )
        engine.awaitConnected()

        // Observe sign requests → auto-sign with keystore
        scope.launch {
            engine.signRequests().collect { msg ->
                try {
                    Timber.d("Sign request: ${msg.action} for flow ${msg.flowId}")
                    when (msg.action) {
                        "generate_proof" -> {
                            val params = msg.params
                            val count = params?.count ?: 1
                            val generated = generateProofsForRequest(
                                audience = params?.audience ?: "",
                                nonce = params?.nonce ?: "",
                                count = count,
                                proofTypesSupported = params?.proofTypesSupported?.keys,
                                proofTypeHint = params?.proofType,
                            )
                            // The "attestation" proof type returns a single GeneratedProofData
                // whose attestedKeyIds already covers the whole batch in order; the
                // "jwt" proof type returns one GeneratedProofData PER credential,
                // each carrying its own single-element attestedKeyIds - flatMap
                // concatenates either shape into one batch-order list. Taking only
                // the first entry's list (as this used to) silently dropped every
                // index past 0 for a "jwt" batch of more than one credential.
                activeAttestedKeyIds = generated.flatMap { it.attestedKeyIds.orEmpty() }.ifEmpty { null }
                            val proofs = generated.map {
                                ProofObject(proofType = it.proofType, jwt = it.jwt, attestation = it.attestation)
                            }
                            Timber.d("Sending sign response with ${proofs.size} proofs for flow ${msg.flowId}, messageId=${msg.messageId}")
                            engine.sendSignResponse(
                                msg.flowId,
                                proofs = proofs,
                                messageId = msg.messageId,
                                credentialRequestExtras = zkIssuanceExtras(msg.flowId),
                            )
                            Timber.d("Sign response sent successfully for flow ${msg.flowId}")
                        }
                        "sign_presentation" -> {
                            val params = msg.params
                            val nonce = params?.nonce ?: ""
                            val audience = params?.audience ?: ""
                            val credsToInclude = params?.credentialsToInclude

                            // Validate audience matches trusted verifier identity
                            validateAudience(msg.flowId, audience)

                            val vpToken = if (!credsToInclude.isNullOrEmpty()) {
                                val allCreds = credentialStore.getAll()
                                val storedMatchResults = pendingMatchResultsByFlow.remove(msg.flowId)
                                Timber.d(
                                    "sign_presentation: flow=${msg.flowId} storedMatchResults=" +
                                        "${storedMatchResults?.map { "${it.queryId}:${it.format}" }}"
                                )
                                val vpParts = credsToInclude.mapNotNull { ref ->
                                    // ref.credentialId arrives as a string over the WMP wire
                                    // protocol - see the CredentialMatch construction sites'
                                    // comments on that separate contract from privatedata-spec.
                                    val cred = allCreds.find { it.id == ref.credentialId.toLongOrNull() }
                                    if (cred == null) {
                                        Timber.w("Credential ...${ref.credentialId.takeLast(4)} not found in store for VP signing")
                                        return@mapNotNull null
                                    }
                                    val matchResult = storedMatchResults?.firstOrNull { r ->
                                        r.queryId == ref.credentialQueryId || r.candidates.any { it.id == cred.id }
                                    }
                                    Timber.d(
                                        "sign_presentation: credentialQueryId=${ref.credentialQueryId} " +
                                            "credId=${cred.id} matchResult.format=${matchResult?.format} " +
                                            "zkSystemTypes=${matchResult?.zkSystemTypes} disclosedClaims=${ref.disclosedClaims}"
                                    )

                                    if (matchResult?.format?.equals("mso_mdoc_zk", ignoreCase = true) == true) {
                                        // ZK-wrapped mDoc presentation (see handleDCAPIRequest's
                                        // identical branch, which this mirrors for the WS-engine/
                                        // redirect-flow transport instead of DC API).
                                        val credBytes = android.util.Base64.decode(cred.raw, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
                                        // cred.kid is commonly null for a softkey-issued credential
                                        // with no explicit per-credential key binding - see the
                                        // identical fallback + comment in handleDCAPIRequest.
                                        // Resolved lazily (checked only inside the signer lambda) -
                                        // see handleDCAPIRequest's identical comment for why.
                                        val kid = cred.kid ?: keystore.listKeys().firstOrNull()?.keyId
                                        // Only bind a pseudonym when actually disclosed for this
                                        // query - see handleDCAPIRequest's identical comment.
                                        val wantsPseudonym = ref.disclosedClaims?.contains(LongfellowZkProofSystem.PSEUDONYM_CLAIM) == true
                                        val verifierIdentity = if (wantsPseudonym) {
                                            // audience has already been checked against the
                                            // trust-evaluated verifier identifier by
                                            // validateAudience above, so it's the confirmed
                                            // client id for this flow. sessionId (when
                                            // present) is the real verifier_context binding
                                            // input - see VerifierIdentity.sessionId's doc
                                            // comment.
                                            VerifierIdentity(
                                                clientId = audience,
                                                ppidContext = matchResult.ppidContext,
                                                sessionId = params?.verifierSessionId,
                                            )
                                        } else {
                                            null
                                        }
                                        val sessionTranscript = MdocDeviceResponseBuilder.buildOpenID4VPSessionTranscript(
                                            clientId = audience,
                                            nonce = nonce,
                                            responseUri = params?.responseUri ?: "",
                                            verifierJwkThumbprint = params?.verifierJwkThumbprint,
                                        )
                                        Timber.d("sign_presentation: generating ZK proof, wantsPseudonym=$wantsPseudonym verifierIdentity=$verifierIdentity")
                                        // ZK proof generation is a multi-second native compute
                                        // with no intermediate progress signal from the engine (the
                                        // last real server step was "credential_selection", and the
                                        // next one - "submitting_response" - only arrives after this
                                        // call returns) - without this, the UI shows a stale
                                        // "Selecting credential" label the whole time. "computing_proof"
                                        // is a CLIENT-ONLY status token, never sent by the server and
                                        // deliberately absent from FlowStepCatalog (which mirrors
                                        // go-wallet-backend's real FlowStep vocabulary 1:1) - it's
                                        // overwritten by the next genuine engine.flowProgress() update
                                        // as soon as one arrives.
                                        (_state.value as? WalletState.FlowActive)
                                            ?.takeIf { it.flowId == msg.flowId }
                                            ?.let { _state.value = it.copy(status = "computing_proof") }
                                        val presented = try {
                                            zkPresentation.present(
                                                ZkMdocPresentation.Request(
                                                    credentialBytes = credBytes,
                                                    requestedSystems = matchResult.zkSystemTypes.orEmpty(),
                                                    sessionTranscript = sessionTranscript,
                                                    requestedClaims = ref.disclosedClaims ?: emptyList(),
                                                    verifierIdentity = verifierIdentity,
                                                ),
                                                signer = { algorithm, data ->
                                                    require(algorithm == COSE_ALG_ES256) {
                                                        "This keystore signs ES256 only, proof system asked for COSE alg $algorithm"
                                                    }
                                                    keystore.sign(
                                                        requireNotNull(kid) { "No signing key available for credential ${cred.id} - cannot generate a ZK proof for it" },
                                                        data,
                                                    )
                                                },
                                            )
                                        } catch (e: ZkMdocPresentation.NoMatchingProofSystem) {
                                            throw WalletException(e.message ?: "No registered ZK proof system satisfies the request")
                                        }
                                        Timber.d("sign_presentation: ZK proof generated, system=${presented.system.systemId} pseudonymOutcome=${presented.proof.pseudonymOutcome} proofBytes.size=${presented.proof.proofBytes.size}")
                                        android.util.Base64.encodeToString(
                                            presented.deviceResponse, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP
                                        )
                                    } else if (cred.format == "mso_mdoc") {
                                        // mDoc DeviceResponse (ISO 18013-5)
                                        val credBytes = android.util.Base64.decode(cred.raw, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
                                        val deviceResponse = keystore.signMdocPresentation(
                                            credentialBytes = credBytes,
                                            disclosedClaims = ref.disclosedClaims,
                                            nonce = nonce,
                                            audience = audience,
                                            responseUri = params?.responseUri ?: "",
                                            verifierJwkThumbprint = params?.verifierJwkThumbprint,
                                            kid = cred.kid,
                                        )
                                        android.util.Base64.encodeToString(deviceResponse, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
                                    } else {
                                        // SD-JWT VP token with KB-JWT
                                        keystore.signVpToken(
                                            credential = cred.raw,
                                            disclosedClaims = ref.disclosedClaims,
                                            nonce = nonce,
                                            audience = audience,
                                            kid = cred.kid,
                                        )
                                    }
                                }
                                // For single credential presentations (most common), return the token directly.
                                // For multiple credentials, join with newline for WMP transport.
                                // Note: The backend assembles the OID4VP-compliant vp_token JSON
                                // object (keyed by credential query ID, §8.1) before submission
                                // to the verifier.
                                vpParts.joinToString("\n")
                            } else {
                                // Fallback: legacy plain VP JWT (no credential data)
                                keystore.signPresentation(
                                    nonce = nonce,
                                    audience = audience,
                                    credentialIds = emptyList(),
                                )
                            }
                            Timber.d("Sending VP sign response for flow ${msg.flowId}, messageId=${msg.messageId}")
                            engine.sendSignResponse(msg.flowId, vpToken = vpToken, messageId = msg.messageId)
                            Timber.d("VP sign response sent successfully for flow ${msg.flowId}")
                        }
                        "request_attestation" -> handleRequestAttestation(engine, msg)
                        "sign_client_auth" -> handleSignClientAuth(engine, msg)
                        else -> {
                            // go-wallet-backend's RequestSign only unblocks on a
                            // sign_response carrying this message_id (there is no
                            // sign-error message); staying silent would stall the
                            // flow for its full 30 s ErrSignTimeout. An empty
                            // response lets the backend decide what a missing
                            // result means for the action it asked for.
                            Timber.w("Unknown sign action: ${msg.action}; sending empty sign_response")
                            engine.sendSignResponse(flowId = msg.flowId, messageId = msg.messageId)
                        }
                    }
                } catch (e: KeystoreException) {
                    Timber.e(e, "Error handling sign request: keystore error")
                    reportSignFailure(msg.flowId, e.message ?: "Signing failed")
                } catch (e: Exception) {
                    Timber.e(e, "Error handling sign request")
                    reportSignFailure(msg.flowId, e.message ?: "Signing failed")
                }
            }
        }

        // Observe match requests → DCQL-filtered credential matching
        scope.launch {
            engine.matchRequests().collect { msg ->
                try {
                    Timber.d("Match request for flow ${msg.flowId}")
                    val allCreds = credentialStore.getAll()
                    val listener = eventListener

                    // Filter credentials using DCQL query from the verifier
                    val dcqlQuery = msg.dcqlQuery?.jsonObject
                    val dcqlOutput = if (dcqlQuery != null) {
                        CredentialMatcher.matchDcql(dcqlQuery, allCreds)
                    } else {
                        // No DCQL query — fall back to all credentials
                        CredentialMatcher.DcqlMatchOutput(
                            queryResults = listOf(CredentialMatcher.MatchResult(
                                queryId = "_default",
                                format = null,
                                candidates = allCreds,
                                requestedClaims = emptyList(),
                            )),
                            credentialSets = null,
                            satisfiableOptions = emptyList(),
                        )
                    }

                    // "mso_mdoc_zk" queries match here on purpose: the
                    // sign_presentation handler above has a full ZK branch
                    // for this transport, keyed off the originating query's
                    // format and zkSystemTypes, which is why the results are
                    // cached in pendingMatchResultsByFlow below. Dropping
                    // those candidates at match time - as an earlier version
                    // did, when this transport could not prove - would
                    // silently turn every engine-relayed ZK request into "no
                    // matching credential".
                    val matchResults = dcqlOutput.queryResults
                    val candidates = matchResults.flatMap { it.candidates }.distinctBy { it.id }
                    // The query each candidate is answered under - first match
                    // wins, the same rule the sign handler applies. Built once
                    // and reused below (ZK flag, queryId per match) so the two
                    // cannot drift apart. Mirrors handleDCAPIRequest.
                    val matchResultByCredentialId = buildMap {
                        for (r in matchResults) for (c in r.candidates) putIfAbsent(c.id, r)
                    }
                    // Which candidates will be presented as a ZK proof rather
                    // than disclosed, so consumption accounting
                    // (CONSUME_NON_ZKP) and the history flag agree with what
                    // is actually sent.
                    val zkRequestedIds = matchResultByCredentialId
                        .filterValues { it.format?.equals("mso_mdoc_zk", ignoreCase = true) == true }
                        .keys
                    val isZk: (StoredCredential) -> Boolean = { it.id in zkRequestedIds }

                    if (candidates.isEmpty()) {
                        // Nothing to ask the user about. Answering with an
                        // empty match_response alone leaves the engine waiting
                        // on consent/decline that will never come, so say so
                        // in the action it acts on too (#336).
                        val reason = noMatchReason(dcqlQuery, allCreds.size)
                        Timber.i("Match request for flow ${msg.flowId} matched nothing: $reason")
                        engine.sendMatchResponse(msg.flowId, emptyList(), reason)
                        engine.sendCredentialsMatched(msg.flowId, emptyList(), reason)
                        return@collect
                    }

                    // Let the app filter further via user selection
                    val selectedIds = if (listener != null) {
                        // trustResult was already computed and cached by
                        // handleWmpTrustEvaluation for this same flow, but
                        // this construction site never read it back - the
                        // consent screen got neither a verifier name NOR the
                        // verified identity (client_id/DID/cert subject) a
                        // missing name could otherwise fall back to. See #218.
                        val trustResultForFlow = lastTrustResults[msg.flowId]
                        listener.onCredentialSelectionRequired(
                            PresentationRequest(
                                verifierName = trustResultForFlow?.entityName,
                                trustResult = trustResultForFlow,
                                matchResults = matchResults,
                                candidates = candidates,
                                credentialSets = dcqlOutput.credentialSets,
                                satisfiableOptions = dcqlOutput.satisfiableOptions,
                            )
                        )
                    } else {
                        eligibleInstances(candidates, isZk).map { it.id }
                    }

                    // The app is trusted to only return IDs it was offered,
                    // but shouldn't be the only thing enforcing consumption -
                    // re-validate here too (defense in depth).
                    val eligibleIds = eligibleInstances(candidates, isZk).map { it.id }.toSet()
                    if (selectedIds.any { it !in eligibleIds }) {
                        throw WalletException("Selected credential has no eligible copies remaining - renew it to get more")
                    }

                    // Track this presentation
                    recordPresentation(PresentationRecord(
                        id = randomUint32Id(),
                        flowId = msg.flowId,
                        credentialIds = selectedIds,
                        credentialNames = selectedIds.mapNotNull { id ->
                            allCreds.find { it.id == id }?.metadata?.name
                        },
                        requestedClaims = matchResults.flatMap { result ->
                            result.requestedClaims.mapNotNull { path -> path.lastOrNull() }
                        }.distinct(),
                        zkProof = selectedIds.any { it in zkRequestedIds },
                        timestamp = System.currentTimeMillis(),
                    ))

                    pendingMatchResultsByFlow[msg.flowId] = matchResults

                    val matches = selectedIds.mapNotNull { id ->
                        allCreds.find { it.id == id }?.let { cred ->
                            val queryId = matchResultByCredentialId[id]?.queryId
                            CredentialMatch(
                                credentialQueryId = queryId,
                                // The WMP engine's own wire protocol keeps
                                // credential_id as a string (a separate
                                // contract from privatedata-spec's numeric
                                // credentialId) - stringify at this boundary.
                                credentialId = cred.id.toString(),
                                format = cred.format,
                                vct = CredentialUtils.vctOf(cred),
                                availableClaims = extractAvailableClaims(cred),
                            )
                        }
                    }
                    engine.sendMatchResponse(msg.flowId, matches)
                } catch (e: SirosException) {
                    Timber.e(e, "Error handling match request")
                } catch (e: Exception) {
                    Timber.e(e, "Error handling match request")
                }
            }
        }

        // Observe flow progress
        scope.launch {
            engine.flowProgress().collect { msg ->
                Timber.d("Flow ${msg.flowId} progress: ${msg.step}")

                // Handle trust evaluation — matching wallet-frontend reference implementation
                if ((msg.step == "evaluating_trust" || msg.step == "evaluating_verifier_trust") &&
                    msg.payload?.jsonObject?.get("trust_evaluation_required")?.jsonPrimitive?.boolean == true
                ) {
                    handleTrustEvaluation(engine, msg.flowId, msg.payload!!.jsonObject)
                }

                // Handle server-side issuer trust result (informational, no response needed).
                // This is distinct from the verifier trust flow — it does NOT overwrite
                // lastTrustResults (which is used for credential selection consent UI).
                if (msg.step == "trust_evaluated" &&
                    msg.payload?.jsonObject?.get("issuer_trust_evaluated")?.jsonPrimitive?.contentOrNull == "true"
                ) {
                    val payload = msg.payload?.jsonObject
                    val trustResult = TrustResult(
                        trusted = payload?.get("trusted")?.jsonPrimitive?.contentOrNull == "true",
                        framework = payload?.get("framework")?.jsonPrimitive?.contentOrNull,
                        reason = payload?.get("reason")?.jsonPrimitive?.contentOrNull,
                        entityName = null,
                        identifier = payload?.get("issuer")?.jsonPrimitive?.contentOrNull,
                    )
                    // Only populate the trust cache — do NOT store in lastTrustResults
                    // (that map is for verifier consent UI in credential_selection step)
                    trustCache.put(trustResult.identifier ?: "", trustResult)
                    Timber.i("Server-side issuer trust: trusted=${trustResult.trusted} for ${trustResult.identifier}")
                }

                // Handle credential selection — verifier wants credentials, user must consent
                if (msg.step == "credential_selection") {
                    handleCredentialSelection(engine, msg.flowId, msg.payload?.jsonObject)
                }

                // Handle authorization required — user must approve in browser
                if (msg.step == "authorization_required") {
                    val payload = msg.payload?.jsonObject
                    Timber.d("Authorization required payload: $payload")

                    // Handle tx_code (PIN input) for pre-authorized code flow
                    val payloadType = payload?.get("type")?.jsonPrimitive?.contentOrNull
                    if (payloadType == "tx_code") {
                        val txCode = eventListener?.onTxCodeRequired(
                            flowId = msg.flowId,
                            description = payload?.get("message")?.jsonPrimitive?.contentOrNull,
                        )
                        if (txCode != null) {
                            Timber.i("Providing tx_code for flow ${msg.flowId}")
                            engine.sendFlowAction(msg.flowId, "provide_pin",
                                kotlinx.serialization.json.buildJsonObject {
                                    put("tx_code", kotlinx.serialization.json.JsonPrimitive(txCode))
                                })
                        } else {
                            Timber.w("No tx_code provided for flow ${msg.flowId}")
                        }
                    } else {
                        val authUrl = payload?.get("authorization_url")?.jsonPrimitive?.contentOrNull
                        val redirectUri = payload?.get("expected_redirect_uri")?.jsonPrimitive?.contentOrNull
                        val state = payload?.get("state")?.jsonPrimitive?.contentOrNull
                        val codeVerifier = payload?.get("code_verifier")?.jsonPrimitive?.contentOrNull
                        val offerJson = payload?.get("credential_offer")?.let { json.encodeToString(JsonElement.serializer(), it) }
                        if (authUrl != null) {
                            // Apply URL rewriter if configured
                            val rewrittenUrl = config.urlRewriter?.invoke(authUrl) ?: authUrl
                            // Extract state from URL query params if not in payload
                            val effectiveState = state ?: android.net.Uri.parse(rewrittenUrl).getQueryParameter("state") ?: ""
                            Timber.d("Authorization required: url=$rewrittenUrl state=$effectiveState")
                            // Save resume context BEFORE handing off to the browser - see
                            // completeAuthorization() for why the flow can't just be resumed
                            // on its original flow_id/session.
                            if (redirectUri != null) {
                                pendingAuthorizations[msg.flowId] = PendingAuthorization(
                                    offerJson = offerJson,
                                    redirectUri = redirectUri,
                                    codeVerifier = codeVerifier,
                                    state = effectiveState,
                                )
                            }
                            eventListener?.onAuthorizationRequired(
                                flowId = msg.flowId,
                                authorizationUrl = rewrittenUrl,
                                redirectUri = redirectUri ?: "",
                                state = effectiveState,
                            )
                        }
                    }
                }

                val current = _state.value
                if (msg.flowId !in terminatedFlowIds &&
                    (current is WalletState.Ready || current is WalletState.FlowActive)
                ) {
                    val userId = (current as? WalletState.Ready)?.userId
                        ?: (current as? WalletState.FlowActive)?.userId ?: ""
                    val displayName = (current as? WalletState.Ready)?.displayName
                        ?: (current as? WalletState.FlowActive)?.displayName
                    _state.value = WalletState.FlowActive(
                        userId = userId,
                        displayName = displayName,
                        flowId = msg.flowId,
                        flowType = msg.step ?: "unknown",
                        status = msg.step ?: "in_progress",
                        credentials = credentialStore.getAll(),
                    )
                }
            }
        }

        // Observe flow completion → sync new credentials
        scope.launch {
            engine.flowComplete().collect { msg ->
                Timber.i("Flow ${msg.flowId} complete")
                terminatedFlowIds.add(msg.flowId)
                pendingMatchResultsByFlow.remove(msg.flowId)

                // Tracks whether any credential in this batch actually made it
                // into the store, so a flow that "completes" per the engine
                // but whose only credential(s) failed to parse doesn't get
                // silently reported as success - see storeFailureReason below.
                var storedCount = 0
                var storeFailureReason: String? = null

                // Shared across every copy in this response so the UI can group
                // them into one card (see StoredCredential.batchId) - ALWAYS
                // assigned, even for a single-credential issuance, matching
                // wallet-frontend's useOID4VCIFlow.ts (batchId = Date.now())
                // exactly: every issuance response is its own batch of at
                // least one, there is no "no batch" sentinel on either client.
                val batchId = System.currentTimeMillis()

                // Credential re-issuance/renewal plan (Phase 2): this
                // flow_complete is a renewal's, so the batch it's about to
                // store supersedes the one renewCredential() was called for
                // - delete that old batch's credential entries AND its
                // privatedata refresh_token entry (per privatedata-spec
                // §6.2 - a stale entry pointing at a no-longer-existing
                // batch must not linger) instead of leaving a duplicate
                // alongside the new one.
                // Snapshot the old batch's claims (before deleting it) so
                // they can be diffed against the new batch's once stored -
                // AttributeDiffService-equivalent, see
                // onCredentialRenewedWithAttributeDiff's doc comment.
                val oldRenewedClaims = pendingRenewalSourceBatchId?.let { oldBatchId ->
                    credentialStore.getAll()
                        .find { it.batchId == oldBatchId && it.instanceId == 0 }
                        ?.let { CredentialUtils.extractClaims(it) }
                }
                pendingRenewalSourceBatchId?.let { oldBatchId ->
                    credentialStore.getAll()
                        .filter { it.batchId == oldBatchId }
                        .forEach {
                            credentialStore.delete(it.id)
                            // Same §6.1.2 rule as deleteCredential's - a
                            // superseded batch's holder state must go with it.
                            bbsHolderStateVault?.remove(it.id.toString())
                        }
                    removeCredentialRefreshToken(oldBatchId)
                    Timber.d("Replaced renewed credential batch $oldBatchId with $batchId")
                }
                val wasRenewal = pendingRenewalSourceBatchId != null
                pendingRenewalSourceBatchId = null

                // Store any new credentials from the flow result
                // Snapshot the issuance state this completion belongs to,
                // before anything below suspends. resetIssuanceGuards() - which
                // a cancelled flow or a logout calls - clears these fields, and
                // a new issuance repopulates them; reading them again after a
                // suspension point would let this completion store its
                // credentials described by, and attributed to, a different
                // flow's offer.
                val flowOffer = activeOffer
                val flowVctm = activeVctm
                val flowVctmDocument = activeVctmDocument
                msg.credentials?.forEachIndexed { index, cred ->
                    if (cred.format == "mso_mdoc") {
                        // mso_mdoc credentials are base64url-encoded CBOR (a
                        // DeviceResponse-shaped envelope, per
                        // wallet-frontend#191), never JWT-shaped - the
                        // parseJwtPayload-based validation/expiry/metadata
                        // path below doesn't apply and would always fail
                        // (base64url text has no "." characters, so
                        // parseJwtPayload always returns null for it),
                        // silently dropping every issued mdoc credential.
                        val parsed = try {
                            val bytes = android.util.Base64.decode(
                                cred.credential,
                                android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP,
                            )
                            org.siros.sdk.credentials.mdoc.MdocCbor.parseStoredCredential(bytes)
                        } catch (e: Exception) {
                            Timber.w(e, "Skipping unparseable mdoc credential in flow ${msg.flowId}")
                            storeFailureReason = "Received credential could not be read (${e.message ?: e::class.simpleName})"
                            return@forEachIndexed
                        }
                        // VICAL issuer-trust (ISO 18013-5 Annex C): defensive
                        // check on the newly-issued credential's issuerAuth,
                        // surfaced via logging only - not a blocking gate,
                        // same convention as evaluateReaderTrust's remote/
                        // local-fallback reader-trust check at presentation
                        // time (see evaluateIssuerTrust's doc comment).
                        val issuerTrust = verifyAndEvaluateIssuerTrust(parsed.issuerSigned.issuerAuth, parsed.docType)
                        if (issuerTrust != null) {
                            Timber.i(
                                "mdoc issuer trust for docType=${parsed.docType}: " +
                                    "trusted=${issuerTrust.trusted} reason=${issuerTrust.reason}",
                            )
                        }
                        val metadata = flowOffer?.let { offer ->
                            val mddlSchema = try {
                                mddlSchemaFetcher.fetch(
                                    issuerUrl = offer.credentialIssuerIdentifier,
                                    scope = offer.credentialConfigurationId,
                                    // The mdoc doctype is already known here (just
                                    // parsed from the issued credential above), so
                                    // the registry-first strategy can actually run.
                                    vct = parsed.docType,
                                    registryUrl = registryUrl,
                                )
                            } catch (e: Exception) {
                                Timber.w(e, "Failed to fetch MDDL schema for ${offer.credentialConfigurationId}")
                                null
                            }
                            CredentialUtils.buildMdocMetadata(offer = offer, mddlSchema = mddlSchema)
                        }
                        val stored = StoredCredential(
                            id = randomUint32Id(),
                            format = cred.format,
                            raw = cred.credential,
                            metadata = metadata,
                            notificationId = cred.notificationId,
                            credentialIssuerIdentifier = flowOffer?.credentialIssuerIdentifier,
                            credentialConfigurationId = flowOffer?.credentialConfigurationId,
                            batchId = batchId,
                            instanceId = index,
                            kid = activeAttestedKeyIds?.getOrNull(index),
                        )
                        credentialStore.save(stored)
                        storedCount++
                        eventListener?.onCredentialReceived(stored)
                        Timber.d("Stored mdoc credential docType=${parsed.docType}")

                        cred.notificationId?.let { notificationId ->
                            credentialNotifier?.sendCredentialNotification(
                                flowId = msg.flowId,
                                notificationId = notificationId,
                                event = CredentialNotificationEvent.ACCEPTED,
                            )
                        }
                        return@forEachIndexed
                    }

                    // A flow that carried a holder commitment gets its result
                    // checked against that commitment before anything is
                    // stored. This branch is taken on the presence of a
                    // preparation rather than on a format string: the wallet
                    // asked for a credential only it could have made
                    // possible, so a result that is not the expected shape is
                    // the mis-issuance being checked for, not a different
                    // format to fall through to. (A JWP would fall through
                    // badly in any case - its payloads are `~`-joined and
                    // hold no claim values, so parseJwtPayload reads nothing
                    // from one and it would be dropped as unparseable.)
                    if (zkPreparationsByFlow.containsKey(msg.flowId)) {
                        // Same check as the ordinary path below. The ZK
                        // acceptance that follows proves the credential matches
                        // what this wallet committed to, which says nothing
                        // about whether it is the type that was offered.
                        verifyIssuedType(cred.format, cred.credential)?.let { reason ->
                            storeFailureReason = reason
                            return@forEachIndexed
                        }
                        val credentialId = acceptZkIssuedCredential(msg.flowId, cred.credential, index)
                        if (credentialId == null) {
                            storeFailureReason =
                                "Issued credential did not match what this wallet committed to"
                            return@forEachIndexed
                        }
                        val stored = StoredCredential(
                            id = credentialId,
                            format = cred.format,
                            raw = cred.credential,
                            metadata = flowOffer?.let { offer ->
                                CredentialUtils.buildMetadata(
                                    offer = offer,
                                    vctm = flowVctm,
                                    rawCredential = cred.credential,
                                )
                            },
                            notificationId = cred.notificationId,
                            credentialIssuerIdentifier = flowOffer?.credentialIssuerIdentifier,
                            credentialConfigurationId = flowOffer?.credentialConfigurationId,
                            batchId = batchId,
                            instanceId = index,
                            // Deliberately not activeAttestedKeyIds: a BBS
                            // credential's binding is to the key committed at
                            // issuance, which is recorded in the holder state
                            // and is not one of the P-256 proof keys this
                            // field names.
                            kid = null,
                        )
                        try {
                            credentialStore.save(stored)
                        } catch (e: kotlinx.coroutines.CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            // The holder state went into the container before
                            // the credential reached the store - it has to,
                            // since the state is what names the credential's
                            // id. A store that refuses the credential would
                            // otherwise leave that entry behind: a long-lived
                            // secret filed under an id nothing will ever look
                            // up, and one nothing else deletes, because
                            // §6.1.2's rule is "deleting the entity deletes
                            // the entry" and the entity never existed.
                            Timber.e(e, "Storing BBS credential $credentialId failed - rolling back its holder state")
                            bbsHolderStateVault?.remove(credentialId.toString())
                            storeFailureReason = "Credential could not be stored"
                            return@forEachIndexed
                        }
                        storedCount++
                        eventListener?.onCredentialReceived(stored)
                        cred.notificationId?.let { notificationId ->
                            credentialNotifier?.sendCredentialNotification(
                                flowId = msg.flowId,
                                notificationId = notificationId,
                                event = CredentialNotificationEvent.ACCEPTED,
                            )
                        }
                        return@forEachIndexed
                    }

                    // Basic validation: ensure credential is parseable
                    val payload = CredentialUtils.parseJwtPayload(cred.credential)
                    if (payload == null) {
                        Timber.w("Skipping unparseable credential in flow ${msg.flowId}")
                        storeFailureReason = "Received credential could not be read"
                        return@forEachIndexed
                    }
                    // Check expiry — don't store already-expired credentials
                    val exp = payload["exp"]?.jsonPrimitive?.longOrNull
                    val now = System.currentTimeMillis() / 1000
                    if (exp != null && exp < now) {
                        Timber.w("Skipping expired credential (exp=$exp, now=$now)")
                        storeFailureReason = "Issued credential was already expired"
                        return@forEachIndexed
                    }
                    verifyIssuedType(cred.format, cred.credential)?.let { reason ->
                        storeFailureReason = reason
                        return@forEachIndexed
                    }
                    val integrity = verifyVctIntegrity(cred.format, payload, flowOffer, flowVctmDocument)
                    integrity.reason?.let { reason ->
                        storeFailureReason = reason
                        return@forEachIndexed
                    }
                    val metadata = flowOffer?.let { offer ->
                        CredentialUtils.buildMetadata(
                            offer = offer,
                            // The re-resolved document when the check found one,
                            // scoped to this credential rather than read back
                            // from shared issuance state that a cancelled or
                            // superseded flow may have replaced meanwhile.
                            vctm = integrity.refreshed?.vctm ?: flowVctm,
                            rawCredential = cred.credential,
                        )
                    }
                    val stored = StoredCredential(
                        id = randomUint32Id(),
                        format = cred.format,
                        raw = cred.credential,
                        metadata = metadata,
                        issuedAt = payload["iat"]?.jsonPrimitive?.longOrNull,
                        expiresAt = exp,
                        notificationId = cred.notificationId,
                        credentialIssuerIdentifier = flowOffer?.credentialIssuerIdentifier,
                        credentialConfigurationId = flowOffer?.credentialConfigurationId,
                        batchId = batchId,
                        instanceId = index,
                        kid = activeAttestedKeyIds?.getOrNull(index),
                    )
                    credentialStore.save(stored)
                    storedCount++
                    eventListener?.onCredentialReceived(stored)

                    // OID4VCI §10: once the credential is stored, tell the backend
                    // to forward a credential_accepted notification to the issuer.
                    cred.notificationId?.let { notificationId ->
                        credentialNotifier?.sendCredentialNotification(
                            flowId = msg.flowId,
                            notificationId = notificationId,
                            event = CredentialNotificationEvent.ACCEPTED,
                        )
                    }
                }

                // Credential re-issuance/renewal plan (Phase 2): durably
                // capture this batch's refresh_token + DPoP key in
                // privatedata (S.credentialRefreshTokens - see
                // setCredentialRefreshToken's doc comment) so renewCredential()
                // can use it later, including after an app restart or on a
                // different device sharing this account.
                msg.refreshToken?.let { token ->
                    flowOffer?.let { offer ->
                        setCredentialRefreshToken(
                            batchId,
                            CredentialRefreshTokenEntry(
                                refreshToken = token,
                                dpopJwk = msg.dpopJwk,
                                dpopKeyId = msg.dpopKeyId,
                                credentialIssuerIdentifier = offer.credentialIssuerIdentifier,
                                credentialConfigurationId = offer.credentialConfigurationId,
                            ),
                        )
                        Timber.d("Captured refresh_token for batch=$batchId issuer=${offer.credentialIssuerIdentifier}")
                    }
                }

                // AttributeDiffService-equivalent (ISSU_59): if this was a
                // renewal, compare the new batch's claims against the old
                // one's - a silent renewal only stays silent when nothing
                // actually changed. See onCredentialRenewedWithAttributeDiff's
                // doc comment for why this fires in addition to (not
                // instead of) onCredentialReceived.
                if (wasRenewal && oldRenewedClaims != null) {
                    credentialStore.getAll().find { it.batchId == batchId && it.instanceId == 0 }?.let { newRepresentative ->
                        val diff = CredentialUtils.computeAttributeDiff(oldRenewedClaims, CredentialUtils.extractClaims(newRepresentative))
                        if (diff.hasChanges) {
                            Timber.i("Renewal of batch=$batchId changed ${diff.changed.size + diff.added.size + diff.removed.size} claim(s)")
                            eventListener?.onCredentialRenewedWithAttributeDiff(newRepresentative, diff)
                        }
                    }
                }

                resetIssuanceGuards()

                // Persist locally + sync to backend immediately
                persistAndSyncKeystore()

                // The engine considers this flow successfully finished, but
                // if it delivered credentials and none of them survived
                // parsing/validation, reporting onFlowComplete here would
                // silently strand the user - the flow "succeeds" with
                // nothing to show for it and no indication anything went
                // wrong. Surface it as a flow error instead so the UI's
                // error dialog (with Retry) fires, matching how any other
                // flow failure is handled.
                val expectedCredentials = msg.credentials?.size ?: 0
                if (expectedCredentials > 0 && storedCount == 0) {
                    val reason = storeFailureReason ?: "Credential could not be processed"
                    Timber.e("Flow ${msg.flowId} completed but no credentials were stored: $reason")
                    eventListener?.onFlowError(msg.flowId, reason)
                } else {
                    eventListener?.onFlowComplete(msg.flowId, msg.redirectUri)
                }
                // The only place the preparation is consumed. It has to
                // outlive the credential loop above, whether or not a
                // credential was accepted: the loop enters the acceptance
                // path at all only while this flow has a preparation, so
                // dropping it on the first accepted credential sends every
                // later entry in the same batch down the ordinary
                // JWT-validation branch and stores it - the exact case
                // acceptZkIssuedCredential's `index > 0` refusal exists to
                // catch. Keeping it also lets a refusal say what the flow
                // had committed to. The flow is over now, so it goes.
                discardZkIssuancePreparation(msg.flowId)

                val current = _state.value
                val userId = (current as? WalletState.FlowActive)?.userId
                    ?: (current as? WalletState.Ready)?.userId ?: ""
                val displayName = (current as? WalletState.FlowActive)?.displayName
                    ?: (current as? WalletState.Ready)?.displayName
                _state.value = WalletState.Ready(
                    userId = userId,
                    displayName = displayName,
                    credentials = credentialStore.getAll(),
                )
            }
        }

        // Observe flow errors
        scope.launch {
            engine.flowErrors().collect { msg ->
                Timber.e("Flow ${msg.flowId} error: ${msg.error.code} — ${msg.error.message}")
                val fid = msg.flowId ?: "unknown"
                terminatedFlowIds.add(fid)
                pendingMatchResultsByFlow.remove(fid)
                val redirectUri = msg.error.details?.get("redirect_uri")?.jsonPrimitive?.contentOrNull
                eventListener?.onFlowError(fid, msg.error.message, redirectUri)
                if (msg.error.code == ERROR_NO_MATCHING_CREDENTIAL) {
                    reportNoMatchingCredential(fid, msg.error)
                }
                // See the flow_complete handler's matching reset: without
                // this, an issuance that fails via an engine-reported error
                // (rather than completing or failing client-side through
                // reportSignFailure) would leave issuanceInFlight stuck,
                // permanently blocking every future issuance attempt.
                resetIssuanceGuards()
                // No credential will ever arrive for this flow, so its
                // holder-side commitment material is dead weight.
                discardZkIssuancePreparation(msg.flowId)

                val current = _state.value
                val userId = (current as? WalletState.FlowActive)?.userId
                    ?: (current as? WalletState.Ready)?.userId ?: ""
                val displayName = (current as? WalletState.FlowActive)?.displayName
                    ?: (current as? WalletState.Ready)?.displayName
                _state.value = WalletState.Ready(
                    userId = userId,
                    displayName = displayName,
                    credentials = credentialStore.getAll(),
                )
            }
        }
    }

    /**
     * Validates that the audience for VP signing matches the trusted verifier identity.
     *
     * This is a defense-in-depth check: if a MITM between the backend engine
     * and the signing step tries to redirect the presentation to a different
     * verifier, this throws rather than merely logging - confirmed via code
     * review that a log-only mismatch meant handleSignRequest's caller
     * proceeded to sign and send the VP token regardless, defeating the
     * audience-binding protection this function's name implies it provides.
     * Only reachable once trust evaluation has actually run and produced an
     * identifier for this flow (the early returns above), so this can't
     * spuriously break a flow where trust evaluation hasn't happened yet.
     */
    private fun validateAudience(flowId: String, audience: String) {
        // Consume (remove) the entry here, at actual point of use, instead
        // of at credential-selection time - see handleCredentialSelection's
        // comment for why removing it earlier defeated this check entirely.
        val trustResult = lastTrustResults.remove(flowId) ?: return
        val expectedId = trustResult.identifier ?: return

        // The audience should contain or match the trusted identifier
        if (audience.isNotBlank() && expectedId.isNotBlank() && audience != expectedId) {
            throw WalletException(
                "Audience mismatch for flow $flowId: " +
                    "sign_request audience='$audience' != trusted identifier='$expectedId'"
            )
        }
    }

    /**
     * Extracts a human-readable string from an AuthZEN evaluation response's
     * context.reason (or similar) field, which per go-trust's
     * EvaluationResponseContext.Reason (map[string]interface{}, e.g.
     * {"user": "...", "admin": "..."}) may be a structured JSON object, not a
     * plain string. Calling .jsonPrimitive directly on a JsonObject throws
     * (it's not a safe cast) - that previously crashed EVERY trust
     * evaluation whose response included a reason, which the outer catch
     * turned into "trusted = false" regardless of what the PDP actually
     * decided (decision was already true in the same response).
     */
    private fun reasonText(element: kotlinx.serialization.json.JsonElement?): String? = when (element) {
        null -> null
        is kotlinx.serialization.json.JsonObject ->
            element["user"]?.jsonPrimitive?.contentOrNull
                ?: element["admin"]?.jsonPrimitive?.contentOrNull
                ?: element.toString()
        else -> element.jsonPrimitive.contentOrNull
    }

    /**
     * Handles trust evaluation step from the engine.
     *
     * 1. Extract subject_id and key material from the progress payload
     * 2. Build an AuthZEN evaluation request
     * 3. Call POST /v1/evaluate on the backend
     * 4. Send back a trust_result flow action
     */
    private fun handleTrustEvaluation(
        engine: WalletEngineSession,
        flowId: String,
        payload: kotlinx.serialization.json.JsonObject,
    ) {
        scope.launch {
            val request = payload["request"]?.jsonObject
            val subjectId = request?.get("subject_id")?.jsonPrimitive?.contentOrNull

            try {
                val subjectType = request?.get("subject_type")?.jsonPrimitive?.contentOrNull

                if (subjectId.isNullOrBlank()) {
                    Timber.e("Trust evaluation request missing subject_id")
                    engine.sendTrustResult(flowId, false, "Missing subject_id")
                    return@launch
                }

                Timber.d("Trust evaluation: subject=$subjectId type=$subjectType")

                // requires_resolution/request_jwt/resolution_subject_id
                // (go-wallet-backend#396/#401, this SDK's #219): set when the
                // engine could not resolve a did:-scheme verifier's key
                // material itself (no verifier PDP configured - an
                // intentional dev/permissive mode) and defers to the
                // frontend/SDK instead. key_material is absent in that case -
                // resolveDidKeyMaterial below is what supplies it, never
                // key_material from the request.
                //
                // resolution_subject_id is a DIFFERENT identifier from
                // subject_id: subject_id is the original wire-form client_id
                // (still carrying OpenID4VP 1.0's decentralized_identifier:
                // prefix, when the verifier used it) that evaluateTrustDirect
                // below must keep seeing unchanged, but /v1/resolve needs the
                // bare DID with that prefix already stripped. Required, not
                // defaulted to subjectId: #401's own
                // TrustEvaluationRequest.Validate() makes ResolutionSubjectID
                // mandatory whenever RequiresResolution is true, so an engine
                // that omits it is itself non-conformant - falling back to
                // the (possibly prefixed) subjectId would silently attempt
                // resolution with the wrong identifier instead of surfacing
                // that clearly.
                val requiresResolution = request?.get("requires_resolution")?.jsonPrimitive?.booleanOrNull == true
                val requestJwt = request?.get("request_jwt")?.jsonPrimitive?.contentOrNull
                val resolutionSubjectId = request?.get("resolution_subject_id")?.jsonPrimitive?.contentOrNull

                val keyMaterial = request?.get("key_material")?.jsonObject
                val resolvedJwk: kotlinx.serialization.json.JsonElement? = if (requiresResolution) {
                    if (resolutionSubjectId.isNullOrBlank()) {
                        throw TrustEvaluationFailedClosedException(
                            "Trust evaluation requires resolution but no resolution_subject_id was supplied"
                        )
                    }
                    if (subjectType == "credential_verifier") {
                        // A verifier's request_jwt is what resolution is FOR
                        // - there's a signed authorization request to verify
                        // against, so requiring one here is correct (unlike
                        // the issuer branch below).
                        if (requestJwt.isNullOrBlank()) {
                            throw TrustEvaluationFailedClosedException(
                                "Trust evaluation requires resolution but no request_jwt was supplied"
                            )
                        }
                        resolveDidKeyMaterial(resolutionSubjectId, requestJwt)
                    } else {
                        // credential_issuer: OID4VCI issuance has no signed
                        // request object to verify request_jwt against - the
                        // backend never sends one for a DID issuer, unlike a
                        // verifier (review finding, #219 follow-up).
                        resolveIssuerDidKeyMaterial(resolutionSubjectId)
                    }
                } else {
                    null
                }

                val trustResult = evaluateTrustDirect(
                    subjectId = subjectId,
                    subjectType = subjectType,
                    keyMaterialType = if (resolvedJwk != null) "jwk" else keyMaterial?.get("type")?.jsonPrimitive?.contentOrNull,
                    x5c = if (resolvedJwk != null) null else keyMaterial?.get("x5c"),
                    jwk = resolvedJwk ?: keyMaterial?.get("jwk"),
                    context = request?.get("context"),
                ).copy(
                    clientIdScheme = request?.get("context")?.jsonObject
                        ?.get("client_id_scheme")?.jsonPrimitive?.contentOrNull,
                )

                // Store for use in credential selection UI
                lastTrustResults[flowId] = trustResult

                // Populate trust cache (only positive results are stored)
                trustCache.put(subjectId, trustResult)

                Timber.i(
                    "Trust evaluation result: decision=${trustResult.trusted} " +
                        "framework=${trustResult.framework} for $subjectId"
                )

                engine.sendTrustResult(flowId, trustResult.trusted)
            } catch (e: TrustEvaluationFailedClosedException) {
                // Deliberately ahead of the cache: the degraded mode below
                // stands in for an unreachable backend, not for one that
                // refused us, and not when this wallet asked for remote-only.
                Timber.e(e, "Trust evaluation failed closed - not consulting the trust cache")
                engine.sendTrustResult(flowId, false, e.message ?: "Trust evaluation failed closed")
            } catch (e: Exception) {
                Timber.e(e, "Trust evaluation failed")

                // Degraded mode: check cache for a recent positive result
                val cached = trustCache.get(subjectId ?: "")
                if (cached != null) {
                    Timber.w("Using cached trust result for $subjectId (backend unreachable)")
                    lastTrustResults[flowId] = cached
                    engine.sendTrustResult(flowId, true)
                } else {
                    engine.sendTrustResult(flowId, false, e.message ?: "Trust evaluation failed")
                }
            }
        }
    }

    /**
     * Resolves a `did:`-scheme verifier's key material via
     * `POST /v1/resolve` and verifies [requestJwt] against it, for the
     * `requires_resolution` path in [handleTrustEvaluation]
     * (go-wallet-backend#396/#401, this SDK's #219).
     *
     * The response's `context.trust_metadata` is treated as a W3C DID
     * Document. OpenID4VP requires the request's particular
     * `verificationMethod` to be identified by the JOSE `kid`: [requestJwt]
     * must carry a non-empty `kid` with a fragment, which is resolved to the
     * EXACTLY matching `verificationMethod` (comparing only the fragment,
     * which handles a fully-qualified kid and one relative to
     * [resolutionSubjectId] identically) - never any other entry, even one
     * also present in the same document. Trying every remaining method as a
     * fallback would let a JWT whose kid selects method A be accepted when a
     * DIFFERENT method B actually signed it, as long as B was also present
     * in the resolved document (review finding).
     *
     * Fails closed (throws [TrustEvaluationFailedClosedException], never
     * silently falls through to unverified/no key material) when resolution
     * fails, the response carries no usable verification method, no method
     * matches the kid, or the JWT's signature does not verify against that
     * one method - a DID-scheme verifier this wallet cannot actually verify
     * must not be treated as trusted, or as absent (which callers might read
     * as legitimately keyless x509_hash/no-attestation cases and proceed
     * regardless).
     *
     * [resolutionSubjectId] is deliberately a distinct value from the
     * `subject_id` used elsewhere for `/v1/evaluate` (go-wallet-backend#401's
     * `ResolutionSubjectID`): `/v1/evaluate`'s subject must stay the
     * original, wire-form identifier (e.g. still carrying OpenID4VP 1.0's
     * `decentralized_identifier:` prefix), but `/v1/resolve` needs the bare
     * DID with that prefix already stripped - one field can't serve both.
     */
    /**
     * Shared by [resolveDidKeyMaterial] and [resolveIssuerDidKeyMaterial]:
     * calls `POST /v1/resolve`, requires an explicit `decision: true` (never
     * trusting `context` from a denied response - see [resolveDidKeyMaterial]'s
     * doc comment), and extracts the resolved DID document's
     * `verificationMethod` array. Fails closed at every step.
     */
    private suspend fun resolveVerificationMethods(resolutionSubjectId: String): JsonArray {
        val client = apiClient ?: throw TrustEvaluationFailedClosedException(
            "Cannot resolve $resolutionSubjectId: not authenticated"
        )
        val response = try {
            client.resolveKey(resolutionSubjectId)
        } catch (e: Exception) {
            throw TrustEvaluationFailedClosedException("Failed to resolve $resolutionSubjectId via /v1/resolve: ${e.message}", e)
        }
        val decision = (response["decision"] as? kotlinx.serialization.json.JsonPrimitive)?.booleanOrNull
        if (decision != true) {
            throw TrustEvaluationFailedClosedException(
                "Resolution of $resolutionSubjectId via /v1/resolve was not decided true"
            )
        }
        // `as? JsonObject`/`as? JsonArray`, not `.jsonObject`/`.jsonArray`: a
        // malformed/unexpected-shape response entry must be skipped (or fail
        // this whole resolution closed), never throw an uncaught exception
        // that escapes to handleTrustEvaluation's generic catch - which may
        // accept a cached positive result, contradicting this path's
        // fail-closed guarantee. Same fix as #150's `.jsonObject` crash.
        return (response["context"] as? JsonObject)
            ?.get("trust_metadata")?.let { it as? JsonObject }
            ?.get("verificationMethod")?.let { it as? JsonArray }
            ?: throw TrustEvaluationFailedClosedException(
                "Resolved DID document for $resolutionSubjectId has no verificationMethod entries"
            )
    }

    /**
     * Normalizes a DID URL/verification-method id for exact comparison: a
     * RELATIVE id (just a fragment, e.g. `"#key-1"`) is resolved against
     * [subjectId] to the full `"<subjectId>#key-1"` form; an id that's
     * already fully-qualified (any other form) is returned unchanged.
     * Returns `null` for a blank/missing id, so callers can fail closed on
     * "no kid supplied" the same way as "kid didn't match anything".
     *
     * Comparing ONLY the fragment (as an earlier version of this fix did)
     * let `did:other#key-1` and `did:subject#key-1` collide - a resolved
     * document containing a verification method for a DIFFERENT DID with
     * the same fragment could be matched instead of (or as well as) the
     * correct one. Comparing full normalized ids closes that (review
     * finding).
     */
    private fun normalizeVerificationMethodId(id: String?, subjectId: String): String? {
        if (id.isNullOrBlank()) return null
        return if (id.startsWith("#")) "$subjectId$id" else id
    }

    private suspend fun resolveDidKeyMaterial(resolutionSubjectId: String, requestJwt: String): JsonElement {
        val signedJwt = try {
            SignedJWT.parse(requestJwt)
        } catch (e: Exception) {
            throw TrustEvaluationFailedClosedException("request_jwt is not a valid JWS: ${e.message}", e)
        }
        val kid = signedJwt.header.keyID
        // Comparing only the fragment (after `#`) is not enough: did:other#key-1
        // and did:subject#key-1 collide on fragment alone, so a document
        // containing both could match the WRONG DID's method. Normalize
        // relative IDs (bare "#key-1") against resolutionSubjectId, then
        // compare the FULL id - never just the suffix (review finding).
        val normalizedKid = normalizeVerificationMethodId(kid, resolutionSubjectId)
        if (normalizedKid == null || normalizedKid.substringAfter('#', missingDelimiterValue = "").isBlank()) {
            throw TrustEvaluationFailedClosedException("request_jwt header is missing a kid with a non-empty fragment")
        }

        val verificationMethods = resolveVerificationMethods(resolutionSubjectId)

        val matchingVm = verificationMethods.mapNotNull { it as? JsonObject }
            .firstOrNull { vm ->
                val vmId = (vm["id"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull
                normalizeVerificationMethodId(vmId, resolutionSubjectId) == normalizedKid
            } ?: throw TrustEvaluationFailedClosedException(
                "No verification method for $resolutionSubjectId matches kid '$normalizedKid'"
            )
        val jwkJson = matchingVm["publicKeyJwk"] as? JsonObject
            ?: throw TrustEvaluationFailedClosedException(
                "Verification method '$normalizedKid' for $resolutionSubjectId has no publicKeyJwk"
            )

        val verified = try {
            val jwk = JWK.parse(jwkJson.toString())
            val verifier: JWSVerifier = when (jwk) {
                is ECKey -> ECDSAVerifier(jwk)
                is RSAKey -> RSASSAVerifier(jwk)
                // Ed25519 (EdDSA/OKP) verification methods are common in
                // did:key/did:web documents emitted by go-trust's
                // supported DID resolvers - without this branch every
                // such verifier would be unresolvable (#219 review
                // finding).
                is OctetKeyPair -> if (jwk.curve == Curve.Ed25519) Ed25519Verifier(jwk) else null
                else -> null
            } ?: throw TrustEvaluationFailedClosedException(
                "Unsupported verification method key type for $resolutionSubjectId"
            )
            signedJwt.verify(verifier)
        } catch (e: TrustEvaluationFailedClosedException) {
            throw e
        } catch (e: Exception) {
            Timber.w(e, "kid-matching verification method for $resolutionSubjectId failed to parse/verify")
            false
        }
        if (!verified) {
            throw TrustEvaluationFailedClosedException(
                "request_jwt signature did not verify against the kid-matching verification method '$normalizedKid' for $resolutionSubjectId"
            )
        }
        return jwkJson
    }

    /**
     * Resolves a `did:`-scheme ISSUER's key material via `POST /v1/resolve`,
     * for the `requires_resolution` path in [handleTrustEvaluation] when the
     * request is for a `credential_issuer` rather than a
     * `credential_verifier` (review finding, #219 follow-up).
     *
     * Unlike [resolveDidKeyMaterial], this takes no `requestJwt` and
     * verifies no signature: OID4VCI issuance has no signed authorization
     * request object to verify against (that's specific to OpenID4VP
     * presentation) - go-wallet-backend still sets `requires_resolution`/
     * `resolution_subject_id` for a DID-scheme issuer, but never
     * `request_jwt`, for exactly this reason. Returns every resolved
     * `verificationMethod`'s `publicKeyJwk` (the PDP evaluates the resolved
     * key material itself, not a possession proof of it here) - unlike the
     * single best-candidate [resolveDidKeyMaterial] returns, there's no
     * signature to narrow the field with, so all of them are forwarded.
     *
     * Still fails closed exactly like [resolveDidKeyMaterial]: throws when
     * the AuthZEN `decision` on the resolve response isn't explicitly
     * `true`, or no verification method is present.
     */
    private suspend fun resolveIssuerDidKeyMaterial(resolutionSubjectId: String): JsonArray {
        val verificationMethods = resolveVerificationMethods(resolutionSubjectId)
        val jwks = verificationMethods.mapNotNull { (it as? JsonObject)?.get("publicKeyJwk") as? JsonObject }
        if (jwks.isEmpty()) {
            throw TrustEvaluationFailedClosedException(
                "Resolved DID document for $resolutionSubjectId has no verification method with a publicKeyJwk"
            )
        }
        return kotlinx.serialization.json.JsonArray(jwks)
    }

    /**
     * Shared low-level trust evaluation: builds an AuthZEN request from raw
     * subject/key-material/context fields and calls `POST /v1/evaluate`.
     *
     * Used by both the engine-relayed `trust_evaluation` step above (payload
     * comes from go-wallet-backend) and [handleDCAPIRequest] (built directly
     * from a parsed OpenID4VP request) - there is no engine/backend relay
     * for DC API presentation (see task #74's revised finding: go-wallet-backend
     * needs no DC-API-specific support because the whole flow, including
     * this SAME generic trust call, runs client-side, mirroring
     * wallet-frontend's proven architecture).
     */
    private suspend fun evaluateTrustDirect(
        subjectId: String,
        subjectType: String?,
        keyMaterialType: String?,
        x5c: kotlinx.serialization.json.JsonElement?,
        jwk: kotlinx.serialization.json.JsonElement?,
        context: kotlinx.serialization.json.JsonElement?,
    ): TrustResult {
        // A verifier/RP or issuer presenting an x5c chain here is the same
        // real-world trust question already answered locally for proximity
        // mdoc readers (RICAL, evaluateReaderTrust) and mdoc issuers (VICAL,
        // evaluateIssuerTrust) - this function is the shared remote-only
        // counterpart for both subject types (engine-relayed trust_evaluation
        // covers issuers too, see the caller at handleTrustEvaluation), so
        // reuse whichever local root set/prefer-local switch matches
        // subjectType instead of leaving it with no offline/local-anchor
        // option. Falls through to remote-only behavior (unchanged) if x5c is
        // absent, jwk-only, or fails to decode as standard base64 DER (e.g. a
        // non-cert placeholder value).
        val isVerifier = subjectType == "credential_verifier"
        val x5chain = try {
            (x5c as? kotlinx.serialization.json.JsonArray)?.map {
                Base64.getDecoder().decode(it.jsonPrimitive.content)
            }
        } catch (_: Exception) {
            null
        }
        if (x5chain != null) {
            val mode = if (isVerifier) {
                effectiveReaderTrustEvaluationMode
            } else {
                effectiveIssuerTrustEvaluationMode
            }
            if (mode == MdocTrustEvaluationMode.LOCAL_ONLY) {
                return if (isVerifier) evaluateReaderTrustLocally(x5chain) else evaluateIssuerTrustLocally(x5chain)
            }
        }

        val client = apiClient ?: throw WalletException(NOT_CONNECTED)

        val evaluationRequest = kotlinx.serialization.json.buildJsonObject {
            putJsonObject("subject") {
                put("type", kotlinx.serialization.json.JsonPrimitive("key"))
                put("id", kotlinx.serialization.json.JsonPrimitive(subjectId))
            }
            putJsonObject("resource") {
                put("type", kotlinx.serialization.json.JsonPrimitive(keyMaterialType ?: "x5c"))
                put("id", kotlinx.serialization.json.JsonPrimitive(subjectId))
                if (x5c != null) {
                    put("key", x5c)
                } else if (jwk is JsonArray) {
                    // resolveIssuerDidKeyMaterial already returns every
                    // resolved verification method's jwk as an array (no
                    // signature to narrow the field with, unlike the
                    // verifier path's single best-candidate) - used as-is,
                    // not re-wrapped in another array of one.
                    put("key", jwk)
                } else if (jwk != null) {
                    put("key", kotlinx.serialization.json.buildJsonArray { add(jwk) })
                }
            }
            putJsonObject("action") {
                put("name", kotlinx.serialization.json.JsonPrimitive(
                    if (subjectType == "credential_verifier") "credential-verifier"
                    else "credential-issuer"
                ))
            }
            context?.let { put("context", it) }
        }

        return try {
            Timber.d("Calling /v1/evaluate for $subjectId")
            val response = client.evaluateTrust(evaluationRequest)

            val decision = response["decision"]?.jsonPrimitive?.boolean ?: false
            val respContext = response["context"]?.jsonObject

            TrustResult(
                trusted = decision,
                framework = respContext?.get("framework")?.jsonPrimitive?.contentOrNull,
                reason = reasonText(respContext?.get("reason"))
                    ?: reasonText(respContext?.get("message")),
                entityName = respContext?.get("entity_name")?.jsonPrimitive?.contentOrNull,
                entityLogo = respContext?.get("logo_uri")?.jsonPrimitive?.contentOrNull,
                clientIdScheme = null,
                identifier = subjectId,
                domain = respContext?.get("domain")?.jsonPrimitive?.contentOrNull,
            )
        } catch (e: Exception) {
            if (x5chain == null) throw e
            val registryName = if (isVerifier) "RICAL" else "VICAL"
            // This path used to fall back on ANY exception, which meant a
            // backend that REFUSED the caller (a 403) silently downgraded to
            // the weaker local check here even though evaluateReaderTrust/
            // evaluateIssuerTrust had been fixed not to - and it ignored
            // REMOTE_ONLY entirely, so a wallet configured to fail closed
            // still accepted a locally-trusted certificate on the DC API path.
            if (!isRemoteTrustEvaluationUnreachable(e)) {
                Timber.e(e, "Remote trust evaluation was rejected by the backend (not unreachable) - failing closed rather than falling back to local $registryName root validation")
                throw TrustEvaluationFailedClosedException(
                    "Remote trust evaluation was rejected by the backend: ${e.message}",
                    e,
                )
            }
            val mode = if (isVerifier) {
                effectiveReaderTrustEvaluationMode
            } else {
                effectiveIssuerTrustEvaluationMode
            }
            if (mode == MdocTrustEvaluationMode.REMOTE_ONLY) {
                Timber.e(e, "Remote trust evaluation is unreachable and this wallet is configured for remote-only evaluation - not attempting local $registryName root validation")
                throw TrustEvaluationFailedClosedException(
                    "Remote trust evaluation is unreachable and this wallet is configured for remote-only evaluation: ${e.message}",
                    e,
                )
            }
            Timber.w(e, "Remote trust evaluation unreachable, falling back to local $registryName root validation")
            if (isVerifier) evaluateReaderTrustLocally(x5chain) else evaluateIssuerTrustLocally(x5chain)
        }
    }

    /**
     * Evaluates a proximity reader's authenticated identity for trust - the
     * `evaluateReaderTrust` dependency [org.siros.sdk.keystore.mdoc.MdocProximitySession]
     * expects, for wiring into [org.siros.sdk.keystore.mdoc.BlePeripheralServer]/
     * [org.siros.sdk.keystore.mdoc.BleCentralClient]. Only ever called with an
     * x5chain whose `readerAuth` COSE_Sign1 signature has ALREADY verified
     * locally (see [MdocCose.verify1]) - this method is purely the trust
     * decision, mirroring [evaluateTrustDirect]'s request shape with a new
     * `"mdoc-reader-auth"` action name against go-trust's `mdocrical`
     * registry.
     *
     * Which path runs is [WalletConfig.readerTrustEvaluationMode]. The
     * default, [MdocTrustEvaluationMode.REMOTE_WITH_LOCAL_FALLBACK],
     * prefers the remote AuthZEN call: it is the only path that honors
     * RICAL's temporary/dynamic trust roots, since go-trust's own registry
     * cache/refresh handles freshness and the wallet just calls it fresh
     * each time. It drops to local X.509 path validation against
     * [WalletConfig.readerTrustRootCertificatesPem] only when go-trust could
     * not be REACHED - a backend that refuses the caller fails closed
     * instead. [MdocTrustEvaluationMode.REMOTE_ONLY] never drops, and
     * [MdocTrustEvaluationMode.LOCAL_ONLY] never asks.
     *
     * @param x5chain the reader's DER-encoded certificate chain, leaf first.
     */
    suspend fun evaluateReaderTrust(x5chain: List<ByteArray>): TrustResult {
        if (x5chain.isEmpty()) {
            return TrustResult(trusted = false, reason = "readerAuth has no certificate chain")
        }
        return evaluateMdocTrust(
            mode = effectiveReaderTrustEvaluationMode,
            framework = "mdocrical",
            entityLabel = "reader",
            registryName = "RICAL",
            remote = { evaluateReaderTrustRemote(x5chain) },
            local = { evaluateReaderTrustLocally(x5chain) },
        )
    }

    /** See [WalletConfig.effectiveReaderTrustEvaluationMode]. */
    private val effectiveReaderTrustEvaluationMode: MdocTrustEvaluationMode
        get() = config.effectiveReaderTrustEvaluationMode

    /** See [effectiveReaderTrustEvaluationMode]. */
    private val effectiveIssuerTrustEvaluationMode: MdocTrustEvaluationMode
        get() = config.effectiveIssuerTrustEvaluationMode

    /**
     * The shared mode/fallback decision behind [evaluateReaderTrust] and
     * [evaluateIssuerTrust], so the two cannot drift apart on a security
     * decision. [remote] and [local] are the registry-specific halves.
     */
    private suspend fun evaluateMdocTrust(
        mode: MdocTrustEvaluationMode,
        framework: String,
        entityLabel: String,
        registryName: String,
        remote: suspend () -> TrustResult,
        local: () -> TrustResult,
    ): TrustResult {
        if (mode == MdocTrustEvaluationMode.LOCAL_ONLY) {
            return local()
        }
        return try {
            remote()
        } catch (e: Exception) {
            if (!isRemoteTrustEvaluationUnreachable(e)) {
                Timber.e(e, "Remote $entityLabel trust evaluation was rejected by the backend (not unreachable) - failing closed rather than falling back to local $registryName root validation")
                return TrustResult(trusted = false, framework = framework, reason = "Remote $entityLabel trust evaluation failed: ${e.message}")
            }
            if (mode == MdocTrustEvaluationMode.REMOTE_ONLY) {
                Timber.e(e, "Remote $entityLabel trust evaluation is unreachable and this wallet is configured for remote-only evaluation - not attempting local $registryName root validation")
                return TrustResult(
                    trusted = false,
                    framework = framework,
                    reason = "Remote $entityLabel trust evaluation is unreachable and this wallet is configured " +
                        "for remote-only evaluation, so local $registryName root validation was not attempted: ${e.message}",
                )
            }
            Timber.w(e, "Remote $entityLabel trust evaluation unreachable, falling back to local $registryName root validation")
            local()
        }
    }

    private suspend fun evaluateReaderTrustRemote(x5chain: List<ByteArray>): TrustResult =
        evaluateMdocTrustRemote(x5chain, actionName = "mdoc-reader-auth", defaultFramework = "mdocrical", subjectPrefix = "reader")

    /**
     * Plain X.509 path validation against [WalletConfig.readerTrustRootCertificatesPem] -
     * no RICAL CBOR parsing, no `trustConstraints` enforcement, since this
     * path exists purely as an offline/unreachable-backend fallback for the
     * stable, known-in-advance official root(s), not a full reimplementation
     * of go-trust's `mdocrical` registry.
     */
    private fun evaluateReaderTrustLocally(x5chain: List<ByteArray>): TrustResult =
        evaluateMdocTrustLocally(
            x5chain,
            rootCertificates = readerTrustRootCertificates,
            rootCertificatesPemConfigSize = config.readerTrustRootCertificatesPem.size,
            frameworkLabel = "local-rical-root",
            entityLabel = "reader",
            registryName = "RICAL",
        )

    /**
     * Evaluates an mdoc credential's issuer authenticated identity for trust
     * (ISO/IEC 18013-5 Annex C, `issuerAuth`) - the wallet-side counterpart
     * to [evaluateReaderTrust], called defensively when a newly-issued
     * `mso_mdoc` credential is about to be stored, before it's trusted.
     * Mirrors [evaluateReaderTrust]'s exact remote-then-local-fallback
     * shape with a new `"mdoc-issuer-auth"` action name; go-trust answers it
     * from whichever issuer registry the deployment has - `mdociaca` (keyed
     * on the issuer URL the DS certificate names, see
     * [evaluateIssuerTrustRemote]) or `vical`. Only ever called with an x5chain whose `issuerAuth`
     * COSE_Sign1 signature has ALREADY verified locally (see
     * [MdocCose.verify1]) - this method is purely the trust decision.
     *
     * Which path runs is [WalletConfig.issuerTrustEvaluationMode], with the
     * same three choices and the same refused-versus-unreachable rule as
     * [evaluateReaderTrust]. The default,
     * [MdocTrustEvaluationMode.REMOTE_WITH_LOCAL_FALLBACK], prefers the
     * remote AuthZEN call: it is the only path that honors VICAL's dynamic
     * updates.
     *
     * @param x5chain the issuer's DER-encoded certificate chain, leaf first.
     * @param docType the credential's mdoc doctype (e.g. `"org.iso.18013.5.1.mDL"`),
     *   used for VICAL's per-certificate docType enforcement - only enforced
     *   remotely (go-trust's `vical` registry skips, not denies, if omitted);
     *   the local fallback never enforces it, same as RICAL's fallback
     *   skipping `trustConstraints`.
     */
    suspend fun evaluateIssuerTrust(x5chain: List<ByteArray>, docType: String?): TrustResult {
        if (x5chain.isEmpty()) {
            return TrustResult(trusted = false, reason = "issuerAuth has no certificate chain")
        }
        return evaluateMdocTrust(
            mode = effectiveIssuerTrustEvaluationMode,
            framework = "vical",
            entityLabel = "issuer",
            registryName = "VICAL",
            remote = { evaluateIssuerTrustRemote(x5chain, docType) },
            local = { evaluateIssuerTrustLocally(x5chain) },
        )
    }

    /**
     * Whether [e] represents the remote AuthZEN backend being unreachable
     * (network failure, backend outage) - the only condition that should
     * fall back to LOCAL, weaker X.509-root validation for
     * [evaluateReaderTrust]/[evaluateIssuerTrust]. An explicit HTTP 4xx from
     * [BackendApiException] means the backend was reachable and rejected
     * the CALLER (an authorization failure), not the trust QUESTION -
     * falling back to a weaker local check on that specific failure would
     * let anything that makes the proxy/backend return e.g. 403 silently
     * downgrade what should be a security-relevant deny (confirmed live at
     * Geneva 2026: a 403 on `/v1/evaluate` was silently treated the same as
     * an unreachable backend).
     */
    private fun isRemoteTrustEvaluationUnreachable(e: Exception): Boolean = when (e) {
        is NetworkException -> true
        is BackendApiException -> e.code == 0 || e.code >= 500
        else -> false
    }

    /**
     * The subject is the issuer's URL as its DS certificate names it (see
     * [MdocIssuerIdentity]), not the certificate's hash: go-trust's
     * `mdociaca` registry - the one that validates an mdoc chain against the
     * issuer's published IACAs - keys its allowlist and its IACA fetch on
     * that URL, and it is the identity the verifier side derives for the
     * same certificate, so both ends ask about the same subject. A `vical`
     * registry ignores the subject and validates the chain, so it is
     * unaffected. Falls back to the hash only for a certificate that names
     * no URL at all, which no registry can resolve either way.
     */
    private suspend fun evaluateIssuerTrustRemote(x5chain: List<ByteArray>, docType: String?): TrustResult =
        evaluateMdocTrustRemote(
            x5chain,
            actionName = "mdoc-issuer-auth",
            defaultFramework = "vical",
            subjectPrefix = "issuer",
            subjectId = MdocIssuerIdentity.fromDer(x5chain[0]),
            extraContext = docType?.let { dt -> { put("doc_type", kotlinx.serialization.json.JsonPrimitive(dt)) } },
        )

    /**
     * Plain X.509 path validation against [WalletConfig.issuerTrustRootCertificatesPem] -
     * no VICAL CBOR parsing, no per-certificate `docType` enforcement, since
     * this path exists purely as an offline/unreachable-backend fallback for
     * the stable, known-in-advance official root(s), not a full
     * reimplementation of go-trust's `vical` registry.
     */
    private fun evaluateIssuerTrustLocally(x5chain: List<ByteArray>): TrustResult =
        evaluateMdocTrustLocally(
            x5chain,
            rootCertificates = issuerTrustRootCertificates,
            rootCertificatesPemConfigSize = config.issuerTrustRootCertificatesPem.size,
            frameworkLabel = "local-vical-root",
            entityLabel = "issuer",
            registryName = "VICAL",
        )

    /**
     * Shared remote-AuthZEN-call implementation for [evaluateReaderTrust]
     * (RICAL, action `mdoc-reader-auth`) and [evaluateIssuerTrust] (VICAL,
     * action `mdoc-issuer-auth`) - both mirror [evaluateTrustDirect]'s
     * request shape exactly, differing only in the action name, the
     * default `framework` label (used when go-trust's response omits its
     * own), an optional `context` block (VICAL's `doc_type` enforcement
     * hint - omitted entirely, not sent empty, when [extraContext] is
     * null), and the subject noun used in the debug log line.
     */
    /**
     * @param subjectId what the registry is asked about. Defaults to the
     *   leaf certificate's SHA-256, which identifies the certificate itself
     *   (RICAL/VICAL validate the chain and ignore it); a caller whose
     *   registry resolves an entity by name passes that name instead.
     *   `resource.id` always stays the certificate hash: it identifies the
     *   key material carried in `resource.key`, not the entity.
     */
    private suspend fun evaluateMdocTrustRemote(
        x5chain: List<ByteArray>,
        actionName: String,
        defaultFramework: String,
        subjectPrefix: String,
        subjectId: String? = null,
        extraContext: (kotlinx.serialization.json.JsonObjectBuilder.() -> Unit)? = null,
    ): TrustResult {
        val client = apiClient ?: throw WalletException(NOT_CONNECTED)
        val certificateId = sha256Hex(x5chain[0])
        val subjectId = subjectId ?: certificateId
        val x5c = kotlinx.serialization.json.buildJsonArray {
            x5chain.forEach { add(kotlinx.serialization.json.JsonPrimitive(java.util.Base64.getEncoder().encodeToString(it))) }
        }

        val evaluationRequest = kotlinx.serialization.json.buildJsonObject {
            putJsonObject("subject") {
                put("type", kotlinx.serialization.json.JsonPrimitive("key"))
                put("id", kotlinx.serialization.json.JsonPrimitive(subjectId))
            }
            putJsonObject("resource") {
                put("type", kotlinx.serialization.json.JsonPrimitive("x5c"))
                put("id", kotlinx.serialization.json.JsonPrimitive(certificateId))
                put("key", x5c)
            }
            putJsonObject("action") {
                put("name", kotlinx.serialization.json.JsonPrimitive(actionName))
            }
            extraContext?.let { putJsonObject("context", it) }
        }

        Timber.d("Calling /v1/evaluate for $subjectPrefix $subjectId ($actionName)")
        val response = client.evaluateTrust(evaluationRequest)

        val decision = response["decision"]?.jsonPrimitive?.boolean ?: false
        val respContext = response["context"]?.jsonObject

        return TrustResult(
            trusted = decision,
            framework = respContext?.get("framework")?.jsonPrimitive?.contentOrNull ?: defaultFramework,
            reason = reasonText(respContext?.get("reason")) ?: reasonText(respContext?.get("message")),
            entityName = respContext?.get("entity_name")?.jsonPrimitive?.contentOrNull,
            identifier = subjectId,
        )
    }

    /**
     * Shared local X.509-path-validation fallback for [evaluateReaderTrust]
     * (RICAL) and [evaluateIssuerTrust] (VICAL) - neither does any RICAL/VICAL
     * CBOR parsing or `trustConstraints`/`docType` enforcement locally, since
     * this path exists purely as an offline/unreachable-backend fallback for
     * the stable, known-in-advance official root(s).
     *
     * Distinguishes "nothing configured" from "configured but every entry
     * failed to parse" (a real Copilot-review finding: a single message here
     * originally masked misconfiguration, since [readerTrustRootCertificates]/
     * [issuerTrustRootCertificates] silently drop unparsable PEMs - see their
     * own doc comments for why a warning is logged there, not here, at the
     * point each entry actually fails to parse).
     */
    private fun evaluateMdocTrustLocally(
        x5chain: List<ByteArray>,
        rootCertificates: List<java.security.cert.X509Certificate>,
        rootCertificatesPemConfigSize: Int,
        frameworkLabel: String,
        entityLabel: String,
        registryName: String,
    ): TrustResult {
        val subjectId = sha256Hex(x5chain[0])
        if (rootCertificates.isEmpty()) {
            val reason = if (rootCertificatesPemConfigSize == 0) {
                "Local $entityLabel trust evaluation is unavailable: no $registryName root certificate configured"
            } else {
                "Local $entityLabel trust evaluation is unavailable: $rootCertificatesPemConfigSize " +
                    "$registryName root certificate(s) configured but none could be parsed - check Timber logs for the parse error"
            }
            return TrustResult(
                trusted = false,
                framework = frameworkLabel,
                reason = reason,
                identifier = subjectId,
            )
        }
        return try {
            val certFactory = java.security.cert.CertificateFactory.getInstance("X.509")
            val certPath = certFactory.generateCertPath(x5chain.map { certFactory.generateCertificate(it.inputStream()) })
            val anchors = rootCertificates.map { java.security.cert.TrustAnchor(it, null) }.toSet()
            val params = java.security.cert.PKIXParameters(anchors).apply { isRevocationEnabled = false }
            java.security.cert.CertPathValidator.getInstance("PKIX").validate(certPath, params)
            val leaf = certPath.certificates.first() as java.security.cert.X509Certificate
            TrustResult(
                trusted = true,
                framework = frameworkLabel,
                reason = "Validated locally against a configured $registryName root certificate",
                entityName = leaf.subjectX500Principal?.name,
                identifier = subjectId,
            )
        } catch (e: Exception) {
            TrustResult(
                trusted = false,
                framework = frameworkLabel,
                reason = "Local $registryName root validation failed: ${e.message}",
                identifier = subjectId,
            )
        }
    }

    /**
     * Parses [WalletConfig.issuerTrustRootCertificatesPem] into certificates,
     * logging (not silently dropping) any entry that fails to parse - same
     * convention as [readerTrustRootCertificates].
     */
    private val issuerTrustRootCertificates: List<java.security.cert.X509Certificate> by lazy {
        val certFactory = java.security.cert.CertificateFactory.getInstance("X.509")
        config.issuerTrustRootCertificatesPem.mapNotNull { pem ->
            runCatching { certFactory.generateCertificate(pem.byteInputStream()) as java.security.cert.X509Certificate }
                .onFailure { Timber.w(it, "Failed to parse a configured VICAL root certificate PEM") }
                .getOrNull()
        }
    }

    /**
     * Verifies an mdoc credential's `issuerAuth` COSE_Sign1 (ISO 18013-5
     * Annex C) against its own embedded x5chain, then hands that chain to
     * [evaluateIssuerTrust] for the actual trust decision - the issuance-
     * time counterpart to [org.siros.sdk.keystore.mdoc.MdocProximitySession]'s
     * presentation-time readerAuth check. Returns null (skip, don't block
     * storage) if `issuerAuth` has no x5chain or its signature doesn't
     * verify, mirroring that same "no badge, not untrusted" convention for
     * a check that can't even be attempted.
     *
     * @param issuerAuth the credential's `issuerAuth` COSE_Sign1 4-element array.
     * @param docType the credential's mdoc doctype, for VICAL docType enforcement.
     */
    private suspend fun verifyAndEvaluateIssuerTrust(issuerAuth: CBORObject, docType: String): TrustResult? {
        return try {
            val chain = MdocCose.extractX5Chain(issuerAuth)
            if (chain.isEmpty()) {
                Timber.w("issuerAuth present but has no x5chain")
                return null
            }
            val issuerCert = java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(chain[0].inputStream()) as java.security.cert.X509Certificate
            val msoBytes = issuerAuth[2].GetByteString()
            if (!MdocCose.verify1(issuerAuth, msoBytes, issuerCert.publicKey)) {
                Timber.w("issuerAuth signature verification failed")
                return null
            }
            evaluateIssuerTrust(chain, docType)
        } catch (e: Exception) {
            Timber.w(e, "issuerAuth verification threw")
            null
        }
    }

    /**
     * Parses [WalletConfig.readerTrustRootCertificatesPem] into certificates,
     * logging (not silently dropping) any entry that fails to parse - a real
     * Copilot-review finding: an operator who pastes a malformed PEM would
     * otherwise get no diagnostic signal beyond "untrusted", with no way to
     * tell a genuine trust decision apart from their own misconfiguration.
     */
    private val readerTrustRootCertificates: List<java.security.cert.X509Certificate> by lazy {
        val certFactory = java.security.cert.CertificateFactory.getInstance("X.509")
        config.readerTrustRootCertificatesPem.mapNotNull { pem ->
            runCatching { certFactory.generateCertificate(pem.byteInputStream()) as java.security.cert.X509Certificate }
                .onFailure { Timber.w(it, "Failed to parse a configured RICAL root certificate PEM") }
                .getOrNull()
        }
    }

    private fun sha256Hex(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /**
     * Handle credential_selection step from the engine.
     *
     * The backend sends DCQL query + verifier info in a flow_progress message.
     * We match credentials locally, show a consent UI via the event listener,
     * and respond with a consent or decline action.
     */
    private fun handleCredentialSelection(
        engine: WalletEngineSession,
        flowId: String,
        payload: kotlinx.serialization.json.JsonObject?,
    ) {
        scope.launch {
            try {
                // `.jsonObject` throws on JsonNull rather than treating it
                // like absent - a real NIST reference-verifier request over
                // mdoc-openid4vp:// (a non-DCQL request shape) has the
                // backend relay this key as JSON `null` rather than omitting
                // it, which crashed here and got misreported to the engine
                // as "User declined the request". `as? JsonObject` treats
                // any non-object value (absent, null, or otherwise) the same
                // way the `dcqlQuery != null` fallback below already expects.
                val dcqlQuery = payload?.get("dcql_query") as? JsonObject
                // Same `as?` as the line above, for the same reason: a JSON
                // null here would throw from `.jsonObject` just as dcql_query
                // did before #150.
                val verifierInfo = payload?.get("verifier") as? JsonObject
                // The backend defaults verifier.name to the raw client_id
                // (e.g. "x509_san_dns:verifier.multipaz.org") whenever the
                // verifier hasn't declared a real client_metadata.client_name -
                // never show that prefixed form to the user. Running every
                // raw name/client_id through ClientIdScheme.parse is safe for
                // a genuine friendly name too: it only matches known scheme
                // prefixes/URLs (falling into PreRegistered otherwise, which
                // passes the string through unchanged).
                val rawVerifierName = verifierInfo?.get("name")?.jsonPrimitive?.contentOrNull
                    ?: verifierInfo?.get("client_id")?.jsonPrimitive?.contentOrNull
                val verifierName = rawVerifierName?.let { ClientIdScheme.parse(it).displayName }

                val allCreds = credentialStore.getAll()
                // "mso_mdoc_zk" queries match here on purpose - see the same
                // note in the matchRequests() collector: sign_presentation's
                // ZK branch serves this transport, and reads these results
                // back from pendingMatchResultsByFlow below.
                val matchResults = if (dcqlQuery != null) {
                    CredentialMatcher.match(dcqlQuery, allCreds)
                } else {
                    listOf(CredentialMatcher.MatchResult(
                        queryId = "_default",
                        format = null,
                        candidates = allCreds,
                        requestedClaims = emptyList(),
                    ))
                }
                val candidates = matchResults.flatMap { it.candidates }.distinctBy { it.id }
                // First match wins, as in the sign handler; built once so the
                // ZK flag below and the handler agree on which query answers
                // which credential. Mirrors handleDCAPIRequest.
                val matchResultByCredentialId = buildMap {
                    for (r in matchResults) for (c in r.candidates) putIfAbsent(c.id, r)
                }
                val zkRequestedIds = matchResultByCredentialId
                    .filterValues { it.format?.equals("mso_mdoc_zk", ignoreCase = true) == true }
                    .keys
                val isZk: (StoredCredential) -> Boolean = { it.id in zkRequestedIds }
                // This (not the matchRequests() collector) is the code path
                // actually exercised by the redirect-flow/haip-vp:// protocol
                // this backend uses for the "credential_selection" progress
                // step - confirmed live: matchRequests() never fires for this
                // flow type. sign_presentation's ZK branch needs this cached
                // so it knows the originating query's format/zkSystemTypes.
                pendingMatchResultsByFlow[flowId] = matchResults

                val listener = eventListener
                // Hoisted: the decline branch below needs to tell "holds
                // nothing of this type" apart from "holds it, but every copy
                // is spent", and the defense-in-depth check further down
                // needs the same list.
                val eligible = eligibleInstances(candidates, isZk)
                // Only where nobody is asked anything: with a listener and
                // something to show, an empty answer really is the user
                // declining, and is reported as one below.
                if (candidates.isEmpty() || (listener == null && eligible.isEmpty())) {
                    // The honest answer, and the one that ends the flow now:
                    // a decline would tell the verifier the user refused, but
                    // the user was never asked, and saying nothing leaves the
                    // flow parked until the engine's five-minute
                    // user-interaction timeout reports a generic FLOW_TIMEOUT.
                    // The engine replies with NO_MATCHING_CREDENTIAL, naming
                    // the types the verifier asked for (#336).
                    val reason = noMatchReason(
                        dcqlQuery,
                        allCreds.size,
                        exhaustedOnly = candidates.isNotEmpty(),
                    )
                    Timber.i("Credential selection for flow $flowId matched nothing: $reason")
                    engine.sendCredentialsMatched(flowId, emptyList(), reason)
                    return@launch
                }
                val selectedIds = if (listener != null) {
                    listener.onCredentialSelectionRequired(
                        PresentationRequest(
                            verifierName = verifierName,
                            // Read only - do NOT remove. The later
                            // sign_presentation step (handleSignRequest ->
                            // validateAudience) still needs this entry;
                            // removing it here silently defeated
                            // validateAudience's defense-in-depth check for
                            // every presentation - it always saw a null
                            // trust result and no-op'd. validateAudience
                            // itself removes the entry once it's actually
                            // consumed.
                            trustResult = lastTrustResults[flowId],
                            matchResults = matchResults,
                            candidates = candidates,
                        )
                    )
                } else {
                    eligible.map { it.id }
                }

                if (selectedIds.isEmpty()) {
                    // A genuine decline: the user was shown credentials that
                    // could have answered this request and chose none.
                    val declinePayload = kotlinx.serialization.json.buildJsonObject {
                        put("reason", kotlinx.serialization.json.JsonPrimitive("user_declined"))
                    }
                    engine.sendFlowAction(flowId, "decline", declinePayload)
                    return@launch
                }

                // The app is trusted to only return IDs it was offered, but
                // shouldn't be the only thing enforcing consumption -
                // re-validate here too (defense in depth).
                val eligibleIds = eligible.map { it.id }.toSet()
                if (selectedIds.any { it !in eligibleIds }) {
                    throw WalletException("Selected credential has no eligible copies remaining - renew it to get more")
                }

                // Record presentation history
                recordPresentation(PresentationRecord(
                    id = randomUint32Id(),
                    flowId = flowId,
                    verifierName = verifierName,
                    credentialIds = selectedIds,
                    credentialNames = selectedIds.mapNotNull { id ->
                        allCreds.find { it.id == id }?.metadata?.name
                    },
                    requestedClaims = matchResults.flatMap { result ->
                        result.requestedClaims.mapNotNull { path -> path.lastOrNull() }
                    }.distinct(),
                    zkProof = selectedIds.any { it in zkRequestedIds },
                    timestamp = System.currentTimeMillis(),
                ))

                // Build consent payload with selected credentials
                // Must match backend ConsentSelection: credential_query_id, credential_id, disclosed_claims
                val consentPayload = kotlinx.serialization.json.buildJsonObject {
                    put("selected_credentials", kotlinx.serialization.json.buildJsonArray {
                        for (id in selectedIds) {
                            allCreds.find { it.id == id } ?: continue
                            val matchResult = matchResults.firstOrNull { r ->
                                r.candidates.any { it.id == id }
                            }
                            add(kotlinx.serialization.json.buildJsonObject {
                                matchResult?.queryId?.let {
                                    put("credential_query_id", kotlinx.serialization.json.JsonPrimitive(it))
                                }
                                // Legacy engine JSON-RPC protocol keeps credential_id as a
                                // string wire contract - stringify at this boundary rather
                                // than changing an unverified backend field type.
                                put("credential_id", kotlinx.serialization.json.JsonPrimitive(id.toString()))
                                // Include disclosed_claims from DCQL match so backend can
                                // round-trip them into sign_request's credentials_to_include.
                                // Each entry in requestedClaims is a full DCQL claim PATH
                                // (e.g. ["eu.europa.ec.eudi.pid.1", "pairwise_pseudonym"] -
                                // [namespace, elementIdentifier]) - only the last segment is
                                // the actual disclosable element id. flatten() (the old,
                                // wrong code here) merged every path segment together,
                                // including the namespace, into one flat list - harmless for
                                // the plain (non-ZK) signing path (MdocDeviceResponseBuilder's
                                // namespace filter just silently ignores an extra string that
                                // never matches a real elementIdentifier), but the native
                                // Longfellow ZK prover validates every requested claim
                                // strictly and throws ("attribute was not found in mdoc:
                                // eu.europa.ec.eudi.pid.1") - confirmed live. Mirrors
                                // handleDCAPIRequest's identical, already-correct
                                // `mapNotNull { it.lastOrNull() }`.
                                val requestedClaims = matchResult?.requestedClaims
                                    ?.mapNotNull { it.lastOrNull() }
                                    ?.distinct()
                                    ?: emptyList()
                                put("disclosed_claims", kotlinx.serialization.json.buildJsonArray {
                                    for (claim in requestedClaims) {
                                        add(kotlinx.serialization.json.JsonPrimitive(claim))
                                    }
                                })
                            })
                        }
                    })
                }
                engine.sendFlowAction(flowId, "consent", consentPayload)
            } catch (e: Exception) {
                Timber.e(e, "Error handling credential selection")
                val declinePayload = kotlinx.serialization.json.buildJsonObject {
                    put("reason", kotlinx.serialization.json.JsonPrimitive("error: ${e.message}"))
                }
                engine.sendFlowAction(flowId, "decline", declinePayload)
            }
        }
    }

    /**
     * Follow up an engine `NO_MATCHING_CREDENTIAL` error (#336).
     *
     * The presentation itself is already reported to the app by the caller,
     * with the engine's message naming the credential types the verifier
     * asked for. What is left is the issuance that asked for the
     * presentation in the first place: vc's `auth_provider: openid4vp` sends
     * the wallet through a verifier as part of issuing (an EU Company
     * Certificate that requires a PID, say), and that issuance flow is parked
     * on `authorization_required` waiting for the browser to come back with a
     * code that now never will.
     *
     * Only the app's half of that can be settled here. The engine's OID4VCI
     * handler waits on `authorization_complete` alone and silently drops any
     * other action for the flow (`Session.WaitForActionWithTimeout`), so
     * there is nothing the SDK can send that would end the parked flow early
     * - it dies on its own user-interaction timeout. Telling the app at least
     * takes the user off a "finish this in your browser" screen that has
     * nothing left to finish.
     *
     * Deliberately conservative: it acts only when exactly one authorization
     * is parked, since nothing in the protocol links a presentation flow to
     * the issuance that triggered it, and guessing wrong would report a
     * failure for an issuance the user may still be completing.
     */
    private fun reportNoMatchingCredential(presentationFlowId: String, error: FlowError) {
        // Every read type-checked rather than coerced: this runs inside the
        // flowErrors collector, where a throw would take the collector down
        // for the rest of the session.
        val requestedTypes = (error.details?.get("requested_types") as? kotlinx.serialization.json.JsonArray)
            ?.mapNotNull { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }.orEmpty()
        Timber.i(
            "Presentation %s cannot be satisfied: requested=%s walletReason=%s",
            presentationFlowId,
            requestedTypes,
            (error.details?.get("no_match_reason") as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull,
        )

        val parked = pendingAuthorizations.keys.filter { it != presentationFlowId }
        if (parked.size != 1) {
            if (parked.size > 1) {
                Timber.w("%d authorizations parked; not guessing which one this presentation belonged to", parked.size)
            }
            return
        }
        val parentFlowId = parked.single()
        pendingAuthorizations.remove(parentFlowId)
        terminatedFlowIds.add(parentFlowId)
        Timber.i("Issuance flow $parentFlowId required this presentation; reporting it as failed too")
        eventListener?.onFlowError(parentFlowId, error.message)
    }

    private fun saveSession(
        session: AuthSession,
        credentialId: ByteArray,
        prfSalt: ByteArray,
        hkdfSalt: ByteArray,
        hkdfInfo: ByteArray,
    ) {
        sessionStore.appToken = session.appToken
        sessionStore.refreshToken = session.refreshToken
        sessionStore.userId = session.uuid
        sessionStore.displayName = session.displayName
        sessionStore.tenantId = config.tenantId
        sessionStore.credentialId = b64UrlEncode(credentialId)
        sessionStore.prfSalt = b64Encode(prfSalt)
        sessionStore.hkdfSalt = b64Encode(hkdfSalt)
        sessionStore.hkdfInfo = b64Encode(hkdfInfo)
    }

    /**
     * Extract available claim names from a stored credential.
     *
     * For SD-JWT credentials, parses disclosures to get claim names.
     * Falls back to credential metadata claims if available.
     */
    private fun extractAvailableClaims(cred: StoredCredential): List<String> {
        val claims = mutableSetOf<String>()

        // Extract from SD-JWT disclosures: each is base64url(["salt","claim_name","value"])
        if (cred.raw.contains("~")) {
            val parts = cred.raw.split("~")
            for (disclosure in parts.drop(1).filter { it.isNotEmpty() }) {
                try {
                    val decoded = java.util.Base64.getUrlDecoder().decode(disclosure)
                    val arr = json.parseToJsonElement(String(decoded, Charsets.UTF_8))
                    val claimName = arr.jsonArray.getOrNull(1)?.jsonPrimitive?.contentOrNull
                    if (claimName != null) {
                        claims.add(claimName)
                    }
                } catch (_: Exception) {
                    // Skip unparseable disclosures
                }
            }
        }

        // Supplement from metadata claims if available
        cred.metadata?.claims?.forEach { claimMeta ->
            val name = claimMeta.path.lastOrNull()
            if (name != null) {
                claims.add(name)
            }
        }

        return claims.toList()
    }

    companion object {
        internal const val HKDF_INFO = "eDiplomas PRF"

        /** Thrown wherever a call needs the backend and the wallet has no session yet. */
        private const val NOT_CONNECTED = "Not connected"

        /** Thrown wherever a signing step needs a server challenge it did not get. */
        private const val MISSING_CHALLENGE = "Missing challenge"

        /**
         * How many reloaded credentials [hydrateReloadedCredentials] fetches
         * metadata for at once. Small: the common case after the first launch
         * is answered from [displayMetadataCache] with no network at all, and
         * when the network is involved a handful of concurrent connections to
         * (usually) one or two issuers is plenty.
         */
        private const val HYDRATION_PARALLELISM = 4
        internal var createEngineSession: (String, String) -> WalletEngineSession =
            { baseUrl, tenantId -> WalletEngineSession(baseUrl, tenantId) }

        private val b64 = Base64.getEncoder()
        private val b64Dec = Base64.getDecoder()
        private val b64Url = Base64.getUrlEncoder().withoutPadding()

        private fun b64Encode(data: ByteArray): String = b64.encodeToString(data)
        private fun b64Decode(data: String): ByteArray = b64Dec.decode(data)
        private fun b64UrlEncode(data: ByteArray): String = b64Url.encodeToString(data)
        private fun b64UrlDecode(data: String): ByteArray = Base64.getUrlDecoder().decode(data)

        /**
         * Create the appropriate [AuthProvider] based on config.
         *
         * Defaults to [CredentialManagerAuthProvider], which delegates to the
         * system Credential Manager: it handles biometric/device-credential
         * authorization itself and supports roaming authenticators (hybrid
         * phone-as-authenticator, USB/NFC/BLE security keys) — required for
         * SIROS ID's passkey-protects-private-data model. Set
         * [WalletConfig.useSystemCredentialManager] to `false` to use
         * [LocalAuthProvider] instead: a from-scratch KeyStore-backed passkey
         * manager with no roaming-authenticator support, intended only as a
         * fallback for environments without a working Credential Manager
         * provider (e.g. some emulators).
         */
        private fun createAuthProvider(activity: Activity, config: WalletConfig): AuthProvider {
            return if (config.useSystemCredentialManager) {
                Timber.i("Using system CredentialManager for passkeys")
                CredentialManagerAuthProvider(activity)
            } else {
                Timber.i("Using local KeyStore-backed passkey provider")
                LocalAuthProvider(activity, requireUserAuth = config.requireUserAuth)
            }
        }

        /**
         * Create a new [SirosWallet] instance.
         *
         * @param activity The host Activity (required for passkey UI).
         * @param config   Backend URL and tenant ID.
         */
        fun create(activity: Activity, config: WalletConfig): SirosWallet {
            return SirosWallet(activity, config)
        }
    }
}

