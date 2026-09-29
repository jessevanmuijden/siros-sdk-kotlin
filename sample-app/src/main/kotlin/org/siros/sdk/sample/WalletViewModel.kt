package org.siros.sdk.sample

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import org.siros.sdk.credentials.CredentialConsumptionPolicy
import org.siros.sdk.credentials.CredentialOffer
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.Ts11CredentialDiscovery
import org.siros.sdk.credentials.Ts11DiscoveredCredential

import org.siros.sdk.keystore.OkHttpR2psTransport
import org.siros.sdk.wallet.dcapi.WalletSessionHolder
import org.siros.sdk.wallet.dcapi.SirosCredentialRegistry
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.credentials.SirosException
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.SignerSecurityProperties
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.keystore.ActivateLifecycleRequest
import org.siros.sdk.keystore.AuthProvider
import org.siros.sdk.keystore.CompositeCtap2Transport
import org.siros.sdk.keystore.DestroyLifecycleRequest
import org.siros.sdk.keystore.DestroyMode
import org.siros.sdk.keystore.DetailedKeyInfo
import org.siros.sdk.keystore.FactorKind
import org.siros.sdk.keystore.Fido2TransportMode
import org.siros.sdk.keystore.LifecycleState
import org.siros.sdk.keystore.LifecycleStatus
import org.siros.sdk.keystore.NfcCtap2Transport
import org.siros.sdk.keystore.PlayIntegrityProvider
import org.siros.sdk.keystore.R2psAuthMode
import org.siros.sdk.keystore.R2psConfig
import org.siros.sdk.keystore.RegisterLifecycleRequest
import org.siros.sdk.keystore.RotateLifecycleRequest
import org.siros.sdk.keystore.UniFFISigner
import org.siros.sdk.keystore.UsbCtap2Transport
import org.siros.sdk.keystore.WscdKeystoreAdapter
import org.siros.sdk.keystore.WscdManager
import org.siros.sdk.wallet.RememberScope
import org.siros.sdk.wallet.RequestWscdChoice
import org.siros.sdk.wallet.SirosWallet
import org.siros.sdk.wallet.WalletConfig
import org.siros.sdk.wallet.WalletEventListener
import org.siros.sdk.wallet.WalletState
import org.siros.sdk.wallet.PresentationRequest
import org.siros.sdk.wallet.DeepLinkType
import org.siros.sdk.wallet.WscdChoiceResult
import org.siros.sdk.wallet.classifyDeepLink
import uniffi.siros_wscd_manager.FfiWscdConfig

/** A terminal issuance/presentation flow failure, shown as a dialog with Retry/Cancel. */
data class FlowErrorInfo(val message: String, val canRetry: Boolean)

/**
 * One in-flight [org.siros.sdk.wallet.RequestWscdChoice] prompt - the SDK
 * asking which registered WSCD plugin to use for an upcoming
 * credential-issuance key batch, because more than one of
 * [WalletConfig.availableKeystores] meets the credential type's required
 * tier and neither a persisted TOFU choice nor [WalletConfig.defaultWscdMapping]
 * resolved it unambiguously. Mirrors proximity's `PendingConsent` shape
 * (see `ProximityEngagementScreen.kt`) exactly - the same
 * suspend-callback-to-dialog bridging pattern, just for a different SDK
 * callback.
 */
data class PendingWscdChoice(
    val issuer: String,
    val credentialType: String,
    val eligiblePluginIds: List<String>,
    /**
     * Call with the chosen plugin ID and how long to remember it to
     * approve, or a null plugin ID to cancel (the [RememberScope] argument
     * is ignored on cancel).
     */
    val respond: (pluginId: String?, rememberScope: RememberScope) -> Unit,
)

/**
 * One in-flight FIDO2 CTAP2 ClientPin prompt - `PreviewSignPlugin`'s
 * `generate_key`/`sign` call `AuthCallback.request_pin()` to obtain a
 * `pinUvAuthToken` (see `preview_sign_protocol::make_credential`/
 * `get_assertion` in siros-wscd-manager). [AuthProvider.requestPin] is
 * synchronous, not suspend (it's invoked off the Android main thread from
 * Rust's own FFI thread pool - see [Ctap2TransportBridge]'s doc comment
 * for the same pattern), so the bridge wraps this same
 * suspend-callback-to-dialog shape in `runBlocking` itself rather than
 * exposing it as a suspend function here.
 */
data class PendingPinEntry(
    val pluginId: String,
    /** Call with the entered PIN to submit, or null to cancel. */
    val respond: (pin: String?) -> Unit,
)

/** Bridges [CompositeCtap2Transport]'s ambiguous-choice callback to a Compose dialog. */
data class PendingTransportChoice(val respond: (Fido2TransportMode?) -> Unit)

/**
 * Sample app ViewModel.
 *
 * The entire wallet lifecycle — auth, key management, engine protocol,
 * credential storage — is handled by [SirosWallet]. This ViewModel only
 * needs to expose UI-level state and forward user actions.
 */
class WalletViewModel(private val activity: Activity) : ViewModel() {

    class Factory(private val activity: Activity) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return WalletViewModel(activity) as T
        }
    }

    // ── Configuration (editable before login) ───────────────────────

    private val _backendUrl: MutableStateFlow<String>
    val backendUrl: StateFlow<String> get() = _backendUrl

    /**
     * Mirror base URLs for the go-zk-circuits catalog service (see
     * [org.siros.sdk.wallet.WalletConfig.zkCircuitUrls]'s doc comment) -
     * unlike [backendUrl], this persists on every update (see
     * [updateZkCircuitUrls]), matching the boolean-toggle settings below
     * rather than backendUrl's read-once-at-construction behavior.
     */
    private val _zkCircuitUrls: MutableStateFlow<List<String>>
    val zkCircuitUrls: StateFlow<List<String>> get() = _zkCircuitUrls

    // Raw text of the "Engine URL (blank = auto)" field - blank means "derive
    // from the current backend URL" (see resolvedEngineUrl()), not "use the
    // BuildConfig.ENGINE_URL local-dev default" as a previous version of this
    // code did. That silently pinned every connection to 127.0.0.1:8082 even
    // after backendUrl was changed to a remote host, which looked to the user
    // like a hung/timed-out registration (the WebAuthn ceremony itself
    // succeeded; only the following engine WebSocket connect failed).
    private val _engineUrlOverride: MutableStateFlow<String>
    val engineUrlOverride: StateFlow<String> get() = _engineUrlOverride

    private val _tenantId: MutableStateFlow<String>
    val tenantId: StateFlow<String> get() = _tenantId

    private val _useWmpProtocol: MutableStateFlow<Boolean>
    val useWmpProtocol: StateFlow<Boolean> get() = _useWmpProtocol

    private val _showCredentialDetails: MutableStateFlow<Boolean>
    val showCredentialDetails: StateFlow<Boolean> get() = _showCredentialDetails

    private val _showDiagnosticMessages: MutableStateFlow<Boolean>
    val showDiagnosticMessages: StateFlow<Boolean> get() = _showDiagnosticMessages

    private val _credentialConsumptionPolicy: MutableStateFlow<CredentialConsumptionPolicy>
    val credentialConsumptionPolicy: StateFlow<CredentialConsumptionPolicy> get() = _credentialConsumptionPolicy

    /** See [org.siros.sdk.wallet.WalletConfig.preferLocalReaderTrustEvaluation]'s doc comment. */
    private val _preferLocalReaderTrustEvaluation: MutableStateFlow<Boolean>
    val preferLocalReaderTrustEvaluation: StateFlow<Boolean> get() = _preferLocalReaderTrustEvaluation

    /**
     * A single PEM-encoded RICAL root certificate for local reader-trust
     * fallback (see [org.siros.sdk.wallet.WalletConfig.readerTrustRootCertificatesPem]) -
     * blank means none configured, matching that config field defaulting to
     * an empty list.
     */
    private val _readerTrustRootCertificatePem: MutableStateFlow<String>
    val readerTrustRootCertificatePem: StateFlow<String> get() = _readerTrustRootCertificatePem

    init {
        // Read test overrides - set either via the settings sheet UI, or (debug
        // builds only) via `adb shell am start ... --es backend_url ... --es
        // tenant_id ...` - see MainActivity.applyIntentTestOverrides(), which
        // copies matching intent extras into this same prefs store before the
        // ViewModel is constructed.
        val prefs = activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
        _backendUrl = MutableStateFlow(prefs.getString("backend_url", null) ?: DEFAULT_BACKEND_URL)
        _engineUrlOverride = MutableStateFlow(prefs.getString("engine_url", null) ?: "")
        _tenantId = MutableStateFlow(prefs.getString("tenant_id", null) ?: DEFAULT_TENANT_ID)
        // JSON-encoded list (no existing precedent in this prefs store for a
        // List<String> value) - falls back to the single-mirror default
        // when absent or unparseable (e.g. a value written by a future
        // format this build doesn't understand).
        _zkCircuitUrls = MutableStateFlow(
            prefs.getString("zk_circuit_urls", null)?.let { raw ->
                runCatching {
                    Json.decodeFromString(ListSerializer(String.serializer()), raw)
                }.getOrNull()
            } ?: listOf(ZkCircuitClient.DEFAULT_ZK_CIRCUIT_URL)
        )
        _useWmpProtocol = MutableStateFlow(prefs.getBoolean("use_wmp_protocol", false))
        // Default follows build type (on for debug, off for release) - a
        // manual override either way is persisted across restarts, so e.g. a
        // tester can still flip it on in a release build if needed.
        _showCredentialDetails = MutableStateFlow(
            prefs.getBoolean("show_credential_details", BuildConfig.DEBUG)
        )
        // Raw FlowStep tokens shown alongside the friendly progress label -
        // default false: seeing both together in practice is redundant, the
        // localized label alone is enough. Kept as an opt-in toggle for
        // debugging (was default true during initial rollout).
        _showDiagnosticMessages = MutableStateFlow(
            prefs.getBoolean("show_diagnostic_messages", false)
        )
        // Core wallet policy (not a UI-only preference like the toggles
        // above) - persisted here, but enforced by SirosWallet itself. Can't
        // set it on `wallet` right here - that property initializes later in
        // declaration order - see its own initializer and rebuildWalletIfNeeded(),
        // both of which apply this value to whichever SirosWallet instance is current.
        _credentialConsumptionPolicy = MutableStateFlow(
            runCatching {
                CredentialConsumptionPolicy.valueOf(
                    prefs.getString("credential_consumption_policy", null) ?: ""
                )
            }.getOrDefault(CredentialConsumptionPolicy.NEVER_CONSUME)
        )
        _preferLocalReaderTrustEvaluation = MutableStateFlow(
            prefs.getBoolean("prefer_local_reader_trust_evaluation", false)
        )
        _readerTrustRootCertificatePem = MutableStateFlow(
            prefs.getString("reader_trust_root_certificate_pem", null) ?: ""
        )
    }

    fun updateBackendUrl(url: String) { _backendUrl.value = url }
    fun updateTenantId(id: String) { _tenantId.value = id }
    fun updateEngineUrl(url: String) { _engineUrlOverride.value = url }

    /**
     * Updates and persists the configured zk-circuits mirror list
     * immediately (unlike [updateBackendUrl], which is read once at
     * [buildWalletConfig] time and not separately persisted here) -
     * matches [updateUseWmpProtocol]'s persist-on-every-update pattern.
     */
    fun updateZkCircuitUrls(urls: List<String>) {
        _zkCircuitUrls.value = urls
        activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
            .edit()
            .putString("zk_circuit_urls", Json.encodeToString(ListSerializer(String.serializer()), urls))
            .apply()
    }

    /**
     * Resolves the engine URL to actually connect to: an explicit override if
     * the user typed one, otherwise derived from the current backend URL -
     * same origin for any remote/reverse-proxied deployment (engine traffic
     * is split from backend traffic by path, e.g. wallet-proxy's
     * /api/v2/wallet, not by port), or backendUrl with the port swapped to
     * 8082 for plain localhost dev (where the engine really is a separate
     * listener on the same host).
     */
    private fun resolvedEngineUrl(): String {
        val override = _engineUrlOverride.value.trim()
        if (override.isNotBlank()) return override
        val backend = _backendUrl.value
        val isLocalhost = backend.contains("127.0.0.1") || backend.contains("localhost")
        return if (isLocalhost) backend.replace(Regex(":\\d+(?=/|$)"), ":8082") else backend
    }
    fun updateUseWmpProtocol(enabled: Boolean) {
        _useWmpProtocol.value = enabled
        activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean("use_wmp_protocol", enabled)
            .apply()
    }

    fun updateShowCredentialDetails(enabled: Boolean) {
        _showCredentialDetails.value = enabled
        activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean("show_credential_details", enabled)
            .apply()
    }

    fun updateShowDiagnosticMessages(enabled: Boolean) {
        _showDiagnosticMessages.value = enabled
        activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean("show_diagnostic_messages", enabled)
            .apply()
    }

    fun updateCredentialConsumptionPolicy(policy: CredentialConsumptionPolicy) {
        _credentialConsumptionPolicy.value = policy
        wallet.credentialConsumptionPolicy = policy
        activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
            .edit()
            .putString("credential_consumption_policy", policy.name)
            .apply()
    }

    fun updatePreferLocalReaderTrustEvaluation(enabled: Boolean) {
        _preferLocalReaderTrustEvaluation.value = enabled
        activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean("prefer_local_reader_trust_evaluation", enabled)
            .apply()
    }

    fun updateReaderTrustRootCertificatePem(pem: String) {
        _readerTrustRootCertificatePem.value = pem
        activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
            .edit()
            .putString("reader_trust_root_certificate_pem", pem)
            .apply()
    }

    // ── Plugin / R2PS configuration ──────────────────────────────────

    /**
     * Which plugin tab is currently open in [WscdScreen] (also the plugin
     * lifecycle actions there - Enroll/Rotate/Destroy/Refresh - operate on;
     * see [activePluginId]). Purely an internal "which tab" UI detail now,
     * NOT a second source of truth for the user's actual WSCD preference -
     * that's [wscdGlobalOverride] (persisted, feeds
     * [org.siros.sdk.wallet.WscdSelectionPolicy]), which this used to
     * duplicate via an separate in-memory-only chip picker. [selectPlugin]
     * only changes which tab is shown/diagnosed; it does NOT persist
     * anything - persisting a preference is now only ever done through
     * [setWscdGlobalOverride] (the tab's own "Preferred WSCD" toggle), and
     * the very first time this session learns the persisted override (see
     * [refreshWscdUserOverrides]) it seeds this StateFlow from it, so the
     * tab shown after login/reconnect matches the user's saved preference
     * rather than always defaulting to the same BuildConfig-based guess
     * below.
     */
    private val _selectedPluginId = MutableStateFlow(
        if (BuildConfig.R2PS_ENABLED) "r2ps" else "softkey",
    )
    val selectedPluginId: StateFlow<String> = _selectedPluginId

    /** Set once [refreshWscdUserOverrides] has seeded [_selectedPluginId] from the persisted override - see that function. */
    private var initialPluginTabSeeded = false

    private val _r2psEnabled = MutableStateFlow(BuildConfig.R2PS_ENABLED)
    val r2psEnabled: StateFlow<Boolean> = _r2psEnabled

    private val _r2psServerUrl = MutableStateFlow(DEFAULT_R2PS_URL)
    val r2psServerUrl: StateFlow<String> = _r2psServerUrl

    /**
     * Which physical transport [registerFido2OnSigner] wires up - dev-screen
     * toggle. Declared here, before [wallet], since [buildWalletConfig] (run
     * as part of constructing [wallet]) reads it via [buildWscdKeystore] ->
     * [registerFido2OnSigner] - a property read inside another property's
     * initializer must already be initialized itself, i.e. appear earlier in
     * the class body (see [_selectedPluginId] above for the same
     * constraint). Reading it before this declaration existed threw a NPE
     * from [MutableStateFlow.getValue] at construction time - a real bug,
     * not just a theoretical ordering concern.
     */
    private val _fido2TransportMode = MutableStateFlow(Fido2TransportMode.AUTO)
    val fido2TransportMode: StateFlow<Fido2TransportMode> = _fido2TransportMode
    fun setFido2TransportMode(mode: Fido2TransportMode) { _fido2TransportMode.value = mode }

    /**
     * Switch [WscdScreen]'s active plugin tab - also registers/restores
     * that plugin on the live diagnostic manager ([wallet]'s
     * [SirosWallet.wscdManager]) if it isn't already, so a previously
     * enrolled key (restored from privatedata - see [registerFido2OnSigner])
     * shows up in the Stored Keys list immediately, without the user
     * needing to tap Enroll again (which would create a brand NEW key
     * rather than just reveal the existing one).
     *
     * Deliberately does NOT persist anything - this is tab navigation, not
     * a preference change (see [_selectedPluginId]'s doc comment). To make
     * a plugin the persisted preference, use [setWscdGlobalOverride]
     * instead (the tab's "Preferred WSCD" toggle).
     */
    fun selectPlugin(pluginId: String) {
        _selectedPluginId.value = pluginId
        _r2psEnabled.value = pluginId == "r2ps"
        val manager = wallet.wscdManager ?: return
        when (pluginId) {
            "fido2" -> {
                registerFido2OnSigner(manager)
                restoreFido2PluginState()
            }
            "r2ps" -> registerR2psOnSigner(manager)
        }
        refreshWscdInfo()
    }
    fun updateR2psEnabled(enabled: Boolean) {
        _r2psEnabled.value = enabled
        if (enabled) _selectedPluginId.value = "r2ps"
        else if (_selectedPluginId.value == "r2ps") _selectedPluginId.value = "softkey"
    }
    fun updateR2psServerUrl(url: String) { _r2psServerUrl.value = url }

    /**
     * Developer-supplied pre-population for [WalletConfig.defaultWscdMapping]
     * - lets an integrator that already knows the right plugin for a given
     * (issuer, credentialType) pair skip [pendingWscdChoice] entirely (see
     * [org.siros.sdk.wallet.WscdSelectionPolicy]'s resolution order). This is
     * host-app/dev config, not an end-user preference, so it's edited from
     * [WscdScreen]'s collapsible Developer section rather than its always-
     * visible one, and - like [selectedPluginId]/[r2psServerUrl] - is in-
     * memory only (not persisted across app restarts): a real integrator
     * would supply this as a genuine compile-time config value, not a
     * runtime user setting.
     */
    private val _defaultWscdMappingText = MutableStateFlow("")
    val defaultWscdMappingText: StateFlow<String> = _defaultWscdMappingText

    /**
     * Parsed form of [defaultWscdMappingText]: one `issuer|credentialType=pluginId`
     * entry per line, blank lines and lines missing `=` ignored. Directly
     * usable as [WalletConfig.defaultWscdMapping] (same `"issuer|credentialType"`
     * key shape that class documents).
     */
    private val _defaultWscdMapping = MutableStateFlow<Map<String, String>>(emptyMap())

    fun updateDefaultWscdMappingText(text: String) {
        _defaultWscdMappingText.value = text
        _defaultWscdMapping.value = text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && it.contains('=') }
            .associate { line ->
                val (key, pluginId) = line.split('=', limit = 2)
                key.trim() to pluginId.trim()
            }
    }

    // ── TS11 registry discovery (best-effort, see WscdScreen.Ts11DiscoveryCard) ──

    /**
     * Result of the last [discoverTs11Schemas] call, for [WscdScreen]'s
     * common (not per-plugin) "Discover from TS11 Registry" action -
     * queries the real `registry.siros.org` directly (see
     * [org.siros.sdk.credentials.Ts11RegistryClient]'s doc comment for why
     * this is preferable to go-wallet-backend's `/type-metadata`
     * cache/proxy for this purpose), and resolves each entry's real display
     * identity (`vct`/`doctype` + name/description) via
     * [Ts11CredentialDiscovery] - a raw registry entry only carries an
     * opaque UUID, not a human name, at the list level (see that class's
     * doc comment). Deliberately minimal: this only fetches and displays
     * candidates filtered by nominal tier match; it does not itself write
     * anything into [defaultWscdMappingText] (see [Ts11DiscoveryCard]'s
     * "Add"/"Add all" actions in WscdScreen.kt for that, and its doc
     * comment for the known issuer-less-schema limitation).
     */
    private val _ts11DiscoveredCredentials = MutableStateFlow<List<Ts11DiscoveredCredential>>(emptyList())
    val ts11DiscoveredCredentials: StateFlow<List<Ts11DiscoveredCredential>> = _ts11DiscoveredCredentials

    private val _ts11DiscoveryInProgress = MutableStateFlow(false)
    val ts11DiscoveryInProgress: StateFlow<Boolean> = _ts11DiscoveryInProgress

    fun discoverTs11Schemas() {
        if (_ts11DiscoveryInProgress.value) return
        _ts11DiscoveryInProgress.value = true
        viewModelScope.launch {
            try {
                _ts11DiscoveredCredentials.value = Ts11CredentialDiscovery().discover()
            } catch (e: Exception) {
                Log.w(TAG, "TS11 registry discovery failed", e)
            } finally {
                _ts11DiscoveryInProgress.value = false
            }
        }
    }

    // ── Add-credential state ────────────────────────────────────────

    private val _availableCredentials = MutableStateFlow<List<CredentialOffer>>(emptyList())
    val availableCredentials: StateFlow<List<CredentialOffer>> = _availableCredentials

    private val _isLoadingOffers = MutableStateFlow(false)
    val isLoadingOffers: StateFlow<Boolean> = _isLoadingOffers

    private val _showAddCredential = MutableStateFlow(false)
    val showAddCredential: StateFlow<Boolean> = _showAddCredential

    /** Offer pending user confirmation before issuance starts. */
    private val _pendingIssuanceOffer = MutableStateFlow<CredentialOffer?>(null)
    val pendingIssuanceOffer: StateFlow<CredentialOffer?> = _pendingIssuanceOffer

    // ── Credential detail state ─────────────────────────────────────

    private val _selectedCredential = MutableStateFlow<StoredCredential?>(null)
    val selectedCredential: StateFlow<StoredCredential?> = _selectedCredential

    // ── Presentation history ────────────────────────────────────────

    private val _presentationHistory = MutableStateFlow<List<PresentationRecord>>(emptyList())
    val presentationHistory: StateFlow<List<PresentationRecord>> = _presentationHistory

    private val _showHistory = MutableStateFlow(false)
    val showHistory: StateFlow<Boolean> = _showHistory

    // ── Activate (QR scan + proximity engagement) state ─────────────

    /** Which mode the merged Activate screen is showing; null means Activate is closed. */
    enum class ActivateMode { Qr, Proximity }

    private val _activateMode = MutableStateFlow<ActivateMode?>(null)
    val activateMode: StateFlow<ActivateMode?> = _activateMode

    /** Opens Activate, always starting in QR mode (the default engagement path). */
    fun openActivate() {
        _activateMode.value = ActivateMode.Qr
    }

    /** Switches an already-open Activate screen into proximity/BLE mode. */
    fun switchToProximityEngagement() {
        _activateMode.value = ActivateMode.Proximity
    }

    /** Leaves Activate entirely, from either mode. */
    fun closeActivate() {
        _activateMode.value = null
    }

    /**
     * Non-null while a QR-triggered flow has been handed off to the wallet/engine
     * but no [WalletState.FlowActive]/[WalletState.Error] has arrived yet.
     *
     * Some issuers/verifiers (e.g. geneva2026.mdoc.online) are slow enough here
     * that, without this, the user sees the scanner close and then... nothing,
     * for long enough to think the scan didn't register and re-scan. The value
     * is the flow type ("issuance"/"presentation"), used to pick the right
     * "Contacting issuer/verifier…" copy; cleared in [observeWalletState] the
     * moment a real subsequent state (FlowActive, Error) takes over, or from
     * [handleQrResult]'s own catch/cancel paths.
     */
    private val _flowStarting = MutableStateFlow<String?>(null)
    val flowStarting: StateFlow<String?> = _flowStarting

    private var flowStartJob: Job? = null

    /** Dismiss the "starting…" step (e.g. user tapped Cancel before any flow state arrived). */
    fun cancelFlowStarting() {
        flowStartJob?.cancel()
        flowStartJob = null
        _flowStarting.value = null
        // Best-effort: if the engine actually registered a flow just as this ran,
        // this also cancels it server-side; cancelCurrentFlow() is a no-op otherwise.
        wallet.cancelCurrentFlow()
    }

    // ── Proximity (ISO 18013-5) engagement dependencies ──────────────
    // Navigation state lives above in `activateMode` - proximity is one of
    // Activate's two modes, not its own independent screen.

    /** For `BlePeripheralServer`'s injected `getCredentials` dependency - see its constructor doc comment. */
    suspend fun getCredentialsForProximity() = wallet.getCredentials()

    /** For `BlePeripheralServer`'s injected `signPresentation` dependency. */
    suspend fun signMdocPresentationForProximity(
        credentialId: Long,
        disclosedClaims: List<String>?,
        sessionTranscriptBytes: ByteArray,
    ) = wallet.signMdocPresentationForProximity(credentialId, disclosedClaims, sessionTranscriptBytes)

    /** For `BlePeripheralServer`/`BleCentralClient`'s injected `filterEligible` dependency. */
    suspend fun filterEligibleForProximity(instances: List<StoredCredential>): List<StoredCredential> =
        wallet.eligibleInstances(instances)

    /** For `PresentationConsentScreen`'s exhausted-query precheck - see [SirosWallet.availableKeyIds]. */
    suspend fun currentAvailableKeyIds(): Set<String> = wallet.availableKeyIds()

    /**
     * For `BlePeripheralServer`/`BleCentralClient`'s injected `evaluateReaderTrust`
     * dependency - adapts `SirosWallet.evaluateReaderTrust`'s richer
     * `TrustResult` (shared with the verifier/issuer trust paths) down to
     * `MdocProximitySession`'s narrower `ReaderTrustResult`.
     */
    suspend fun evaluateReaderTrustForProximity(x5chain: List<ByteArray>): org.siros.sdk.keystore.mdoc.ReaderTrustResult {
        val result = wallet.evaluateReaderTrust(x5chain)
        return org.siros.sdk.keystore.mdoc.ReaderTrustResult(
            trusted = result.trusted,
            reason = result.reason,
            entityName = result.entityName,
        )
    }

    // ── Loading / error feedback ────────────────────────────────────

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage

    fun clearError() { _errorMessage.value = null }

    // ── Info feedback (non-error, transient confirmations e.g. batch receipt) ─

    private val _infoMessage = MutableStateFlow<String?>(null)
    val infoMessage: StateFlow<String?> = _infoMessage

    fun clearInfo() { _infoMessage.value = null }

    /**
     * Credentials received so far in the current flow. Flows in this app run
     * one at a time, so a plain counter reset on consumption (in
     * onFlowComplete) is enough - no need to key it by flowId, which
     * onCredentialReceived doesn't carry anyway.
     */
    private var receivedCredentialCount = 0

    // ── Flow error feedback (issuance/presentation flows that fail server-side,
    // e.g. an untrusted issuer) ──────────────────────────────────────────────
    // Distinct from the transient Snackbar above: a flow error is terminal for
    // that flow (see SirosWallet's WalletEventListener.onFlowError), so the
    // user needs an explicit next action rather than a message that auto-dismisses.

    /** Re-runs whichever flow-starting call (QR scan or offer button) last ran, for Retry. */
    private var lastFlowRetry: (() -> Unit)? = null

    private val _flowErrorDialog = MutableStateFlow<FlowErrorInfo?>(null)
    val flowErrorDialog: StateFlow<FlowErrorInfo?> = _flowErrorDialog

    fun retryLastFlow() {
        val retry = lastFlowRetry
        _flowErrorDialog.value = null
        retry?.invoke()
    }

    fun dismissFlowError() {
        _flowErrorDialog.value = null
    }

    /**
     * Every registered WSCD plugin ID this session's [WalletConfig.availableKeystores]
     * actually offers - populated at [buildWalletConfig] time (see that
     * function, called below to construct [wallet]), for the Settings tab's
     * "preferred WSCD" / per-issuer override pickers to offer as options.
     * [buildWalletConfig] builds every known plugin ID unconditionally (not
     * only the one currently selected), so this always includes fido2/r2ps
     * even before the user has separately enrolled either through the WSCA
     * Developer screen. Declared here, before [wallet], since
     * [buildWalletConfig] (run as part of constructing [wallet]) writes to
     * it - a property used inside another property's initializer must
     * already be initialized itself, i.e. appear earlier in the class body
     * (see [_selectedPluginId] above for the same constraint on the
     * plugin-selection field it reads).
     */
    private val _availableWscdPluginIds = MutableStateFlow<List<String>>(emptyList())
    val availableWscdPluginIds: StateFlow<List<String>> = _availableWscdPluginIds

    // Keyed by manager instance -> the transport mode it was last registered
    // with. A plain "registered once, ever" guard (as R2PS still uses below)
    // is wrong here: buildWalletConfig() eagerly registers fido2 with
    // whatever _fido2TransportMode happened to be at WALLET-CONSTRUCTION
    // time (before the user can touch the dev screen's transport toggle) -
    // a one-shot guard would then permanently lock that manager to the
    // wrong transport, ignoring every later switch. Re-registering on the
    // SAME manager is safe (Rust's register_plugin is a plain HashMap
    // insert, no destructive side effect), so re-register whenever the
    // desired mode differs from what's currently registered, rather than
    // only ever once.
    // Declared here, before [wallet], since [buildWalletConfig] (run as part
    // of constructing [wallet]) reads it via [buildWscdKeystore] ->
    // [registerFido2OnSigner] - a property read inside another property's
    // initializer must already be initialized itself, i.e. appear earlier in
    // the class body (see [_selectedPluginId]/[_fido2TransportMode] above for
    // the same constraint). Left at its natural declaration point (right
    // next to [registerFido2OnSigner], far below [wallet]) threw the exact
    // same class of NPE those properties' own doc comments already warn
    // about - "$propertyName must not be null" from Kotlin's own
    // not-yet-initialized-property intrinsics check - confirmed live on a
    // real device: buildWscdKeystore's try/catch swallowed it and dropped
    // the fido2 keystore from the session entirely. ([wallet] itself was
    // the other such read, from inside [registerFido2OnSigner]; that one is
    // gone - see its doc comment and [restoreFido2PluginState].)
    private val fido2RegisteredTransport = java.util.Collections.synchronizedMap(
        java.util.IdentityHashMap<WscdManager, Fido2TransportMode>(),
    )

    /**
     * Managers whose FIDO2 plugin currently holds the key state persisted
     * in privatedata (restored via [restoreFido2PluginState], or freshly
     * exported by [saveFido2PluginState]). Guarded by the same lock as
     * [fido2RegisteredTransport]. Kept separately from that map because
     * "registered" and "holds the saved keys" are different facts: at
     * construction time there is no logged-in wallet to read saved state
     * from, so every plugin starts out registered but empty, and is only
     * caught up once the wallet becomes [WalletState.Ready].
     */
    private val fido2StateRestored: MutableSet<WscdManager> =
        java.util.Collections.newSetFromMap(java.util.IdentityHashMap<WscdManager, Boolean>())

    // ── Wallet ──────────────────────────────────────────────────────

    private var wallet: SirosWallet = SirosWallet.create(
        activity,
        buildWalletConfig(),
    ).also { it.credentialConsumptionPolicy = _credentialConsumptionPolicy.value }

    /**
     * Observable wallet state — collect this from your Composable.
     * Exposed via an indirection so that rebuilding the wallet (which
     * replaces the [SirosWallet] instance) does not leave Compose
     * subscribed to the old, destroyed instance's state flow.
     */
    private val _walletState = MutableStateFlow<WalletState>(wallet.state.value)
    val state: StateFlow<WalletState> = _walletState
    private var walletStateJob: Job? = null

    private fun observeWalletState() {
        walletStateJob?.cancel()
        walletStateJob = viewModelScope.launch {
            wallet.state.collect { newState ->
                _walletState.value = newState
                // A real subsequent state has arrived (FlowActive with the
                // engine's first progress step, an Error, or a bounce back to
                // Ready) - the transitional "starting…" step's job is done.
                _flowStarting.value = null
                // Keep the DC API credential-provider registry (and the
                // session it presents against) in sync with the wallet's
                // actual state - see WalletSessionHolder's doc comment for
                // why the DC API Activity needs this instead of its own
                // login flow.
                //
                // Keyed on whether this wallet currently *has* presentable
                // credentials, not on whether its engine happens to be
                // connected. Those are different questions, and answering the
                // second was a bug: a transient WebSocket failure took the
                // user's credentials out of the browser's credential picker,
                // and since the engine gives up after five reconnect attempts
                // they stayed out. Every site then reported "your info wasn't
                // found" while the app itself still listed the credentials
                // perfectly happily. Observed on a Pixel from one DNS blip:
                //
                //   Engine WebSocket failure … UnknownHostException
                //   WebSocket reconnection exhausted (5 attempts)
                //
                // A presentation started from the picker does not need the
                // engine — the matcher runs in the picker's own process and
                // the wallet signs locally — so dropping the registration on a
                // connectivity wobble removed a capability that still worked.
                when (newState) {
                    // Both carry credentials and both mean "logged in, keystore
                    // unlocked". FlowActive used to fall into the `else` below,
                    // which deregistered the wallet for the duration of any
                    // issuance or presentation flow.
                    is WalletState.Ready, is WalletState.FlowActive -> {
                        WalletSessionHolder.update(wallet)
                        SirosCredentialRegistry.refresh(
                            context = activity,
                            credentials = newState.credentialsOrEmpty(),
                            // What this wallet can actually prove. Without it a
                            // mso_mdoc_zk request matches nothing, which is the
                            // right answer for a wallet that cannot produce the
                            // proof and the wrong one for this app.
                            // Identifiers only. Whether a specific circuit is
                            // fetchable is known at proof time, not here, so
                            // declaring particular attribute counts would claim
                            // knowledge this wallet does not have and refuse
                            // requests it can satisfy.
                            zkSystems = wallet.zkSystemIds
                                .map { SirosCredentialRegistry.ZkSystem(it, emptyMap()) },
                            useStockMatcher = BuildConfig.STOCK_DC_MATCHER,
                        )
                        refreshWscdTofuMapping()
                        refreshWscdUserOverrides()
                        restoreFido2PluginState()
                        maybeOfferWscdAutoEnroll()
                    }
                    // No usable credentials: logged out, the keystore is
                    // locked and nothing can be signed until PRF unlock, or
                    // this wallet instance is suspended/revoked (SID-AUTH-06),
                    // which is a logged-out wallet that cannot log back in.
                    // Offering an entry we cannot honour walks the user through
                    // a consent screen and then fails.
                    is WalletState.Disconnected,
                    is WalletState.KeystoreLocked,
                    is WalletState.LifecycleBlocked -> {
                        WalletSessionHolder.update(null)
                        SirosCredentialRegistry.clear(activity)
                    }

                    // Transient, and deliberately left alone. `Connecting` is
                    // every reconnect; `Error` is recoverable and the app
                    // offers a retry. Whatever was registered stays registered
                    // and stays correct, because neither state says the
                    // credentials went anywhere.
                    is WalletState.Connecting, is WalletState.Error -> Unit
                }
            }
        }
    }

    /**
     * The credentials a state carries, for the two states that carry any.
     *
     * `Ready` and `FlowActive` both hold a credential list and both mean the
     * keystore is unlocked; nothing else in [WalletState] does. Written as one
     * function so the DC API registry is fed from a single definition of
     * "presentable", rather than each call site deciding again.
     */
    private fun WalletState.credentialsOrEmpty(): List<StoredCredential> = when (this) {
        is WalletState.Ready -> credentials
        is WalletState.FlowActive -> credentials
        else -> emptyList()
    }

    /** Pending authorization flow ID (set when browser opens, consumed on redirect). */
    private var pendingAuthFlowId: String? = null

    // ── Presentation consent state ─────────────────────────────────

    private val _pendingPresentationRequest = MutableStateFlow<PresentationRequest?>(null)
    val pendingPresentationRequest: StateFlow<PresentationRequest?> = _pendingPresentationRequest

    private var presentationContinuation: kotlinx.coroutines.CancellableContinuation<List<Long>>? = null

    init {
        observeWalletState()
        setupEventListener()
    }

    private fun setupEventListener() {
        wallet.setEventListener(object : WalletEventListener {
            override suspend fun onCredentialSelectionRequired(
                request: PresentationRequest,
            ): List<Long> {
                // Show consent UI and suspend until user responds
                return kotlinx.coroutines.suspendCancellableCoroutine { cont ->
                    presentationContinuation = cont
                    _pendingPresentationRequest.value = request
                }
            }

            override fun onAuthorizationRequired(
                flowId: String,
                authorizationUrl: String,
                redirectUri: String,
                state: String,
            ) {
                Log.d(TAG, "Authorization required for flow $flowId")
                pendingAuthFlowId = flowId

                // The SDK already applies the urlRewriter from WalletConfig,
                // so authorizationUrl is the external URL ready for the browser.
                Log.d(TAG, "Opening browser: $authorizationUrl")
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(authorizationUrl))
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                activity.startActivity(intent)
            }

            override fun onTxCodeRequired(
                flowId: String,
                description: String?,
            ): String? {
                Log.i(TAG, "tx_code required for flow $flowId: $description")
                // Extract PIN from description (e.g. "Input the one-time code: <123456> for testing purposes")
                val match = Regex("<(\\d+)>").find(description ?: "")
                val pin = match?.groupValues?.get(1)
                if (pin != null) {
                    Log.i(TAG, "Auto-providing tx_code from description: $pin")
                    return pin
                }
                Log.w(TAG, "No tx_code found in description, cannot auto-respond")
                return null
            }

            override fun onFlowError(flowId: String, errorMessage: String, redirectUri: String?) {
                Log.e(TAG, "Flow $flowId failed: $errorMessage")
                if (pendingAuthFlowId == flowId) {
                    pendingAuthFlowId = null
                }
                receivedCredentialCount = 0
                _flowErrorDialog.value = FlowErrorInfo(errorMessage, canRetry = lastFlowRetry != null)

                // Mirrors onFlowComplete below - a verifier can return a
                // redirect_uri from its error-response endpoint too (e.g. on
                // user-decline), so the user isn't left stranded in the
                // wallet just because the flow ended in an error rather than
                // success.
                openVerifierRedirect(redirectUri)
            }

            override fun onCredentialReceived(credential: StoredCredential) {
                receivedCredentialCount++
            }

            override fun onFlowComplete(flowId: String, redirectUri: String?) {
                if (receivedCredentialCount > 0) {
                    _infoMessage.value = activity.getString(
                        R.string.flow_credentials_received,
                        receivedCredentialCount,
                    )
                    receivedCredentialCount = 0
                } else if ((wallet.state.value as? WalletState.FlowActive)?.flowType == "presentation") {
                    // onFlowComplete fires before the SDK transitions FlowActive -> Ready
                    // (see SirosWallet's handleFlowComplete/WMP onComplete), so flowType
                    // is still readable here. Issuance gets the credential-count message
                    // above; presentation has no analogous per-item count, so a plain
                    // confirmation is the equivalent "something happened" signal for a
                    // flow whose whole point is watching this screen after a QR scan.
                    _infoMessage.value = activity.getString(R.string.flow_presentation_sent)
                }

                // Some verifiers (e.g. verifier.multipaz.org) return a
                // redirect_uri with their direct_post.jwt response so the
                // user's browser can be sent back to the verifier's own
                // result page. Without this, the flow just silently ends
                // on the wallet side with no way back to the verifier.
                openVerifierRedirect(redirectUri)
            }
        })
    }

    /** Opens a verifier-provided redirect_uri (from flow completion or decline) in the browser. */
    private fun openVerifierRedirect(redirectUri: String?) {
        if (redirectUri == null) return
        Log.d(TAG, "Opening verifier redirect: $redirectUri")
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(redirectUri))
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        activity.startActivity(intent)
    }

    /** User consented to share selected credentials. */
    fun acceptPresentation(selectedIds: List<Long>) {
        _pendingPresentationRequest.value = null
        presentationContinuation?.resume(selectedIds, null)
        presentationContinuation = null
    }

    /** User declined the presentation request. */
    fun declinePresentation() {
        _pendingPresentationRequest.value = null
        presentationContinuation?.resume(emptyList(), null)
        presentationContinuation = null
    }

    /**
     * Handle an OAuth redirect from the browser.
     * Called by MainActivity when the deep-link classifier returns [DeepLinkType.AuthCallback].
     */
    fun handleAuthRedirect(code: String, state: String) {
        val flowId = pendingAuthFlowId

        if (flowId != null) {
            Log.i(TAG, "Auth redirect: code=${code.take(8)}..., state=${state.take(8)}...")
            pendingAuthFlowId = null
            wallet.completeAuthorization(flowId, code, state)
        } else {
            Log.e(TAG, "Auth redirect but no pending flow")
            _errorMessage.value = activity.getString(R.string.error_auth_failed)
        }
    }

    fun login(accountId: String? = null) {
        rebuildWalletIfNeeded()
        _isLoading.value = true
        viewModelScope.launch {
            try {
                wallet.login(accountId)
            } catch (e: Exception) {
                _errorMessage.value = localizedErrorMessage(e)
            } finally {
                _isLoading.value = false
            }
        }
    }

    fun register(displayName: String) {
        rebuildWalletIfNeeded()
        _isLoading.value = true
        viewModelScope.launch {
            try {
                wallet.register(displayName)
            } catch (e: Exception) {
                _errorMessage.value = localizedErrorMessage(e)
            } finally {
                _isLoading.value = false
            }
        }
    }

    fun startIssuance(credentialOfferUri: String) {
        viewModelScope.launch {
            try {
                wallet.startIssuance(credentialOfferUri)
            } catch (e: Exception) {
                Log.e(TAG, "startIssuance failed", e)
                _errorMessage.value = localizedErrorMessage(e)
            }
        }
    }

    fun startPresentation(requestUri: String) {
        viewModelScope.launch {
            try {
                wallet.startPresentation(requestUri)
            } catch (e: Exception) {
                Log.e(TAG, "startPresentation failed", e)
                _errorMessage.value = localizedErrorMessage(e)
            }
        }
    }

    /**
     * Auto-authenticate for testing/conformance only.
     * Only active in debug builds — production apps must require explicit user login.
     */
    private suspend fun ensureAuthenticatedForTesting() {
        if (!BuildConfig.DEBUG) return // No-op in release builds
        fun isConnectedState(state: WalletState): Boolean {
            return state is WalletState.Ready || state is WalletState.FlowActive
        }

        suspend fun waitForConnected(timeoutMs: Long = 15000): Boolean {
            val started = System.currentTimeMillis()
            while (System.currentTimeMillis() - started < timeoutMs) {
                if (isConnectedState(wallet.state.value)) return true
                delay(200)
            }
            return isConnectedState(wallet.state.value)
        }

        // Already connected? Done.
        if (isConnectedState(wallet.state.value)) return

        // If state is Connecting, wait briefly for it to finish.
        if (wallet.state.value is WalletState.Connecting) {
            if (waitForConnected()) return
        }

        // Rebuild wallet if in Error state so login/register start fresh.
        if (wallet.state.value is WalletState.Error) {
            rebuildWalletIfNeeded()
        }

        try {
            Log.i(TAG, "Automation auth: attempting login")
            wallet.login()
            if (waitForConnected()) return
            Log.w(TAG, "Automation auth: login returned but wallet not ready, trying register")
        } catch (e: Exception) {
            Log.w(TAG, "Automation auth: login failed (${e.message}), trying register")
        }

        // Rebuild if login left us in Error state.
        if (wallet.state.value is WalletState.Error) {
            rebuildWalletIfNeeded()
        }

        try {
            Log.i(TAG, "Automation auth: attempting register")
            wallet.register("Conformance User")
            if (waitForConnected()) return
        } catch (e: Exception) {
            Log.e(TAG, "Automation auth: register failed", e)
            throw e
        }

        if (!isConnectedState(wallet.state.value)) {
            throw IllegalStateException("Wallet not connected after auth (state=${wallet.state.value})")
        }
    }

    fun cancelCurrentFlow() {
        wallet.cancelCurrentFlow()
    }

    fun disconnect() {
        wallet.logout()
        _showAddCredential.value = false
        _availableCredentials.value = emptyList()
        // Navigation state must not survive the session it belongs to: left
        // set, the Devices sub-screen would be what the next login renders
        // instead of the wallet tabs.
        _showDevices.value = false
        _walletInstances.value = emptyList()
        _activateMode.value = null
    }

    /** Delete the current account - also removes it from the cached "Welcome back" list. */
    fun deleteAccount() {
        wallet.deleteAccount()
        _showAddCredential.value = false
        _availableCredentials.value = emptyList()
        _showDevices.value = false
        _walletInstances.value = emptyList()
        _activateMode.value = null
    }

    // ── Account & Passkey management ────────────────────────────────

    /** Remove a cached account from the local registry. */
    fun forgetAccount(accountId: String) {
        wallet.forgetAccount(accountId)
    }

    /** List passkeys registered for the current account. */
    fun listPasskeys(): List<org.siros.sdk.wallet.CachedPasskey> {
        return wallet.listPasskeys()
    }

    /** Rename a passkey's user-visible nickname. */
    fun renamePasskey(credentialId: String, nickname: String) {
        wallet.renamePasskey(credentialId, nickname)
    }

    /** Open the add-credential screen — fetches available offers from issuers. */
    fun openAddCredential() {
        _showAddCredential.value = true
        _isLoadingOffers.value = true
        viewModelScope.launch {
            try {
                // Filter out the plain "siros_id" offer: the "Scan Physical ID
                // card" row above the list (onStartIDV/startIDV()) is the one,
                // unified path to a SIROS ID credential - it drives real
                // FaceTec identity verification before issuance. Leaving the
                // no-questions-asked issuer offer alongside it would give the
                // user two competing, confusing routes to the same
                // credential, one of which silently skips verification.
                _availableCredentials.value = wallet.getAvailableCredentials()
                    .filterNot { it.credentialConfigurationId == SIROS_ID_CREDENTIAL_CONFIGURATION_ID }
                android.util.Log.d("SIROS_VM", "Available credentials: ${_availableCredentials.value.size}")
            } catch (e: Exception) {
                android.util.Log.e("SIROS_VM", "getAvailableCredentials failed", e)
                _availableCredentials.value = emptyList()
                _errorMessage.value = e.message ?: "Failed to load available credentials"
            } finally {
                _isLoadingOffers.value = false
            }
        }
    }

    /** Close the add-credential screen. */
    fun closeAddCredential() {
        _showAddCredential.value = false
    }

    /** User picked a credential to issue. */
    fun selectCredentialOffer(offer: CredentialOffer) {
        _pendingIssuanceOffer.value = offer
    }

    /** User confirmed the pending issuance offer. */
    fun confirmIssuance() {
        val offer = _pendingIssuanceOffer.value ?: return
        _pendingIssuanceOffer.value = null
        _showAddCredential.value = false
        startIssuanceByOffer(offer)
    }

    /**
     * Renew [credential]'s batch (credential re-issuance/renewal plan,
     * Phase 2, §4.4's silent-vs-user-facing design): try the silent
     * OID4VCI `refresh_token` grant first (no user interaction) via
     * [SirosWallet.renewCredential] - if a refresh_token was ever captured
     * for this batch and the issuer accepts it, this replaces the batch in
     * place with no visible flow at all. Only if that's unavailable (no
     * stored refresh_token) or fails does this fall back to the existing
     * full `authorization_code` re-issuance path (the issuer-browsing-free
     * flow this method used to always take), per ISSU_60's
     * graceful-retry requirement.
     *
     * The UI never distinguishes "silent refresh available" from "full
     * re-issuance only" up front - every renew affordance (detail-screen
     * icon, long-press menu, exhausted-credential overlay) is always shown
     * and always calls this same method, since the user has no way to know
     * in advance which path applies and showing two different actions would
     * only confuse them. [R.string.credential_renew_not_possible] is the
     * one remaining user-visible outcome, for the residual case where even
     * full re-issuance isn't possible (no known issuer/credential
     * configuration on file for this credential at all).
     */
    fun renewCredential(credential: StoredCredential) {
        viewModelScope.launch {
            try {
                wallet.renewCredential(credential.batchId)
                return@launch
            } catch (e: Exception) {
                Log.i(TAG, "Silent renewal unavailable/failed for batch ${credential.batchId}, falling back to full re-issuance", e)
            }
            val issuerId = credential.credentialIssuerIdentifier
            val configId = credential.credentialConfigurationId
            if (issuerId == null || configId == null) {
                _errorMessage.value = activity.getString(R.string.credential_renew_not_possible)
                return@launch
            }
            startIssuanceByOffer(
                CredentialOffer(
                    credentialConfigurationId = configId,
                    credentialIssuerIdentifier = issuerId,
                    credentialName = credential.metadata?.name ?: credential.format,
                    issuerName = credential.metadata?.issuer?.name ?: issuerId,
                ),
                replacesBatchId = credential.batchId,
            )
        }
    }

    private fun startIssuanceByOffer(offer: CredentialOffer, replacesBatchId: Long? = null) {
        lastFlowRetry = { startIssuanceByOffer(offer, replacesBatchId) }
        viewModelScope.launch {
            try {
                wallet.startIssuanceByOffer(offer, replacesBatchId)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start issuance for ${offer.credentialConfigurationId}", e)
                _errorMessage.value = e.message ?: "Failed to start issuance"
            }
        }
    }

    /** User cancelled the pending issuance offer. */
    fun cancelIssuance() {
        _pendingIssuanceOffer.value = null
    }

    // ── Identity Verification (FaceTec IDV) ─────────────────────────

    /** IDV server URL — defaults to facetec-api co-hosted with the backend. */
    val idvServerUrl: String get() = _backendUrl.value.trimEnd('/') + "/idv"

    fun startIDV() {
        _showAddCredential.value = false
        viewModelScope.launch {
            try {
                _isLoading.value = true
                val token = wallet.getAccessToken() // Auth token for facetec-api
                val delegate = org.siros.sdk.idv.facetec.FaceTecCaptureDelegate()
                val client = org.siros.sdk.idv.RemoteIDVClient(
                    org.siros.sdk.idv.RemoteIDVClient.Config(
                        serverUrl = idvServerUrl,
                        authToken = "Bearer $token",
                    )
                )
                val provider = org.siros.sdk.idv.RemoteIDVProvider(client, delegate)
                wallet.verifyIdentityAndIssue(provider, activity)
            } catch (e: Exception) {
                android.util.Log.e("SIROS_VM", "IDV failed", e)
                _errorMessage.value = e.message ?: "Identity verification failed"
            } finally {
                _isLoading.value = false
            }
        }
    }

    // ── Credential detail ───────────────────────────────────────────

    fun openCredentialDetail(credential: StoredCredential) {
        if (!_showCredentialDetails.value) return
        _selectedCredential.value = credential
    }

    fun closeCredentialDetail() {
        _selectedCredential.value = null
    }

    fun deleteCredential(credentialId: Long) {
        _selectedCredential.value = null
        viewModelScope.launch {
            try {
                wallet.deleteCredential(credentialId)
            } catch (e: Exception) {
                _errorMessage.value = e.message ?: "Delete failed"
            }
        }
    }

    // ── Presentation history ────────────────────────────────────────

    fun openHistory() {
        _presentationHistory.value = wallet.presentationHistory
        _showHistory.value = true
    }

    fun closeHistory() {
        _showHistory.value = false
    }

    // ── WSCD lifecycle ──────────────────────────────────────────────

    private val _lifecycleState = MutableStateFlow<LifecycleState?>(null)
    val lifecycleState: StateFlow<LifecycleState?> = _lifecycleState

    private val _enrollmentInProgress = MutableStateFlow(false)
    val enrollmentInProgress: StateFlow<Boolean> = _enrollmentInProgress

    /**
     * True while [enrollWscd]/[rotateLifecycle]/[destroyLifecycle] is in
     * flight - lets the WSCA Developer screen disable all three buttons
     * while any one of them is running. Without this, rapid re-tapping
     * (e.g. a user impatiently tapping Enroll again while a slow real CTAP2
     * ceremony is still awaiting a touch) launches overlapping coroutines
     * that interleave unpredictably - confirmed on real hardware producing
     * a burst of concurrent register/activate/destroy calls within the
     * same ~100ms window.
     */
    private val _wscdLifecycleBusy = MutableStateFlow(false)
    val wscdLifecycleBusy: StateFlow<Boolean> = _wscdLifecycleBusy

    /**
     * True once the user has entered their FIDO2 PIN (see
     * [awaitFido2PinEntry]) and the app is now waiting for them to actually
     * present the physical authenticator - i.e. hold a YubiKey against the
     * phone's NFC antenna, or plug/keep it plugged in over USB. Drives
     * [Fido2PresentKeyGuide]'s visual instructions.
     *
     * This split exists because holding an NFC key against the back of the
     * phone and typing a PIN on the touchscreen at the same time is not
     * physically possible with one hand free - the PIN must be collected
     * BEFORE the tap-and-hold begins, not mid-ceremony while the key is
     * already in place (see [awaitFido2PinEntry]'s doc comment for the full
     * rationale, confirmed against real hardware testing).
     */
    private val _fido2AwaitingPresentation = MutableStateFlow(false)
    val fido2AwaitingPresentation: StateFlow<Boolean> = _fido2AwaitingPresentation

    /** The currently in-flight enroll/rotate coroutine, if any - lets [cancelWscdLifecycleOp] abort it. */
    private var wscdLifecycleJob: kotlinx.coroutines.Job? = null

    /**
     * Abort the in-flight [enrollWscd]/[rotateLifecycle] operation, e.g. the
     * user backing out of [Fido2PresentKeyGuide] instead of presenting the
     * key. Cancelling the job still runs its `finally` block (resetting
     * [wscdLifecycleBusy]/[fido2AwaitingPresentation] and clearing
     * [prefetchedFido2Pin]), so this can't leave the screen stuck the way an
     * unbounded hang used to.
     */
    fun cancelWscdLifecycleOp() {
        wscdLifecycleJob?.cancel()
    }

    // ── WSCD auto-enroll offer ────────────────────────────────────────

    /** Which plugin ID (if any) is currently offering to auto-enroll - see [maybeOfferWscdAutoEnroll]. */
    private val _pendingAutoEnrollOffer = MutableStateFlow<String?>(null)
    val pendingAutoEnrollOffer: StateFlow<String?> = _pendingAutoEnrollOffer

    /**
     * Offered at most once per process - a user who dismisses it isn't
     * re-nagged every time [WalletState.Ready] re-emits (e.g. after a
     * token refresh), and one who accepts obviously doesn't need it again
     * once [enrollWscd] runs.
     */
    private var autoEnrollOffered = false

    /**
     * Checked every time the wallet becomes [WalletState.Ready] (i.e. right
     * after a successful login, and on later re-connects). If the login
     * credential's [org.siros.sdk.auth.WscdAutoEnrollHint] (see that
     * interface's doc comment) suggests this might be a WSCD-capable
     * device, that plugin is available in this session, and nothing is
     * enrolled for it yet, offers the user a one-tap prompt to enroll it -
     * see [respondToAutoEnrollOffer] for what accepting actually does.
     */
    private fun maybeOfferWscdAutoEnroll() {
        if (autoEnrollOffered) return
        viewModelScope.launch {
            val hint = wallet.wscdAutoEnrollHint() ?: return@launch
            if (!hint.suggestsWscdCapableDevice()) return@launch
            val pluginId = hint.hintedWscdPluginId
            if (pluginId !in _availableWscdPluginIds.value) return@launch
            if (wallet.wscdCredentials(pluginId) != null) return@launch
            autoEnrollOffered = true
            _pendingAutoEnrollOffer.value = pluginId
        }
    }

    /**
     * The user's answer to [pendingAutoEnrollOffer]. Accepting switches to
     * that plugin's tab (so [activePluginId]/[enrollWscd] resolve to it,
     * exactly as if the user had opened [WscdScreen] and picked it
     * themselves) and starts the normal enroll flow - same PIN-first +
     * present-key sequence as the manual Enroll button, since accepting
     * this offer is still only a HINT that the device supports signing;
     * the enrollment attempt itself is what actually confirms it.
     */
    fun respondToAutoEnrollOffer(accept: Boolean) {
        val pluginId = _pendingAutoEnrollOffer.value ?: return
        _pendingAutoEnrollOffer.value = null
        if (accept) {
            selectPlugin(pluginId)
            enrollWscd()
        }
    }

    /**
     * Stored reference to the UniFFISigner for diagnostic-only calls
     * ([UniFFISigner.listKeysDetailed]/[UniFFISigner.securityProperties])
     * that aren't part of the [WscdManager]/[org.siros.sdk.keystore.KeystoreManager]
     * surface at all - everything else (lifecycle, plugin registration)
     * goes through [wallet]'s own [SirosWallet.wscdManager].
     */
    private var wscdSigner: UniFFISigner? = null

    // buildWalletConfig() now builds a separate manager instance per plugin
    // ID (see availableKeystores) in addition to whichever one backs the
    // active `wscdSigner`/`wallet.wscdManager` - a single shared Boolean
    // here would make the FIRST manager instance's registration silently
    // suppress every later instance's, including the live one enrollWscd()
    // actually cares about. Tracked per manager INSTANCE (identity, not
    // equals) instead.
    private val r2psRegisteredManagers = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<WscdManager, Boolean>())

    /** Register the R2PS plugin on the given manager (idempotent per instance). */
    private fun registerR2psOnSigner(manager: WscdManager) {
        if (!r2psRegisteredManagers.add(manager)) return
        // Generate ephemeral P-256 key pair for the R2PS message envelope
        // (JWS/JWE identity) - required regardless of auth mode.
        val kpg = java.security.KeyPairGenerator.getInstance("EC")
        kpg.initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val clientKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
            android.util.Base64.encodeToString(kp.private.encoded, android.util.Base64.NO_WRAP)
                .chunked(64).joinToString("\n") +
            "\n-----END PRIVATE KEY-----"
        val serverPubPem = "-----BEGIN PUBLIC KEY-----\n" +
            android.util.Base64.encodeToString(kp.public.encoded, android.util.Base64.NO_WRAP)
                .chunked(64).joinToString("\n") +
            "\n-----END PUBLIC KEY-----"
        val r2psConfig = R2psConfig(
            serverUrl = _r2psServerUrl.value,
            clientId = "sample-app",
            context = "wallet",
            clientKeyPem = clientKeyPem,
            serverPublicKeyPem = serverPubPem,
            authMode = R2psAuthMode.Opaque,
        )
        manager.registerR2psPlugin(r2psConfig, OkHttpR2psTransport(serverUrl = _r2psServerUrl.value))
        Log.i(TAG, "R2PS plugin registered at ${_r2psServerUrl.value}")
    }

    /**
     * Register the FIDO2 previewSign plugin on the given manager with
     * whichever transport [_fido2TransportMode] currently selects -
     * re-registering if that differs from what's currently registered (see
     * [fido2RegisteredTransport]'s doc comment), or if [savedState] carries
     * key state this manager has not been given yet.
     *
     * Deliberately does NOT read [wallet]: it is called from
     * [buildWalletConfig]'s eager keystore construction, which runs inside
     * [wallet]'s own property initializer, before [wallet] exists. It used
     * to read `wallet.wscdCredentials("fido2")` here, and on a cold start
     * that threw an NPE which [buildWscdKeystore]'s try/catch turned into
     * "no fido2 keystore at all" - the plugin was not registered empty, it
     * was dropped from [WalletConfig.availableKeystores] entirely until the
     * next wallet rebuild. Saved key state is instead restored once there is
     * a logged-in wallet to read it from - see [restoreFido2PluginState] -
     * and callers that already hold it (e.g. [enrollWscd]) pass it in.
     *
     * @param savedState the privatedata-synced key state to restore (see
     *   [SirosWallet.wscdCredentials]), or null to register the plugin with
     *   no keys. Callers that generate a NEW key must re-save via
     *   [saveFido2PluginState] afterward - this function only restores.
     */
    private fun registerFido2OnSigner(manager: WscdManager, savedState: String? = null) = synchronized(fido2RegisteredTransport) {
        // The check-and-write on fido2RegisteredTransport must be atomic as
        // a whole, not just each individual map op (synchronizedMap already
        // makes those thread-safe on their own) - a genuine concurrent call
        // for the same manager could otherwise both see a stale "not yet
        // registered for this mode" result and both proceed to
        // re-register/create a fresh transport instance.
        val mode = _fido2TransportMode.value
        val restoring = savedState != null && manager !in fido2StateRestored
        if (fido2RegisteredTransport[manager] == mode && !restoring) return@synchronized
        val transport = when (mode) {
            Fido2TransportMode.AUTO -> CompositeCtap2Transport(
                UsbCtap2Transport(activity.applicationContext),
                NfcCtap2Transport(activity),
                ::requestTransportChoice,
            )
            Fido2TransportMode.USB -> UsbCtap2Transport(activity.applicationContext)
            Fido2TransportMode.NFC -> NfcCtap2Transport(activity)
        }
        if (savedState != null) {
            manager.registerFido2PluginWithState(transport, savedState.toByteArray(Charsets.UTF_8))
            fido2StateRestored.add(manager)
            Log.i(TAG, "FIDO2 previewSign plugin restored from saved state (transport=$mode)")
        } else {
            manager.registerFido2Plugin(transport)
            // A fresh plugin instance (this is a re-registration for a new
            // transport mode, or the very first one) holds no keys, whatever
            // the previous instance held - so a later restore pass must
            // treat this manager as not yet caught up.
            fido2StateRestored.remove(manager)
            Log.i(TAG, "FIDO2 previewSign plugin registered (transport=$mode)")
        }
        fido2RegisteredTransport[manager] = mode
    }

    /**
     * The FIDO2 key state persisted in privatedata for this account, or null
     * if there is none (or the wallet cannot be read right now - not logged
     * in, keystore locked). Never throws: a failed read must degrade to "no
     * keys to restore", exactly what a fresh account looks like.
     */
    private suspend fun savedFido2State(): String? = try {
        wallet.wscdCredentials("fido2")
    } catch (e: Exception) {
        Log.w(TAG, "Could not read saved FIDO2 plugin state", e)
        null
    }

    /**
     * Give every manager that has the FIDO2 plugin registered the key state
     * persisted in privatedata, once. Called whenever the wallet becomes
     * [WalletState.Ready] - the first moment privatedata is readable - so a
     * FIDO2 key enrolled in an earlier process, or on another device sharing
     * this account, is addressable in this one. Without this, every
     * credential bound to such a key looked like a "shadow" (key-unavailable)
     * credential after a cold start even though the key was never lost.
     */
    private fun restoreFido2PluginState() {
        viewModelScope.launch {
            val savedState = savedFido2State() ?: return@launch
            val pending = synchronized(fido2RegisteredTransport) {
                fido2RegisteredTransport.keys.filter { it !in fido2StateRestored }
            }
            pending.forEach { registerFido2OnSigner(it, savedState) }
        }
    }

    /**
     * Re-export the FIDO2 plugin's current key state and persist it via
     * privatedata (see [SirosWallet.saveWscdCredentials]), so keys
     * enrolled/generated in this process are addressable from any device
     * sharing this account. Must be called after any operation that could
     * have added a FIDO2 key - currently only [enrollWscd] does; real
     * credential issuance's own key generation
     * (`resolveEffectiveKeystoreForIssuance`/`generateKeypairs` in the SDK)
     * does NOT yet call this, so a FIDO2 key generated via that path - as
     * opposed to this dev screen's Enroll button - will NOT currently
     * survive a restart either. Fixing that needs an equivalent hook at
     * the SDK level, not here.
     */
    private suspend fun saveFido2PluginState(manager: WscdManager) {
        try {
            wallet.saveWscdCredentials("fido2", String(manager.exportFido2State(), Charsets.UTF_8))
            // What this manager holds IS now the saved state; a later
            // restore pass must not re-register it from an older copy.
            synchronized(fido2RegisteredTransport) { fido2StateRestored.add(manager) }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to save FIDO2 plugin state", e)
        }
    }

    /**
     * Enroll the WSCD: register + activate lifecycle.
     * Identity binding is handled separately via OID4VCI credential issuance
     * (deferred flow + key attestation), not at this layer.
     */
    fun enrollWscd() {
        if (_wscdLifecycleBusy.value) return
        _wscdLifecycleBusy.value = true
        _enrollmentInProgress.value = true
        wscdLifecycleJob = viewModelScope.launch {
            try {
                // Collect the FIDO2 PIN BEFORE touching the transport at all
                // - see _fido2AwaitingPresentation's doc comment for why
                // this can't happen mid-ceremony (the old behavior) without
                // forcing the user to set an NFC key down to type.
                if (activePluginId == "fido2") {
                    val pin = awaitFido2PinEntry()
                    if (pin == null) {
                        _errorMessage.value = "Enrollment cancelled"
                        return@launch
                    }
                    prefetchedFido2Pin = pin.toByteArray()
                    _fido2AwaitingPresentation.value = true
                }
                // A hard ceiling on the WHOLE operation, not just its
                // individual sub-steps: CompositeCtap2Transport's USB/NFC
                // race (and each transport's own internal waits) already
                // time out on their own, but a bug in any of that racing
                // logic could still hang indefinitely - confirmed on real
                // hardware (an NFC reconnect cascade left this coroutine
                // stuck, silently blocking every later Enroll/Rotate/Destroy
                // tap since wscdLifecycleBusy never got a chance to reset).
                // Without an outer bound here, that kind of hang is
                // unrecoverable without restarting the app.
                kotlinx.coroutines.withTimeout(WSCD_LIFECYCLE_OP_TIMEOUT_MS) {
                val manager = wallet.wscdManager
                if (manager == null) {
                    _errorMessage.value = "WSCD signer not initialized"
                    return@withTimeout
                }
                val pluginId = activePluginId
                // Lazily register R2PS plugin if switching at runtime
                if (pluginId == "r2ps") {
                    registerR2psOnSigner(manager)
                } else if (pluginId == "fido2") {
                    // With saved state, so the export after enrolment carries
                    // the keys already held for this account, not just the
                    // new one.
                    registerFido2OnSigner(manager, savedFido2State())
                }
                val contextId = lifecycleContextId
                val factorKind = when (pluginId) {
                    "r2ps" -> FactorKind.Opaque
                    else -> FactorKind.RawSign
                }

                val regOutcome = manager.registerLifecycle(
                    RegisterLifecycleRequest(
                        pluginId = pluginId,
                        contextId = contextId,
                        factorKind = factorKind,
                    ),
                )
                _lifecycleState.value = regOutcome.state
                Log.i(TAG, "Lifecycle registered: context=$contextId state=${regOutcome.state}")

                val actOutcome = manager.activateLifecycle(
                    ActivateLifecycleRequest(
                        pluginId = pluginId,
                        contextId = contextId,
                    ),
                )
                _lifecycleState.value = actOutcome.state
                Log.i(TAG, "Lifecycle activated: context=$contextId state=${actOutcome.state}")
                if (pluginId == "fido2") saveFido2PluginState(manager)
                Log.i(MainActivity.WSCA_TEST_TAG, """{"action":"enroll","status":"ok","state":"${actOutcome.state}","context_id":"$contextId"}""")
                }
            } catch (e: Exception) {
                Log.e(TAG, "WSCD enrollment failed", e)
                Log.e(MainActivity.WSCA_TEST_TAG, """{"action":"enroll","status":"error","error":"${e.message?.replace("\"", "'")}"}""")
                _errorMessage.value = if (e is kotlinx.coroutines.TimeoutCancellationException) {
                    "Enrollment timed out - no security key detected in time"
                } else {
                    "Enrollment failed: ${e.message}"
                }
            } finally {
                _enrollmentInProgress.value = false
                _wscdLifecycleBusy.value = false
                _fido2AwaitingPresentation.value = false
                prefetchedFido2Pin = null
            }
        }
    }

    // ── Devices screen state (wallet instance lifecycle, SID-AUTH-06) ──

    private val _showDevices = MutableStateFlow(false)
    val showDevices: StateFlow<Boolean> = _showDevices

    private val _walletInstances = MutableStateFlow<List<org.siros.sdk.auth.WalletInstance>>(emptyList())
    val walletInstances: StateFlow<List<org.siros.sdk.auth.WalletInstance>> = _walletInstances

    private val _devicesLoading = MutableStateFlow(false)
    val devicesLoading: StateFlow<Boolean> = _devicesLoading

    /** The instance whose status write is in flight, so its row can show a spinner. */
    private val _devicesBusyInstanceId = MutableStateFlow<String?>(null)
    val devicesBusyInstanceId: StateFlow<String?> = _devicesBusyInstanceId

    private val _devicesError = MutableStateFlow<String?>(null)
    val devicesError: StateFlow<String?> = _devicesError

    private val _deactivating = MutableStateFlow(false)
    val deactivating: StateFlow<Boolean> = _deactivating

    /**
     * What the last `deactivateWallet` call reported. Kept so the screen can
     * say whether the backend confirmed the erasure - an incomplete one still
     * deactivated the wallet, but leaves residual server-side data for an
     * administrator, and the user should be told which of the two happened.
     */
    private val _deactivationOutcome = MutableStateFlow<org.siros.sdk.auth.DeactivationOutcome?>(null)
    val deactivationOutcome: StateFlow<org.siros.sdk.auth.DeactivationOutcome?> = _deactivationOutcome

    fun openDevices() {
        _showDevices.value = true
        _deactivationOutcome.value = null
        refreshDevices()
    }

    fun closeDevices() {
        _showDevices.value = false
        _devicesError.value = null
    }

    fun refreshDevices() {
        viewModelScope.launch { loadDevices() }
    }

    /**
     * The listing itself. Suspending rather than launching, so a caller that
     * must not re-enable its buttons until the list is current (see
     * [setWalletInstanceStatus]) can await it in the same coroutine - a
     * fire-and-forget refresh would let a second status write start against a
     * list still showing the pre-write state, and the two refreshes could then
     * land out of order.
     */
    private suspend fun loadDevices() {
        _devicesLoading.value = true
        _devicesError.value = null
        try {
            _walletInstances.value = wallet.listWalletInstances()
        } catch (e: Exception) {
            Log.w(TAG, "listWalletInstances failed", e)
            _devicesError.value = localizedErrorMessage(e)
        } finally {
            _devicesLoading.value = false
        }
    }

    /**
     * Suspend, reactivate or revoke one instance. The SDK re-logs in after the
     * write (the change cuts this session's tokens off), so when the target is
     * this device the wallet may land in [WalletState.LifecycleBlocked] and
     * this screen disappears behind the blocked login screen - which is the
     * truthful outcome, not an error to report here.
     */
    fun setWalletInstanceStatus(
        instanceId: String,
        status: org.siros.sdk.auth.WalletInstanceStatus,
        reason: String? = null,
    ) {
        viewModelScope.launch {
            _devicesBusyInstanceId.value = instanceId
            _devicesError.value = null
            try {
                wallet.setWalletInstanceStatus(instanceId, status, reason)
                loadDevices()
            } catch (e: Exception) {
                Log.w(TAG, "setWalletInstanceStatus failed", e)
                _devicesError.value = localizedErrorMessage(e)
            } finally {
                _devicesBusyInstanceId.value = null
            }
        }
    }

    /**
     * Deactivate the wallet. The SDK forgets the local account in both
     * outcomes (the revocations stand even when the erasure cascade did not
     * finish), so this screen closes either way and the result is kept only to
     * be shown once before it does.
     */
    fun deactivateWallet(reason: String? = null) {
        viewModelScope.launch {
            _deactivating.value = true
            _devicesError.value = null
            try {
                val outcome = wallet.deactivateWallet(reason)
                _deactivationOutcome.value = outcome
                _walletInstances.value = emptyList()
                _showAddCredential.value = false
                _availableCredentials.value = emptyList()
                _showDevices.value = false
                // deactivateWallet also forgets the account and logs out, so
                // this screen is gone by the next recomposition. Report the
                // outcome through the app-wide banner instead, which the login
                // screen renders too - otherwise a user who deactivated with
                // an unfinished erasure would never learn that their provider
                // still has cleanup to do.
                if (outcome.complete) {
                    _infoMessage.value =
                        activity.getString(R.string.devices_deactivate_complete, outcome.revoked)
                } else {
                    _errorMessage.value =
                        activity.getString(R.string.devices_deactivate_incomplete, outcome.revoked)
                }
            } catch (e: Exception) {
                Log.e(TAG, "deactivateWallet failed", e)
                _devicesError.value = localizedErrorMessage(e)
            } finally {
                _deactivating.value = false
            }
        }
    }

    // ── WSCA developer screen state ─────────────────────────────────

    private val _showWscaDeveloper = MutableStateFlow(false)
    val showWscaDeveloper: StateFlow<Boolean> = _showWscaDeveloper

    private val _wscdKeys = MutableStateFlow<List<DetailedKeyInfo>>(emptyList())
    val wscdKeys: StateFlow<List<DetailedKeyInfo>> = _wscdKeys

    private val _wscdKeySecurityProps = MutableStateFlow<Map<String, SignerSecurityProperties>>(emptyMap())
    val wscdKeySecurityProps: StateFlow<Map<String, SignerSecurityProperties>> = _wscdKeySecurityProps

    private val _wscdLifecycleStatus = MutableStateFlow<LifecycleStatus?>(null)
    val wscdLifecycleStatus: StateFlow<LifecycleStatus?> = _wscdLifecycleStatus

    /**
     * The context ID used for this plugin's lifecycle session - fixed and
     * deterministic per plugin (not a fresh timestamp-based ID per enroll,
     * as this used to generate), so it never needs its own persistence:
     * any process, on any device sharing this account, can recompute the
     * exact same context ID a restored key was registered under.
     * `register_lifecycle`'s Rust implementation overwrites this context's
     * entry on every call, so re-enrolling under the same ID (e.g.
     * destroy -> enroll again) is exactly the intended "one active
     * enrollment per plugin" flow this dev screen models - it does not
     * accumulate multiple simultaneous enrollments per plugin.
     */
    private val lifecycleContextId: String
        get() = "ctx-$activePluginId"

    /** The plugin ID used for the current lifecycle session. */
    private val activePluginId: String
        get() = _selectedPluginId.value

    fun openWscaDeveloper() {
        _showWscaDeveloper.value = true
        refreshWscdInfo()
    }

    fun closeWscaDeveloper() {
        _showWscaDeveloper.value = false
    }

    fun refreshWscdInfo() {
        viewModelScope.launch {
            val signer = wscdSigner
            if (signer != null) {
                try {
                    val keys = signer.listKeysDetailed()
                    _wscdKeys.value = keys
                    val props = mutableMapOf<String, SignerSecurityProperties>()
                    for (key in keys) {
                        try {
                            props[key.keyId] = signer.securityProperties(key.keyId)
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to get security properties for ${key.keyId}", e)
                        }
                    }
                    _wscdKeySecurityProps.value = props
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to list keys", e)
                }
            }
            val manager = wallet.wscdManager ?: return@launch
            // lifecycleContextId is now deterministic per plugin (see its
            // own doc comment) and PreviewSignPlugin::from_state restores
            // the plugin's lifecycle map, not just its keys - so this call
            // correctly reflects "not enrolled" for a plugin with no
            // lifecycle context yet, and "Active" for a restored one,
            // without needing to derive anything from listKeys() here.
            try {
                _wscdLifecycleStatus.value = manager.lifecycleStatus(activePluginId, lifecycleContextId)
                _lifecycleState.value = _wscdLifecycleStatus.value?.state
            } catch (e: Exception) {
                Log.w(TAG, "Failed to get lifecycle status", e)
            }
        }
    }

    // ── WSCD selection policy (WscdSelectionPolicy) ──────────────────

    /**
     * The active account's persisted WSCD TOFU mapping (see
     * [org.siros.sdk.wallet.WscdSelectionPolicy]) - `"issuer|credentialType"`
     * -> plugin ID - for the Settings tab. Refreshed explicitly (see
     * [refreshWscdTofuMapping]), same pattern as [wscdKeys]/[refreshWscdInfo]:
     * there's no reactive change stream for this SDK-internal state, only
     * discrete points where the host app knows it may have changed.
     */
    private val _wscdTofuMapping = MutableStateFlow<Map<String, String>>(emptyMap())
    val wscdTofuMapping: StateFlow<Map<String, String>> = _wscdTofuMapping

    fun refreshWscdTofuMapping() {
        _wscdTofuMapping.value = wallet.wscdTofuMapping()
    }

    /** "Forget this choice" - clears one persisted TOFU entry and refreshes. */
    fun forgetWscdTofuMapping(issuer: String, credentialType: String) {
        wallet.clearWscdTofuMapping(issuer, credentialType)
        refreshWscdTofuMapping()
    }

    /** "Forget all choices" - clears every persisted TOFU entry and refreshes. */
    fun forgetAllWscdTofuMappings() {
        wallet.clearAllWscdTofuMappings()
        refreshWscdTofuMapping()
    }

    /**
     * The active account's explicit user overrides (see
     * [org.siros.sdk.wallet.WscdSelectionPolicy]'s doc comment on the
     * distinction from TOFU): [_wscdGlobalOverride] is the single "always use
     * this plugin, every issuer" preference,
     * [_wscdUserOverrides] is the `"issuer|credentialType"` -> plugin ID map
     * of per-issuer overrides. Refreshed the same way as [_wscdTofuMapping]
     * (see [refreshWscdTofuMapping]'s doc comment) - no reactive change
     * stream, only discrete points where the host app knows it may have
     * changed.
     */
    private val _wscdGlobalOverride = MutableStateFlow<String?>(null)
    val wscdGlobalOverride: StateFlow<String?> = _wscdGlobalOverride

    private val _wscdUserOverrides = MutableStateFlow<Map<String, String>>(emptyMap())
    val wscdUserOverrides: StateFlow<Map<String, String>> = _wscdUserOverrides

    fun refreshWscdUserOverrides() {
        _wscdGlobalOverride.value = wallet.currentGlobalUserOverride()
        _wscdUserOverrides.value = wallet.currentUserOverrides()
        // Seed the initially-shown WSCD tab from the user's persisted
        // preference - but only the first time this session learns it, so
        // later refreshes (e.g. a reconnect) don't yank the user back to
        // their preferred tab while they're deliberately looking at another
        // one. See _selectedPluginId's doc comment for why this can't
        // happen any earlier (no wallet/account exists yet at that point).
        if (!initialPluginTabSeeded) {
            initialPluginTabSeeded = true
            _wscdGlobalOverride.value?.let { _selectedPluginId.value = it }
        }
    }

    /** Set (or, with `pluginId = null`, clear) the single global user override and refresh. */
    fun setWscdGlobalOverride(pluginId: String?) {
        if (pluginId != null) wallet.setGlobalUserOverride(pluginId) else wallet.clearGlobalUserOverride()
        refreshWscdUserOverrides()
    }

    /** Set a per-(issuer, credentialType) user override and refresh. */
    fun setWscdUserOverride(issuer: String, credentialType: String, pluginId: String) {
        wallet.setUserOverride(issuer, credentialType, pluginId)
        refreshWscdUserOverrides()
    }

    /** Clear one per-(issuer, credentialType) user override and refresh. */
    fun clearWscdUserOverride(issuer: String, credentialType: String) {
        wallet.clearUserOverride(issuer, credentialType)
        refreshWscdUserOverrides()
    }

    private val _pendingWscdChoice = MutableStateFlow<PendingWscdChoice?>(null)
    val pendingWscdChoice: StateFlow<PendingWscdChoice?> = _pendingWscdChoice

    /**
     * The user's answer to the current [pendingWscdChoice] dialog, or
     * cancellation if `pluginId` is null (in which case `rememberScope` is
     * ignored). See [RememberScope]'s doc comment for what each scope does.
     */
    fun respondToWscdChoice(pluginId: String?, rememberScope: RememberScope = RememberScope.THIS_ISSUER) {
        _pendingWscdChoice.value?.respond?.invoke(pluginId, rememberScope)
    }

    /**
     * Bridges [org.siros.sdk.wallet.WscdSelectionPolicy]'s suspending
     * "ask the host app which plugin to use" callback to a Compose dialog,
     * via [_pendingWscdChoice] - exactly [ProximityEngagementScreen]'s
     * `requestConsent` pattern (suspend, publish state, resume on the
     * user's answer), just wired at [WalletConfig] construction time
     * instead of from inside a screen Composable, since this callback must
     * exist before [SirosWallet.create] is even called.
     */
    private val requestWscdChoice: RequestWscdChoice = { issuer, credentialType, eligiblePluginIds ->
        withContext(Dispatchers.Main.immediate) {
            suspendCancellableCoroutine { continuation ->
                val pending = PendingWscdChoice(
                    issuer = issuer,
                    credentialType = credentialType,
                    eligiblePluginIds = eligiblePluginIds,
                    respond = { pluginId, rememberScope ->
                        _pendingWscdChoice.value = null
                        if (continuation.isActive) {
                            continuation.resume(
                                if (pluginId != null) {
                                    WscdChoiceResult.Chosen(pluginId, rememberScope)
                                } else {
                                    WscdChoiceResult.Cancelled
                                },
                                onCancellation = null,
                            )
                        }
                    },
                )
                _pendingWscdChoice.value = pending
                continuation.invokeOnCancellation {
                    if (_pendingWscdChoice.value === pending) _pendingWscdChoice.value = null
                }
            }
        }
    }

    private val _pendingTransportChoice = MutableStateFlow<PendingTransportChoice?>(null)
    val pendingTransportChoice: StateFlow<PendingTransportChoice?> = _pendingTransportChoice

    /** The user's answer to the current [pendingTransportChoice] dialog, or cancellation if `mode` is null. */
    fun respondToTransportChoice(mode: Fido2TransportMode?) {
        _pendingTransportChoice.value?.respond?.invoke(mode)
    }

    /**
     * Bridges [CompositeCtap2Transport]'s "ask which transport to use"
     * callback to a Compose dialog - same suspend/publish/resume shape as
     * [requestWscdChoice]/[PendingPinEntry].
     */
    private suspend fun requestTransportChoice(): Fido2TransportMode? =
        withContext(Dispatchers.Main.immediate) {
            suspendCancellableCoroutine { continuation ->
                val pending = PendingTransportChoice { mode ->
                    _pendingTransportChoice.value = null
                    if (continuation.isActive) continuation.resume(mode, onCancellation = null)
                }
                _pendingTransportChoice.value = pending
                continuation.invokeOnCancellation {
                    if (_pendingTransportChoice.value === pending) _pendingTransportChoice.value = null
                }
            }
        }

    private val _pendingPinEntry = MutableStateFlow<PendingPinEntry?>(null)
    val pendingPinEntry: StateFlow<PendingPinEntry?> = _pendingPinEntry

    /** The user's answer to the current [pendingPinEntry] dialog, or cancellation if `pin` is null. */
    fun respondToPinEntry(pin: String?) {
        _pendingPinEntry.value?.respond?.invoke(pin)
    }

    /**
     * Show the PIN dialog and suspend until the user submits or cancels -
     * the real suspend-native version of this bridge, usable directly from
     * a coroutine (unlike [requestFido2Pin], which must block a non-Main
     * thread since it's called synchronously from Rust's FFI callback).
     *
     * Called from [enrollWscd]/[rotateLifecycle] BEFORE any transport work
     * starts, so the PIN is already known by the time the user needs to
     * present the physical authenticator - see [_fido2AwaitingPresentation]'s
     * doc comment for why this ordering matters: entering a PIN needs the
     * touchscreen, but holding an NFC key against the phone needs both
     * hands, and the CTAP2 ceremony needs one continuous physical session
     * once it starts. Asking for the PIN mid-ceremony (the old behavior)
     * forced the user to set the key down to type, which could drop the
     * NFC session entirely.
     */
    private suspend fun awaitFido2PinEntry(): String? = withContext(Dispatchers.Main.immediate) {
        suspendCancellableCoroutine { continuation ->
            val pending = PendingPinEntry(
                pluginId = "fido2",
                respond = { pin ->
                    _pendingPinEntry.value = null
                    if (continuation.isActive) {
                        continuation.resume(pin, onCancellation = null)
                    }
                },
            )
            _pendingPinEntry.value = pending
            continuation.invokeOnCancellation {
                if (_pendingPinEntry.value === pending) _pendingPinEntry.value = null
            }
        }
    }

    /**
     * Cached by [enrollWscd]/[rotateLifecycle] right after
     * [awaitFido2PinEntry] resolves, so [requestFido2Pin] - called from
     * Rust's FFI thread mid-ceremony - can return it immediately instead of
     * popping the dialog again while the user is physically holding the key
     * in place. Cleared in the `finally` block of whichever operation set
     * it, so a PIN never outlives the one operation it was collected for.
     */
    @Volatile
    private var prefetchedFido2Pin: ByteArray? = null

    /**
     * Bridges [org.siros.sdk.keystore.AuthProvider.requestPin] (synchronous,
     * called off the main thread - see [PendingPinEntry]'s doc comment) to
     * a Compose dialog, via [_pendingPinEntry]. `runBlocking` here is safe
     * for the same reason it's safe in [Ctap2TransportBridge].
     *
     * Prefers [prefetchedFido2Pin] when set (the normal case for
     * [enrollWscd]/[rotateLifecycle], which prefetch it up front - see that
     * field's doc comment) so this returns instantly without ever showing a
     * dialog mid-ceremony. Falls back to the blocking dialog for any call
     * path that didn't prefetch (e.g. a FIDO2 signature requested during
     * real credential presentation, outside the dev-screen flows).
     */
    private fun requestFido2Pin(): ByteArray {
        prefetchedFido2Pin?.let { return it }
        return kotlinx.coroutines.runBlocking(Dispatchers.Main.immediate) {
            val pin = awaitFido2PinEntry()
            pin ?: throw RuntimeException("PIN entry cancelled")
        }.toByteArray()
    }

    /**
     * Emit WSCA status as structured JSON to logcat for test automation.
     * The test harness parses lines with tag [MainActivity.WSCA_TEST_TAG].
     */
    fun emitWscaTestStatus() {
        viewModelScope.launch {
            val signer = wscdSigner
            val state = _lifecycleState.value?.name ?: "null"
            val ctxId = lifecycleContextId
            val plugin = activePluginId
            val keys = try {
                signer?.listKeysDetailed()?.joinToString(",") { k ->
                    """{"kid":"${k.keyId}","alg":"${k.algorithm}","plugin":"${k.pluginId}","created":${k.createdAt}}"""
                } ?: ""
            } catch (_: Exception) { "" }
            val json = """{"action":"status","state":"$state","context_id":"$ctxId","plugin":"$plugin","r2ps_enabled":${_r2psEnabled.value},"keys":[$keys]}"""
            Log.i(MainActivity.WSCA_TEST_TAG, json)
        }
    }

    fun rotateLifecycle() {
        if (_wscdLifecycleBusy.value) return
        _wscdLifecycleBusy.value = true
        wscdLifecycleJob = viewModelScope.launch {
            try {
                // See enrollWscd's identical prefetch step for why the PIN
                // must be collected before any transport work starts.
                if (activePluginId == "fido2") {
                    val pin = awaitFido2PinEntry()
                    if (pin == null) {
                        _errorMessage.value = "Rotation cancelled"
                        return@launch
                    }
                    prefetchedFido2Pin = pin.toByteArray()
                    _fido2AwaitingPresentation.value = true
                }
                kotlinx.coroutines.withTimeout(WSCD_LIFECYCLE_OP_TIMEOUT_MS) {
                val manager = wallet.wscdManager
                val ctxId = lifecycleContextId
                if (manager == null) {
                    _errorMessage.value = "WSCD not enrolled"
                    Log.e(MainActivity.WSCA_TEST_TAG, """{"action":"rotate","status":"error","error":"WSCD not enrolled (manager=false)"}""")
                    return@withTimeout
                }
                val outcome = manager.rotateLifecycle(
                    RotateLifecycleRequest(
                        pluginId = activePluginId,
                        contextId = ctxId,
                    ),
                )
                _lifecycleState.value = outcome.state
                Log.i(TAG, "Lifecycle rotated: context=$ctxId state=${outcome.state}")
                Log.i(MainActivity.WSCA_TEST_TAG, """{"action":"rotate","status":"ok","state":"${outcome.state}","context_id":"$ctxId"}""")
                refreshWscdInfo()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Lifecycle rotation failed", e)
                Log.e(MainActivity.WSCA_TEST_TAG, """{"action":"rotate","status":"error","error":"${e.message?.replace("\"", "'")}"}""")
                _errorMessage.value = if (e is kotlinx.coroutines.TimeoutCancellationException) {
                    "Rotation timed out - no security key detected in time"
                } else {
                    "Rotation failed: ${e.message}"
                }
            } finally {
                _wscdLifecycleBusy.value = false
                _fido2AwaitingPresentation.value = false
                prefetchedFido2Pin = null
            }
        }
    }

    // There's deliberately only one Destroy action exposed to callers. The
    // old LocalOnly/RemoteRevokeIfSupported split as two separate UI buttons
    // was confusing (for the fido2 plugin they currently behave identically
    // - see preview_sign.rs's destroy_lifecycle, which never reads
    // request.mode) and put a decision on the user that's really the
    // plugin's to make. Always requesting RemoteRevokeIfSupported lets each
    // plugin's own destroy_lifecycle hook decide whether there's any remote
    // side effect to attempt (r2ps.rs does; preview_sign.rs is a local-only
    // no-op) without the caller needing to know which.
    fun destroyLifecycle() {
        if (_wscdLifecycleBusy.value) return
        _wscdLifecycleBusy.value = true
        viewModelScope.launch {
            try {
                kotlinx.coroutines.withTimeout(WSCD_LIFECYCLE_OP_TIMEOUT_MS) {
                val manager = wallet.wscdManager
                val ctxId = lifecycleContextId
                if (manager == null) {
                    _errorMessage.value = "WSCD not enrolled"
                    Log.e(MainActivity.WSCA_TEST_TAG, """{"action":"destroy","status":"error","error":"WSCD not enrolled (manager=false)"}""")
                    return@withTimeout
                }
                val outcome = manager.destroyLifecycle(
                    DestroyLifecycleRequest(
                        pluginId = activePluginId,
                        contextId = ctxId,
                        mode = DestroyMode.RemoteRevokeIfSupported,
                    ),
                )
                _lifecycleState.value = outcome.state
                Log.i(TAG, "Lifecycle destroyed: state=${outcome.state} remotePerformed=${outcome.remotePerformed}")
                Log.i(MainActivity.WSCA_TEST_TAG, """{"action":"destroy","status":"ok","state":"${outcome.state}","remote_performed":"${outcome.remotePerformed}"}""")
                refreshWscdInfo()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Lifecycle destruction failed", e)
                Log.e(MainActivity.WSCA_TEST_TAG, """{"action":"destroy","status":"error","error":"${e.message?.replace("\"", "'")}"}""")
                _errorMessage.value = if (e is kotlinx.coroutines.TimeoutCancellationException) {
                    "Destruction timed out"
                } else {
                    "Destruction failed: ${e.message}"
                }
            } finally {
                _wscdLifecycleBusy.value = false
            }
        }
    }

    // ── QR scanner ──────────────────────────────────────────────────

    fun handleQrResult(uri: String) {
        closeActivate()
        lastFlowRetry = { handleQrResult(uri) }

        // Classification is pure/synchronous (see DeepLinkClassifier.kt), so it's
        // safe to resolve up front and reuse below rather than re-classifying
        // inside the coroutine - that also lets us set the right "starting…"
        // copy (issuance vs. presentation) immediately, in the same frame the
        // scanner closes, instead of only after the network work below begins.
        val link = classifyDeepLink(uri, REDIRECT_SCHEME)
        _flowStarting.value = when (link) {
            is DeepLinkType.CredentialOffer -> "issuance"
            // PresentationRequest, Unknown (fallback below treats it as a
            // presentation attempt), and AuthCallback (not reachable from a QR
            // scan in practice) all get the same generic "verifier" copy.
            else -> "presentation"
        }

        flowStartJob = viewModelScope.launch {
            try {
                val jUri = try { java.net.URI(uri) } catch (_: Exception) { null }
                Log.i(TAG, "handleQrResult: ${jUri?.scheme}://${jUri?.host}")
                ensureAuthenticatedForTesting()
                when (link) {
                    is DeepLinkType.CredentialOffer -> {
                        Log.i(TAG, "Routing to issuance")
                        // Everything from here through the engine actually reporting
                        // back (resolving display metadata, VCTM, client attestation -
                        // see SirosWallet.startIssuance) can be slow against a real
                        // issuer; _flowStarting stays visible until observeWalletState
                        // sees the resulting FlowActive/Error come through.
                        wallet.startIssuance(link.uri)
                    }
                    is DeepLinkType.PresentationRequest -> {
                        Log.i(TAG, "Routing to presentation")
                        wallet.startPresentation(link.uri)
                    }
                    else -> {
                        // Fallback: treat unclassified URIs as presentation requests
                        // (covers plain https://...?request_uri= patterns from QR codes)
                        Log.i(TAG, "Routing to presentation (unclassified)")
                        wallet.startPresentation(uri)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "QR/deep-link flow failed", e)
                _errorMessage.value = e.message ?: "QR flow failed"
                _flowStarting.value = null
            }
        }
    }

    /**
     * Rebuild the SirosWallet instance if the user changed the
     * backend URL or tenant ID since the last creation.
     */
    private fun rebuildWalletIfNeeded() {
        val current = wallet
        val currentState = current.state.value
        if (currentState is WalletState.Disconnected || currentState is WalletState.Error) {
            current.destroy()
            wallet = SirosWallet.create(
                activity,
                buildWalletConfig(),
            ).also { it.credentialConsumptionPolicy = _credentialConsumptionPolicy.value }
            observeWalletState()
            setupEventListener()
        }
    }

    /**
     * Builds a WSCD-backed [org.siros.sdk.keystore.KeystoreManager] for
     * [pluginId] - the same `UniFFISigner`/`FfiWscdConfig` construction
     * [buildWalletConfig] always used for its single `keystore` field,
     * extracted so [WalletConfig.availableKeystores] can offer more than one
     * plugin without duplicating this logic. [trackAsDiagnosticSigner]
     * should be `true` only for the plugin this call site treats as the
     * session's "current" one - [wscdSigner] backs the WSCA Developer
     * screen's diagnostics ([refreshWscdInfo]) and [enrollWscd]'s lifecycle
     * calls, both of which only make sense for a single active plugin at a
     * time.
     */
    private fun buildWscdKeystore(pluginId: String, trackAsDiagnosticSigner: Boolean): org.siros.sdk.keystore.KeystoreManager? =
        try {
            val wscdConfig = FfiWscdConfig(defaultPlugin = pluginId)
            val signer = UniFFISigner(
                wscdConfig,
                authProvider = object : AuthProvider {
                    override fun requestPin(pluginId: String): ByteArray {
                        // Dispatches on the FFI-supplied `pluginId` - the
                        // authoritative signal for which plugin this
                        // particular call is actually for. Previously this
                        // guessed from `activePluginId` (the dev-screen's
                        // currently-selected tab), which has nothing to do
                        // with which plugin a real credential-issuance
                        // operation is using: confirmed via live hardware
                        // testing, real FIDO2 issuance silently sent the
                        // fixed R2PS test PIN ("test-pin-1234", 13 bytes) to
                        // the authenticator because the dev-screen tab
                        // happened to be on something else - the
                        // authenticator correctly rejected it as
                        // PIN_INVALID every time, with nothing indicating
                        // why the wrong PIN kept getting sent.
                        return when (pluginId) {
                            "fido2" -> requestFido2Pin()
                            else -> "test-pin-1234".toByteArray()
                        }
                    }
                    override fun requestWebauthnAssertion(
                        pluginId: String,
                        challenge: ByteArray,
                        rpId: String,
                        allowedCredentials: List<ByteArray>,
                    ): ByteArray {
                        throw RuntimeException("WebAuthn assertion not implemented in sample app")
                    }
                },
            )
            if (pluginId == "r2ps") {
                registerR2psOnSigner(signer)
            } else if (pluginId == "fido2") {
                registerFido2OnSigner(signer)
            }
            Log.i(TAG, "WSCD keystore initialized with plugin: $pluginId")
            if (trackAsDiagnosticSigner) wscdSigner = signer
            WscdKeystoreAdapter(signer)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to initialize WSCD keystore for plugin $pluginId, falling back to default", e)
            null
        }

    private fun buildWalletConfig(): WalletConfig {
        val proxyUrl = BuildConfig.ISSUER_PROXY_URL
        // Disable user-auth-bound keys on emulators/Waydroid where the lock screen
        // cannot be reliably unlocked via ADB.
        val isEmulator = Build.FINGERPRINT.contains("generic") ||
            Build.PRODUCT.contains("sdk") ||
            Build.MODEL.contains("Emulator") ||
            Build.HARDWARE == "ranchu" ||
            Build.MANUFACTURER.equals("waydroid", ignoreCase = true) ||
            Build.BRAND == "google" && Build.DEVICE?.startsWith("generic") == true

        // Build WSCD-backed keystore with the selected plugin
        val selectedPlugin = _selectedPluginId.value
        val keystore = buildWscdKeystore(selectedPlugin, trackAsDiagnosticSigner = true)

        // Every known plugin this session can actually back, keyed by plugin
        // ID, for WalletConfig.availableKeystores - lets WscdSelectionPolicy
        // pick among them by required tier instead of always using the
        // single `keystore` above. Each is unconditionally offered here, not
        // only once the user has separately "enrolled" it via the WSCA
        // Developer screen: registering a plugin (UsbCtap2Transport,
        // OkHttpR2psTransport) is side-effect-free until it's actually asked
        // to sign, so there's no reason to withhold it from
        // WscdSelectionPolicy's auto-pick logic - only fido2/r2ps hardware
        // itself needs to be present at actual signing time. The currently
        // selected plugin (if it initialized successfully) reuses the EXACT
        // SAME instance as `keystore` above (not a second copy), both so it
        // isn't built/registered twice and so SirosWallet's
        // `currentDefaultPluginId` lookup (`=== keystore`) still recognizes it.
        val availableKeystores = buildMap {
            if (keystore != null) put(selectedPlugin, keystore)
            listOfNotNull("softkey", "fido2", if (_r2psEnabled.value) "r2ps" else null)
                .filter { it != selectedPlugin }
                .forEach { pluginId ->
                    buildWscdKeystore(pluginId, trackAsDiagnosticSigner = false)?.let { put(pluginId, it) }
                }
        }
        _availableWscdPluginIds.value = availableKeystores.keys.sorted()

        // 0/unset = disabled (default) - a real cloud project number is tied
        // to the host app's own Play Console/Firebase project and can't be
        // hardcoded into the SDK or sample app; native attestation simply
        // stays off (matching pre-native-attestation behavior) until one is
        // supplied.
        val playIntegrityCloudProjectNumber = BuildConfig.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER
        val nativeAttestationProvider = if (playIntegrityCloudProjectNumber != 0L) {
            PlayIntegrityProvider(activity, playIntegrityCloudProjectNumber)
        } else {
            null
        }

        return WalletConfig(
            backendUrl = _backendUrl.value,
            tenantId = _tenantId.value,
            zkCircuitUrls = _zkCircuitUrls.value,
            // Explicit override > derived from backendUrl (see resolvedEngineUrl())
            engineUrl = resolvedEngineUrl(),
            useWmpProtocol = _useWmpProtocol.value,
            redirectUri = REDIRECT_URI,
            // Emulators/Waydroid don't reliably have a working Credential Manager
            // passkey provider - fall back to the local KeyStore-backed provider there.
            useSystemCredentialManager = !isEmulator,
            requireUserAuth = !isEmulator,
            keystore = keystore,
            nativeAttestationProvider = nativeAttestationProvider,
            urlRewriter = if (proxyUrl.isNotBlank()) { url ->
                // Rewrite Docker-internal issuer URLs to the dev proxy
                url.replace("https://vc-proxy:8443", proxyUrl)
                    .replace("http://vc-proxy:8443", proxyUrl)
            } else null,
            availableKeystores = availableKeystores,
            // Developer-supplied via WscdScreen's collapsible Developer
            // section ("Default WSCD Mapping" text box) - dev/host-app
            // config, not an end-user setting, so it lives there rather
            // than in that screen's always-visible user-facing section.
            defaultWscdMapping = _defaultWscdMapping.value.takeIf { it.isNotEmpty() },
            requestWscdChoice = requestWscdChoice,
            preferLocalReaderTrustEvaluation = _preferLocalReaderTrustEvaluation.value,
            readerTrustRootCertificatesPem = _readerTrustRootCertificatePem.value.takeIf { it.isNotBlank() }
                ?.let { listOf(it) } ?: emptyList(),
            // Mirrors enrollWscd/rotateLifecycle's own prefetch-PIN-before-
            // transport pattern (see awaitFido2PinEntry's doc comment) for
            // real credential issuance too - found necessary via live
            // hardware testing: without this, a real sign request's only
            // PIN surface was a blocking dialog popped mid-CTAP2-ceremony,
            // with no "present your key now" cue for the transport-connect
            // wait that happens first.
            onWscdOperationStart = { pluginId ->
                if (pluginId == "fido2") {
                    val pin = awaitFido2PinEntry()
                    if (pin != null) {
                        prefetchedFido2Pin = pin.toByteArray()
                        _fido2AwaitingPresentation.value = true
                    }
                }
            },
            onWscdOperationEnd = {
                _fido2AwaitingPresentation.value = false
                prefetchedFido2Pin = null
            },
        )
    }

    companion object {
        private const val TAG = "SIROS_VM"
        private val DEFAULT_BACKEND_URL = BuildConfig.DEFAULT_BACKEND_URL
        private const val DEFAULT_TENANT_ID = "default"
        private const val DEFAULT_R2PS_URL = "http://192.168.240.1:9443"
        private const val REDIRECT_URI = "siros-sample://callback"
        private const val REDIRECT_SCHEME = "siros-sample"

        /**
         * OID4VCI `credential_configuration_id` for the SIROS ID credential
         * (see vc-issuer's config: `credential_configurations.siros_id`) -
         * used to hide the plain issuer offer from [openAddCredential]'s list
         * in favor of the "Scan Physical ID card" / [startIDV] row, which is
         * the one path meant to actually issue this credential.
         */
        private const val SIROS_ID_CREDENTIAL_CONFIGURATION_ID = "siros_id"

        /**
         * Hard ceiling for enroll/rotate/destroy so a hang anywhere in the
         * underlying transport (confirmed possible on real hardware, e.g. an
         * NFC reconnect cascade) can't permanently strand
         * [wscdLifecycleBusy] at true and lock the WSCA screen's actions.
         */
        private const val WSCD_LIFECYCLE_OP_TIMEOUT_MS = 60_000L

        /** Map SDK error codes to Android string resource IDs. */
        private val ERROR_CODE_RESOURCES = mapOf(
            "network_error" to R.string.error_network_error,
            "network_timeout" to R.string.error_network_timeout,
            "auth_failed" to R.string.error_auth_failed,
            "auth_expired" to R.string.error_auth_expired,
            "keystore_error" to R.string.error_keystore_error,
            "keystore_locked" to R.string.error_keystore_locked,
            "wallet_error" to R.string.error_wallet_error,
            "wallet_not_connected" to R.string.error_wallet_not_connected,
            "wallet_prf_unsupported" to R.string.error_wallet_prf_unsupported,
            "idv_cancelled" to R.string.error_idv_cancelled,
            "idv_unavailable" to R.string.error_idv_unavailable,
            "idv_liveness_failed" to R.string.error_idv_liveness_failed,
            "idv_verification_failed" to R.string.error_idv_verification_failed,
            "idv_network_error" to R.string.error_idv_network_error,
            "ctap2_not_available" to R.string.error_ctap2_not_available,
            "ctap2_connection_failed" to R.string.error_ctap2_connection_failed,
            "ctap2_timeout" to R.string.error_ctap2_timeout,
            "ctap2_device_disconnected" to R.string.error_ctap2_device_disconnected,
            "insufficient_credentials" to R.string.error_insufficient_credentials,
            "flow_error" to R.string.error_flow_error,
        )
    }

    /**
     * Resolve a localized error message from an exception.
     * Uses [SirosException.errorCode] to look up a translated string resource,
     * falling back to the generic error message if no match is found.
     */
    private fun localizedErrorMessage(e: Exception): String {
        val code = (e as? SirosException)?.errorCode
        val resId = code?.let { ERROR_CODE_RESOURCES[it] }
        return if (resId != null) {
            activity.getString(resId)
        } else {
            activity.getString(R.string.error_generic)
        }
    }
}
