package org.siros.sdk.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Contactless
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.vectorResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.wallet.WalletState
import android.util.Log
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import org.siros.sdk.wallet.DeepLinkType
import org.siros.sdk.wallet.classifyDeepLink

class MainActivity : ComponentActivity() {
    private lateinit var viewModel: WalletViewModel
    private val tag = "SIROS_MAIN"
    private var pendingWscaIntent: android.content.Intent? = null

    /**
     * Copies backend_url/tenant_id/engine_url string extras from the launch
     * intent into the "siros_test_overrides" prefs store WalletViewModel
     * reads at construction time - e.g.:
     *   adb shell am start -n org.siros.sdk.sample/.MainActivity \
     *     --es backend_url "https://sirosid-<env>-wallet-proxy.fly.dev" \
     *     --es tenant_id "default"
     * Debug builds only (matches the existing ACTION_WSCA_TEST precedent) -
     * an exported activity honoring these in a release build would let any
     * app on the device silently redirect a real wallet's backend URL.
     * Must run before the ViewModel is constructed (i.e. before setContent),
     * since it only reads these prefs once, in its init block.
     */
    private fun applyIntentTestOverrides(intent: android.content.Intent?) {
        if (!BuildConfig.DEBUG || intent == null) return
        val backendUrl = intent.getStringExtra("backend_url")
        val tenantId = intent.getStringExtra("tenant_id")
        val engineUrl = intent.getStringExtra("engine_url")
        if (backendUrl == null && tenantId == null && engineUrl == null) return
        getSharedPreferences("siros_test_overrides", MODE_PRIVATE).edit().apply {
            backendUrl?.let { putString("backend_url", it) }
            tenantId?.let { putString("tenant_id", it) }
            engineUrl?.let { putString("engine_url", it) }
        }.apply()
    }

    private fun dispatchIncomingUri(uri: android.net.Uri?) {
        if (uri == null || !::viewModel.isInitialized) return

        Log.i(tag, "Incoming URI: ${uri.scheme}://${uri.host}")
        when (val link = classifyDeepLink(uri, REDIRECT_SCHEME)) {
            is DeepLinkType.AuthCallback -> viewModel.handleAuthRedirect(link.code, link.state)
            is DeepLinkType.CredentialOffer -> viewModel.handleQrResult(link.uri)
            is DeepLinkType.PresentationRequest -> viewModel.handleQrResult(link.uri)
            is DeepLinkType.Unknown -> Log.d(tag, "Ignoring non-wallet URI: ${uri.scheme}://${uri.host}")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Must run before WalletViewModel.Factory constructs the ViewModel -
        // it only reads siros_test_overrides prefs once, in its init block.
        applyIntentTestOverrides(intent)
        // Queue WSCA test intent for dispatch after ViewModel is ready
        if (intent?.action == ACTION_WSCA_TEST && BuildConfig.DEBUG) {
            pendingWscaIntent = intent
        }
        val vmFactory = WalletViewModel.Factory(this)
        setContent {
            SirosTheme {
                Surface(
                    modifier = Modifier.fillMaxSize().navigationBarsPadding(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    viewModel = viewModel(factory = vmFactory)
                    LaunchedEffect(Unit) {
                        dispatchIncomingUri(intent?.data)
                        pendingWscaIntent?.let {
                            dispatchWscaTestAction(it)
                            pendingWscaIntent = null
                        }
                    }
                    WalletScreen(viewModel)
                }
            }
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        if (intent.action == ACTION_WSCA_TEST && BuildConfig.DEBUG) {
            if (::viewModel.isInitialized) {
                dispatchWscaTestAction(intent)
            } else {
                pendingWscaIntent = intent
            }
        } else {
            dispatchIncomingUri(intent.data)
        }
    }

    /**
     * Handle WSCA test automation intents (debug builds only).
     *
     * Dispatches to the real ViewModel lifecycle methods — same code path
     * as the UI buttons. Results are emitted via logcat with tag [WSCA_TEST_TAG]
     * so the test harness can parse outcomes.
     *
     * Usage from adb:
     *   adb shell am start -n $PKG/.MainActivity -a org.siros.sdk.sample.WSCA_TEST \
     *     --es wsca_action enroll [--es plugin_id r2ps] [--es factor_kind opaque]
     */
    private fun dispatchWscaTestAction(intent: android.content.Intent) {
        if (!::viewModel.isInitialized) {
            Log.e(WSCA_TEST_TAG, """{"action":"error","error":"ViewModel not initialized"}""")
            return
        }
        val action = intent.getStringExtra("wsca_action") ?: run {
            Log.e(WSCA_TEST_TAG, """{"action":"error","error":"missing wsca_action extra"}""")
            return
        }
        Log.i(WSCA_TEST_TAG, """{"action":"$action","status":"dispatching"}""")
        when (action) {
            "enroll" -> viewModel.enrollWscd()
            "rotate" -> viewModel.rotateLifecycle()
            "destroy" -> viewModel.destroyLifecycle()
            "status" -> viewModel.emitWscaTestStatus()
            "config" -> {
                intent.getStringExtra("plugin_id")?.let {
                    viewModel.selectPlugin(it)
                }
                intent.getStringExtra("r2ps_enabled")?.let {
                    viewModel.updateR2psEnabled(it.toBooleanStrictOrNull() ?: false)
                }
                intent.getStringExtra("r2ps_url")?.let {
                    viewModel.updateR2psServerUrl(it)
                }
                Log.i(WSCA_TEST_TAG, """{"action":"config","status":"applied","plugin_id":"${viewModel.selectedPluginId.value}","r2ps_enabled":${viewModel.r2psEnabled.value},"r2ps_url":"${viewModel.r2psServerUrl.value}"}""")
            }
            "refresh" -> viewModel.refreshWscdInfo()
            else -> Log.e(WSCA_TEST_TAG, """{"action":"error","error":"unknown action: $action"}""")
        }
    }

    companion object {
        private const val REDIRECT_SCHEME = "siros-sample"
        internal const val ACTION_WSCA_TEST = "org.siros.sdk.sample.WSCA_TEST"
        internal const val WSCA_TEST_TAG = "WSCA_TEST_RESULT"
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletScreen(viewModel: WalletViewModel) {
    val walletState by viewModel.state.collectAsState()
    val r2psServerUrl by viewModel.r2psServerUrl.collectAsState()
    val showAddCredential by viewModel.showAddCredential.collectAsState()
    val availableCredentials by viewModel.availableCredentials.collectAsState()
    val isLoadingOffers by viewModel.isLoadingOffers.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val errorMessage by viewModel.errorMessage.collectAsState()
    val infoMessage by viewModel.infoMessage.collectAsState()
    val flowErrorDialog by viewModel.flowErrorDialog.collectAsState()
    val pendingWscdChoice by viewModel.pendingWscdChoice.collectAsState()
    val pendingPinEntry by viewModel.pendingPinEntry.collectAsState()
    val pendingTransportChoice by viewModel.pendingTransportChoice.collectAsState()
    val fido2AwaitingPresentation by viewModel.fido2AwaitingPresentation.collectAsState()
    val fido2TransportMode by viewModel.fido2TransportMode.collectAsState()
    val pendingAutoEnrollOffer by viewModel.pendingAutoEnrollOffer.collectAsState()
    val presentationHistory by viewModel.presentationHistory.collectAsState()
    val selectedCredential by viewModel.selectedCredential.collectAsState()
    val showHistory by viewModel.showHistory.collectAsState()
    val activateMode by viewModel.activateMode.collectAsState()
    val flowStarting by viewModel.flowStarting.collectAsState()
    val pendingPresentation by viewModel.pendingPresentationRequest.collectAsState()
    val useWmpProtocol by viewModel.useWmpProtocol.collectAsState()
    val showCredentialDetails by viewModel.showCredentialDetails.collectAsState()

    LaunchedEffect(errorMessage) {
        errorMessage?.let {
            // withDismissAction shows Material3's built-in close (X) icon on the
            // snackbar; Long duration gives users time to read an error before it
            // auto-dismisses, while the X still lets them dismiss immediately.
            snackbarHostState.showSnackbar(
                message = it,
                withDismissAction = true,
                duration = SnackbarDuration.Long,
            )
            viewModel.clearError()
        }
    }

    LaunchedEffect(infoMessage) {
        infoMessage?.let {
            snackbarHostState.showSnackbar(message = it, withDismissAction = true)
            viewModel.clearInfo()
        }
    }

    // Terminal flow failure (e.g. untrusted issuer) - unlike the Snackbar above,
    // this needs an explicit user decision rather than an auto-dismissing toast,
    // since the flow itself is already over and won't resume on its own.
    flowErrorDialog?.let { info ->
        androidx.compose.material3.AlertDialog(
            onDismissRequest = viewModel::dismissFlowError,
            title = { Text(stringResource(R.string.flow_error_title)) },
            text = { Text(info.message) },
            confirmButton = {
                TextButton(onClick = viewModel::retryLastFlow, enabled = info.canRetry) {
                    Text(stringResource(R.string.error_retry))
                }
            },
            dismissButton = {
                TextButton(onClick = viewModel::dismissFlowError) {
                    Text(stringResource(R.string.flow_cancel))
                }
            },
        )
    }

    // The SDK asking which registered WSCD plugin to use for an upcoming
    // credential-issuance key batch (see WscdSelectionPolicy's doc comment) -
    // fires when more than one plugin meets the credential type's required
    // tier and neither a persisted choice nor a dev-supplied default mapping
    // resolves it. Can appear regardless of which tab/screen is showing
    // (issuance can be triggered from a QR scan, a deep link, etc.), so -
    // like flowErrorDialog above - it's rendered here rather than inside any
    // one screen.
    pendingWscdChoice?.let { pending ->
        WscdChoiceDialog(pending, onChoose = viewModel::respondToWscdChoice)
    }

    // FIDO2 CTAP2 ClientPin asking for the authenticator's real PIN (see
    // PendingPinEntry's doc comment) - same rationale as pendingWscdChoice
    // above for rendering it here rather than inside one specific screen.
    pendingPinEntry?.let { pending ->
        PinEntryDialog(pending, onSubmit = viewModel::respondToPinEntry)
    }

    // CompositeCtap2Transport found both USB and NFC available around the
    // same time (see that class's AMBIGUITY_GRACE_MS doc comment) - same
    // rationale as pendingPinEntry above for rendering it here.
    pendingTransportChoice?.let {
        TransportChoiceDialog(respond = viewModel::respondToTransportChoice)
    }

    // PIN accepted, now waiting for the user to physically present the key
    // (see WalletViewModel.fido2AwaitingPresentation's doc comment for why
    // this is a separate step from PIN entry above, not shown at the same
    // time).
    if (fido2AwaitingPresentation) {
        Fido2PresentKeyGuide(
            mode = fido2TransportMode,
            onCancel = viewModel::cancelWscdLifecycleOp,
        )
    }

    // Offered once per process right after a successful login - see
    // WalletViewModel.maybeOfferWscdAutoEnroll's doc comment. Rendered here
    // (not inside one specific screen) for the same reason as the other
    // pending-* dialogs above: it can fire regardless of which screen is
    // currently showing.
    pendingAutoEnrollOffer?.let { pluginId ->
        AutoEnrollOfferDialog(pluginId = pluginId, onRespond = viewModel::respondToAutoEnrollOffer)
    }

    // The wallet instance this installation logs in with is suspended, or the
    // wallet was deactivated and its data erased (SID-AUTH-06). Not an error
    // to retry: only someone else - another device, the provider - can lift
    // it, so this gets its own screen rather than the login screen's
    // "Welcome back" with a passkey that will be refused again.
    (walletState as? WalletState.LifecycleBlocked)?.let { blocked ->
        WalletBlockedScreen(
            reason = blocked.reason,
            message = blocked.message,
            onRetry = { viewModel.login() },
            // The account is already forgotten by the time a revoked wallet
            // reaches here; logging out is what puts the app back on the
            // login/register screen where a new enrollment starts.
            onEnrollAgain = viewModel::disconnect,
            isLoading = isLoading,
        )
        return
    }

    // Not logged in → show login screen (no app chrome)
    if (walletState is WalletState.Disconnected || walletState is WalletState.Connecting) {
        val cachedAccounts = (walletState as? WalletState.Disconnected)?.cachedAccounts ?: emptyList()
        val backendUrlState by viewModel.backendUrl.collectAsState()
        val tenantIdState by viewModel.tenantId.collectAsState()
        val engineUrlOverrideState by viewModel.engineUrlOverride.collectAsState()
        val zkCircuitUrlsState by viewModel.zkCircuitUrls.collectAsState()
        val preferLocalReaderTrustEvaluationState by viewModel.preferLocalReaderTrustEvaluation.collectAsState()
        val readerTrustRootCertificatePemState by viewModel.readerTrustRootCertificatePem.collectAsState()
        LoginScreen(
            cachedAccounts = cachedAccounts,
            backendUrl = backendUrlState,
            tenantId = tenantIdState,
            engineUrl = engineUrlOverrideState,
            useWmpProtocol = useWmpProtocol,
            zkCircuitUrls = zkCircuitUrlsState,
            preferLocalReaderTrustEvaluation = preferLocalReaderTrustEvaluationState,
            readerTrustRootCertificatePem = readerTrustRootCertificatePemState,
            showPreLoginSettings = BuildConfig.SHOW_PRE_LOGIN_SETTINGS,
            isLoading = isLoading || walletState is WalletState.Connecting,
            snackbarHostState = snackbarHostState,
            onLogin = viewModel::login,
            onLoginAccount = { account -> viewModel.login(account.accountId) },
            onForgetAccount = viewModel::forgetAccount,
            onRegister = { name -> viewModel.register(name) },
            onUpdateBackendUrl = viewModel::updateBackendUrl,
            onUpdateTenantId = viewModel::updateTenantId,
            onUpdateEngineUrl = viewModel::updateEngineUrl,
            onUpdateUseWmpProtocol = viewModel::updateUseWmpProtocol,
            onUpdateZkCircuitUrls = viewModel::updateZkCircuitUrls,
            onUpdatePreferLocalReaderTrustEvaluation = viewModel::updatePreferLocalReaderTrustEvaluation,
            onUpdateReaderTrustRootCertificatePem = viewModel::updateReaderTrustRootCertificatePem,
        )
        return
    }

    // Fatal error without a valid session → full-screen error, no navigation chrome.
    // The user must tap "Retry" (which disconnects → back to login).
    if (walletState is WalletState.Error) {
        ErrorView(
            message = (walletState as WalletState.Error).message,
            onRetry = viewModel::disconnect,
        )
        return
    }

    // WSCA developer sub-screen state (read here so it's available in the `when` below)
    val showWscaDeveloper by viewModel.showWscaDeveloper.collectAsState()
    val showDevices by viewModel.showDevices.collectAsState()
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }

    // Measured height of the custom bottom tab bar Row below, so the shared
    // SnackbarHost (which spans every sub-screen in the Box below - see its
    // comment) can pad itself above the bar instead of rendering on top of it.
    // Reset to 0 via DisposableEffect when the bar itself isn't composed (any
    // branch other than the main tabs below), so it doesn't leave stale
    // padding under the snackbar on those other screens.
    var bottomNavBarHeightPx by remember { mutableIntStateOf(0) }

    // Everything below shares one Box so the SnackbarHost always has somewhere to
    // render, no matter which sub-screen is active - previously each sub-screen
    // branch `return`ed before ever reaching a SnackbarHost, so post-login errors
    // (e.g. a failed credential issuance) were silently swallowed.
    Box(modifier = Modifier.fillMaxSize()) {
        when {
            // Presentation consent dialog — shown as a full-screen overlay
            pendingPresentation != null -> {
                // Recomputed per new presentation request, not cached: a key
                // lost since the last check must be reflected immediately -
                // see SirosWallet.availableKeyIds's doc comment.
                var availableKeyIds by remember(pendingPresentation) { mutableStateOf(emptySet<String>()) }
                LaunchedEffect(pendingPresentation) {
                    availableKeyIds = viewModel.currentAvailableKeyIds()
                }
                PresentationConsentScreen(
                    request = pendingPresentation!!,
                    onAccept = viewModel::acceptPresentation,
                    onDecline = viewModel::declinePresentation,
                    presentationHistory = presentationHistory,
                    consumptionPolicy = viewModel.credentialConsumptionPolicy.collectAsState().value,
                    availableKeyIds = availableKeyIds,
                )
            }

            // Credential detail sub-screen
            selectedCredential != null -> CredentialDetailScreen(
                credential = selectedCredential!!,
                onBack = viewModel::closeCredentialDetail,
                onDelete = { viewModel.deleteCredential(selectedCredential!!.id) },
                onRenew = { viewModel.renewCredential(selectedCredential!!) },
            )

            // Presentation history sub-screen
            showHistory -> PresentationHistoryScreen(
                history = presentationHistory,
                onBack = viewModel::closeHistory,
            )

            // Settings → Devices: this user's wallet instances (SID-AUTH-06).
            showDevices -> DevicesScreen(
                instances = viewModel.walletInstances.collectAsState().value,
                loading = viewModel.devicesLoading.collectAsState().value,
                busyInstanceId = viewModel.devicesBusyInstanceId.collectAsState().value,
                deactivating = viewModel.deactivating.collectAsState().value,
                deactivationOutcome = viewModel.deactivationOutcome.collectAsState().value,
                errorMessage = viewModel.devicesError.collectAsState().value,
                onBack = viewModel::closeDevices,
                onRefresh = viewModel::refreshDevices,
                onSetStatus = viewModel::setWalletInstanceStatus,
                onDeactivateWallet = viewModel::deactivateWallet,
            )

            // Consolidated WSCD settings sub-screen (one tab per plugin -
            // see WscdScreen.kt's doc comment; replaces the old standalone
            // "WSCA Developer" screen plus the WSCD cards that used to live
            // in the Settings tab below).
            showWscaDeveloper -> {
                val wscdKeys by viewModel.wscdKeys.collectAsState()
                val wscdLifecycleStatus by viewModel.wscdLifecycleStatus.collectAsState()
                val wscdKeySecurityProps by viewModel.wscdKeySecurityProps.collectAsState()
                val selectedPluginId by viewModel.selectedPluginId.collectAsState()
                WscdScreen(
                    lifecycleState = viewModel.lifecycleState.collectAsState().value,
                    lifecycleStatus = wscdLifecycleStatus,
                    keys = wscdKeys,
                    keySecurityProps = wscdKeySecurityProps,
                    selectedPluginId = selectedPluginId,
                    r2psServerUrl = r2psServerUrl,
                    defaultWscdMappingText = viewModel.defaultWscdMappingText.collectAsState().value,
                    fido2TransportMode = viewModel.fido2TransportMode.collectAsState().value,
                    wscdLifecycleBusy = viewModel.wscdLifecycleBusy.collectAsState().value,
                    wscdGlobalOverride = viewModel.wscdGlobalOverride.collectAsState().value,
                    wscdUserOverrides = viewModel.wscdUserOverrides.collectAsState().value,
                    wscdTofuMapping = viewModel.wscdTofuMapping.collectAsState().value,
                    ts11DiscoveredCredentials = viewModel.ts11DiscoveredCredentials.collectAsState().value,
                    ts11DiscoveryInProgress = viewModel.ts11DiscoveryInProgress.collectAsState().value,
                    onSelectPlugin = viewModel::selectPlugin,
                    onSelectFido2TransportMode = viewModel::setFido2TransportMode,
                    onR2psServerUrlChange = viewModel::updateR2psServerUrl,
                    onDefaultWscdMappingTextChange = viewModel::updateDefaultWscdMappingText,
                    onEnroll = viewModel::enrollWscd,
                    onRotate = viewModel::rotateLifecycle,
                    onDestroy = viewModel::destroyLifecycle,
                    onRefresh = viewModel::refreshWscdInfo,
                    onSetWscdGlobalOverride = viewModel::setWscdGlobalOverride,
                    onSetWscdUserOverride = viewModel::setWscdUserOverride,
                    onClearWscdUserOverride = viewModel::clearWscdUserOverride,
                    onForgetWscdTofuMapping = viewModel::forgetWscdTofuMapping,
                    onForgetAllWscdTofuMapping = viewModel::forgetAllWscdTofuMappings,
                    onDiscoverTs11Schemas = viewModel::discoverTs11Schemas,
                    onBack = viewModel::closeWscaDeveloper,
                )
            }

            // Activate sub-screen: QR scan and ISO 18013-5 proximity (BLE)
            // engagement are two modes of one merged entry point - see
            // WalletViewModel.ActivateMode's doc comment.
            activateMode != null -> when (activateMode!!) {
                WalletViewModel.ActivateMode.Qr -> QrScannerScreen(
                    onQrScanned = viewModel::handleQrResult,
                    onBack = viewModel::closeActivate,
                )
                WalletViewModel.ActivateMode.Proximity -> ProximityEngagementScreen(
                    getCredentials = viewModel::getCredentialsForProximity,
                    signPresentation = viewModel::signMdocPresentationForProximity,
                    filterEligible = viewModel::filterEligibleForProximity,
                    evaluateReaderTrust = viewModel::evaluateReaderTrustForProximity,
                    onBack = viewModel::closeActivate,
                )
            }

            // Transitional "starting…" sub-screen: shown the instant a QR-triggered
            // flow is handed off to the wallet/engine, until a real subsequent state
            // (FlowActive below, or an error) takes over - see flowStarting's doc
            // comment in WalletViewModel for why this exists (slow issuers/verifiers).
            flowStarting != null -> FlowStartingView(
                flowType = flowStarting,
                onCancel = viewModel::cancelFlowStarting,
            )

            // Add credential sub-screen
            showAddCredential -> {
                Scaffold(
                    topBar = {
                        TopAppBar(
                            title = { Text(stringResource(R.string.add_credential_title)) },
                            colors = TopAppBarDefaults.topAppBarColors(
                                containerColor = MaterialTheme.colorScheme.surface,
                                titleContentColor = MaterialTheme.colorScheme.onSurface,
                            ),
                            navigationIcon = {
                                IconButton(onClick = viewModel::closeAddCredential) {
                                    Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.nav_back))
                                }
                            },
                        )
                    },
                ) { padding ->
                    val pendingOffer by viewModel.pendingIssuanceOffer.collectAsState()
                    AddCredentialScreen(
                        offers = availableCredentials,
                        isLoading = isLoadingOffers,
                        onOfferSelected = viewModel::selectCredentialOffer,
                        pendingOffer = pendingOffer,
                        onConfirmIssuance = viewModel::confirmIssuance,
                        onCancelIssuance = viewModel::cancelIssuance,
                        onStartIDV = viewModel::startIDV,
                        onRetry = viewModel::openAddCredential,
                        modifier = Modifier.padding(padding),
                    )
                }
            }

            // Main app with bottom navigation
            else -> Column(modifier = Modifier.fillMaxSize()) {
        DisposableEffect(Unit) {
            onDispose { bottomNavBarHeightPx = 0 }
        }
        // Top bar
        TopAppBar(
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Image(
                        painter = painterResource(R.drawable.ic_siros_mark),
                        contentDescription = stringResource(R.string.topbar_logo_description),
                        modifier = Modifier.size(28.dp),
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = stringResource(R.string.topbar_title),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(
                containerColor = MaterialTheme.colorScheme.surface,
                titleContentColor = MaterialTheme.colorScheme.onSurface,
            ),
            actions = {
                IconButton(onClick = viewModel::switchToProximityEngagement) {
                    Icon(
                        Icons.Filled.Contactless,
                        "Proximity Engagement (Interop Test)",
                    )
                }
                IconButton(onClick = viewModel::openActivate) {
                    Icon(
                        ImageVector.vectorResource(R.drawable.ic_qr_scan),
                        stringResource(R.string.qr_scan_button),
                    )
                }
            },
        )

        // Recomputed whenever wallet state changes (new credential, key
        // restored after unlock, etc.) so the credential list's "shadow"
        // (renew-only) display state - see CredentialCard.isExhausted -
        // never lags behind the signer's actual key inventory.
        var credentialsTabAvailableKeyIds by remember { mutableStateOf(emptySet<String>()) }
        LaunchedEffect(walletState) {
            credentialsTabAvailableKeyIds = viewModel.currentAvailableKeyIds()
        }

        // Content area
        Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
            when (val state = walletState) {
                is WalletState.Ready -> {
                    when (selectedTab) {
                        2 -> SettingsTab(
                            state = state,
                            backendUrl = viewModel.backendUrl.collectAsState().value,
                            tenantId = viewModel.tenantId.collectAsState().value,
                            useWmpProtocol = useWmpProtocol,
                            zkCircuitUrls = viewModel.zkCircuitUrls.collectAsState().value,
                            presentationCount = presentationHistory.size,
                            onDisconnect = viewModel::disconnect,
                            onDeleteAccount = viewModel::deleteAccount,
                            onShowHistory = viewModel::openHistory,
                            onShowWscdSettings = viewModel::openWscaDeveloper,
                            onShowDevices = viewModel::openDevices,
                            onForgetAccount = viewModel::forgetAccount,
                            passkeys = viewModel.listPasskeys(),
                            onRenamePasskey = viewModel::renamePasskey,
                            showCredentialDetails = showCredentialDetails,
                            onUpdateShowCredentialDetails = viewModel::updateShowCredentialDetails,
                            showDiagnosticMessages = viewModel.showDiagnosticMessages.collectAsState().value,
                            onUpdateShowDiagnosticMessages = viewModel::updateShowDiagnosticMessages,
                            credentialConsumptionPolicy = viewModel.credentialConsumptionPolicy.collectAsState().value,
                            onUpdateCredentialConsumptionPolicy = viewModel::updateCredentialConsumptionPolicy,
                            preferLocalReaderTrustEvaluation = viewModel.preferLocalReaderTrustEvaluation.collectAsState().value,
                            onUpdatePreferLocalReaderTrustEvaluation = viewModel::updatePreferLocalReaderTrustEvaluation,
                            readerTrustRootCertificatePem = viewModel.readerTrustRootCertificatePem.collectAsState().value,
                            onUpdateReaderTrustRootCertificatePem = viewModel::updateReaderTrustRootCertificatePem,
                        )
                        // selectedTab can transiently be 1 (the "Add" action, not a
                        // real persisted tab) right as a flow finishes and the state
                        // drops back to Ready - fall through to the credentials list
                        // rather than rendering nothing.
                        else -> CredentialsTab(
                            state = state,
                            presentationHistory = presentationHistory,
                            onCredentialClick = viewModel::openCredentialDetail,
                            onRenewCredential = viewModel::renewCredential,
                            onDeleteCredential = { viewModel.deleteCredential(it.id) },
                            onAddCredential = viewModel::openAddCredential,
                            availableKeyIds = credentialsTabAvailableKeyIds,
                        )
                    }
                }
                is WalletState.FlowActive -> {
                    FlowActiveView(
                        state = state,
                        onCancel = viewModel::cancelCurrentFlow,
                        showDiagnosticMessages = viewModel.showDiagnosticMessages.collectAsState().value,
                    )
                }
                is WalletState.Error -> {
                    ErrorView(message = state.message, onRetry = viewModel::disconnect)
                }
                else -> { /* Disconnected/Connecting handled above */ }
            }
        }

        // Bottom tab bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .onGloballyPositioned { bottomNavBarHeightPx = it.size.height }
                .background(MaterialTheme.colorScheme.surfaceVariant)
                .padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceEvenly,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.clickable { selectedTab = 0 },
            ) {
                Icon(
                    ImageVector.vectorResource(R.drawable.ic_wallet),
                    stringResource(R.string.nav_credentials),
                    tint = if (selectedTab == 0) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.nav_credentials),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (selectedTab == 0) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.clickable {
                    selectedTab = 1
                    viewModel.openAddCredential()
                },
            ) {
                Icon(
                    Icons.Filled.Add,
                    stringResource(R.string.nav_add),
                    tint = if (selectedTab == 1) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.nav_add),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (selectedTab == 1) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.clickable { selectedTab = 2 },
            ) {
                Icon(
                    Icons.Outlined.Settings,
                    stringResource(R.string.nav_settings),
                    tint = if (selectedTab == 2) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.nav_settings),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (selectedTab == 2) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
        }

        val bottomNavBarHeightDp = with(LocalDensity.current) { bottomNavBarHeightPx.toDp() }
        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = bottomNavBarHeightDp),
        )
    }
}

// ── Login Screen ────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LoginScreen(
    cachedAccounts: List<org.siros.sdk.wallet.CachedAccount>,
    backendUrl: String,
    tenantId: String,
    engineUrl: String,
    useWmpProtocol: Boolean,
    zkCircuitUrls: List<String>,
    preferLocalReaderTrustEvaluation: Boolean = false,
    readerTrustRootCertificatePem: String = "",
    showPreLoginSettings: Boolean,
    isLoading: Boolean,
    snackbarHostState: SnackbarHostState,
    onLogin: () -> Unit,
    onLoginAccount: (org.siros.sdk.wallet.CachedAccount) -> Unit,
    onForgetAccount: (String) -> Unit,
    onRegister: (String) -> Unit,
    onUpdateBackendUrl: (String) -> Unit,
    onUpdateTenantId: (String) -> Unit,
    onUpdateEngineUrl: (String) -> Unit,
    onUpdateUseWmpProtocol: (Boolean) -> Unit,
    onUpdateZkCircuitUrls: (List<String>) -> Unit,
    onUpdatePreferLocalReaderTrustEvaluation: (Boolean) -> Unit = {},
    onUpdateReaderTrustRootCertificatePem: (String) -> Unit = {},
) {
    var showRegister by remember { mutableStateOf(false) }
    var showOtherLogin by remember { mutableStateOf(false) }
    var registerName by remember { mutableStateOf("") }
    var showBackendInfo by remember { mutableStateOf(false) }
    var showSettingsSheet by remember { mutableStateOf(false) }

    if (showSettingsSheet) {
        PreLoginSettingsSheet(
            backendUrl = backendUrl,
            tenantId = tenantId,
            engineUrl = engineUrl,
            useWmpProtocol = useWmpProtocol,
            zkCircuitUrls = zkCircuitUrls,
            preferLocalReaderTrustEvaluation = preferLocalReaderTrustEvaluation,
            readerTrustRootCertificatePem = readerTrustRootCertificatePem,
            onUpdateBackendUrl = onUpdateBackendUrl,
            onUpdateTenantId = onUpdateTenantId,
            onUpdateEngineUrl = onUpdateEngineUrl,
            onUpdateUseWmpProtocol = onUpdateUseWmpProtocol,
            onUpdateZkCircuitUrls = onUpdateZkCircuitUrls,
            onUpdatePreferLocalReaderTrustEvaluation = onUpdatePreferLocalReaderTrustEvaluation,
            onUpdateReaderTrustRootCertificatePem = onUpdateReaderTrustRootCertificatePem,
            onDismiss = { showSettingsSheet = false },
        )
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            if (showPreLoginSettings) {
                TopAppBar(
                    title = {},
                    actions = {
                        IconButton(
                            onClick = { showSettingsSheet = true },
                        ) {
                            Icon(
                                Icons.Outlined.Settings,
                                contentDescription = "Settings",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    },
                )
            }
        },
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 32.dp, vertical = 16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
            Spacer(modifier = Modifier.height(24.dp))
            Image(
                painter = painterResource(R.drawable.ic_siros_mark),
                contentDescription = stringResource(R.string.topbar_logo_description),
                modifier = Modifier.size(56.dp),
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.login_title),
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
            )
            // Info icon showing backend URL
            Row(
                modifier = Modifier.clickable { showBackendInfo = !showBackendInfo },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Outlined.Info, contentDescription = "Backend info", modifier = Modifier.size(14.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    if (showBackendInfo) backendUrl else stringResource(R.string.login_tagline),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(modifier = Modifier.height(20.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    when {
                        // Mode C: Registration
                        showRegister -> {
                            Text(stringResource(R.string.login_register_button),
                                style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                            OutlinedTextField(
                                value = registerName,
                                onValueChange = { if (it.toByteArray().size <= 64) registerName = it },
                                label = { Text("Display name") },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                enabled = !isLoading,
                                shape = RoundedCornerShape(12.dp),
                                supportingText = { Text("${registerName.toByteArray().size}/64") },
                            )
                            Button(
                                onClick = { onRegister(registerName) },
                                modifier = Modifier.fillMaxWidth().height(48.dp),
                                enabled = !isLoading && registerName.isNotBlank(),
                                shape = RoundedCornerShape(12.dp),
                            ) {
                                if (isLoading) {
                                    CircularProgressIndicator(modifier = Modifier.size(20.dp),
                                        color = MaterialTheme.colorScheme.onPrimary, strokeWidth = 2.dp)
                                    Spacer(modifier = Modifier.width(8.dp))
                                }
                                Text("Sign up with passkey")
                            }
                            TextButton(onClick = { showRegister = false }) {
                                Text("Already have an account? Login")
                            }
                        }

                        // Mode A: Cached accounts (returning users)
                        cachedAccounts.isNotEmpty() && !showOtherLogin -> {
                            Text("Welcome back",
                                style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                            cachedAccounts.forEach { account ->
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Button(
                                        onClick = { onLoginAccount(account) },
                                        modifier = Modifier.weight(1f).height(48.dp),
                                        enabled = !isLoading,
                                        shape = RoundedCornerShape(12.dp),
                                    ) {
                                        if (isLoading) {
                                            CircularProgressIndicator(modifier = Modifier.size(20.dp),
                                                color = MaterialTheme.colorScheme.onPrimary, strokeWidth = 2.dp)
                                            Spacer(modifier = Modifier.width(8.dp))
                                        }
                                        Text(account.displayName, maxLines = 1)
                                    }
                                    Spacer(modifier = Modifier.width(8.dp))
                                    IconButton(onClick = { onForgetAccount(account.accountId) }) {
                                        Icon(Icons.Default.Close, contentDescription = "Forget account")
                                    }
                                }
                            }
                            TextButton(onClick = { showOtherLogin = true }) {
                                Text("Use other account")
                            }
                        }

                        // Mode B: Generic passkey login
                        else -> {
                            Button(
                                onClick = onLogin,
                                modifier = Modifier.fillMaxWidth().height(48.dp),
                                enabled = !isLoading,
                                shape = RoundedCornerShape(12.dp),
                            ) {
                                if (isLoading) {
                                    CircularProgressIndicator(modifier = Modifier.size(20.dp),
                                        color = MaterialTheme.colorScheme.onPrimary, strokeWidth = 2.dp)
                                    Spacer(modifier = Modifier.width(8.dp))
                                }
                                Text(stringResource(R.string.login_button))
                            }
                            TextButton(onClick = { showRegister = true }) {
                                Text("New here? Sign up")
                            }
                            if (cachedAccounts.isNotEmpty()) {
                                TextButton(onClick = { showOtherLogin = false }) {
                                    Text("Back to saved accounts")
                                }
                            }
                        }
                    }
                }
            } // Column
        } // Box
    } // Scaffold padding
    } // Scaffold
} // LoginScreen

// ── Pre-Login Settings Bottom Sheet ────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PreLoginSettingsSheet(
    backendUrl: String,
    tenantId: String,
    engineUrl: String,
    useWmpProtocol: Boolean,
    zkCircuitUrls: List<String>,
    preferLocalReaderTrustEvaluation: Boolean = false,
    readerTrustRootCertificatePem: String = "",
    onUpdateBackendUrl: (String) -> Unit,
    onUpdateTenantId: (String) -> Unit,
    onUpdateEngineUrl: (String) -> Unit,
    onUpdateUseWmpProtocol: (Boolean) -> Unit,
    onUpdateZkCircuitUrls: (List<String>) -> Unit,
    onUpdatePreferLocalReaderTrustEvaluation: (Boolean) -> Unit = {},
    onUpdateReaderTrustRootCertificatePem: (String) -> Unit = {},
    onDismiss: () -> Unit,
) {
    var editBackendUrl by remember { mutableStateOf(backendUrl) }
    var editTenantId by remember { mutableStateOf(tenantId) }
    var editEngineUrl by remember { mutableStateOf(engineUrl) }
    // One URL per line for editing - joined/split at the boundary with
    // onUpdateZkCircuitUrls rather than storing List<String> as Compose
    // TextField state directly.
    var editZkCircuitUrls by remember { mutableStateOf(zkCircuitUrls.joinToString("\n")) }
    var editReaderTrustRootCertificatePem by remember { mutableStateOf(readerTrustRootCertificatePem) }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
                .padding(bottom = 32.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                "Connection Settings",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
            Text(
                "Configure before registering. Changes take effect on next connection.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = editBackendUrl,
                onValueChange = { editBackendUrl = it; onUpdateBackendUrl(it) },
                label = { Text("Backend URL") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = editTenantId,
                onValueChange = { editTenantId = it; onUpdateTenantId(it) },
                label = { Text("Tenant ID") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = editEngineUrl,
                onValueChange = { editEngineUrl = it; onUpdateEngineUrl(it) },
                label = { Text("Engine URL (blank = auto)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = editZkCircuitUrls,
                onValueChange = { text ->
                    editZkCircuitUrls = text
                    val urls = text.split("\n").map { it.trim() }.filter { it.isNotBlank() }
                    onUpdateZkCircuitUrls(urls)
                },
                label = { Text(stringResource(R.string.settings_zk_circuit_urls)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = false,
            )

            // Transport protocol toggle
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("WMP Protocol", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        if (useWmpProtocol) "JSON-RPC 2.0 (WMP)" else "Legacy engine protocol",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = useWmpProtocol,
                    onCheckedChange = onUpdateUseWmpProtocol,
                )
            }

            // RICAL reader-trust local fallback (Geneva 2026 interop event) -
            // off by default: the remote go-trust `mdocrical` AuthZEN call
            // is preferred since only it honors RICAL's temporary/dynamic
            // trust roots. See WalletConfig.preferLocalReaderTrustEvaluation.
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Evaluate reader trust locally", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "Skip the remote RICAL trust check and validate proximity readers " +
                            "only against the root certificate below.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = preferLocalReaderTrustEvaluation,
                    onCheckedChange = onUpdatePreferLocalReaderTrustEvaluation,
                )
            }
            OutlinedTextField(
                value = editReaderTrustRootCertificatePem,
                onValueChange = { text ->
                    editReaderTrustRootCertificatePem = text
                    onUpdateReaderTrustRootCertificatePem(text)
                },
                label = { Text("RICAL root certificate (PEM)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = false,
            )
        }
    }
}

// ── Credentials Tab ─────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CredentialsTab(
    state: WalletState.Ready,
    presentationHistory: List<org.siros.sdk.credentials.PresentationRecord>,
    onCredentialClick: (org.siros.sdk.credentials.StoredCredential) -> Unit,
    onRenewCredential: (org.siros.sdk.credentials.StoredCredential) -> Unit,
    onDeleteCredential: (org.siros.sdk.credentials.StoredCredential) -> Unit,
    onAddCredential: () -> Unit,
    modifier: Modifier = Modifier,
    availableKeyIds: Set<String> = emptySet(),
) {
    // One entry per batch (see StoredCredential.batchId) instead of one per
    // issued copy - mirrors wallet-frontend's fetchVcData grouping so a
    // 5-copy batch issuance shows as a single card with a remaining-copies
    // ribbon, not five swipeable duplicates.
    val grouped = remember(state.credentials, presentationHistory, availableKeyIds) {
        org.siros.sdk.credentials.CredentialUtils.groupForDisplay(state.credentials, presentationHistory, availableKeyIds)
    }

    // Long-press action menu (Renew/Delete) - a quicker path to the same two
    // actions already reachable via the detail screen's icons/the exhausted-
    // credential overlay, for a credential the user hasn't tapped into yet.
    var actionMenuFor by remember { mutableStateOf<org.siros.sdk.credentials.StoredCredential?>(null) }
    var pendingDeleteFor by remember { mutableStateOf<org.siros.sdk.credentials.StoredCredential?>(null) }

    actionMenuFor?.let { credential ->
        ModalBottomSheet(onDismissRequest = { actionMenuFor = null }) {
            Column(modifier = Modifier.fillMaxWidth().padding(bottom = 24.dp)) {
                Text(
                    credential.metadata?.name ?: credential.format,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
                )
                TextButton(
                    onClick = {
                        actionMenuFor = null
                        onRenewCredential(credential)
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.padding(end = 16.dp))
                        Text(stringResource(R.string.credential_renew))
                    }
                }
                TextButton(
                    onClick = {
                        actionMenuFor = null
                        pendingDeleteFor = credential
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            Icons.Filled.Delete,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(end = 16.dp),
                        )
                        Text(stringResource(R.string.credential_detail_delete), color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }

    pendingDeleteFor?.let { credential ->
        AlertDialog(
            onDismissRequest = { pendingDeleteFor = null },
            title = { Text(stringResource(R.string.credential_detail_delete_confirm_title)) },
            text = {
                Text(stringResource(
                    R.string.credential_detail_delete_confirm_message,
                    credential.metadata?.name ?: credential.format,
                ))
            },
            confirmButton = {
                TextButton(onClick = {
                    pendingDeleteFor = null
                    onDeleteCredential(credential)
                }) {
                    Text(
                        stringResource(R.string.credential_detail_delete_confirm),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDeleteFor = null }) {
                    Text(stringResource(R.string.cancel))
                }
            },
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Text(
            text = stringResource(R.string.credentials_welcome, state.displayName ?: stringResource(R.string.user_fallback_name)),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = if (grouped.size == 1) stringResource(R.string.credentials_count_one, 1)
                   else stringResource(R.string.credentials_count_other, grouped.size),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(16.dp))

        if (grouped.isEmpty()) {
            EmptyCredentialsCard(onClick = onAddCredential)
        } else {
            // A partially-overlapping, interactive deck instead of a plain
            // scrolling list: the phone screen has far more vertical than
            // horizontal real estate, so a one-at-a-time horizontal pager
            // wastes the available space, but a full-height list of cards
            // asks for a lot of scrolling to see what's further down.
            // CredentialStack owns its own scrolling (a card's drag and a
            // plain vertical scroll are the same gesture, so it has to
            // arbitrate between them itself) and its own reorder state, so
            // there's nothing further to wrap it in here.
            CredentialStack(
                entries = grouped,
                onCredentialClick = onCredentialClick,
                onCredentialLongClick = { actionMenuFor = it },
                onRenewCredential = onRenewCredential,
                onDeleteCredential = { pendingDeleteFor = it },
                modifier = Modifier.fillMaxSize(),
            )
        }
    }
}

@Composable
fun EmptyCredentialsCard(onClick: () -> Unit) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                imageVector = Icons.Filled.Add,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.primary,
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = stringResource(R.string.credentials_empty_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Medium,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.credentials_empty_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
}

// ── Settings Tab ────────────────────────────────────────────────────

/** Localized display label for a [org.siros.sdk.credentials.CredentialConsumptionPolicy] value. */
private fun credentialConsumptionPolicyLabelRes(policy: org.siros.sdk.credentials.CredentialConsumptionPolicy): Int =
    when (policy) {
        org.siros.sdk.credentials.CredentialConsumptionPolicy.CONSUME_ALL -> R.string.credential_consumption_consume_all
        org.siros.sdk.credentials.CredentialConsumptionPolicy.CONSUME_NON_ZKP -> R.string.credential_consumption_consume_non_zkp
        org.siros.sdk.credentials.CredentialConsumptionPolicy.NEVER_CONSUME -> R.string.credential_consumption_never_consume
    }

@Composable
fun SettingsTab(
    state: WalletState.Ready,
    backendUrl: String,
    tenantId: String,
    useWmpProtocol: Boolean,
    zkCircuitUrls: List<String> = listOf(org.siros.sdk.credentials.ZkCircuitClient.DEFAULT_ZK_CIRCUIT_URL),
    presentationCount: Int,
    onDisconnect: () -> Unit,
    onDeleteAccount: () -> Unit,
    onShowHistory: () -> Unit,
    onShowWscdSettings: () -> Unit,
    onShowDevices: () -> Unit = {},
    onForgetAccount: ((String) -> Unit)? = null,
    passkeys: List<org.siros.sdk.wallet.CachedPasskey> = emptyList(),
    onRenamePasskey: ((String, String) -> Unit)? = null,
    onUpdateUseWmpProtocol: ((Boolean) -> Unit)? = null,
    showCredentialDetails: Boolean = false,
    onUpdateShowCredentialDetails: ((Boolean) -> Unit)? = null,
    showDiagnosticMessages: Boolean = true,
    onUpdateShowDiagnosticMessages: ((Boolean) -> Unit)? = null,
    credentialConsumptionPolicy: org.siros.sdk.credentials.CredentialConsumptionPolicy =
        org.siros.sdk.credentials.CredentialConsumptionPolicy.NEVER_CONSUME,
    onUpdateCredentialConsumptionPolicy: ((org.siros.sdk.credentials.CredentialConsumptionPolicy) -> Unit)? = null,
    // RICAL reader-trust local fallback - see PreLoginSettingsSheet's identical
    // controls for why this exists. Duplicated here (not moved) because
    // PreLoginSettingsSheet also configures backendUrl/tenantId, which must
    // stay reachable before a session exists; reader trust is just as useful
    // to flip mid-session (e.g. right before a proximity test), where the
    // pre-login sheet is no longer reachable at all.
    preferLocalReaderTrustEvaluation: Boolean = false,
    onUpdatePreferLocalReaderTrustEvaluation: ((Boolean) -> Unit)? = null,
    readerTrustRootCertificatePem: String = "",
    onUpdateReaderTrustRootCertificatePem: ((String) -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Text(
            text = stringResource(R.string.settings_title),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(modifier = Modifier.height(24.dp))

        // Account section
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        ) {
            Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
                Text(
                    text = stringResource(R.string.settings_account_section),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(12.dp))
                SettingsRow(stringResource(R.string.settings_signed_in_as), state.displayName ?: state.userId)
                SettingsRow(stringResource(R.string.settings_backend_url), backendUrl)
                SettingsRow(stringResource(R.string.settings_zk_circuit_urls), zkCircuitUrls.joinToString(", "))
                SettingsRow(stringResource(R.string.settings_tenant_id), tenantId)
                SettingsRow(stringResource(R.string.settings_credentials_stored), state.credentials.size.toString())
                SettingsRow(stringResource(R.string.settings_app_version), BuildConfig.VERSION_NAME)
                SettingsRow("Transport", if (useWmpProtocol) "WMP (JSON-RPC 2.0)" else "Legacy")
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            stringResource(R.string.settings_credential_details),
                            style = MaterialTheme.typography.bodyLarge,
                        )
                        Text(
                            stringResource(R.string.settings_credential_details_description),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = showCredentialDetails,
                        onCheckedChange = onUpdateShowCredentialDetails,
                        enabled = onUpdateShowCredentialDetails != null,
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            stringResource(R.string.settings_diagnostic_messages),
                            style = MaterialTheme.typography.bodyLarge,
                        )
                        Text(
                            stringResource(R.string.settings_diagnostic_messages_description),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = showDiagnosticMessages,
                        onCheckedChange = onUpdateShowDiagnosticMessages,
                        enabled = onUpdateShowDiagnosticMessages != null,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Reader trust (RICAL) section - see PreLoginSettingsSheet's
        // identical controls for the full rationale; kept reachable here too
        // since flipping it mid-session (right before a proximity test) is
        // the common case, and this tab - unlike the pre-login sheet - is
        // still reachable once a wallet session is active.
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        ) {
            Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
                Text(
                    "Reader Trust (RICAL)",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Evaluate reader trust locally", style = MaterialTheme.typography.bodyLarge)
                        Text(
                            "Skip the remote RICAL trust check and validate proximity readers " +
                                "only against the root certificate below.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = preferLocalReaderTrustEvaluation,
                        onCheckedChange = onUpdatePreferLocalReaderTrustEvaluation,
                        enabled = onUpdatePreferLocalReaderTrustEvaluation != null,
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = readerTrustRootCertificatePem,
                    onValueChange = { onUpdateReaderTrustRootCertificatePem?.invoke(it) },
                    label = { Text("RICAL root certificate (PEM)") },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = onUpdateReaderTrustRootCertificatePem != null,
                    singleLine = false,
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Credential consumption policy section
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        ) {
            Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
                Text(
                    stringResource(R.string.settings_credential_consumption_title),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.settings_credential_consumption_description),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(12.dp))
                Column(Modifier.selectableGroup()) {
                    for (policy in org.siros.sdk.credentials.CredentialConsumptionPolicy.entries) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .selectable(
                                    selected = policy == credentialConsumptionPolicy,
                                    onClick = { onUpdateCredentialConsumptionPolicy?.invoke(policy) },
                                    role = Role.RadioButton,
                                    enabled = onUpdateCredentialConsumptionPolicy != null,
                                )
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(
                                selected = policy == credentialConsumptionPolicy,
                                onClick = { onUpdateCredentialConsumptionPolicy?.invoke(policy) },
                                enabled = onUpdateCredentialConsumptionPolicy != null,
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(stringResource(credentialConsumptionPolicyLabelRes(policy)), style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // WSCD settings - a single entry point into the consolidated,
        // tabbed WscdScreen (one tab per plugin: softkey/r2ps/fido2), which
        // now owns everything that used to be spread across four separate
        // cards here (WSCD Choices/TOFU, Preferred WSCD, WSCD Overrides,
        // WSCD Lifecycle/Enroll) plus the old standalone "WSCA Developer"
        // screen - see WscdScreen.kt's doc comment for the full
        // consolidation. Enroll/Rotate/Destroy/Refresh live in that
        // screen's collapsible Developer section, since they're
        // diagnostic/test actions, not something an end user taps
        // routinely.
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        ) {
            Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
                Text(
                    "Security Key (WSCD)",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    "Which secure key storage (software, R2PS remote HSM, or a FIDO2 security " +
                        "key) backs each credential, plus enrollment and developer diagnostics.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedButton(
                    onClick = onShowWscdSettings,
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text("WSCD Settings")
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Devices (wallet instances, SID-AUTH-06) - one entry point into the
        // Devices sub-screen, which owns the list and the two actions; this
        // card stays a link, like the WSCD one above.
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        ) {
            Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
                Text(
                    stringResource(R.string.devices_title),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.devices_description),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedButton(
                    onClick = onShowDevices,
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text(stringResource(R.string.devices_manage_button))
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Passkeys section
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        ) {
            Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
                Text("Passkeys", style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(modifier = Modifier.height(8.dp))
                if (passkeys.isEmpty()) {
                    Text("No passkeys registered", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    passkeys.forEach { passkey ->
                        var editing by remember { mutableStateOf(false) }
                        var nickname by remember { mutableStateOf(passkey.nickname) }
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            if (editing) {
                                OutlinedTextField(
                                    value = nickname,
                                    onValueChange = { nickname = it },
                                    modifier = Modifier.weight(1f),
                                    singleLine = true,
                                    shape = RoundedCornerShape(8.dp),
                                )
                                IconButton(onClick = {
                                    onRenamePasskey?.invoke(passkey.credentialId, nickname)
                                    editing = false
                                }) {
                                    Icon(Icons.Default.Check, contentDescription = "Save",
                                        modifier = Modifier.size(18.dp))
                                }
                                IconButton(onClick = { editing = false; nickname = passkey.nickname }) {
                                    Icon(Icons.Default.Close, contentDescription = "Cancel",
                                        modifier = Modifier.size(18.dp))
                                }
                            } else {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        passkey.nickname.ifEmpty { "Passkey ${passkey.credentialId.take(8)}..." },
                                        style = MaterialTheme.typography.bodyMedium,
                                    )
                                    Text(
                                        "ID: ${passkey.credentialId.take(16)}...",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                IconButton(onClick = { editing = true }) {
                                    Icon(Icons.Default.Edit, contentDescription = "Rename",
                                        modifier = Modifier.size(18.dp))
                                }
                            }
                        }
                    }
                }
            }
        }

        // Other accounts section (if there are cached accounts)
        if (state.cachedAccounts.size > 1) {
            Spacer(modifier = Modifier.height(16.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
                    Text("Other Accounts", style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(modifier = Modifier.height(8.dp))
                    state.cachedAccounts
                        .filter { it.accountId != "${tenantId}:${state.userId}" }
                        .forEach { account ->
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(account.displayName, modifier = Modifier.weight(1f),
                                    style = MaterialTheme.typography.bodyMedium)
                                Text(account.tenantId, style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                                if (onForgetAccount != null) {
                                    IconButton(onClick = { onForgetAccount(account.accountId) },
                                        modifier = Modifier.size(32.dp)) {
                                        Icon(Icons.Default.Close, contentDescription = "Remove",
                                            modifier = Modifier.size(16.dp))
                                    }
                                }
                            }
                        }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Presentation history link
        OutlinedButton(
            onClick = onShowHistory,
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(12.dp),
        ) {
            Text(stringResource(R.string.settings_presentation_history) + " ($presentationCount)")
        }

        Spacer(modifier = Modifier.height(32.dp))

        // Logout
        OutlinedButton(
            onClick = onDisconnect,
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(12.dp),
        ) {
            Text(stringResource(R.string.settings_logout))
        }

        // Delete account
        Spacer(modifier = Modifier.height(8.dp))
        var showDeleteConfirm by remember { mutableStateOf(false) }
        OutlinedButton(
            onClick = { showDeleteConfirm = true },
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
        ) {
            Text("Delete Account")
        }
        if (showDeleteConfirm) {
            androidx.compose.material3.AlertDialog(
                onDismissRequest = { showDeleteConfirm = false },
                title = { Text("Delete Account?") },
                text = { Text("This will remove all local data, credentials, and passkeys. This cannot be undone.") },
                confirmButton = {
                    TextButton(onClick = {
                        showDeleteConfirm = false
                        onDeleteAccount()
                    }) {
                        Text("Delete", color = MaterialTheme.colorScheme.error)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showDeleteConfirm = false }) {
                        Text("Cancel")
                    }
                },
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
private fun SettingsRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.primary,
        )
    }
}

// ── Flow Starting View ──────────────────────────────────────────────

/**
 * Transitional feedback step shown the instant a QR-triggered flow is handed
 * off to the wallet/engine, before the engine has reported back with the
 * first real [WalletState.FlowActive] progress step (or an error).
 *
 * Without this, closing the QR scanner leaves the user staring at whatever
 * screen was behind it with no indication anything is happening - long
 * enough against a slow issuer/verifier that a user may conclude the scan
 * didn't register and re-scan. This view has no progress fraction of its own
 * (there's no flow yet to report progress on) - it exists purely to bridge
 * that silent gap.
 */
@Composable
fun FlowStartingView(
    flowType: String?,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        SirosSpinner(progress = null)
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = when (flowType) {
                "issuance" -> stringResource(R.string.flow_starting_issuance)
                else -> stringResource(R.string.flow_starting_presentation)
            },
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Medium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.flow_starting_subtitle),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(32.dp))
        OutlinedButton(
            onClick = onCancel,
            shape = RoundedCornerShape(12.dp),
        ) {
            Text(stringResource(R.string.flow_cancel))
        }
    }
}

// ── Flow Active View ────────────────────────────────────────────────

@Composable
fun FlowActiveView(
    state: WalletState.FlowActive,
    onCancel: () -> Unit,
    showDiagnosticMessages: Boolean = true,
    modifier: Modifier = Modifier,
) {
    val stepProgress = flowStepProgress(state.flowType, state.status)

    // The visual must never sit frozen for the full duration of a
    // long-running step (most notably native ZK proof generation, which can
    // take real wall-clock time with zero intermediate progress signal from
    // the underlying Rust/Longfellow library) - so the displayed value is
    // decoupled from raw step-completion events via FlowProgressAnimator,
    // which eases the display value forward on its own ticker between real
    // events and snaps to the genuine value the instant one arrives. A fresh
    // animator per flowId keeps state from leaking across flows.
    val progressAnimator = remember(state.flowId) { FlowProgressAnimator() }
    val displayProgress by progressAnimator.displayProgress.collectAsState()
    LaunchedEffect(state.flowId) { progressAnimator.run() }
    LaunchedEffect(stepProgress) { progressAnimator.onRealProgress(stepProgress) }

    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        SirosSpinner(progress = if (stepProgress != null) displayProgress else null)
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = when (state.flowType) {
                "issuance" -> stringResource(R.string.flow_issuing)
                "presentation" -> stringResource(R.string.flow_presenting)
                else -> stringResource(R.string.flow_processing)
            },
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Medium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(flowStepLabelRes(state.status)),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (showDiagnosticMessages) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.flow_diagnostic_label, state.status),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
            )
        }
        Spacer(modifier = Modifier.height(32.dp))
        OutlinedButton(
            onClick = onCancel,
            shape = RoundedCornerShape(12.dp),
        ) {
            Text(stringResource(R.string.flow_cancel))
        }
    }
}

// ── Error View ──────────────────────────────────────────────────────

@Composable
fun ErrorView(message: String, onRetry: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = stringResource(R.string.error_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Medium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(24.dp))
        Button(onClick = onRetry, shape = RoundedCornerShape(12.dp)) {
            Text(stringResource(R.string.error_retry))
        }
    }
}
