// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.siros.sdk.credentials.CredentialFamily
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.keystore.mdoc.BleCentralClient
import org.siros.sdk.keystore.mdoc.BlePeripheralServer
import org.siros.sdk.keystore.mdoc.DeviceEngagement
import org.siros.sdk.keystore.mdoc.NfcHandoverSelect
import org.siros.sdk.keystore.mdoc.ProximityConsentResult
import org.siros.sdk.keystore.mdoc.ReaderTrustResult
import org.siros.sdk.keystore.mdoc.RequestProximityConsent
import org.siros.sdk.keystore.mdoc.ActiveEngagement

/**
 * ISO 18013-5 §8.2/§9.2 device engagement, shown as a QR code (§8.2.2.3),
 * NFC static handover (§9.2.1, via [ActiveEngagement]/`MdocHostApduService`),
 * a real "mdoc peripheral server mode" BLE GATT server ([BlePeripheralServer]),
 * AND a real "mdoc central client mode" BLE GATT client ([BleCentralClient])
 * - the engagement offers both BLE modes (§8.2.2.3's `BleOptions`), and both
 * run simultaneously since it isn't known in advance which one a given
 * reader will pick; whichever one actually completes a presentation stops
 * the other. This is a genuinely completable proximity presentation, not
 * just an engagement demo, PROVIDED a stored credential's docType matches
 * what the reader asks for - and, now, provided the user approves the
 * consent dialog this screen shows once a matching credential is found.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProximityEngagementScreen(
    getCredentials: suspend () -> List<StoredCredential>,
    signPresentation: suspend (credentialId: Long, disclosedClaims: List<String>?, sessionTranscriptBytes: ByteArray) -> ByteArray,
    filterEligible: suspend (List<StoredCredential>) -> List<StoredCredential>,
    evaluateReaderTrust: suspend (x5chain: List<ByteArray>) -> ReaderTrustResult,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val engagement = remember {
        DeviceEngagement.create(supportsCentralClientMode = true, supportsPeripheralServerMode = true)
    }
    val qrBitmap = remember(engagement) { QrCodeGenerator.generate(engagement.mdocUri) }

    val blePermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        listOf(
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.BLUETOOTH_SCAN,
        )
    } else {
        // BLUETOOTH_ADVERTISE/CONNECT don't exist pre-S (peripheral-server
        // mode already worked without them via the legacy BLUETOOTH/
        // BLUETOOTH_ADMIN manifest permissions) - but scanning for
        // central-client-mode needs this classic runtime permission on
        // API 28-30, since BLUETOOTH_SCAN's neverForLocation exemption is
        // an S+-only concept.
        listOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
    }
    var hasBlePermissions by remember {
        mutableStateOf(
            blePermissions.all {
                ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
            },
        )
    }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { results -> hasBlePermissions = results.values.all { it } }

    LaunchedEffect(Unit) {
        if (!hasBlePermissions && blePermissions.isNotEmpty()) {
            permissionLauncher.launch(blePermissions.toTypedArray())
        }
    }

    var currentStep by remember { mutableStateOf("waiting_for_reader") }
    var result by remember { mutableStateOf<Boolean?>(null) }
    var blePermissionsDenied by remember { mutableStateOf(false) }
    var pendingConsent by remember { mutableStateOf<PendingConsent?>(null) }
    // Per-role outcome, so a terminal failure is only reported once BOTH
    // BLE roles have finished unsuccessfully - the two run concurrently, and
    // one failing (e.g. central-client mode never finding a reader) must
    // not preempt the other still succeeding shortly after.
    var peripheralOutcome by remember { mutableStateOf<Boolean?>(null) }
    var centralOutcome by remember { mutableStateOf<Boolean?>(null) }
    // BLE callbacks run on Dispatchers.IO (see BlePeripheralServer/
    // BleCentralClient) - Compose state writes must happen on the main
    // thread, so every onStep/onComplete hops here first.
    val uiScope = rememberCoroutineScope()

    // Bridges BlePeripheralServer/BleCentralClient's suspending consent
    // request to this screen's AlertDialog: suspends the caller (a
    // background BLE coroutine running on Dispatchers.IO) until the user
    // taps Approve or Deny. withContext(Main.immediate) hops back to the
    // main thread first - Compose state writes (pendingConsent) must
    // happen there, not on IO.
    val requestConsent: RequestProximityConsent = { docType, requestedClaims, matchingFamilies, readerTrust ->
        withContext(Dispatchers.Main.immediate) {
            suspendCancellableCoroutine { continuation ->
                val consent = PendingConsent(
                    docType = docType,
                    requestedClaims = requestedClaims,
                    matchingFamilies = matchingFamilies,
                    readerTrust = readerTrust,
                    respond = { chosen ->
                        pendingConsent = null
                        if (continuation.isActive) {
                            continuation.resume(
                                if (chosen != null) ProximityConsentResult.Approved(chosen) else ProximityConsentResult.Denied,
                                onCancellation = null,
                            )
                        }
                    },
                )
                pendingConsent = consent
                // If this suspended call is itself cancelled (e.g. the BLE
                // role's coroutine scope is torn down by stop() while the
                // user hasn't answered yet), clear the dialog rather than
                // leaving a stale request on screen with no way to resolve it.
                continuation.invokeOnCancellation {
                    if (pendingConsent === consent) pendingConsent = null
                }
            }
        }
    }

    DisposableEffect(engagement) {
        ActiveEngagement.handoverSelectBytes = NfcHandoverSelect.build(engagement)
        onDispose { ActiveEngagement.handoverSelectBytes = null }
    }

    DisposableEffect(engagement, hasBlePermissions) {
        var peripheralServer: BlePeripheralServer? = null
        var centralClient: BleCentralClient? = null
        if (hasBlePermissions) {
            blePermissionsDenied = false
            peripheralServer = BlePeripheralServer(
                context = context,
                engagement = engagement,
                getHandoverSelectBytes = { ActiveEngagement.handoverSelectBytes },
                getCredentials = getCredentials,
                signPresentation = signPresentation,
                requestConsent = requestConsent,
                filterEligible = filterEligible,
                evaluateReaderTrust = evaluateReaderTrust,
                onStep = { step -> uiScope.launch(Dispatchers.Main.immediate) { currentStep = step } },
                onComplete = { success ->
                    uiScope.launch(Dispatchers.Main.immediate) {
                        peripheralOutcome = success
                        if (success) {
                            // Whichever mode the reader actually picked has
                            // now finished - the other is just wasting radio
                            // time scanning/advertising for a connection
                            // that will never come, so stop it.
                            centralClient?.stop()
                            result = true
                        } else {
                            // This role's own session is done regardless of
                            // whether the other role has also finished - its
                            // GATT server/advertising must be torn down now,
                            // not left alive until the whole screen disposes.
                            // Without this, a reader that already received
                            // (or was denied) a response is left waiting on a
                            // connection nothing will ever answer again -
                            // confirmed live via a OneProof interop capture
                            // where the reader sat stuck for 90+ seconds
                            // after this role's own "no matching credential"
                            // failure, until the user manually backed out.
                            peripheralServer?.stop()
                            // Only report terminal failure once the OTHER
                            // role has also finished/failed - it may yet
                            // succeed on its own.
                            if (centralOutcome != null) {
                                result = false
                            }
                        }
                    }
                },
            )
            fun startCentralClient() {
                centralClient?.stop()
                centralOutcome = null
                centralClient = BleCentralClient(
                    context = context,
                    engagement = engagement,
                    getHandoverSelectBytes = { ActiveEngagement.handoverSelectBytes },
                    getCredentials = getCredentials,
                    signPresentation = signPresentation,
                    requestConsent = requestConsent,
                    filterEligible = filterEligible,
                    evaluateReaderTrust = evaluateReaderTrust,
                    onStep = { step -> uiScope.launch(Dispatchers.Main.immediate) { currentStep = step } },
                    onComplete = { success ->
                        uiScope.launch(Dispatchers.Main.immediate) {
                            centralOutcome = success
                            if (success) {
                                peripheralServer?.stop()
                                result = true
                            } else {
                                // See the peripheralServer onComplete's matching
                                // comment above - same reasoning, mirrored role.
                                centralClient?.stop()
                                if (peripheralOutcome != null) {
                                    result = false
                                }
                            }
                        }
                    },
                ).also { it.start() }
            }
            startCentralClient()
            peripheralServer.start()
            // A physical NFC tap completes at an unpredictable, possibly much
            // later time than this effect running (walk up, position, hold
            // steady - real seconds, not milliseconds) - see
            // ActiveEngagement.onHandoverServed's doc comment. A reader that
            // picked mdoc central client mode via NFC can only start
            // advertising for BleCentralClient to find once it actually has
            // the engagement, so give the scan a fresh window at exactly
            // that moment rather than trusting the window that started when
            // this effect first ran (which may already be gone).
            ActiveEngagement.onHandoverServed = {
                uiScope.launch(Dispatchers.Main.immediate) {
                    // Deliberately NOT gated on centralOutcome == null: the
                    // very common case is that the FIRST central-client scan
                    // (started at mount, before the physical NFC tap even
                    // happens) already timed out and set centralOutcome to
                    // false well before this signal fires - that's exactly
                    // the stale failure this restart exists to override, not
                    // a reason to skip it. Only the overall result matters:
                    // once the whole presentation has concluded (either way),
                    // there's nothing left to restart for.
                    if (result == null) {
                        startCentralClient()
                    }
                }
            }
        } else {
            blePermissionsDenied = true
        }
        onDispose {
            ActiveEngagement.onHandoverServed = null
            peripheralServer?.stop()
            centralClient?.stop()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Tap to share") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when {
            result != null -> ProximityTerminalView(
                success = result == true,
                onClose = onBack,
                modifier = Modifier.fillMaxSize().padding(padding),
            )
            currentStep != "waiting_for_reader" -> ProximityProgressView(
                step = currentStep,
                onCancel = onBack,
                modifier = Modifier.fillMaxSize().padding(padding),
            )
            else -> Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text(
                    text = "Scan with an ISO 18013-5 mdoc reader",
                    style = MaterialTheme.typography.titleMedium,
                    textAlign = TextAlign.Center,
                )
                Spacer(modifier = Modifier.height(16.dp))
                Image(
                    bitmap = qrBitmap.asImageBitmap(),
                    contentDescription = "Device engagement QR code",
                    modifier = Modifier.fillMaxWidth().height(280.dp),
                )
                Spacer(modifier = Modifier.height(16.dp))
                HorizontalDivider()
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = if (blePermissionsDenied) {
                        "Bluetooth permissions not granted - BLE data retrieval disabled " +
                            "(QR/NFC engagement still active)."
                    } else {
                        "NFC is also active: tap this device against a reader's NFC antenna " +
                            "for static handover instead of scanning the QR code. Both BLE data " +
                            "retrieval modes are active - peripheral server mode is advertising, and " +
                            "central client mode is scanning for a reader - a real reader can " +
                            "complete a presentation via whichever mode it supports, if a stored " +
                            "credential matches its requested docType."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }

    pendingConsent?.let { consent ->
        ProximityConsentDialog(consent, filterEligible)
    }
}

/**
 * Progress bar + step label for an in-flight proximity presentation, once a
 * reader has connected - mirrors [FlowActiveView]'s look for the
 * issuance/redirect-presentation flows, using the "proximity" step list.
 *
 * Includes an explicit, labeled Cancel action (mirroring [FlowActiveView]'s
 * own Cancel button) for every in-flight step, including
 * `"submitting_response"` right before the mdoc response is signed/sent -
 * previously the only escape hatch here was the generic TopAppBar back
 * arrow, which happened to abort the BLE session as a side effect
 * ([ProximityEngagementScreen]'s `onDispose`) but wasn't a visible, labeled
 * affordance. [onCancel] reuses that exact same abort path (it's the
 * screen's `onBack`) rather than inventing a second mechanism.
 */
@Composable
private fun ProximityProgressView(step: String, onCancel: () -> Unit, modifier: Modifier = Modifier) {
    val stepProgress = flowStepProgress("proximity", step)

    // Same decoupled-from-step-completion animator as FlowActiveView: real
    // execution order can deviate slightly (e.g. both BLE modes reporting
    // steps interleaved before one wins), and a long-running step (e.g. ZK
    // proof generation ahead of `"submitting_response"`) has no intermediate
    // progress signal of its own - see FlowProgressAnimator's doc comment.
    val progressAnimator = remember { FlowProgressAnimator() }
    val displayProgress by progressAnimator.displayProgress.collectAsState()
    LaunchedEffect(Unit) { progressAnimator.run() }
    LaunchedEffect(stepProgress) { progressAnimator.onRealProgress(stepProgress) }

    Column(
        modifier = modifier.padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        SirosSpinner(progress = if (stepProgress != null) displayProgress else null)
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = stringResource(R.string.flow_presenting),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Medium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(flowStepLabelRes(step)),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
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

/**
 * Terminal state once a proximity presentation has completed or failed -
 * shows a clear "Close" action rather than "Cancel", since there is nothing
 * left to cancel: per the user's explicit requirement, this UX must not
 * offer a Cancel button once the flow is done.
 */
@Composable
private fun ProximityTerminalView(success: Boolean, onClose: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            imageVector = if (success) Icons.Filled.CheckCircle else Icons.Filled.Error,
            contentDescription = null,
            tint = if (success) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            modifier = Modifier.height(64.dp).width(64.dp),
        )
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = stringResource(
                if (success) R.string.flow_presentation_sent else R.string.proximity_presentation_failed,
            ),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Medium,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(32.dp))
        Button(onClick = onClose) {
            Text(stringResource(R.string.flow_close))
        }
    }
}

/** Holds one in-flight consent request's details plus how to answer it - see [RequestProximityConsent]. */
private data class PendingConsent(
    val docType: String,
    val requestedClaims: List<String>,
    val matchingFamilies: List<CredentialFamily>,
    /** See [RequestProximityConsent]'s `readerTrust` parameter doc comment. */
    val readerTrust: ReaderTrustResult?,
    /** Call with the chosen family to approve, or null to deny. */
    val respond: (CredentialFamily?) -> Unit,
)

/**
 * RICAL reader-trust indicator for the consent dialog (Geneva 2026 interop
 * requirement: reader trust must be a visible, distinguishable signal, not
 * enforced/blocking - see this session's RICAL plan). Three states:
 * trusted (verified signature + trusted chain), untrusted (verified
 * signature but an untrusted/unresolved chain), and no badge at all when
 * [readerTrust] is null - see [ReaderTrustResult]'s doc comment for why "no
 * `readerAuth`/invalid signature" is deliberately silent rather than shown
 * as "untrusted".
 */
@Composable
private fun ReaderTrustBadge(readerTrust: ReaderTrustResult?) {
    if (readerTrust == null) return
    val (icon, tint, label) = if (readerTrust.trusted) {
        Triple(Icons.Filled.CheckCircle, MaterialTheme.colorScheme.primary, "Trusted reader" + (readerTrust.entityName?.let { ": $it" } ?: ""))
    } else {
        Triple(Icons.Filled.Error, MaterialTheme.colorScheme.error, "Reader identity not trusted" + (readerTrust.reason?.let { " ($it)" } ?: ""))
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.height(18.dp).width(18.dp))
        Spacer(modifier = Modifier.width(6.dp))
        Text(label, style = MaterialTheme.typography.labelMedium, color = tint)
    }
}

@Composable
private fun ProximityConsentDialog(consent: PendingConsent, filterEligible: suspend (List<StoredCredential>) -> List<StoredCredential>) {
    // A family with zero eligible instances (every copy already used under
    // the active consumption policy, OR its signing key was lost - see
    // CredentialUtils.eligibleInstances's doc comment) is shown, not
    // silently omitted - so the user isn't confused about where their
    // credential went - but disabled: the SDK refuses to sign with an
    // exhausted/keyless instance regardless (defense in depth), so letting
    // the user pick one here would just fail later.
    //
    // filterEligible is suspend (it needs a live keystore.listKeys() round
    // trip), so this can't be a plain `remember` - computed once per
    // [consent] in a LaunchedEffect instead, re-picking [selected] onto a
    // real eligible family once the async result lands if the synchronous
    // initial guess (matchingFamilies.first()) wasn't already one.
    var eligibleFamilies by remember(consent) { mutableStateOf(emptySet<CredentialFamily>()) }
    var selected by remember(consent) { mutableStateOf(consent.matchingFamilies.first()) }
    LaunchedEffect(consent) {
        val result = mutableSetOf<CredentialFamily>()
        for (family in consent.matchingFamilies) {
            if (filterEligible(family.instances).isNotEmpty()) result += family
        }
        eligibleFamilies = result
        if (selected !in result) {
            selected = consent.matchingFamilies.firstOrNull { it in result } ?: selected
        }
    }
    val selectedIsEligible = selected in eligibleFamilies

    AlertDialog(
        onDismissRequest = { consent.respond(null) },
        title = { Text("Share credential?") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                // A real, recognizable preview of the actual credential -
                // not just its raw docType string - so the user can tell at
                // a glance whether this is really their own mDL/etc.
                CredentialCard(credential = selected.representative, modifier = Modifier.fillMaxWidth())
                Spacer(modifier = Modifier.height(16.dp))
                ReaderTrustBadge(consent.readerTrust)
                Spacer(modifier = Modifier.height(8.dp))
                Text("A reader is requesting the following, from this credential:", style = MaterialTheme.typography.bodyMedium)
                Spacer(modifier = Modifier.height(8.dp))
                for (claim in consent.requestedClaims) {
                    Text("• $claim", style = MaterialTheme.typography.bodyMedium)
                }
                if (consent.matchingFamilies.size > 1) {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text("You have more than one matching credential - choose which to share:", style = MaterialTheme.typography.labelLarge)
                    Spacer(modifier = Modifier.height(4.dp))
                    Column(Modifier.selectableGroup()) {
                        for (family in consent.matchingFamilies) {
                            val credential = family.representative
                            val isEligible = family in eligibleFamilies
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .selectable(
                                        selected = family == selected,
                                        onClick = { selected = family },
                                        role = Role.RadioButton,
                                        enabled = isEligible,
                                    )
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RadioButton(selected = family == selected, onClick = { selected = family }, enabled = isEligible)
                                Spacer(modifier = Modifier.width(8.dp))
                                Column {
                                    Text(
                                        text = credential.metadata?.vct ?: credential.metadata?.doctype ?: consent.docType,
                                        color = if (isEligible) {
                                            MaterialTheme.colorScheme.onSurface
                                        } else {
                                            MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                                        },
                                    )
                                    if (!isEligible) {
                                        Text(
                                            text = "No copies left - renew in Settings",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.error,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { consent.respond(selected) }, enabled = selectedIsEligible) { Text("Share") }
        },
        dismissButton = {
            TextButton(onClick = { consent.respond(null) }) { Text("Decline") }
        },
    )
}
