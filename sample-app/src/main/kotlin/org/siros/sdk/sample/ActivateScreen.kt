// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.runtime.Composable
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.keystore.mdoc.ReaderTrustResult
import org.siros.sdk.sample.WalletViewModel.ActivateMode

/**
 * Merged QR scan + ISO 18013-5 proximity (BLE) engagement screen. QR scanning
 * is the default mode; [QrScannerScreen] surfaces a low-emphasis
 * "use proximity instead" CTA that calls [onUseProximityInstead] to switch.
 *
 * This is a thin dispatcher, not a refactor of either underlying screen -
 * [QrScannerScreen] and [ProximityEngagementScreen] each keep their own
 * Scaffold/TopAppBar, so switching modes is a plain content swap with no
 * shared chrome to keep in sync. Both screens' [onBack] always means "leave
 * Activate entirely" - switching to proximity mode is forward-only, back
 * never returns to QR from proximity.
 */
@Composable
fun ActivateScreen(
    mode: ActivateMode,
    onQrScanned: (String) -> Unit,
    onUseProximityInstead: () -> Unit,
    getCredentials: suspend () -> List<StoredCredential>,
    signPresentation: suspend (credentialId: Long, disclosedClaims: List<String>?, sessionTranscriptBytes: ByteArray) -> ByteArray,
    filterEligible: suspend (List<StoredCredential>) -> List<StoredCredential>,
    evaluateReaderTrust: suspend (x5chain: List<ByteArray>) -> ReaderTrustResult,
    onBack: () -> Unit,
) {
    when (mode) {
        ActivateMode.Qr -> QrScannerScreen(
            onQrScanned = onQrScanned,
            onBack = onBack,
            onUseProximityInstead = onUseProximityInstead,
        )
        ActivateMode.Proximity -> ProximityEngagementScreen(
            getCredentials = getCredentials,
            signPresentation = signPresentation,
            filterEligible = filterEligible,
            evaluateReaderTrust = evaluateReaderTrust,
            onBack = onBack,
        )
    }
}
