// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import org.siros.sdk.keystore.Fido2TransportMode
import kotlin.math.min

/**
 * Shown between PIN entry and the actual CTAP2 ceremony completing (see
 * [WalletViewModel.fido2AwaitingPresentation]'s doc comment for why PIN
 * entry and physical presentation are deliberately split into two steps).
 * Purely instructional - there's nothing to submit here, just a "Cancel"
 * escape hatch (via [WalletViewModel.cancelWscdLifecycleOp]) for a user who
 * changes their mind or can't get the key to respond.
 *
 * [mode] selects which illustration(s) to show: [Fido2TransportMode.AUTO]
 * (the default) doesn't know in advance which transport the user will
 * present, so it shows both NFC and USB instructions; [Fido2TransportMode.USB]/
 * [Fido2TransportMode.NFC] show only the relevant one.
 *
 * [discovering] is true for enrolment's FIRST tap - the SDK only describes the key there (no PIN has been asked for
 * or accepted yet - see [Fido2EnrolmentSession][org.siros.sdk.keystore.Fido2EnrolmentSession]'s doc comment), so the
 * text says to present the key, not that a PIN was accepted.
 */
@Composable
fun Fido2PresentKeyGuide(mode: Fido2TransportMode, discovering: Boolean = false, onCancel: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Present your security key") },
        text = {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (discovering) {
                        "Present the physical key and hold it in place - the " +
                            "wallet needs to look at it before it can continue."
                    } else {
                        "Your PIN has been accepted. Both hands are now free - " +
                            "present the physical key and hold it in place until " +
                            "this finishes."
                    },
                    textAlign = TextAlign.Center,
                )
                if (mode == Fido2TransportMode.AUTO || mode == Fido2TransportMode.NFC) {
                    NfcTapIllustration()
                    Text(
                        "NFC: hold the key flat against the back of the phone, " +
                            "roughly in the upper third - exact spot varies by " +
                            "phone model.",
                        textAlign = TextAlign.Center,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (mode == Fido2TransportMode.AUTO || mode == Fido2TransportMode.USB) {
                    UsbPlugIllustration()
                    Text(
                        "USB: keep the key plugged in.",
                        textAlign = TextAlign.Center,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onCancel) { Text("Cancel") }
        },
    )
}

/** A phone silhouette with a key shape held near its top edge and a pulsing NFC wave. */
@Composable
private fun NfcTapIllustration() {
    val transition = rememberInfiniteTransition(label = "nfc-pulse")
    val pulse by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1400, easing = LinearEasing), RepeatMode.Restart),
        label = "nfc-pulse-value",
    )
    val outline = MaterialTheme.colorScheme.onSurfaceVariant
    val accent = MaterialTheme.colorScheme.primary

    Canvas(modifier = Modifier.fillMaxWidth().height(120.dp)) {
        val phoneWidth = min(size.width * 0.34f, 70.dp.toPx())
        val phoneHeight = phoneWidth * 2f
        val phoneLeft = size.width / 2f - phoneWidth / 2f
        val phoneTop = size.height / 2f - phoneHeight / 2f
        val corner = 10.dp.toPx()

        drawRoundRect(
            color = outline,
            topLeft = Offset(phoneLeft, phoneTop),
            size = androidx.compose.ui.geometry.Size(phoneWidth, phoneHeight),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(corner, corner),
            style = Stroke(width = 3.dp.toPx()),
        )

        // The key: a small rounded pill positioned over the phone's upper-back area.
        val tapCenter = Offset(phoneLeft + phoneWidth / 2f, phoneTop + phoneHeight * 0.28f)
        val keyWidth = phoneWidth * 0.55f
        val keyHeight = phoneWidth * 0.95f
        drawRoundRect(
            color = accent,
            topLeft = Offset(tapCenter.x - keyWidth / 2f, tapCenter.y - keyHeight / 2f),
            size = androidx.compose.ui.geometry.Size(keyWidth, keyHeight),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(keyWidth / 3f, keyWidth / 3f),
        )

        // Pulsing NFC wave: two arcs expanding outward and fading, looping.
        for (i in 0..1) {
            val phase = ((pulse + i * 0.5f) % 1f)
            val radius = phoneWidth * (0.55f + phase * 0.65f)
            val alpha = (1f - phase).coerceIn(0f, 1f)
            drawArc(
                color = accent.copy(alpha = alpha * 0.8f),
                startAngle = -55f,
                sweepAngle = 110f,
                useCenter = false,
                topLeft = Offset(tapCenter.x - radius, tapCenter.y - radius),
                size = androidx.compose.ui.geometry.Size(radius * 2f, radius * 2f),
                style = Stroke(width = 3.dp.toPx()),
            )
        }
    }
}

/** A phone silhouette with a connector plugging into its bottom edge. */
@Composable
private fun UsbPlugIllustration() {
    val outline = MaterialTheme.colorScheme.onSurfaceVariant
    val accent = MaterialTheme.colorScheme.primary

    Canvas(modifier = Modifier.fillMaxWidth().height(90.dp)) {
        val phoneWidth = min(size.width * 0.34f, 70.dp.toPx())
        val phoneHeight = phoneWidth * 1.8f
        val phoneLeft = size.width / 2f - phoneWidth / 2f
        val phoneTop = size.height / 2f - phoneHeight / 2f + 10.dp.toPx()
        val corner = 10.dp.toPx()

        drawRoundRect(
            color = outline,
            topLeft = Offset(phoneLeft, phoneTop),
            size = androidx.compose.ui.geometry.Size(phoneWidth, phoneHeight),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(corner, corner),
            style = Stroke(width = 3.dp.toPx()),
        )

        // USB-C port notch at the bottom edge.
        val portWidth = phoneWidth * 0.22f
        val portCenterX = phoneLeft + phoneWidth / 2f
        val portTop = phoneTop + phoneHeight - 3.dp.toPx()
        drawRoundRect(
            color = outline,
            topLeft = Offset(portCenterX - portWidth / 2f, portTop),
            size = androidx.compose.ui.geometry.Size(portWidth, 6.dp.toPx()),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(3.dp.toPx(), 3.dp.toPx()),
        )

        // Key connector plugged in from below, as a small rectangle + connecting line.
        val connectorWidth = portWidth * 0.8f
        val connectorHeight = 24.dp.toPx()
        val connectorTop = portTop + 6.dp.toPx()
        drawRoundRect(
            color = accent,
            topLeft = Offset(portCenterX - connectorWidth / 2f, connectorTop),
            size = androidx.compose.ui.geometry.Size(connectorWidth, connectorHeight),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(4.dp.toPx(), 4.dp.toPx()),
        )
        drawRoundRect(
            color = accent,
            topLeft = Offset(portCenterX - phoneWidth * 0.3f, connectorTop + connectorHeight),
            size = androidx.compose.ui.geometry.Size(phoneWidth * 0.6f, phoneWidth * 0.45f),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(6.dp.toPx(), 6.dp.toPx()),
        )
    }
}
