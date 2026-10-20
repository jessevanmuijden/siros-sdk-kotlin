// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.siros.sdk.credentials.PresentationConsentRequest
import org.siros.sdk.wallet.ConsentScreen
import org.siros.sdk.wallet.PresentationConsentText

/**
 * Asks for consent to a `circuit_zk` presentation. The SDK built the request and owns the wording
 * ([PresentationConsentText]); this only renders [ConsentScreen] and reports the decision. The verifier id
 * value is shown on a detail line (long ones shortened in the middle; tap to see the whole value).
 */
@Composable
fun PresentationConsentDialog(request: PresentationConsentRequest, onAgree: () -> Unit, onDecline: () -> Unit) {
    val context = LocalContext.current
    val screen = remember(request) { PresentationConsentText.forContext(context).render(request) }
    PresentationConsentContent(screen, onAgree, onDecline)
}

@Composable
internal fun PresentationConsentContent(screen: ConsentScreen, onAgree: () -> Unit, onDecline: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDecline,
        title = { Text(screen.title) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                Text(screen.header, style = MaterialTheme.typography.bodyMedium)
                screen.verifierDetail?.let { detail ->
                    var expanded by remember(detail) { mutableStateOf(false) }
                    Text(
                        if (expanded) detail.full else detail.shortened,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.clickable { expanded = !expanded },
                    )
                }
                screen.entries.forEach { entry ->
                    entry.credentialName?.let { Text(it, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 12.dp)) }
                    entry.issuerName?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                    entry.lines.forEach { Text(it, modifier = Modifier.padding(top = 6.dp)) }
                }
                Text(screen.footer, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 12.dp))
            }
        },
        confirmButton = { TextButton(onClick = onAgree) { Text(screen.shareLabel) } },
        dismissButton = { TextButton(onClick = onDecline) { Text(screen.cancelLabel) } },
    )
}
