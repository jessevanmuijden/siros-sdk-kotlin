// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.siros.sdk.wallet.TransactionConsentEntry
import org.siros.sdk.wallet.TransactionConsentField
import org.siros.sdk.wallet.TransactionConsentRequest

/**
 * How one transaction's fields are placed on the confirmation screen (EC TS12
 * 3.3.1): level 1 prominently, levels 2 and 3 on the main screen, level 4
 * omitted. The SDK orders and tags the fields; this only places them.
 */
class TransactionConsentLayout(
    val prominent: List<TransactionConsentField>,
    val main: List<TransactionConsentField>,
) {
    companion object {
        fun of(entry: TransactionConsentEntry): TransactionConsentLayout = TransactionConsentLayout(
            prominent = entry.fields.filter { it.level == 1 },
            main = entry.fields.filter { it.level == 2 || it.level == 3 },
        )
    }
}

/**
 * Shows a payment confirmation request built by the SDK and reports the
 * user's decision. Labels (title, affirmative and denial buttons, security
 * hint) come from the request; nothing here interprets the transaction.
 *
 * When [TransactionConsentRequest.requestSigned] is `false` the sender could
 * not be verified (EC TS12 3.1): a warning is shown and the confirm button
 * stays disabled until the user explicitly acknowledges it.
 */
@Composable
fun TransactionConsentDialog(
    request: TransactionConsentRequest,
    onConfirm: () -> Unit,
    onDeny: () -> Unit,
) {
    val unsigned = request.requestSigned == false
    var acknowledged by remember(request) { mutableStateOf(false) }
    // The SDK never builds a request without entries; if it ever did, there is nothing to confirm.
    val first = request.entries.firstOrNull() ?: run {
        LaunchedEffect(request) { onDeny() }
        return
    }

    AlertDialog(
        onDismissRequest = onDeny,
        title = { Text(first.title ?: stringResource(R.string.transaction_consent_default_title)) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                request.verifier?.let {
                    Text(stringResource(R.string.transaction_consent_requested_by, it), style = MaterialTheme.typography.bodySmall)
                }
                request.credentialName?.let {
                    Text(stringResource(R.string.transaction_consent_credential, it), style = MaterialTheme.typography.bodySmall)
                }
                if (unsigned) UnsignedWarning(acknowledged) { acknowledged = it }
                request.entries.forEachIndexed { index, entry ->
                    if (index > 0) HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
                    TransactionEntryView(entry)
                }
                // EC TS12 3.3.1: the transaction is shown together with the attributes that will be disclosed.
                DisclosuresView(request)
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm, enabled = !unsigned || acknowledged) {
                Text(first.affirmativeLabel)
            }
        },
        dismissButton = {
            TextButton(onClick = onDeny) {
                Text(first.denialLabel ?: stringResource(R.string.transaction_consent_default_deny))
            }
        },
    )
}

@Composable
private fun TransactionEntryView(entry: TransactionConsentEntry) {
    val layout = TransactionConsentLayout.of(entry)
    Column(modifier = Modifier.fillMaxWidth().padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        layout.prominent.forEach { f ->
            Column {
                Text(f.label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(f.value, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            }
        }
        layout.main.forEach { f ->
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(f.label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(f.value, style = MaterialTheme.typography.bodyMedium)
            }
        }
        entry.securityHint?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun UnsignedWarning(acknowledged: Boolean, onAcknowledged: (Boolean) -> Unit) {
    Spacer(Modifier.height(8.dp))
    Text(
        stringResource(R.string.transaction_consent_unsigned_warning),
        color = MaterialTheme.colorScheme.error,
        style = MaterialTheme.typography.bodyMedium,
    )
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = acknowledged, onCheckedChange = onAcknowledged)
        Text(stringResource(R.string.transaction_consent_unsigned_ack), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun DisclosuresView(request: TransactionConsentRequest) {
    if (request.disclosures.isEmpty()) return
    HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
    val all = stringResource(R.string.transaction_consent_discloses_all)
    request.disclosures.forEach { d ->
        val claims = d.claims?.takeIf { it.isNotEmpty() }?.joinToString(", ") ?: all
        Text(
            stringResource(R.string.transaction_consent_discloses, d.credentialName.orEmpty(), claims),
            style = MaterialTheme.typography.bodySmall,
        )
    }
}
