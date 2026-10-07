// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.siros.sdk.wallet.TransactionLogEntry
import org.siros.sdk.wallet.TransactionOutcome
import java.text.DateFormat
import java.util.Date

/** The wallet's record of payment confirmation attempts (EC TS12 5.3), newest first. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TransactionLogScreen(entries: List<TransactionLogEntry>, onBack: () -> Unit) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.transaction_log_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.transaction_log_back)) }
                },
            )
        },
    ) { padding ->
        if (entries.isEmpty()) {
            Text(
                stringResource(R.string.transaction_log_empty),
                modifier = Modifier.padding(padding).padding(24.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize().padding(padding)) {
                items(entries) { e ->
                    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
                        Text(
                            e.typeName ?: e.transactionType ?: stringResource(R.string.transaction_log_unknown_type),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            stringResource(
                                when (e.outcome) {
                                    TransactionOutcome.CONSENTED -> R.string.transaction_log_outcome_consented
                                    TransactionOutcome.DECLINED -> R.string.transaction_log_outcome_declined
                                    TransactionOutcome.REFUSED -> R.string.transaction_log_outcome_refused
                                },
                            ),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        e.transactionId?.let { Text(stringResource(R.string.transaction_log_id, it), style = MaterialTheme.typography.bodySmall) }
                        e.entities.forEach { (k, v) ->
                            val label = when (k) {
                                "payee" -> R.string.transaction_entity_payee
                                "pisp" -> R.string.transaction_entity_pisp
                                "service" -> R.string.transaction_entity_service
                                "aisp" -> R.string.transaction_entity_aisp
                                else -> null
                            }
                            Text(
                                if (label != null) stringResource(R.string.transaction_log_entity, stringResource(label), v) else v,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        e.verifier?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                        e.reason?.let { Text(stringResource(R.string.transaction_log_reason, it), style = MaterialTheme.typography.bodySmall) }
                        Spacer(Modifier.height(2.dp))
                        Text(
                            DateFormat.getDateTimeInstance().format(Date(e.timestampMillis)),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    HorizontalDivider()
                }
            }
        }
    }
}
