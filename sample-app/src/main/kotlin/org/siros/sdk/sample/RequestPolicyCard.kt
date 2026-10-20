package org.siros.sdk.sample

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.siros.sdk.wallet.NonDisclosureMode
import org.siros.sdk.wallet.SignedRequestRule
import org.siros.sdk.wallet.VerifierIdTypeOrder
import org.siros.sdk.wallet.WalletPolicyOptions
import org.siros.sdk.wallet.dcapi.ExpectedOriginsMode

/**
 * The wallet's request policy as settings. A thin view over
 * [WalletPolicyOptions]: every decision lives in the SDK, this only edits the
 * data and hands it back. Applied when the wallet is next created.
 */
@Composable
fun RequestPolicyCard(
    policy: WalletPolicyOptions,
    onChange: ((WalletPolicyOptions) -> Unit)?,
    modifier: Modifier = Modifier,
) {
    val enabled = onChange != null
    fun update(new: WalletPolicyOptions) = onChange?.invoke(new)
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
            Text(
                stringResource(R.string.settings_policy_title),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                stringResource(R.string.settings_policy_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(12.dp))

            PolicyChoice(
                title = R.string.settings_policy_non_disclosure,
                options = NonDisclosureMode.entries,
                selected = policy.nonDisclosure,
                label = { if (it == NonDisclosureMode.DEFAULT) R.string.settings_policy_non_disclosure_default else R.string.settings_policy_non_disclosure_none },
                enabled = enabled,
            ) { update(policy.copy(nonDisclosure = it)) }

            PolicySwitch(R.string.settings_policy_circuit_zk, R.string.settings_policy_circuit_zk_description, policy.circuitZk, enabled) {
                update(policy.copy(circuitZk = it))
            }
            PolicySwitch(
                R.string.settings_policy_fake_prover, R.string.settings_policy_fake_prover_description,
                policy.fakeProver, enabled && policy.circuitZk,
            ) { update(policy.copy(fakeProver = it)) }

            PolicyChoice(
                title = R.string.settings_policy_expected_origins,
                options = ExpectedOriginsMode.entries,
                selected = policy.expectedOrigins,
                label = {
                    when (it) {
                        ExpectedOriginsMode.OFF -> R.string.settings_policy_origins_off
                        ExpectedOriginsMode.IF_PRESENT -> R.string.settings_policy_origins_if_present
                        ExpectedOriginsMode.REQUIRED -> R.string.settings_policy_origins_required
                    }
                },
                enabled = enabled,
            ) { update(policy.copy(expectedOrigins = it)) }

            PolicyChoice(
                title = R.string.settings_policy_signed_request,
                options = SignedRequestRule.entries,
                selected = policy.signedRequest,
                label = { if (it == SignedRequestRule.CIRCUIT_ZK_ONLY) R.string.settings_policy_signed_circuit_zk_only else R.string.settings_policy_signed_always },
                enabled = enabled,
            ) { update(policy.copy(signedRequest = it)) }

            Text(
                stringResource(R.string.settings_policy_verifier_ids),
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                stringResource(R.string.settings_policy_verifier_ids_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val types = policy.verifierIdTypes
            if (types.isEmpty()) {
                Text(
                    stringResource(R.string.settings_policy_verifier_ids_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            types.forEachIndexed { index, type ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("${index + 1}. $type", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                    TextButton(
                        onClick = { update(policy.copy(verifierIdTypes = VerifierIdTypeOrder.move(types, index, -1))) },
                        enabled = enabled && index > 0,
                    ) { Text(stringResource(R.string.settings_policy_verifier_ids_up)) }
                    TextButton(
                        onClick = { update(policy.copy(verifierIdTypes = VerifierIdTypeOrder.move(types, index, 1))) },
                        enabled = enabled && index < types.lastIndex,
                    ) { Text(stringResource(R.string.settings_policy_verifier_ids_down)) }
                    TextButton(
                        onClick = { update(policy.copy(verifierIdTypes = VerifierIdTypeOrder.remove(types, index))) },
                        enabled = enabled,
                    ) { Text(stringResource(R.string.settings_policy_verifier_ids_remove)) }
                }
            }
            var draft by remember { mutableStateOf("") }
            val added = VerifierIdTypeOrder.add(types, draft)
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    label = { Text(stringResource(R.string.settings_policy_verifier_ids_new)) },
                    singleLine = true,
                    enabled = enabled,
                    modifier = Modifier.weight(1f),
                )
                TextButton(
                    onClick = { added?.let { update(policy.copy(verifierIdTypes = it)); draft = "" } },
                    enabled = enabled && added != null,
                ) { Text(stringResource(R.string.settings_policy_verifier_ids_add)) }
            }
            TextButton(
                onClick = { update(policy.copy(verifierIdTypes = VerifierIdTypeOrder.DEFAULT)) },
                enabled = enabled && types != VerifierIdTypeOrder.DEFAULT,
            ) { Text(stringResource(R.string.settings_policy_verifier_ids_reset)) }
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.settings_policy_applies_next),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun PolicySwitch(title: Int, description: Int, checked: Boolean, enabled: Boolean, onChecked: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(stringResource(title), style = MaterialTheme.typography.bodyLarge)
            Text(stringResource(description), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onChecked, enabled = enabled)
    }
}

@Composable
private fun <T> PolicyChoice(
    title: Int,
    options: List<T>,
    selected: T,
    label: (T) -> Int,
    enabled: Boolean,
    onSelect: (T) -> Unit,
) {
    Text(stringResource(title), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(top = 8.dp))
    Column(Modifier.selectableGroup()) {
        for (option in options) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .selectable(selected = option == selected, onClick = { onSelect(option) }, role = Role.RadioButton, enabled = enabled)
                    .padding(vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = option == selected, onClick = null, enabled = enabled)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(label(option)), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}
