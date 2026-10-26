// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.IconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.res.stringResource
import org.siros.sdk.keystore.PinRequest
import org.siros.sdk.keystore.R as KeystoreR

/**
 * Shown when [WalletViewModel]'s `requestFido2Pin` bridge fires - the
 * WSCD asking for the authenticator's real CTAP2 ClientPin PIN (see
 * [PendingPinEntry]'s doc comment). Enter it wrong too many times and
 * the authenticator enforces its own retry lockout (`CTAP2_ERR_PIN_INVALID`,
 * then a transient `CTAP2_ERR_PIN_AUTH_BLOCKED` clearable only by a power
 * cycle) - this dialog has no way to know the correct PIN in advance, so
 * it can't guard against that itself.
 *
 * CTAP2 PINs aren't necessarily numeric (FIDO2 allows any UTF-8 PIN), so
 * this uses a general password keyboard rather than a numeric one.
 */
@Composable
fun PinEntryDialog(pending: PendingPinEntry, onSubmit: (String?) -> Unit) {
    var pin by remember(pending) { mutableStateOf("") }
    var pinVisible by remember(pending) { mutableStateOf(false) }
    val focusRequester = remember(pending) { FocusRequester() }

    LaunchedEffect(pending) { focusRequester.requestFocus() }

    AlertDialog(
        onDismissRequest = { onSubmit(null) },
        title = {
            val request = pending.request
            Text(
                when {
                    request is PinRequest.Choose && request.confirm -> stringResource(KeystoreR.string.siros_pin_confirm_title)
                    request is PinRequest.Choose -> stringResource(KeystoreR.string.siros_pin_choose_title)
                    else -> "Enter security key PIN"
                },
            )
        },
        text = {
            Column {
            // Why the user is asked again; the SDK's own short localised text.
            pending.request.notice?.let { notice ->
                val minLength = (pending.request as? PinRequest.Choose)?.minLength ?: 0
                Text(stringResource(notice.messageRes, minLength))
            }
            OutlinedTextField(
                value = pin,
                onValueChange = { pin = it },
                label = { Text("PIN") },
                singleLine = true,
                visualTransformation = if (pinVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    IconButton(onClick = { pinVisible = !pinVisible }) {
                        Icon(
                            imageVector = if (pinVisible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                            contentDescription = if (pinVisible) "Hide PIN" else "Show PIN",
                        )
                    }
                },
                modifier = androidx.compose.ui.Modifier.focusRequester(focusRequester),
            )
            }
        },
        confirmButton = {
            Button(onClick = { onSubmit(pin) }, enabled = pin.isNotEmpty()) { Text("Submit") }
        },
        dismissButton = {
            TextButton(onClick = { onSubmit(null) }) { Text("Cancel") }
        },
    )
}
