// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp

/**
 * The wallet's default landing screen: the SIROS mark and a single primary
 * CTA - a QR-scan symbol - so a first-time user has one obvious next step
 * instead of choosing up front between QR scanning and proximity/BLE
 * presentation (see [ActivateScreen], which offers that choice one level in
 * via its own "use proximity instead" secondary CTA). When the wallet has no
 * credentials yet, a smaller secondary link to Add Credential is also shown -
 * it disappears once the wallet holds at least one credential, since the
 * Credentials tab's own "+" action (and its empty-state card) cover that
 * case from then on.
 */
@Composable
fun HomeScreen(
    hasCredentials: Boolean,
    onActivate: () -> Unit,
    onAddCredential: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Image(
            painter = painterResource(R.drawable.ic_siros_mark),
            contentDescription = stringResource(R.string.topbar_logo_description),
            modifier = Modifier.size(112.dp),
        )
        Spacer(modifier = Modifier.height(32.dp))
        Button(
            onClick = onActivate,
            modifier = Modifier.size(80.dp),
            shape = CircleShape,
            contentPadding = PaddingValues(0.dp),
        ) {
            Icon(
                imageVector = Icons.Filled.QrCodeScanner,
                contentDescription = stringResource(R.string.home_activate_button),
                modifier = Modifier.size(36.dp),
            )
        }
        if (!hasCredentials) {
            Spacer(modifier = Modifier.height(16.dp))
            TextButton(onClick = onAddCredential) {
                Text(stringResource(R.string.home_add_credential_button))
            }
        }
    }
}
