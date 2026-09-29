// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp

/**
 * The wallet's default landing screen: the SIROS mark itself, enlarged and
 * made tappable, IS the single primary CTA - a QR-scan symbol is painted
 * directly on it in white - so a first-time user has one obvious next step
 * instead of choosing up front between QR scanning and proximity/BLE
 * presentation. A long-press on the ball is a shortcut straight into
 * proximity/BLE mode (see [ActivateScreen]'s "use proximity instead"
 * secondary CTA for the equivalent, less-discoverable in-screen path). When
 * the wallet has no credentials yet, a smaller secondary link to Add
 * Credential is also shown - it disappears once the wallet holds at least
 * one credential, since the Credentials tab's own "+" action (and its
 * empty-state card) cover that case from then on.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun HomeScreen(
    hasCredentials: Boolean,
    onActivate: () -> Unit,
    onActivateProximity: () -> Unit,
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
        Box(
            modifier = Modifier
                .size(260.dp)
                .clip(CircleShape)
                .combinedClickable(onClick = onActivate, onLongClick = onActivateProximity),
            contentAlignment = Alignment.Center,
        ) {
            Image(
                painter = painterResource(R.drawable.ic_siros_mark),
                contentDescription = stringResource(R.string.home_activate_button),
                modifier = Modifier.fillMaxSize(),
            )
            Icon(
                imageVector = Icons.Filled.QrCodeScanner,
                contentDescription = null,
                modifier = Modifier.size(42.dp),
                tint = Color.White,
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
