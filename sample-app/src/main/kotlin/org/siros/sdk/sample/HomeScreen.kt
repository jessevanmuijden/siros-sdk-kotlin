// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
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
 *
 * [showPhotoIdOnboarding] independently shows a labeled card offering the
 * FaceTec-backed PhotoID onboarding flow directly from Home (bypassing the
 * Credentials tab's Add Credential list entirely) - the caller is
 * responsible for deciding when that's true (currently: a local sample-app
 * setting, since this isn't gated by any real per-tenant server capability
 * yet - see [WalletViewModel.showPhotoIdOnboarding]) combined with the
 * wallet not already holding a PhotoID credential (see
 * [WalletViewModel.hasPhotoIdCredential]).
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun HomeScreen(
    hasCredentials: Boolean,
    onActivate: () -> Unit,
    onActivateProximity: () -> Unit,
    onAddCredential: () -> Unit,
    showPhotoIdOnboarding: Boolean = false,
    onStartPhotoIdOnboarding: () -> Unit = {},
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
        if (showPhotoIdOnboarding) {
            Spacer(modifier = Modifier.height(24.dp))
            PhotoIdOnboardingCard(onClick = onStartPhotoIdOnboarding)
        }
    }
}

@Composable
private fun PhotoIdOnboardingCard(onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.primaryContainer),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    Icons.Outlined.Info,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onPrimaryContainer,
                    modifier = Modifier.size(20.dp),
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.home_photo_id_onboarding_title),
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                )
                Text(
                    text = stringResource(R.string.home_photo_id_onboarding_description),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Icon(
                Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
