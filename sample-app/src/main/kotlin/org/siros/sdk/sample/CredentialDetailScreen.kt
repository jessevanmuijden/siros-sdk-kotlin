// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.Surface
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.DisplayClaim
import org.siros.sdk.credentials.interop.CredentialStatus
import org.siros.sdk.credentials.interop.HolderBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Full credential detail screen with Info/Claims/Raw tabs.
 *
 * Modeled after the wallet-frontend CredentialDetail page:
 * - Info tab: issuer, format, type, dates, logo
 * - Claims tab: decoded claims (SD-JWT/mdoc) as key/value list
 * - Raw tab: raw credential string for debugging
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CredentialDetailScreen(
    credential: StoredCredential,
    onBack: () -> Unit,
    onDelete: () -> Unit,
    onRenew: () -> Unit,
    /**
     * Why this credential cannot currently be used, from the SDK's run of
     * DIIP's Validity and Revocation Algorithm (see
     * `WalletViewModel.credentialStatuses`). Null means it can be used.
     */
    credentialStatus: CredentialStatus? = null,
) {
    var showDeleteDialog by remember { mutableStateOf(false) }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text(stringResource(R.string.credential_detail_delete_confirm_title)) },
            text = {
                Text(stringResource(
                    R.string.credential_detail_delete_confirm_message,
                    credential.metadata?.name ?: credential.format,
                ))
            },
            confirmButton = {
                TextButton(onClick = {
                    showDeleteDialog = false
                    onDelete()
                }) {
                    Text(
                        stringResource(R.string.credential_detail_delete_confirm),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            },
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.credential_detail_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.nav_back))
                    }
                },
                actions = {
                    IconButton(onClick = onRenew) {
                        Icon(
                            Icons.Filled.Refresh,
                            stringResource(R.string.credential_renew),
                        )
                    }
                    IconButton(onClick = { showDeleteDialog = true }) {
                        Icon(
                            Icons.Filled.Delete,
                            stringResource(R.string.credential_detail_delete),
                            tint = MaterialTheme.colorScheme.error,
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            // Compact card header
            CredentialCard(
                credential = credential,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                credentialStatus = credentialStatus,
            )

            // Why the credential cannot be used, spelled out - the card's
            // one-word ribbon says which outcome, this says what it means.
            if (credentialStatus != null && !credentialStatus.isUsable) {
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                    shape = RoundedCornerShape(8.dp),
                    color = credentialStatus.ribbonColor().copy(alpha = 0.12f),
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            Icons.Filled.Warning,
                            contentDescription = null,
                            tint = credentialStatus.ribbonColor(),
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = stringResource(credentialStatus.detailRes()),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                }
            }

            // Tabs
            var selectedTab by rememberSaveable { mutableIntStateOf(0) }
            val tabTitles = listOf(
                stringResource(R.string.credential_detail_tab_info),
                stringResource(R.string.credential_detail_tab_claims),
                stringResource(R.string.credential_detail_tab_raw),
            )

            TabRow(selectedTabIndex = selectedTab) {
                tabTitles.forEachIndexed { index, title ->
                    Tab(
                        selected = selectedTab == index,
                        onClick = { selectedTab = index },
                        text = { Text(title) },
                    )
                }
            }

            when (selectedTab) {
                0 -> InfoTab(credential)
                1 -> ClaimsTab(credential)
                2 -> RawTab(credential)
            }
        }
    }
}

@Composable
private fun InfoTab(credential: StoredCredential) {
    val meta = credential.metadata
    val dateFormatter = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // Logo
        meta?.logo?.uri?.let { logoUri ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                val logo = rememberNormalizedLogoModel(logoUri)
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .clip(RoundedCornerShape(8.dp)),
                ) {
                    // Full-bleed raster background (if any) drawn underneath the
                    // (now `<image>`-free) SVG - see NormalizedLogo's doc comment;
                    // without this a logo SVG with an embedded full-card raster
                    // <image> mis-renders via AndroidSVG with a dark band roughly
                    // 30% down, the same bug already fixed for full-size cards.
                    logo.backgroundImageBytes?.let { backgroundBytes ->
                        AsyncImage(
                            model = backgroundBytes,
                            contentDescription = null,
                            modifier = Modifier.fillMaxSize(),
                            contentScale = ContentScale.Crop,
                        )
                    }
                    AsyncImage(
                        model = logo.model,
                        contentDescription = meta.logo?.altText,
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.Fit,
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = meta.name ?: credential.format,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                DetailRow(stringResource(R.string.credential_detail_issuer), meta?.issuer?.name ?: "-")
                DetailRow(stringResource(R.string.credential_detail_format), credential.format)
                // Which interoperability profile this credential was issued
                // under, read off its own holder binding. Informational: the
                // wallet needs no setting to present it correctly, and this is
                // simply what a dual-ecosystem wallet is hard to debug without.
                CredentialUtils.holderBinding(credential)?.let { binding ->
                    DetailRow(
                        stringResource(R.string.credential_detail_holder_binding),
                        when (binding) {
                            HolderBinding.DID_JWK -> "DIIP (cnf.kid)"
                            HolderBinding.EMBEDDED_JWK -> "HAIP (cnf.jwk)"
                        },
                    )
                }
                val typeId = meta?.vct ?: meta?.doctype
                if (typeId != null) {
                    DetailRow(stringResource(R.string.credential_detail_type), typeId)
                }
                credential.issuedAt?.let {
                    DetailRow(stringResource(R.string.credential_detail_issued), dateFormatter.format(Date(it * 1000)))
                }
                credential.expiresAt?.let {
                    DetailRow(stringResource(R.string.credential_detail_expires), dateFormatter.format(Date(it * 1000)))
                }
            }
        }

        meta?.description?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ClaimsTab(credential: StoredCredential) {
    val claims = remember(credential) { CredentialUtils.extractClaims(credential) }

    if (claims.isEmpty()) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = stringResource(R.string.credential_detail_no_claims),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    } else {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            claims.forEach { claim ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant,
                    ),
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            text = claim.label,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        CopyableTextBlock(
                            text = claim.value,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        val desc = claim.description
                        if (desc != null) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = desc,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun RawTab(credential: StoredCredential) {
    // credential.raw is "<jwt>~<disclosure>~<disclosure>~..." per the SD-JWT
    // spec, not one JSON blob - decode it into its actual parts so each is
    // individually readable and copyable, instead of one opaque string.
    val parts = remember(credential.raw) { CredentialUtils.parseSdJwtParts(credential.raw) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // Security warning — raw credentials are sensitive
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer,
            ),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = "\u26a0\ufe0f This is sensitive data. Do not screenshot or share.",
                style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier.padding(12.dp),
            )
        }

        parts.header?.let { header ->
            RawSection(stringResource(R.string.credential_detail_raw_header), header.toString())
        }
        parts.payload?.let { payload ->
            RawSection(stringResource(R.string.credential_detail_raw_payload), payload.toString())
        }
        parts.disclosures.forEachIndexed { index, disclosure ->
            RawSection(
                stringResource(R.string.credential_detail_raw_disclosure, index + 1),
                disclosure.toString(),
            )
        }
        if (parts.header == null && parts.payload == null && parts.disclosures.isEmpty()) {
            // Unparseable - still show the raw string rather than nothing.
            CopyableTextBlock(text = credential.raw, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
private fun RawSection(label: String, text: String) {
    Column {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(4.dp))
        CopyableTextBlock(text = text, modifier = Modifier.fillMaxWidth())
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(0.4f),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(0.6f),
        )
    }
}
