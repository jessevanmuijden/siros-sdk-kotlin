// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.PointerInputScope
import androidx.compose.ui.input.pointer.changedToUpIgnoreConsumed
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.positionChange
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.zIndex
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.ImageLoader
import coil.decode.SvgDecoder
import coil.request.ImageRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import org.siros.sdk.credentials.CredentialInstance
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.CredentialWithInstances
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.SvgTemplateRenderer
import org.siros.sdk.credentials.interop.CredentialStatus
import timber.log.Timber
import kotlin.math.roundToInt

/**
 * Credit-card style credential display.
 *
 * Uses background_color/text_color from credential metadata when available,
 * otherwise falls back to Material theme surface colors.
 * Aspect ratio 1.6:1 matches the web frontend's card proportions.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun CredentialCard(
    credential: StoredCredential,
    onClick: (() -> Unit)? = null,
    /**
     * Long-press action - shows a Renew/Delete action menu (see
     * [CredentialsTab]'s `pendingActionMenuFor` state). Ignored (no gesture
     * registered) if null, same as [onClick].
     */
    onLongClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
    /**
     * Every copy in this credential's batch (see [StoredCredential.batchId]),
     * including itself - a single-copy credential still gets a one-element
     * list. Mirrors wallet-frontend's `vcEntity.instances`: the ribbon shows
     * how many copies haven't been used in a presentation yet. Null (the
     * default) hides the ribbon entirely - for callers, like the detail
     * screen's compact header, that don't have batch/usage data on hand
     * rather than showing a misleading "0".
     */
    instances: List<CredentialInstance>? = null,
    /**
     * Called when the user taps "Renew" on a fully-exhausted credential
     * (every batch instance already used - see [instances]). Only ever
     * shown/invoked when [instances] is non-null and every instance's
     * `sigCount > 0`; ignored (no button rendered) if null.
     */
    onRenewClick: (() -> Unit)? = null,
    /**
     * Called when the user taps "Delete" on a fully-exhausted/"shadow"
     * credential (see [onRenewClick]'s doc comment for when this state
     * applies) - a shadow credential isn't reachable via long-press (see
     * [isExhausted]'s use in this card's `combinedClickable` gate below), so
     * without this the only way to remove one was renewing it first, even
     * though the user may simply want it gone. Ignored (no button rendered)
     * if null, same as [onRenewClick].
     */
    onDeleteClick: (() -> Unit)? = null,
    /**
     * Why this credential cannot currently be used, from the SDK's run of
     * DIIP's Validity and Revocation Algorithm (see
     * `SirosWallet.refreshCredentialStatuses`). Null - the default - means it
     * can be used, or that no evaluation has run yet.
     *
     * The card renders it and computes none of it: establishing revocation
     * means fetching the issuer's Token Status List, which belongs in the
     * SDK, not in a Compose render.
     */
    credentialStatus: CredentialStatus? = null,
) {
    // Null when the caller doesn't have batch/usage data on hand (see
    // [instances]'s doc comment) - only gates the greyed-out/Renew state
    // when we actually know the count, never on the strength of an absence.
    // A copy that's unused but keyless still can't actually be presented -
    // "remaining" (and therefore the "shadow"/renew-only state below) counts
    // only copies that are both, so a lost key can't masquerade as a live,
    // presentable one (see CredentialInstance.hasKey's doc comment).
    val remainingCount = instances?.count { it.sigCount == 0 && it.hasKey }
    val isExhausted = remainingCount == 0
    // A credential whose metadata has not been built yet is still a
    // credential, and it already carries everything a card needs: its
    // configuration id, its issuer, and its own type in its payload. Reading
    // that directly is what hydration would have written, and means the card
    // no longer depends on whether hydration has run - which is what left it
    // showing "?" for an issuer and its own wire format for a name.
    val meta = credential.metadata ?: CredentialUtils.buildFallbackMetadata(credential)
    val bgColor = meta?.backgroundColor?.toComposeColor()
        // A type that declares no colour used to land on the theme's
        // primaryContainer - and so did every other such type, which is why
        // four EU Business Wallet credentials drew as four copies of one
        // card. A tint derived from the type identifier is stable for a type
        // across devices and installs, differs between types, and asks
        // nothing of the issuer.
        ?: typeTintColor(meta?.vct ?: meta?.doctype, isSystemInDarkTheme())
        ?: MaterialTheme.colorScheme.primaryContainer
    // Falls back to a color derived from the actual bgColor above (not an
    // unrelated theme token) - a credential that declares backgroundColor
    // without textColor previously fell back to onPrimaryContainer, which is
    // only a valid pairing for the theme's OWN primaryContainer, not for an
    // arbitrary issuer-declared background (e.g. a saturated blue), producing
    // unreadable text.
    //
    // A declared textColor is only honored if it actually contrasts
    // adequately against bgColor - confirmed via live testing (a real PID
    // credential's declared pairing was nearly unreadable). Trusting an
    // issuer-declared color pair unconditionally means a bad VCTM display
    // block breaks legibility with no way for the wallet to recover; a
    // computed high-contrast color always exists as a safe fallback, so
    // there's no reason to render text the user can't read.
    val declaredFgColor = meta?.textColor?.toComposeColor()
    val fgColor = if (declaredFgColor != null && contrastRatio(declaredFgColor, bgColor) >= MIN_READABLE_CONTRAST_RATIO) {
        declaredFgColor
    } else {
        contrastingTextColor(bgColor)
    }

    // VCTM SVG template rendering (if the issuer's VCTM published one) - shows
    // a spinner while fetching (never flashes the flat color+logo layout as a
    // false "this is the real card" state first), and falls back to that flat
    // layout only once fetch/render has actually failed or there's no
    // template at all - never leaves the card blank/broken either way.
    val context = LocalContext.current
    val isDarkTheme = isSystemInDarkTheme()
    // Keyed on meta?.svgTemplates too, not just credential.id: metadata is
    // null on the first Ready emission after a reload (hydrateReloadedCredentials()
    // re-fetches VCTM and re-emits asynchronously) - without this, a card that
    // composed before that re-emission would stay stuck on its initial
    // NotApplicable/flat state forever, since credential.id alone doesn't
    // change when svgTemplates later arrives.
    // meta == null (not yet hydrated) is deliberately treated as "loading",
    // not "no template" - metadata being null doesn't mean the credential has
    // no SVG template, only that hydrateReloadedCredentials() hasn't finished
    // yet. Collapsing that into NotApplicable was what caused a flash of the
    // flat/blue card before the real metadata (and its SVG) arrived.
    //
    // Since the SDK persists fallback metadata (CredentialMetadata.hydration
    // == "fallback") for any credential whose VCTM/MDDL can't be fetched, and
    // answers repeat launches from an on-device cache, meta is only ever null
    // for the brief window between the first Ready emission and hydration
    // completing - not for "the issuer is down", which used to mean a spinner
    // on every launch. A fallback has no svgTemplates, so it takes the
    // NotApplicable branch and renders the flat layout at once.
    var svgState by remember(credential.id, meta?.svgTemplates) {
        mutableStateOf<SvgLoadState>(
            when {
                meta == null -> SvgLoadState.Loading
                meta.svgTemplates.isNullOrEmpty() -> SvgLoadState.NotApplicable
                else -> SvgLoadState.Loading
            }
        )
    }
    LaunchedEffect(credential.id, meta?.svgTemplates, isDarkTheme) {
        if (meta == null) {
            // Wait (bounded) for hydration to populate metadata; the
            // remember/LaunchedEffect keys above cancel and re-fire this
            // block once meta?.svgTemplates actually changes. If that never
            // happens this delay completes uncancelled and we settle to the
            // flat layout instead of spinning forever.
            //
            // The ceiling used to be 5 s, sized for a live VCTM fetch to an
            // issuer. Hydration now either answers from the SDK's on-device
            // cache (milliseconds) or persists fallback metadata immediately
            // when the negative cache says a fetch isn't due, so a null here
            // that outlives ~1.5 s means something is genuinely wrong - and
            // the right response to that is the flat card, not more waiting.
            svgState = SvgLoadState.Loading
            delay(HYDRATION_WAIT_CEILING_MS)
            svgState = SvgLoadState.NotApplicable
            return@LaunchedEffect
        }
        val templates = meta.svgTemplates
        if (templates.isNullOrEmpty()) {
            Timber.i("CredentialCard ${credential.id} (${meta.vct ?: meta.doctype}): no SVG template, using flat layout")
            svgState = SvgLoadState.NotApplicable
            return@LaunchedEffect
        }
        svgState = SvgLoadState.Loading
        val preferredScheme = if (isDarkTheme) "dark" else "light"
        val template = templates.find { it.colorScheme == preferredScheme } ?: templates.first()
        // A data: URI template can be hundreds of KB - logging it verbatim
        // both floods logcat and gets silently truncated mid-base64 by its
        // per-entry size limit, useless either way. Log its scheme/length
        // instead; an http(s) URI is short and safe to log in full.
        val uriDescription = if (template.uri.startsWith("data:")) {
            "data: URI (${template.uri.length} chars)"
        } else {
            template.uri
        }
        Timber.i(
            "CredentialCard ${credential.id} (${meta.vct ?: meta.doctype}): using SVG template " +
                "$uriDescription (colorScheme=${template.colorScheme})",
        )
        val cacheKey = svgRenderCacheKey(credential, template.uri, preferredScheme, bgColor)
        val cached = svgRenderCache.get(cacheKey)
        val payload = if (cached != null) {
            Timber.i("CredentialCard ${credential.id}: using cached SVG render")
            cached
        } else {
            fetchAndSubstituteSvg(credential, template.uri, bgColor)?.also {
                svgRenderCache.put(cacheKey, it)
            }
        }
        svgState = if (payload != null) {
            SvgLoadState.Loaded(payload.svgBytes, payload.backgroundImageBytes)
        } else {
            SvgLoadState.Failed
        }
    }
    val svgImageLoader = remember(context) {
        ImageLoader.Builder(context).components { add(SvgDecoder.Factory()) }.build()
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(1.6f)
            .then(
                if (!isExhausted && (onClick != null || onLongClick != null)) {
                    Modifier.combinedClickable(onClick = onClick ?: {}, onLongClick = onLongClick)
                } else {
                    Modifier
                },
            ),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = bgColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
    ) {
        Box {
            when (val state = svgState) {
                is SvgLoadState.Loaded -> {
                    // The full-bleed background (if any) is decoded through Coil's
                    // normal bitmap path, not svgImageLoader/AndroidSVG - see
                    // extractFullBleedBackgroundImage's doc comment for why.
                    if (state.backgroundImageBytes != null) {
                        coil.compose.AsyncImage(
                            model = state.backgroundImageBytes,
                            contentDescription = null,
                            modifier = Modifier.fillMaxSize(),
                            contentScale = ContentScale.FillBounds,
                        )
                    }
                    coil.compose.AsyncImage(
                        model = ImageRequest.Builder(context)
                            .data(state.svgBytes)
                            .size(829, 504)
                            .build(),
                        imageLoader = svgImageLoader,
                        contentDescription = meta?.name ?: credential.format,
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.FillBounds,
                    )
                }
                SvgLoadState.Loading -> {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = fgColor)
                    }
                }
                SvgLoadState.NotApplicable, SvgLoadState.Failed -> {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.SpaceBetween,
            ) {
            // Top: issuer badge (logo or initial), when the credential says
            // who issued it. When it does not, the row is left out rather
            // than filled in: a circle holding "?" beside the word "?" tells
            // the holder nothing twice, and an empty corner tells them the
            // same thing once, quietly.
            val issuerName = issuerLabel(meta?.issuer?.name, meta?.issuer?.url)
            val logoUri = meta?.logo?.uri
            if (issuerName != null || logoUri != null) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (logoUri != null) {
                    coil.compose.AsyncImage(
                        model = coilLogoModel(logoUri),
                        contentDescription = meta?.logo?.altText ?: issuerName,
                        modifier = Modifier
                            .size(32.dp)
                            .clip(CircleShape),
                        contentScale = ContentScale.Crop,
                    )
                } else if (issuerName != null) {
                    Box(
                        modifier = Modifier
                            .size(32.dp)
                            .clip(CircleShape)
                            .background(fgColor.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = issuerName.take(1).uppercase(),
                            style = MaterialTheme.typography.labelMedium,
                            color = fgColor,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                }
                if (issuerName != null) {
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = issuerName,
                        style = MaterialTheme.typography.labelMedium,
                        color = fgColor.copy(alpha = 0.7f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            }

            Spacer(modifier = Modifier.weight(1f))

            // Bottom: credential name + format badge
            val labels = cardLabels(meta?.name, credential.format, meta?.vct ?: meta?.doctype)
            Column {
                Text(
                    text = labels.title,
                    style = MaterialTheme.typography.titleLarge,
                    color = fgColor,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    if (labels.typeBadge != null) {
                        Text(
                            text = labels.typeBadge,
                            style = MaterialTheme.typography.labelSmall,
                            color = fgColor.copy(alpha = 0.5f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
        }
            }
            }

            // Status ribbon overlay - bottom-right, matching wallet-frontend's
            // ExpiredRibbon (CredentialImage.jsx renders it opposite the
            // usages/copy-count ribbon so the two never collide).
            //
            // Falls back to the credential's own `exp` when the SDK has not
            // evaluated this credential yet, so a card rendered before the
            // first refresh still says "expired" rather than nothing.
            // expiresAt is a JWT `exp` claim - always epoch SECONDS, not millis.
            val status = credentialStatus
                ?: CredentialStatus.EXPIRED.takeIf {
                    credential.expiresAt?.let { exp -> exp * 1000L < System.currentTimeMillis() } == true
                }
            if (status != null && !status.isUsable) {
                Box(
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
                        .padding(8.dp)
                        .background(
                            color = status.ribbonColor(),
                            shape = RoundedCornerShape(4.dp),
                        )
                        .padding(horizontal = 6.dp, vertical = 2.dp),
                ) {
                    Text(
                        text = stringResource(status.labelRes()).uppercase(),
                        style = MaterialTheme.typography.labelSmall,
                        color = status.ribbonContentColor(),
                        fontWeight = FontWeight.Bold,
                    )
                }
            }

            // Remaining-copies ribbon - top-right, mirrors wallet-frontend's
            // UsagesRibbon (CredentialImage.jsx): count of batch copies not
            // yet used in a presentation (sigCount == 0), so it counts down
            // as copies get consumed rather than showing the fixed batch size.
            if (remainingCount != null) {
                Box(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(8.dp)
                        .background(
                            color = if (remainingCount > 0) {
                                MaterialTheme.colorScheme.tertiaryContainer
                            } else {
                                MaterialTheme.colorScheme.surfaceVariant
                            },
                            shape = RoundedCornerShape(50),
                        )
                        .padding(horizontal = 8.dp, vertical = 3.dp),
                ) {
                    Text(
                        text = remainingCount.toString(),
                        style = MaterialTheme.typography.labelSmall,
                        color = if (remainingCount > 0) {
                            MaterialTheme.colorScheme.onTertiaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        fontWeight = FontWeight.Bold,
                    )
                }
            }

            // Every batch instance already used or keyless - the card enters
            // the "shadow" display state (it can no longer be presented, see
            // CredentialUtils.eligibleInstances/CredentialInstance.hasKey):
            // a dashed outline in place of the card's normal solid edge, a
            // dimmed scrim, and a renew icon overlay in place of the normal
            // face, rather than leaving it looking like a live, selectable
            // credential.
            if (isExhausted) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(Color.Black.copy(alpha = 0.45f))
                        .drawWithContent {
                            drawContent()
                            val strokeWidthPx = 3.dp.toPx()
                            val cornerRadiusPx = 16.dp.toPx()
                            drawRoundRect(
                                color = Color.White.copy(alpha = 0.85f),
                                topLeft = Offset(strokeWidthPx / 2, strokeWidthPx / 2),
                                size = Size(size.width - strokeWidthPx, size.height - strokeWidthPx),
                                cornerRadius = CornerRadius(cornerRadiusPx, cornerRadiusPx),
                                style = Stroke(
                                    width = strokeWidthPx,
                                    pathEffect = PathEffect.dashPathEffect(floatArrayOf(14f, 10f)),
                                ),
                            )
                        },
                    contentAlignment = Alignment.Center,
                ) {
                    Row(horizontalArrangement = Arrangement.spacedBy(24.dp)) {
                        if (onRenewClick != null) {
                            TextButton(onClick = onRenewClick) {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Icon(
                                        imageVector = Icons.Filled.Refresh,
                                        contentDescription = null,
                                        tint = Color.White,
                                        modifier = Modifier.size(32.dp),
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = stringResource(R.string.credential_renew),
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                    )
                                }
                            }
                        }
                        if (onDeleteClick != null) {
                            TextButton(onClick = onDeleteClick) {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Icon(
                                        imageVector = Icons.Filled.Delete,
                                        contentDescription = null,
                                        tint = Color.White,
                                        modifier = Modifier.size(32.dp),
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = stringResource(R.string.credential_detail_delete),
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/** Loading state for a credential card's VCTM SVG template rendering. */
private sealed class SvgLoadState {
    /** This credential's metadata has no svg_templates - render the flat card immediately. */
    data object NotApplicable : SvgLoadState()
    /** Fetch/substitute in progress - show a spinner, not the flat card. */
    data object Loading : SvgLoadState()
    /**
     * [svgBytes] is the (possibly image-stripped, see [extractFullBleedBackgroundImage])
     * SVG markup; [backgroundImageBytes] is a full-bleed raster `<image>` pulled
     * out of it to be decoded and drawn separately - confirmed via live
     * hardware testing that coil-svg/AndroidSVG mis-renders a full-card
     * embedded base64 `<image>` (a stable ~30%-down dark band that isn't
     * present in the image's own pixel data, doesn't reproduce with inkscape
     * on the exact same bytes, and doesn't reproduce at all on a
     * template with no embedded `<image>`), so the raster background is
     * decoded through Coil's normal (non-SVG) bitmap path instead and
     * layered underneath the (now `<image>`-free) SVG's vector/text content.
     */
    data class Loaded(val svgBytes: ByteArray, val backgroundImageBytes: ByteArray?) : SvgLoadState()
    /** Fetch or render failed - fall back to the flat card. */
    data object Failed : SvgLoadState()
}

private val svgHttpClient = OkHttpClient()

/**
 * Fetch a VCTM SVG rendering template and substitute this credential's claim
 * values into it (see [SvgTemplateRenderer]). Returns null on any failure
 * (network, non-2xx response, decode) - callers fall back to the flat
 * color+logo card layout rather than showing anything broken.
 *
 * [cardBackground] is the same background this card would otherwise render
 * flat against (from VCTM's `background_color`, or the theme default) - used
 * to correct any low-contrast text color the SVG itself declares (see
 * [correctSvgTextContrast]'s doc comment for why this is necessary: a real
 * issuer template rendered unreadably, confirmed via live testing, and
 * [SvgTemplateRenderer.substitute] only replaces claim-value text tokens, it
 * never touches the SVG's own styling).
 */
private data class SvgRenderPayload(val svgBytes: ByteArray, val backgroundImageBytes: ByteArray?)

/**
 * Process-lifetime cache of rendered card SVGs, keyed by everything that
 * can affect the output (credential, template, color scheme, background).
 * Without this, every recomposition of [CredentialCard] - not just app
 * launch, but every navigation back to the credential list - redid the
 * full fetch/decode-base64 + claim-substitution + viewBox/height/contrast-
 * correction + background-image-extraction pipeline from scratch, even
 * though the result is fully deterministic for a given credential (whose
 * `raw` bytes and metadata never change in place - renewal replaces the
 * whole [StoredCredential] under a new id, per the batch-replacement
 * pattern, rather than mutating one) plus render parameters. 64 entries is
 * comfortably above a realistic on-screen credential count; this is a
 * memory cache only (cleared on process death), not a disk cache - stale
 * output from a leaked cache entry would be a worse bug than a cache miss
 * after a process restart.
 */
private val svgRenderCache = android.util.LruCache<String, SvgRenderPayload>(64)

private fun svgRenderCacheKey(
    credential: StoredCredential,
    templateUri: String,
    colorScheme: String,
    cardBackground: Color,
): String = "${credential.id}|$templateUri|$colorScheme|${cardBackground.value}"

private suspend fun fetchAndSubstituteSvg(credential: StoredCredential, templateUri: String, cardBackground: Color): SvgRenderPayload? {
    return try {
        withContext(Dispatchers.IO) {
            val svgText = if (templateUri.startsWith("data:")) {
                decodeSvgDataUri(templateUri) ?: return@withContext null
            } else {
                val request = Request.Builder().url(templateUri).build()
                svgHttpClient.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) null else response.body?.string()
                } ?: return@withContext null
            }
            val claims = CredentialUtils.extractClaims(credential)
            val substituted = SvgTemplateRenderer.substitute(svgText, claims)
            val viewBoxed = ensureSvgViewBox(substituted)
            val sized = ensureSvgImageHeight(viewBoxed)
            val corrected = correctSvgTextContrast(sized, cardBackground)
            val (stripped, backgroundBytes) = extractFullBleedBackgroundImage(corrected)
            if (backgroundBytes != null) {
                Timber.i("CredentialCard ${credential.id}: extracted a full-bleed background <image> (${backgroundBytes.size} bytes) to render outside AndroidSVG")
            }
            SvgRenderPayload(stripped.toByteArray(Charsets.UTF_8), backgroundBytes)
        }
    } catch (e: CancellationException) {
        // The composable left composition (e.g. user navigated away) - not a
        // real failure. Must propagate, not be swallowed: the LaunchedEffect
        // key change that triggers this cancellation also re-runs the block
        // from scratch, so there's nothing to log or fall back to here.
        throw e
    } catch (e: Exception) {
        Timber.w(e, "Failed to fetch/render SVG template for credential ${credential.id}")
        null
    }
}

/**
 * Decode a `data:` URI's payload into its SVG text, returning null if it
 * isn't a decodable inline SVG.
 *
 * Confirmed necessary via live testing: re-issuing a credential caused
 * `svgTemplates[].uri` to arrive as a `data:image/svg+xml;base64,...` URI
 * instead of an HTTPS one (same underlying template, different delivery
 * mechanism) - [fetchAndSubstituteSvg]'s OkHttp fetch throws
 * `IllegalArgumentException` for any non-http(s) scheme, so this must be
 * handled before ever reaching [Request.Builder].
 */
/**
 * A background tint for a credential type that declares no colour of its own,
 * derived from the type identifier so the same type is always the same colour
 * and two types are all but never the same.
 *
 * Hue and saturation come from the identifier; lightness is fixed per theme,
 * which is what keeps this safe: every generated tint sits in the same
 * lightness band, so [contrastingTextColor] resolves against it exactly as it
 * does against a declared colour, and no hash can produce an unreadable card.
 *
 * The hash is written out rather than taken from [String.hashCode] because
 * this colour is part of what a credential looks like to its holder: it should
 * not change because a runtime changed its mind about string hashing.
 *
 * @return null when there is no identifier to derive from, so the caller can
 *   fall back to its theme colour.
 */
internal fun typeTintColor(typeId: String?, dark: Boolean): Color? {
    if (typeId.isNullOrBlank()) return null
    // FNV-1a, 32-bit.
    var hash = 0x811C9DC5u
    for (ch in typeId) {
        hash = hash xor ch.code.toUInt()
        hash *= 0x01000193u
    }
    val slot = (hash % (TINT_HUES * TINT_TONES).toUInt()).toInt()
    val tone = slot / TINT_HUES
    // The tone varies saturation and leaves lightness alone. Raising
    // lightness for a paler tone squeezes the hues together - two tints 15
    // degrees apart both came out near white and read as one colour - and it
    // would also move the card out of the single lightness band the contrast
    // guarantee below depends on.
    return hslColor(
        hue = (slot % TINT_HUES) * (360f / TINT_HUES),
        saturation = (if (dark) 0.30f else 0.40f) + tone * 0.16f,
        lightness = if (dark) 0.26f else 0.80f,
    )
}

/**
 * Hue steps, and tones per hue, for [typeTintColor].
 *
 * The hue is quantised rather than taken straight from the hash so that two
 * types cannot land a couple of degrees apart and read as the same colour -
 * an ungrouped hash did exactly that, putting two of ours at 340 and 342.
 * Quantising trades that near-miss for an honest exact collision: with
 * [TINT_HUES] x [TINT_TONES] slots, two types can share one, and there is no
 * way to rule that out without the types agreeing with each other. Sharing a
 * colour with one other type is a far smaller problem than the alternative
 * this replaced, where every type without a declared colour shared one.
 */
private const val TINT_HUES = 24
private const val TINT_TONES = 3

/** HSL to [Color]; hue in degrees, saturation and lightness in 0..1. */
internal fun hslColor(hue: Float, saturation: Float, lightness: Float): Color {
    val c = (1f - kotlin.math.abs(2f * lightness - 1f)) * saturation
    val hPrime = ((hue % 360f) + 360f) % 360f / 60f
    val x = c * (1f - kotlin.math.abs(hPrime % 2f - 1f))
    val (r1, g1, b1) = when (hPrime.toInt()) {
        0 -> Triple(c, x, 0f)
        1 -> Triple(x, c, 0f)
        2 -> Triple(0f, c, x)
        3 -> Triple(0f, x, c)
        4 -> Triple(x, 0f, c)
        else -> Triple(c, 0f, x)
    }
    val m = lightness - c / 2f
    return Color(
        red = (r1 + m).coerceIn(0f, 1f),
        green = (g1 + m).coerceIn(0f, 1f),
        blue = (b1 + m).coerceIn(0f, 1f),
    )
}

/**
 * What a card says on its two text slots, decided together so that neither
 * repeats the other.
 *
 * Deciding them separately is what produced a card reading "dc+sd-jwt" as
 * its name and "DC+SD-JWT" again underneath: each slot fell back on its own
 * and both landed on the wire format, which was not worth saying even once.
 *
 * The format is no longer a slot of its own. It is what a credential is
 * encoded as, not what it is, and it survives here only as the last thing
 * left to call a credential that says nothing else about itself.
 *
 * @property title the large line: the credential's name, else its type, else
 *   its wire format.
 * @property typeBadge the small label beneath, null when the title is
 *   already saying it.
 */
internal data class CardLabels(val title: String, val typeBadge: String?)

internal fun cardLabels(name: String?, format: String, typeId: String?): CardLabels {
    val badge = typeId?.takeIf { it.isNotBlank() }?.let { credentialTypeBadge(it) }
    // A "name" that is only the format or the type repeated is not a name.
    val realName = name?.takeIf {
        it.isNotBlank() && !it.equals(format, ignoreCase = true) && it != typeId && it != badge
    }
    return when {
        realName != null -> CardLabels(realName, badge)
        badge != null -> CardLabels(badge, null)
        else -> CardLabels(format, null)
    }
}

/**
 * How to name the issuer, or null when the credential does not say.
 *
 * A credential built from an offer carries the issuer's display name; one
 * the wallet had to reconstruct carries only the identifier it was issued
 * from, and its host is a better answer than nothing.
 */
internal fun issuerLabel(name: String?, url: String?): String? {
    name?.takeIf { it.isNotBlank() }?.let { return it }
    val raw = url?.takeIf { it.isNotBlank() } ?: return null
    return try {
        java.net.URI(raw).host ?: raw
    } catch (_: Exception) {
        raw
    }
}

/**
 * The short label for a credential type, for the badge beside the format.
 *
 * Only a URL-shaped identifier gets shortened, to its last path segment
 * minus any document extension, which is the part that names the type:
 * `https://example.com/credentials/student-id` reads as `student-id` and
 * `https://registry.siros.org/sunet/mdl.vctm.json` as `mdl`.
 *
 * Everything else is left whole. Cutting at the last dot, which is what this
 * used to do, is right for a hostname and wrong for every reverse-DNS or URN
 * identifier in use: `uri:eu.ebw.oid.1` and `eu.we-build.iban-ov.1` both came
 * out as "1", and `urn:eudi:pid:arf-1.8:1` as "8:1". A type identifier is
 * short enough to show, and a wrong fragment of one is worse than the whole.
 */
internal fun credentialTypeBadge(typeId: String): String {
    val afterScheme = typeId.substringAfter("://", typeId)
    // Only a real path can be shortened. Without this, a bare origin loses
    // its own name: "https://example.com/" would read as "example".
    val path = afterScheme.substringAfter('/', "")
    if (path.isBlank()) return typeId
    val lastSegment = path.trimEnd('/').substringAfterLast('/')
    if (lastSegment.isEmpty()) return typeId
    return lastSegment.substringBefore('.').ifEmpty { lastSegment }
}

internal fun decodeSvgDataUri(uri: String): String? {
    val comma = uri.indexOf(',')
    if (comma < 0) return null
    val meta = uri.substring(0, comma)
    val payload = uri.substring(comma + 1)
    return try {
        if (meta.contains("base64")) {
            java.util.Base64.getDecoder().decode(payload).toString(Charsets.UTF_8)
        } else {
            java.net.URLDecoder.decode(payload, "UTF-8")
        }
    } catch (e: Exception) {
        Timber.w(e, "Failed to decode data: URI SVG template")
        null
    }
}

/**
 * Parse a CSS color string (#RRGGBB or #RGB) to a Compose [Color].
 */
internal fun String.toComposeColor(): Color? {
    val hex = this.removePrefix("#")
    return try {
        when (hex.length) {
            3 -> Color(
                red = hex[0].digitToInt(16) * 17,
                green = hex[1].digitToInt(16) * 17,
                blue = hex[2].digitToInt(16) * 17,
            )
            6 -> Color(
                red = hex.substring(0, 2).toInt(16),
                green = hex.substring(2, 4).toInt(16),
                blue = hex.substring(4, 6).toInt(16),
            )
            8 -> Color(
                alpha = hex.substring(0, 2).toInt(16),
                red = hex.substring(2, 4).toInt(16),
                green = hex.substring(4, 6).toInt(16),
                blue = hex.substring(6, 8).toInt(16),
            )
            else -> null
        }
    } catch (_: Exception) {
        null
    }
}

/** Black or white, whichever contrasts better against [background] (relative luminance). */
internal fun contrastingTextColor(background: Color): Color =
    // Whichever actually reads better, not whichever side of mid-grey the
    // background falls on. The two agree at the extremes and disagree in a
    // wide band in between: a saturated blue card sits at luminance 0.39, so
    // the old threshold chose white at 2.4:1 where black gives 8.8:1.
    // Choosing by ratio also puts a floor under every card - the two choices
    // are equal at luminance 0.179, where both give 4.6:1 - so no background,
    // declared by an issuer or derived here, can produce unreadable text.
    if (contrastRatio(Color.Black, background) >= contrastRatio(Color.White, background)) {
        Color.Black
    } else {
        Color.White
    }

/**
 * WCAG-style contrast ratio between two colors, from 1 (identical/no
 * contrast) to 21 (pure black on pure white) - `(L1 + 0.05) / (L2 + 0.05)`
 * where L1/L2 are the lighter/darker relative luminances.
 */
internal fun contrastRatio(a: Color, b: Color): Float {
    val lighter = maxOf(a.luminance(), b.luminance())
    val darker = minOf(a.luminance(), b.luminance())
    return (lighter + 0.05f) / (darker + 0.05f)
}

/**
 * Below WCAG's 3:1 minimum for large text - chosen for a card's short
 * name/issuer text, which typically renders at title/label sizes well
 * above the 18pt/14pt-bold threshold that ratio applies to. An
 * issuer-declared text/background pairing below this is treated as
 * unreadable, not merely non-ideal (see [CredentialCard]'s use of this).
 */
internal const val MIN_READABLE_CONTRAST_RATIO = 3.0f

/**
 * Longest a card shows its loading indicator waiting for `metadata` to be
 * hydrated before settling to the flat layout. Generous relative to the
 * cache-served/fallback path the SDK now takes (milliseconds), short enough
 * that a genuinely stuck hydration never reads as "the wallet is slow" - see
 * the `meta == null` branch in [CredentialCard].
 */
internal const val HYDRATION_WAIT_CEILING_MS = 1_500L

/** Matches a `<text ...>` or `<tspan ...>` opening tag, whose own `fill` attribute (if any) [correctSvgTextContrast] inspects. */
private val SVG_TEXT_TAG = Regex("""<(?:text|tspan)\b[^>]*>""")

/** Matches a `fill="#hex"`/`fill='#hex'` attribute within an already-isolated tag string. */
private val SVG_FILL_ATTR = Regex("""fill=(["'])(#[0-9A-Fa-f]{3,8})\1""")

/**
 * Overrides a low-contrast `fill="#hex"` on each `<text>`/`<tspan>` element
 * in [svg] with a computed high-contrast color against [background], when
 * (and only when) the declared one fails [MIN_READABLE_CONTRAST_RATIO] -
 * confirmed necessary via live testing: a real issuer's SVG credential
 * template baked in unreadable text-color contrast, and
 * [SvgTemplateRenderer.substitute]'s pure `{{claimId}}` token replacement
 * has no way to touch an SVG's own styling.
 *
 * Deliberately narrow, matching what a hand-rolled regex over arbitrary SVG
 * can safely do: only a DIRECT `fill="#hex"` attribute on the text/tspan
 * element itself is inspected/corrected. A fill inherited from a parent
 * `<g>`, set via a CSS class/`<style>` block, or expressed as a named color
 * (`"black"`) or `url(#gradient)` reference is left untouched - resolving
 * those would need a real DOM walk with style/inheritance resolution, well
 * beyond what a string-substitution-based renderer should take on. An
 * already-adequate-contrast fill is also left untouched, preserving the
 * issuer's actual design wherever it already works.
 */
internal fun correctSvgTextContrast(svg: String, background: Color): String =
    SVG_TEXT_TAG.replace(svg) { tagMatch ->
        val tag = tagMatch.value
        val fillMatch = SVG_FILL_ATTR.find(tag)
        val declared = fillMatch?.groupValues?.get(2)?.toComposeColor()
        if (fillMatch == null || declared == null || contrastRatio(declared, background) >= MIN_READABLE_CONTRAST_RATIO) {
            tag
        } else {
            val corrected = contrastingTextColor(background)
            val correctedHex = "#%02X%02X%02X".format(
                (corrected.red * 255).toInt(),
                (corrected.green * 255).toInt(),
                (corrected.blue * 255).toInt(),
            )
            val quote = fillMatch.groupValues[1]
            tag.replaceRange(fillMatch.range, "fill=$quote$correctedHex$quote")
        }
    }

/** Matches the outer `<svg ...>` root tag's opening portion, up to (not including) its `>`. */
private val SVG_ROOT_TAG_OPEN = Regex("""<svg\b[^>]*""")

/** True if a tag string already declares a `viewBox` attribute. */
private val SVG_HAS_VIEWBOX_ATTR = Regex("""\bviewBox=["']""")

/** True if a tag string already declares a `preserveAspectRatio` attribute. */
private val SVG_HAS_PRESERVE_ASPECT_RATIO_ATTR = Regex("""\bpreserveAspectRatio=["']""")

/** Matches a plain-number `width="NNN"`/`height="NNN"` attribute (no unit, no `%`) within an isolated tag string. */
private val SVG_DIMENSION_ATTR = Regex("""\b(width|height)=(["'])(\d+(?:\.\d+)?)\2""")

/**
 * Injects a `viewBox` on the SVG root when it's missing entirely, derived
 * from the root's own plain-number `width`/`height` attributes.
 *
 * Confirmed necessary via live testing: a real issuer's SVG credential
 * template (wwwallet.org's demo PID) declares `<svg width="829"
 * height="504" version="1.1">` with NO `viewBox` at all. Without one,
 * percentage dimensions on children (e.g. [ensureSvgImageHeight]'s
 * `width="100%"` background image) are only unambiguous if every renderer
 * resolves them against the SAME reference size - some resolve against the
 * root's declared width/height, others against whatever pixel canvas they
 * actually decide to rasterize into (which won't exactly match 829x504
 * when the surrounding UI's own aspect ratio differs, however slightly).
 * That mismatch showed up as the whole graphic rendering visibly shifted.
 * An explicit `viewBox="0 0 829 504"` removes the ambiguity outright: every
 * spec-compliant renderer resolves percentages against the viewBox, and
 * fits that fixed coordinate space into whatever final size it's asked
 * for via its own well-defined scaling transform, not per-element guesswork.
 *
 * That fitting transform is where a SECOND bug surfaced, confirmed by
 * rendering the same template through both a browser `<img>` (CSS
 * `object-fit` overrides SVG-internal fitting, so no gap) and an `<object>`
 * embed at a deliberately mismatched aspect ratio (SVG-internal fitting
 * applies, and a visible gap appeared): adding a `viewBox` with no
 * `preserveAspectRatio` activates the SVG default, `xMidYMid meet` -
 * uniform scale-to-fit, letterboxing whichever axis doesn't exactly match.
 * On device, this API's Card composable already stretches non-uniformly to
 * fill (`ContentScale.FillBounds`) - the on-device Android SVG decoder
 * apparently rasterizes at a size whose aspect ratio doesn't match this
 * template's, and `xMidYMid meet`'s letterbox gap baked directly into the
 * decoded bitmap survives that later stretch untouched, showing as the
 * Card's own flat background color visibly filling a fraction of the
 * card. `preserveAspectRatio="none"` (added alongside the viewBox)
 * disables that letterboxing, matching what `FillBounds` already wants.
 *
 * A no-op when a `viewBox` already exists, or when the root's `width`/
 * `height` aren't both plain numbers (e.g. already percentages, or
 * missing) - there's nothing safe to derive a viewBox from in that case.
 */
internal fun ensureSvgViewBox(svg: String): String {
    val rootMatch = SVG_ROOT_TAG_OPEN.find(svg) ?: return svg
    val rootTag = rootMatch.value
    if (SVG_HAS_VIEWBOX_ATTR.containsMatchIn(rootTag)) return svg

    val dimensions = SVG_DIMENSION_ATTR.findAll(rootTag).associate { it.groupValues[1] to it.groupValues[3] }
    val width = dimensions["width"] ?: return svg
    val height = dimensions["height"] ?: return svg

    val preserveAspectRatio = if (SVG_HAS_PRESERVE_ASPECT_RATIO_ATTR.containsMatchIn(rootTag)) {
        ""
    } else {
        " preserveAspectRatio=\"none\""
    }
    return svg.replaceRange(rootMatch.range, "$rootTag viewBox=\"0 0 $width $height\"$preserveAspectRatio")
}

/** Matches a `<image ...>` opening tag (self-closing or not), whose `width`/`height` [ensureSvgImageHeight] inspects. */
private val SVG_IMAGE_TAG = Regex("""<image\b[^>]*>""")

/** Matches a percentage `width="NN%"`/`width='NN%'` attribute within an already-isolated tag string. */
private val SVG_IMAGE_WIDTH_PERCENT_ATTR = Regex("""width=(["'])(\d+%)\1""")

/** True if the tag string already declares a `height` attribute (any value). */
private val SVG_HAS_HEIGHT_ATTR = Regex("""\bheight=["']""")

/**
 * Injects a missing `height` on an `<image>` element that declares a
 * percentage `width` but no `height` at all, mirroring the exact width
 * value - confirmed necessary via live testing: a real issuer's SVG
 * credential template (wwwallet.org's demo PID) has its full-bleed
 * background `<image>` declare `width="100%"` with no `height` attribute
 * whatsoever. Per SVG 1.1 (which this template itself declares via
 * `version="1.1"`), an `<image>` with no height defaults to height 0 -
 * invisible - unless the renderer implements the newer SVG2/CSS
 * auto-sizing fallback (deriving height from the embedded image's own
 * intrinsic dimensions), which browsers commonly do but this app's
 * Android SVG decoder apparently doesn't. The graphic simply never
 * appeared, leaving only this card's own flat `backgroundColor` showing
 * through - not a rendering failure, an invisible-by-spec element.
 *
 * Deliberately narrow, matching what a hand-rolled regex over arbitrary
 * SVG can safely do: only a percentage-width `<image>` missing `height`
 * entirely is corrected, and it's set to the SAME percentage as `width` -
 * a safe, well-justified default when the image is clearly meant to fill
 * its container (which is exactly what `width="100%"` signals). An
 * absolute-unit width (e.g. `width="220"`, seen on this same template's
 * separate placeholder-photo `<image>`) is a different, more ambiguous
 * case - correctly sizing it would need the embedded image's own
 * intrinsic pixel dimensions, which isn't attempted here. An `<image>`
 * that already declares a `height` (any value) is never touched.
 */
internal fun ensureSvgImageHeight(svg: String): String =
    SVG_IMAGE_TAG.replace(svg) { tagMatch ->
        val tag = tagMatch.value
        val widthMatch = SVG_IMAGE_WIDTH_PERCENT_ATTR.find(tag)
        if (widthMatch == null || SVG_HAS_HEIGHT_ATTR.containsMatchIn(tag)) {
            tag
        } else {
            val percentage = widthMatch.groupValues[2]
            val selfClosing = tag.endsWith("/>")
            val body = (if (selfClosing) tag.dropLast(2) else tag.dropLast(1)).trimEnd()
            val closer = if (selfClosing) " />" else ">"
            "$body height=\"$percentage\"$closer"
        }
    }

/** Matches an `x="0"`/`y="0"` attribute (any whitespace-equivalent zero), within an already-isolated tag string. */
private val SVG_IMAGE_ZERO_ATTR = mapOf(
    "x" to Regex("""\bx=(["'])0(?:\.0+)?\1"""),
    "y" to Regex("""\by=(["'])0(?:\.0+)?\1"""),
)

/** Matches a `height="NN%"`/`height='NN%'` attribute within an already-isolated tag string. */
private val SVG_IMAGE_HEIGHT_PERCENT_ATTR = Regex("""height=(["'])(\d+%)\1""")

/** Captures an embedded raster `xlink:href="data:image/<mime>;base64,<data>"` (or bare `href=`) value. */
private val SVG_IMAGE_DATA_HREF = Regex("""(?:xlink:href|href)=(["'])data:image/(png|jpeg|jpg|webp);base64,([^"']*)\1""")

/**
 * Pulls a full-card raster `<image>` (x=0, y=0, width=100%, height=100%,
 * embedded as a base64 data URI) out of [svg] entirely, returning the
 * decoded image bytes alongside the SVG with that element removed.
 *
 * Confirmed via live hardware testing (real YubiKey-issued PID credential,
 * 2026-08-10): the exact SVG bytes handed to Coil render perfectly via
 * `inkscape` on a desktop, and the extracted PNG's own pixel data is a
 * uniform light-blue field with no dark region anywhere in it - yet the
 * on-device render (coil-svg / AndroidSVG) consistently shows a dark band
 * roughly 30% down the card. A sibling template with no embedded `<image>`
 * at all (a diploma credential, otherwise passing through the exact same
 * [ensureSvgViewBox]/[ensureSvgImageHeight]/[correctSvgTextContrast]
 * pipeline) renders correctly. That isolates the bug to AndroidSVG's
 * handling of a large embedded base64 `<image>` specifically, not the SVG
 * markup or this app's own substitution logic - so instead of asking
 * AndroidSVG to composite the raster background, it's decoded and drawn as
 * a plain bitmap layer underneath the (now image-free) SVG, which only has
 * to render vector/text content - the same kind of content the working
 * diploma template consists of.
 *
 * Deliberately narrow: only a `<image>` that is unambiguously "cover the
 * whole card" (x=0, y=0, width=100%, height=100%) is extracted. A smaller,
 * absolute-positioned `<image>` (e.g. this same template's placeholder
 * photo) is left in place for AndroidSVG to render as before - there's no
 * evidence that case is affected, and it isn't large enough to be a likely
 * source of the same bug.
 */
internal fun extractFullBleedBackgroundImage(svg: String): Pair<String, ByteArray?> {
    val match = SVG_IMAGE_TAG.findAll(svg).firstOrNull { tagMatch ->
        val tag = tagMatch.value
        SVG_IMAGE_ZERO_ATTR.getValue("x").containsMatchIn(tag) &&
            SVG_IMAGE_ZERO_ATTR.getValue("y").containsMatchIn(tag) &&
            SVG_IMAGE_WIDTH_PERCENT_ATTR.find(tag)?.groupValues?.get(2) == "100%" &&
            SVG_IMAGE_HEIGHT_PERCENT_ATTR.find(tag)?.groupValues?.get(2) == "100%"
    } ?: return svg to null

    val hrefMatch = SVG_IMAGE_DATA_HREF.find(match.value) ?: return svg to null
    val bytes = try {
        java.util.Base64.getDecoder().decode(hrefMatch.groupValues[3])
    } catch (e: IllegalArgumentException) {
        Timber.w(e, "Failed to decode embedded background <image> data URI")
        return svg to null
    }
    return svg.replaceRange(match.range, "") to bytes
}

/**
 * Coil's default components handle raw byte arrays (via `ByteArrayMapper` ->
 * `ByteBufferFetcher`, both built in) but never decode a `data:` URI *string*
 * on their own - passing one straight to `AsyncImage.model` just fails
 * silently. Issuer-published logos are frequently embedded this way (e.g.
 * geneva2026.mdoc.online's `credential_metadata.display[].logo.uri`), so
 * unwrap the base64 payload ourselves and hand Coil the bytes directly
 * instead of the URI string.
 */
internal fun coilLogoModel(uri: String): Any {
    if (!uri.startsWith("data:")) return uri
    val comma = uri.indexOf(',')
    if (comma < 0 || !uri.substring(0, comma).contains("base64")) return uri
    return try {
        java.util.Base64.getDecoder().decode(uri.substring(comma + 1))
    } catch (e: Exception) {
        uri
    }
}

/**
 * Result of normalizing a logo/preview SVG: [model] is what a Coil
 * `AsyncImage`/`SubcomposeAsyncImage` should load as the (possibly
 * `<image>`-stripped) foreground layer; [backgroundImageBytes] is a
 * full-bleed raster `<image>` pulled out of it (see
 * [extractFullBleedBackgroundImage]) that must be drawn as a separate
 * bitmap layer *underneath* [model] - null when there was nothing to
 * extract, in which case a caller can render [model] alone exactly as
 * before this type existed.
 */
internal data class NormalizedLogo(val model: Any, val backgroundImageBytes: ByteArray? = null)

/**
 * Async counterpart to [coilLogoModel] for logo/preview URIs that need
 * fetching (remote `http(s)`) rather than just base64-decoding an already-
 * inline `data:` URI. Applies the same [ensureSvgViewBox]/
 * [ensureSvgImageHeight]/[extractFullBleedBackgroundImage] normalization an
 * already-stored credential's card SVG gets in [fetchAndSubstituteSvg] -
 * without it, a logo/preview URI pointing at an SVG whose `<image>` element
 * omits `height` (a real, confirmed-live issuer template:
 * demo-issuer.wwwallet.org's EHIC card) renders fully blank with no error,
 * or - if the SVG has a full-bleed embedded raster `<image>` - renders with
 * AndroidSVG's confirmed ~30%-down dark-band mis-render (see
 * [extractFullBleedBackgroundImage]'s doc comment), since the plain
 * [coilLogoModel] path (used by the Add Credentials offer list and the
 * stored-credential detail screen, neither of which goes through
 * [fetchAndSubstituteSvg]'s pipeline) hands Coil the untouched SVG
 * bytes/URI.
 *
 * Falls back to [coilLogoModel]'s existing behavior (or the raw [uri]) on
 * any fetch/decode failure - never worse than what callers had before this
 * function existed.
 */
internal suspend fun fetchAndNormalizeLogoModel(uri: String): NormalizedLogo {
    if (uri.startsWith("data:")) {
        if (!uri.startsWith("data:image/svg+xml", ignoreCase = true)) {
            return NormalizedLogo(coilLogoModel(uri))
        }
        val svgText = decodeSvgDataUri(uri) ?: return NormalizedLogo(coilLogoModel(uri))
        return normalizeSvgLogoOrFallback(svgText, uri)
    }
    if (!uri.startsWith("http")) return NormalizedLogo(uri)
    return try {
        withContext(Dispatchers.IO) {
            val request = Request.Builder().url(uri).build()
            svgHttpClient.newCall(request).execute().use { response ->
                val body = if (response.isSuccessful) response.body?.string() else null
                if (body == null) {
                    NormalizedLogo(uri)
                } else {
                    val contentType = response.header("Content-Type") ?: ""
                    val looksLikeSvg = contentType.contains("svg", ignoreCase = true) ||
                        body.trimStart().startsWith("<svg", ignoreCase = true)
                    if (looksLikeSvg) normalizeSvgLogoOrFallback(body, uri) else NormalizedLogo(uri)
                }
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Timber.w(e, "Failed to fetch/normalize remote logo: $uri")
        NormalizedLogo(uri)
    }
}

private fun normalizeSvgLogoOrFallback(svgText: String, fallback: String): NormalizedLogo = try {
    val sized = ensureSvgImageHeight(ensureSvgViewBox(svgText))
    val (stripped, backgroundBytes) = extractFullBleedBackgroundImage(sized)
    NormalizedLogo(stripped.toByteArray(Charsets.UTF_8), backgroundBytes)
} catch (e: Exception) {
    Timber.w(e, "Failed to normalize logo SVG, falling back: $fallback")
    NormalizedLogo(fallback)
}

/**
 * Remembers a [NormalizedLogo] for [uri] via [fetchAndNormalizeLogoModel],
 * starting from [coilLogoModel]'s synchronous result so there's no
 * flash-of-nothing while the async fetch/normalize is in flight - it just
 * gets replaced once ready, identically to the synchronous behavior for any
 * URI the normalization doesn't end up touching.
 */
@Composable
internal fun rememberNormalizedLogoModel(uri: String): NormalizedLogo {
    var logo by remember(uri) { mutableStateOf(NormalizedLogo(coilLogoModel(uri))) }
    LaunchedEffect(uri) {
        logo = fetchAndNormalizeLogoModel(uri)
    }
    return logo
}

/**
 * Fraction of a [CredentialCard]'s own height left visible above the card
 * placed after it in [CredentialStack]. Card `i` sits at `y = i * peekHeight`,
 * so every card but the frontmost is covered from that point down by the one
 * in front of it - a smaller fraction shows more of the stack at once but
 * less of each individual card's face. 0.32 is enough to read a flat
 * (no-template) card's name/issuer row, which sits near the top of
 * [CredentialCard]'s layout, without needing its SVG template rendered at
 * all.
 */
private const val CREDENTIAL_PEEK_FRACTION = 0.32f

/**
 * The [androidx.compose.ui.platform.testTag] of a stacked card, keyed on its
 * batch id - public so instrumented tests can address one card in
 * [CredentialStack] without depending on its current position, which is the
 * whole point of a deck the user can reorder.
 */
fun credentialStackCardTestTag(batchId: Long): String = "credential-stack-card-$batchId"

/**
 * How far (as a fraction of a card's own height) a drag has to travel before
 * [CredentialStack] treats it as "pull this card out" rather than a gesture
 * that snaps back to where the card already was. Deliberately smaller than
 * the peek itself - the whole point is that a short, easy drag is enough to
 * bring a buried card forward, not a full card's worth of travel.
 */
private const val CREDENTIAL_PULL_THRESHOLD_FRACTION = 0.18f

/**
 * Tap, long-press and vertical drag on one card, mutually exclusive and
 * resolved by hand rather than by layering [CredentialCard]'s own built-in
 * `combinedClickable` under a separate `Modifier.draggable` - that
 * combination was tried first and silently ate every tap: two independent
 * gesture detectors on nodes at different depths both reach for the same
 * down event, and whichever claims it first starves the other, rather than
 * the two cooperating the way `clickable` + `draggable` siblings on a single
 * node are documented to. Written once here so [CredentialStack] never has
 * to reason about that interaction again.
 *
 * A quick release with no meaningful movement is [onTap]; holding still past
 * the platform's long-press timeout is [onLongPress] - and having fired,
 * nothing further happens for the rest of that gesture, so the eventual
 * release isn't also read as a tap. Movement past touch slop, whichever
 * comes first, becomes a drag: [onDragStart] once, then [onDrag] with each
 * frame's raw vertical delta, then [onDragEnd] on release.
 */
private suspend fun PointerInputScope.detectCredentialStackGestures(
    onTap: () -> Unit,
    onLongPress: () -> Unit,
    onDragStart: () -> Unit,
    onDrag: (deltaY: Float) -> Unit,
    onDragEnd: () -> Unit,
) {
    awaitEachGesture {
        awaitFirstDown(requireUnconsumed = false)
        val touchSlop = viewConfiguration.touchSlop
        var dragging = false
        var longPressFired = false
        var accumulatedY = 0f
        // Counts down in real time, independently of whether any pointer
        // event arrives - a finger held perfectly still can mean the OS
        // never delivers a single intermediate event between the down and
        // the eventual up, so checking elapsed time only when an event
        // shows up (as an earlier version of this function did) never
        // catches the long-press at all: the up event breaks the loop
        // before any check runs, and every long, still press reads as a
        // plain tap. Racing the wait itself against the deadline, instead
        // of reacting to events after the fact, is what makes a held-still
        // press actually resolve to long-press rather than requiring some
        // movement to ever notice the clock.
        var remainingMillis = viewConfiguration.longPressTimeoutMillis

        while (true) {
            val event = if (dragging || longPressFired) {
                awaitPointerEvent()
            } else {
                val waitStart = System.nanoTime()
                val result = withTimeoutOrNull(remainingMillis) { awaitPointerEvent() }
                val waited = (System.nanoTime() - waitStart) / 1_000_000
                remainingMillis = (remainingMillis - waited).coerceAtLeast(0)
                if (result == null) {
                    longPressFired = true
                    onLongPress()
                    continue
                }
                result
            }

            val change = event.changes.firstOrNull()
            if (change == null || change.changedToUpIgnoreConsumed()) {
                when {
                    dragging -> onDragEnd()
                    longPressFired -> Unit
                    else -> onTap()
                }
                break
            }

            if (dragging) {
                onDrag(change.positionChange().y)
                change.consume()
                continue
            }

            if (!longPressFired) {
                accumulatedY += change.positionChange().y
                if (kotlin.math.abs(accumulatedY) > touchSlop) {
                    dragging = true
                    onDragStart()
                    change.consume()
                }
            }
        }
    }
}

/**
 * A deck of [CredentialCard]s, each overlapping the one placed before it
 * rather than laid out full-height one after another - a wallet's whole
 * point is holding more credentials than fit on a screen shown one at a
 * time, and a plain scrolling list of full cards asks for exactly that much
 * scrolling to see what else is there.
 *
 * The stack is a real deck, not a static illustration of one: tapping a
 * card that isn't already at the front brings it forward (the same way
 * flipping through a hand of physical cards does - repeated taps cycle
 * through the whole stack), and dragging a card any real distance pulls it
 * the rest of the way out and drops it at the front, or lets go and it
 * settles back where it was if the drag didn't go far enough to mean it.
 * Getting to a credential this way never leaves this screen - full detail
 * only opens for the card that's *already* frontmost, since a second tap on
 * the one card already brought forward is the point where there's nothing
 * left for "bring it forward" to do.
 *
 * Every card still fully exists in the layout; only the *drawing* overlaps,
 * so what ends up hidden behind the front of the stack is precisely what
 * the frontmost card paints over - nothing here is cropped, faded, or
 * otherwise altered to fake the effect. Order is kept as this composable's
 * own state, keyed on each credential's stable batch id so a card's
 * position (and any settle animation in flight) survives recomposition
 * from something unrelated changing, like SVG hydration finishing - and so
 * a credential added or removed while the stack is on screen updates the
 * deck without resetting anyone else's position in it.
 *
 * [CredentialCard] itself is given no click/long-click handlers here - every
 * touch on a stacked card is read by [detectCredentialStackGestures] on the
 * wrapping [Box] instead, which is what makes tap, long-press and drag
 * resolve correctly against each other in the first place.
 */
@Composable
fun CredentialStack(
    entries: List<CredentialWithInstances>,
    onCredentialClick: (StoredCredential) -> Unit,
    onCredentialLongClick: (StoredCredential) -> Unit,
    onRenewCredential: (StoredCredential) -> Unit,
    onDeleteCredential: (StoredCredential) -> Unit,
    modifier: Modifier = Modifier,
    /**
     * Why each credential cannot currently be used, by credential id - the
     * SDK's run of DIIP's Validity and Revocation Algorithm (see
     * `WalletViewModel.credentialStatuses`). Credentials absent from the map
     * are usable. Threaded straight through to each stacked [CredentialCard].
     */
    credentialStatuses: Map<Long, CredentialStatus> = emptyMap(),
) {
    if (entries.isEmpty()) return
    val entryIds = entries.map { it.credential.batchId }
    val byId = remember(entries) { entries.associateBy { it.credential.batchId } }

    // Front-to-back order of batch ids; the LAST id is frontmost (fully
    // visible, nothing placed after it to cover it). Reconciled - not
    // replaced - whenever the actual set of credentials changes: survivors
    // keep their relative order (and so keep whatever position the user put
    // them in), a newly-added credential joins at the front.
    var order by remember { mutableStateOf(entryIds) }
    LaunchedEffect(entryIds) {
        val currentSet = entryIds.toSet()
        val kept = order.filter { it in currentSet }
        val added = entryIds.filter { it !in kept }
        if (kept != order || added.isNotEmpty()) {
            order = kept + added
        }
    }

    // Disabling the page's own scroll for the (brief) duration of an actual
    // card-pull, rather than trusting the two gestures to arbitrate
    // themselves: a card's drag and the deck's own vertical scroll are the
    // same axis, and letting both react to one gesture at once would read as
    // the page and the card fighting each other instead of one clean pull.
    var anyCardDragging by remember { mutableStateOf(false) }
    val scrollState = rememberScrollState()

    BoxWithConstraints(
        modifier = modifier
            .fillMaxWidth()
            .verticalScroll(scrollState, enabled = !anyCardDragging),
    ) {
        val density = LocalDensity.current
        val cardHeight = maxWidth / 1.6f
        val peek = cardHeight * CREDENTIAL_PEEK_FRACTION
        val peekPx = with(density) { peek.toPx() }
        val pullThresholdPx = with(density) { (cardHeight * CREDENTIAL_PULL_THRESHOLD_FRACTION).toPx() }
        val totalHeight = cardHeight + peek * (order.size - 1).coerceAtLeast(0)

        Box(modifier = Modifier.fillMaxWidth().height(totalHeight)) {
            order.forEachIndexed { index, id ->
                val entry = byId[id] ?: return@forEachIndexed
                key(id) {
                    val isFrontmost = index == order.lastIndex
                    val targetY = index * peekPx
                    val settledY = remember { Animatable(targetY) }
                    var dragOffset by remember { mutableFloatStateOf(0f) }
                    var isDragging by remember { mutableStateOf(false) }

                    // Settles to this card's stack slot whenever it isn't the
                    // one currently being dragged - which covers both an
                    // ordinary reorder (targetY changed) and the moment a
                    // drag just ended (isDragging just became false).
                    LaunchedEffect(targetY, isDragging) {
                        if (!isDragging) {
                            settledY.animateTo(
                                targetY,
                                spring(dampingRatio = Spring.DampingRatioNoBouncy, stiffness = Spring.StiffnessMediumLow),
                            )
                        }
                    }

                    val scale by animateFloatAsState(
                        targetValue = if (isDragging) 1.04f else 1f,
                        label = "credentialStackDragScale",
                    )

                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(cardHeight)
                            .testTag(credentialStackCardTestTag(id))
                            .graphicsLayer {
                                translationY = settledY.value + dragOffset
                                scaleX = scale
                                scaleY = scale
                            }
                            .zIndex(if (isDragging) order.size.toFloat() else index.toFloat())
                            .pointerInput(id, isFrontmost) {
                                detectCredentialStackGestures(
                                    onTap = {
                                        if (isFrontmost) {
                                            onCredentialClick(entry.credential)
                                        } else {
                                            order = (order - id) + id
                                        }
                                    },
                                    onLongPress = { onCredentialLongClick(entry.credential) },
                                    onDragStart = {
                                        isDragging = true
                                        anyCardDragging = true
                                    },
                                    onDrag = { deltaY -> dragOffset += deltaY },
                                    onDragEnd = {
                                        isDragging = false
                                        anyCardDragging = false
                                        val pulledFarEnough = kotlin.math.abs(dragOffset) > pullThresholdPx
                                        dragOffset = 0f
                                        if (pulledFarEnough && !isFrontmost) {
                                            order = (order - id) + id
                                        }
                                    },
                                )
                            },
                    ) {
                        CredentialCard(
                            credential = entry.credential,
                            instances = entry.instances,
                            onClick = null,
                            onLongClick = null,
                            onRenewClick = { onRenewCredential(entry.credential) },
                            onDeleteClick = { onDeleteCredential(entry.credential) },
                            credentialStatus = credentialStatuses[entry.credential.id],
                        )
                    }
                }
            }
        }
    }
}
