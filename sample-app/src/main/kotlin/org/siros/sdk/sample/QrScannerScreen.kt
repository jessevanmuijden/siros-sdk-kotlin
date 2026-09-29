// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import timber.log.Timber
import java.util.concurrent.Executors

/**
 * QR code scanner screen, multiplexed for both OID4VCI credential offer URIs
 * and OID4VP presentation request URIs. Forwards any decoded barcode value to
 * [onQrScanned] unfiltered - classification (and the deliberate fallback for
 * unrecognized shapes) lives entirely in the caller (WalletViewModel.handleQrResult),
 * not here.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrScannerScreen(
    onQrScanned: (String) -> Unit,
    onBack: () -> Unit,
    onUseProximityInstead: (() -> Unit)? = null,
) {
    val context = LocalContext.current
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            launcher.launch(Manifest.permission.CAMERA)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.qr_scanner_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.nav_back))
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            if (hasCameraPermission) {
                CameraPreviewWithScanner(
                    onQrScanned = onQrScanned,
                    modifier = Modifier.weight(1f),
                )
            } else {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Text(
                        text = stringResource(R.string.qr_scanner_permission_required),
                        style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(
                        onClick = { launcher.launch(Manifest.permission.CAMERA) },
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        Text(stringResource(R.string.qr_scanner_grant_permission))
                    }
                }
            }

            // Alternative engagement mode - low-emphasis so it never competes
            // with the viewfinder above or the paste-URI fallback below.
            if (onUseProximityInstead != null) {
                TextButton(
                    onClick = onUseProximityInstead,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.activate_use_proximity_instead))
                }
            }

            // Paste URI section (useful for testing / pre-authorized offers)
            HorizontalDivider()
            var pasteUri by remember { mutableStateOf("") }
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
            ) {
                Text(
                    text = stringResource(R.string.qr_scanner_paste_label),
                    style = MaterialTheme.typography.labelLarge,
                )
                Spacer(modifier = Modifier.height(4.dp))
                OutlinedTextField(
                    value = pasteUri,
                    onValueChange = { pasteUri = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("openid-credential-offer://...") },
                    singleLine = true,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Button(
                    onClick = { if (pasteUri.isNotBlank()) onQrScanned(pasteUri.trim()) },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = pasteUri.isNotBlank(),
                ) {
                    Text(stringResource(R.string.qr_scanner_paste_button))
                }
            }
        }
    }
}

/** How long the detection flash/checkmark stays on screen before handing off to [onQrScanned]. */
private const val DETECTION_FEEDBACK_DELAY_MS = 350L

@Composable
@androidx.annotation.OptIn(androidx.camera.core.ExperimentalGetImage::class)
private fun CameraPreviewWithScanner(
    onQrScanned: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    // Set the instant a barcode is decoded (on the analyzer's background thread,
    // dispatched to the main thread - see the executor.execute below). Drives the
    // detection overlay immediately, independent of onQrScanned's handoff, so the
    // user gets visual confirmation the scan succeeded even before the app reacts.
    var detectedValue by remember { mutableStateOf<String?>(null) }
    val scanned = detectedValue != null

    // Delay the actual handoff briefly so the detection overlay below is visible
    // for at least one frame before this screen is navigated away from - without
    // this, onQrScanned (which immediately closes the scanner) would fire in the
    // same frame the overlay would have appeared in, and the user would never see it.
    LaunchedEffect(detectedValue) {
        val value = detectedValue ?: return@LaunchedEffect
        kotlinx.coroutines.delay(DETECTION_FEEDBACK_DELAY_MS)
        onQrScanned(value)
    }

    Box(modifier = modifier.fillMaxSize()) {
        AndroidView(
            factory = { ctx ->
                val previewView = PreviewView(ctx)
                val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
                val mainExecutor = ContextCompat.getMainExecutor(ctx)

                cameraProviderFuture.addListener({
                    val cameraProvider = cameraProviderFuture.get()

                    val preview = Preview.Builder().build().also {
                        it.surfaceProvider = previewView.surfaceProvider
                    }

                    val analyzer = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()

                    val scanner = BarcodeScanning.getClient()
                    val executor = Executors.newSingleThreadExecutor()

                    analyzer.setAnalyzer(executor) { imageProxy ->
                        val mediaImage = imageProxy.image
                        if (mediaImage != null && detectedValue == null) {
                            val inputImage = InputImage.fromMediaImage(
                                mediaImage,
                                imageProxy.imageInfo.rotationDegrees,
                            )
                            scanner.process(inputImage)
                                .addOnSuccessListener { barcodes ->
                                    for (barcode in barcodes) {
                                        if (barcode.valueType == Barcode.TYPE_URL ||
                                            barcode.valueType == Barcode.TYPE_TEXT
                                        ) {
                                            val value = barcode.rawValue ?: continue
                                            // Don't pre-filter by classification here - onQrScanned
                                            // (WalletViewModel.handleQrResult) already classifies and,
                                            // deliberately, treats an unclassified URI as a presentation
                                            // request attempt (covers bare reference-URL QR codes with no
                                            // recognized scheme/query shape, e.g. some verifiers' "Link"
                                            // pages). A stricter gate here would silently drop those before
                                            // handleQrResult's own fallback ever runs.
                                            val parsed = android.net.Uri.parse(value)
                                            Timber.d("QR scanned: ${parsed.scheme}://${parsed.host}")
                                            // Compose state must be written on the main thread;
                                            // this analyzer callback runs on its own executor.
                                            mainExecutor.execute { detectedValue = value }
                                            break
                                        }
                                    }
                                }
                                .addOnCompleteListener {
                                    imageProxy.close()
                                }
                        } else {
                            imageProxy.close()
                        }
                    }

                    try {
                        cameraProvider.unbindAll()
                        cameraProvider.bindToLifecycle(
                            lifecycleOwner,
                            CameraSelector.DEFAULT_BACK_CAMERA,
                            preview,
                            analyzer,
                        )
                    } catch (e: Exception) {
                        Timber.e(e, "Camera bind failed")
                    }
                }, mainExecutor)

                previewView
            },
            modifier = Modifier.fillMaxSize(),
        )

        // Detection flash: a brief colored border around the whole preview,
        // the instant a QR code is decoded - immediate, obvious peripheral
        // feedback that doesn't depend on the user looking at any one spot.
        AnimatedVisibility(
            visible = scanned,
            enter = fadeIn(animationSpec = tween(durationMillis = 80)),
            exit = fadeOut(animationSpec = tween(durationMillis = 200)),
            modifier = Modifier.fillMaxSize(),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .border(width = 6.dp, color = DetectionAccentColor),
            )
        }

        // Detection checkmark: centered confirmation icon, the immediate and
        // visually obvious signal that the scan succeeded, before the app
        // hands off to the "starting…" feedback step.
        AnimatedVisibility(
            visible = scanned,
            enter = fadeIn(animationSpec = tween(durationMillis = 120)),
            exit = fadeOut(animationSpec = tween(durationMillis = 150)),
            modifier = Modifier.align(Alignment.Center),
        ) {
            Box(
                modifier = Modifier
                    .size(96.dp)
                    .background(color = DetectionAccentColor.copy(alpha = 0.85f), shape = CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Filled.CheckCircle,
                    contentDescription = stringResource(R.string.qr_scanner_detected),
                    tint = Color.White,
                    modifier = Modifier.size(56.dp),
                )
            }
        }

        // Hint overlay
        Text(
            text = stringResource(R.string.qr_scanner_hint),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
            textAlign = TextAlign.Center,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(32.dp),
        )
    }
}

/** Accent color for the QR-detection flash/checkmark overlay - a clear "success" green. */
private val DetectionAccentColor = Color(0xFF2E7D32)
