// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import timber.log.Timber
import java.io.File

/**
 * One `prep_prove`/`prove` timing sample from [VegaProofSystem] - the
 * per-call numbers [VegaProofSystem.generateProof] already logs via
 * [Timber] at INFO level, captured structurally instead so they can be
 * pulled off a real device and analyzed in bulk rather than grepped out of
 * a rotating logcat buffer (which, for a long test session, has already
 * been observed to roll past the entries that mattered - see this
 * project's own device-debugging notes).
 *
 * @param event "generateProof" (a real presentation) or "prewarm" (a
 *   speculative precompute via [VegaProofSystem.prewarm], which never calls
 *   `prove`) - distinguishes the two call sites sharing this sink.
 * @param usedCachedState whether this call's `prep_prove` stage was skipped
 *   because [VegaProofCache] already held a state for this exact
 *   (credential, disclosed-claims) pair.
 * @param prepProveMs wall time for the `prep_prove` stage, or null if it was
 *   skipped (a cache hit).
 * @param proveMs wall time for the `prove` stage, or null for a "prewarm"
 *   event (which never calls `prove`).
 * @param deviceModel/@param abi [android.os.Build.MODEL]/[android.os.Build.SUPPORTED_ABIS]'s
 *   first entry, read by the caller (not defaulted here) so this type stays
 *   a plain data holder - this module has no Robolectric setup, and a
 *   default argument touching `android.os.Build` would crash the instant a
 *   plain (non-instrumented) unit test ever constructed one.
 */
@Serializable
data class VegaProfilingEntry(
    val timestampMs: Long,
    val event: String,
    val usedCachedState: Boolean,
    val prepProveMs: Long?,
    val proveMs: Long?,
    val deviceModel: String,
    val abi: String,
)

/** Receives one [VegaProfilingEntry] per `prep_prove`/`prove` call. See [VegaProofSystem]'s `profilingSink` constructor parameter. */
fun interface VegaProfilingSink {
    suspend fun record(entry: VegaProfilingEntry)
}

/**
 * Appends each [VegaProfilingEntry] as one JSON-Lines record to [file], the
 * concrete sink [SirosWallet] wires in when
 * [org.siros.sdk.wallet.WalletConfig.vegaProfilingEnabled] is set.
 *
 * [file] should live under the app's external-files directory
 * (`Context.getExternalFilesDir(null)`), not internal storage - that is
 * what lets the data be retrieved with a plain
 * `adb pull /sdcard/Android/data/<applicationId>/files/<name>`, with no
 * root and no `run-as` dance, on a debuggable build.
 *
 * Not cleared automatically: entries accumulate across app runs until the
 * host deletes the file (or the user clears app storage), so a multi-run
 * profiling session can be pulled as one file covering all of them.
 */
class VegaProfilingFileSink(private val file: File) : VegaProfilingSink {
    private val mutex = Mutex()

    override suspend fun record(entry: VegaProfilingEntry) {
        mutex.withLock {
            runCatching {
                file.parentFile?.mkdirs()
                file.appendText(Json.encodeToString(entry) + "\n")
            }.onFailure { Timber.w(it, "Failed to write Vega profiling entry to $file") }
        }
    }
}
