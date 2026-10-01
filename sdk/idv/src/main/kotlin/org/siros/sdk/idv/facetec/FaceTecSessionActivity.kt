// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv.facetec

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import kotlinx.coroutines.CompletableDeferred
import org.siros.sdk.idv.IDVException
import org.siros.sdk.idv.IDVResult
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Invisible host for one FaceTec 10 session, started by [FaceTecIDVProvider].
 *
 * FaceTec runs its session in an Activity of its own and reports the result through the
 * *starting* Activity's `onActivityResult`. A library cannot hook the app's Activity, so the
 * provider starts this one, which asks for the camera, initializes FaceTec, starts the session
 * and completes the provider's pending result when FaceTec reports back.
 */
internal class FaceTecSessionActivity : Activity() {
    /** What a session needs that cannot travel in an Intent. */
    class PendingSession(
        val api: FaceTecApi,
        val deviceKeyIdentifier: String,
        val relay: FaceTecSessionRequestRelay,
        val result: CompletableDeferred<IDVResult>,
    ) {
        val processor: Any = api.newSessionRequestProcessor(relay)
    }

    companion object {
        const val EXTRA_SESSION_ID = "org.siros.sdk.idv.facetec.SESSION_ID"
        private const val REQUEST_CAMERA_PERMISSION = 0x5150

        private val pending = ConcurrentHashMap<String, PendingSession>()

        fun register(session: PendingSession): String =
            UUID.randomUUID().toString().also { pending[it] = session }

        fun unregister(id: String) {
            pending.remove(id)
        }
    }

    private var sessionId: String? = null
    private var session: PendingSession? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        sessionId = intent.getStringExtra(EXTRA_SESSION_ID)
        session = sessionId?.let { pending[it] }
        if (session == null) {
            // The process was restarted, so whoever was waiting for this session is gone.
            finish()
            return
        }
        // Recreated (e.g. rotated) while FaceTec's own Activity is on top: the session is
        // already running and its result will arrive in onActivityResult.
        if (savedInstanceState != null) return

        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startSession()
        } else {
            requestPermissions(arrayOf(Manifest.permission.CAMERA), REQUEST_CAMERA_PERMISSION)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQUEST_CAMERA_PERMISSION) return

        if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) {
            startSession()
        } else {
            fail(IDVException.Unavailable("camera permission denied"))
        }
    }

    private fun startSession() {
        val s = session ?: return
        try {
            s.api.preload(this)
            s.api.initialize(
                context = this,
                deviceKeyIdentifier = s.deviceKeyIdentifier,
                processor = s.processor,
                onSuccess = { instance ->
                    // FaceTec calls back on a worker thread.
                    runOnUiThread {
                        try {
                            s.api.startPhotoIdMatch(instance, this, s.processor)
                        } catch (t: Throwable) {
                            fail(IDVException.Unavailable("FaceTec session could not be started: $t"))
                        }
                    }
                },
                onError = { error ->
                    runOnUiThread { fail(IDVException.Unavailable("FaceTec initialization failed: $error")) }
                },
            )
        } catch (t: Throwable) {
            // Throwable: a FaceTec AAR that does not match the device fails with an Error
            // (e.g. UnsatisfiedLinkError), and the caller must still get an answer.
            fail(IDVException.Unavailable("FaceTec could not be initialized: $t"))
        }
    }

    // FaceTec reports its session result through the legacy startActivityForResult API.
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val s = session ?: return

        val status = try {
            s.api.sessionStatus(requestCode, resultCode, data)
        } catch (t: Throwable) {
            fail(IDVException.ProviderError("no_session_result", "FaceTec session result could not be read: $t"))
            return
        }
        complete { sessionOutcome(status, s.relay) }
    }

    private fun fail(e: IDVException) = complete { throw e }

    private fun complete(outcome: () -> IDVResult) {
        val s = session ?: return
        try {
            s.result.complete(outcome())
        } catch (e: IDVException) {
            s.result.completeExceptionally(e)
        }
        sessionId?.let(::unregister)
        finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        // Finishing without a result (e.g. the user backed out before FaceTec started).
        if (isFinishing) session?.result?.completeExceptionally(IDVException.Cancelled())
    }
}
