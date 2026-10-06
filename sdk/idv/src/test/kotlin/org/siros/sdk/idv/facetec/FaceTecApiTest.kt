// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv.facetec

import android.app.Activity
import android.content.Context
import com.facetec.sdk.FaceTecInitializationError
import com.facetec.sdk.FaceTecSDK
import com.facetec.sdk.FaceTecSDKInstance
import com.facetec.sdk.FaceTecSessionRequestProcessor
import com.facetec.sdk.FaceTecSessionResult
import com.facetec.sdk.FaceTecSessionStatus
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException

/**
 * Runs [FaceTecApi]'s reflection against the FaceTec 10 test doubles in `src/test/java`, which
 * mirror com.facetec:facetec-sdk:10.1.17's signatures.
 */
class FaceTecApiTest {
    private val api = FaceTecApi()
    private val context = mockk<Context>()
    private val activity = mockk<Activity>()

    @Before
    fun reset() = FaceTecSDK.reset()

    @Test
    fun `every FaceTec 10 class and method resolves`() {
        assertNull(api.missingApi())
    }

    @Test
    fun `no FaceTec SDK on the classpath is reported, not thrown`() {
        val api = FaceTecApi(hiding("com.facetec."))

        assertNotNull(api.missingApi())
        assertTrue(api.missingApi()!!.contains("ClassNotFoundException"))
    }

    @Test
    fun `a FaceTec 9 SDK, which has no FaceTecSessionRequestProcessor, is reported as missing`() {
        val api = FaceTecApi(hiding(FaceTecApi.PROCESSOR))

        assertTrue(api.missingApi()!!.contains(FaceTecApi.PROCESSOR))
    }

    @Test
    fun `preload and initialize pass their arguments through`() {
        val processor = api.newSessionRequestProcessor(FaceTecSessionRequestRelay { _, _ -> error("unused") })
        var instance: Any? = null

        api.preload(context)
        api.initialize(context, "device-key", processor, onSuccess = { instance = it }, onError = { error(it) })

        assertSame(context, FaceTecSDK.preloadedWith)
        assertEquals("device-key", FaceTecSDK.deviceKeyIdentifier)
        assertSame(processor, FaceTecSDK.processor)
        assertTrue(instance is FaceTecSDKInstance)
    }

    @Test
    fun `an initialization error is reported by the constant's name, not its display text`() {
        FaceTecSDK.failInitializationWith = FaceTecInitializationError.DEVICE_NOT_SUPPORTED
        var reported: String? = null

        api.initialize(context, "k", api.newSessionRequestProcessor(FaceTecSessionRequestRelay { _, _ -> error("unused") }), { error("unexpected") }, { reported = it })

        assertEquals("DEVICE_NOT_SUPPORTED", reported)
    }

    @Test
    fun `startPhotoIdMatch starts the liveness then photo ID match session`() {
        val processor = api.newSessionRequestProcessor(FaceTecSessionRequestRelay { _, _ -> error("unused") })

        api.startPhotoIdMatch(FaceTecSDKInstance(), activity, processor)

        assertSame(activity, FaceTecSDKInstance.startedWith)
        assertSame(processor, FaceTecSDKInstance.startedProcessor)
    }

    @Test
    fun `the processor relays a request blob and hands the response blob back`() {
        val posted = mutableListOf<String>()
        val relay = FaceTecSessionRequestRelay { blob, _ ->
            posted += blob
            ProcessRequestResponse(responseBlob = "response-for-$blob")
        }
        val callback = RecordingCallback()

        (api.newSessionRequestProcessor(relay) as FaceTecSessionRequestProcessor).onSessionRequest("blob-1", callback)

        assertEquals(listOf("blob-1"), posted)
        assertEquals("response-for-blob-1", callback.response)
        assertFalse(callback.aborted)
    }

    @Test
    fun `the processor aborts the session when the request cannot be relayed`() {
        val relay = FaceTecSessionRequestRelay { _, _ -> throw IOException("offline") }
        val callback = RecordingCallback()

        (api.newSessionRequestProcessor(relay) as FaceTecSessionRequestProcessor).onSessionRequest("blob", callback)

        assertTrue(callback.aborted)
        assertNull(callback.response)
    }

    @Test
    fun `the processor answers Object methods itself`() {
        var calls = 0
        val processor = api.newSessionRequestProcessor(FaceTecSessionRequestRelay { _, _ -> calls++; error("unused") })

        assertTrue(processor == processor)
        assertFalse(processor.equals(Any()))
        assertEquals(System.identityHashCode(processor), processor.hashCode())
        assertTrue(processor.toString().contains("FaceTecSessionRequestProcessor"))
        assertEquals(0, calls)
    }

    @Test
    fun `the session status is read by the constant's name`() {
        FaceTecSDK.sessionResult = FaceTecSessionResult(FaceTecSessionStatus.USER_CANCELLED_ID_SCAN)

        assertEquals("USER_CANCELLED_ID_SCAN", api.sessionStatus(1, 0, null))
    }

    @Test
    fun `no session result gives no status`() {
        FaceTecSDK.sessionResult = null

        assertNull(api.sessionStatus(1, 0, null))
    }

    @Test
    fun `an exception thrown inside FaceTec surfaces as itself, not as a reflection wrapper`() {
        val failure = IllegalStateException("camera busy")
        FaceTecSDK.preloadThrows = failure

        val thrown = runCatching { api.preload(context) }.exceptionOrNull()

        assertSame(failure, thrown)
    }

    private class RecordingCallback : FaceTecSessionRequestProcessor.Callback {
        var response: String? = null
        var aborted = false

        override fun processResponse(responseBlob: String) {
            response = responseBlob
        }

        override fun updateProgress(progress: Float) = Unit

        override fun abortOnCatastrophicError() {
            aborted = true
        }
    }

    /** A class loader that pretends classes whose name starts with [prefix] do not exist. */
    private fun hiding(prefix: String) =
        object : ClassLoader(FaceTecApiTest::class.java.classLoader) {
            override fun loadClass(name: String, resolve: Boolean): Class<*> {
                if (name.startsWith(prefix)) throw ClassNotFoundException(name)
                return super.loadClass(name, resolve)
            }
        }
}
