// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv.facetec

import android.app.Activity
import android.content.Context
import android.content.Intent
import java.lang.reflect.InvocationHandler
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Proxy

/**
 * Every call this module makes into the FaceTec SDK, by reflection, so the SDK has no
 * compile-time dependency on FaceTec's (privately distributed) AAR: an app that wants FaceTec
 * adds the AAR itself.
 *
 * Targets the FaceTec **10** API (checked against 10.1.17): one `FaceTecSessionRequestProcessor`
 * relays opaque blobs to the backend, and `start3DLivenessThen3D2DPhotoIDMatch` runs liveness,
 * the document scan and the NFC chip read in one session. Every class and method looked up is
 * named in the constants below and resolved together by [missingApi], so a FaceTec release that
 * renames one fails that check (and its unit tests) instead of failing silently on a device.
 *
 * @param classLoader Where to look for the FaceTec classes; tests substitute their own.
 */
internal class FaceTecApi(
    private val classLoader: ClassLoader = FaceTecApi::class.java.classLoader!!,
) {
    companion object {
        const val SDK = "com.facetec.sdk.FaceTecSDK"
        const val SDK_INSTANCE = "com.facetec.sdk.FaceTecSDKInstance"
        const val INITIALIZE_CALLBACK = "com.facetec.sdk.FaceTecSDK\$InitializeCallback"
        const val PROCESSOR = "com.facetec.sdk.FaceTecSessionRequestProcessor"
        const val PROCESSOR_CALLBACK = "com.facetec.sdk.FaceTecSessionRequestProcessor\$Callback"
        const val SESSION_RESULT = "com.facetec.sdk.FaceTecSessionResult"
    }

    private class Resolved(
        val initializeCallback: Class<*>,
        val processor: Class<*>,
        val preload: Method,
        val initializeWithSessionRequest: Method,
        val getActivitySessionResult: Method,
        val start3DLivenessThen3D2DPhotoIDMatch: Method,
        val getStatus: Method,
        val processResponse: Method,
        val abortOnCatastrophicError: Method,
    )

    private val resolved: Result<Resolved> by lazy { runCatching { resolve() } }

    private fun cls(name: String): Class<*> = Class.forName(name, false, classLoader)

    private fun resolve(): Resolved {
        val sdk = cls(SDK)
        val instance = cls(SDK_INSTANCE)
        val initializeCallback = cls(INITIALIZE_CALLBACK)
        val processor = cls(PROCESSOR)
        val processorCallback = cls(PROCESSOR_CALLBACK)
        val sessionResult = cls(SESSION_RESULT)
        return Resolved(
            initializeCallback = initializeCallback,
            processor = processor,
            preload = sdk.getMethod("preload", Context::class.java),
            initializeWithSessionRequest = sdk.getMethod(
                "initializeWithSessionRequest",
                Context::class.java,
                String::class.java,
                processor,
                initializeCallback,
            ),
            getActivitySessionResult = sdk.getMethod(
                "getActivitySessionResult",
                Int::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
                Intent::class.java,
            ),
            start3DLivenessThen3D2DPhotoIDMatch = instance.getMethod(
                "start3DLivenessThen3D2DPhotoIDMatch",
                Activity::class.java,
                processor,
            ),
            getStatus = sessionResult.getMethod("getStatus"),
            processResponse = processorCallback.getMethod("processResponse", String::class.java),
            abortOnCatastrophicError = processorCallback.getMethod("abortOnCatastrophicError"),
        )
    }

    private val api: Resolved get() = resolved.getOrThrow()

    /**
     * `null` when every FaceTec 10 class and method this module uses resolves; otherwise a
     * description of what is missing (no FaceTec SDK on the classpath, or an incompatible one).
     */
    fun missingApi(): String? =
        resolved.exceptionOrNull()?.let { "${it.javaClass.simpleName}: ${it.message}" }

    fun preload(context: Context) {
        call { api.preload.invoke(null, context) }
    }

    /**
     * Starts FaceTec's asynchronous initialization. Exactly one of [onSuccess] (with the
     * `FaceTecSDKInstance`) or [onError] (with the `FaceTecInitializationError` constant's
     * name) is called later, on a thread of the SDK's choosing.
     */
    fun initialize(
        context: Context,
        deviceKeyIdentifier: String,
        processor: Any,
        onSuccess: (instance: Any) -> Unit,
        onError: (error: String) -> Unit,
    ) {
        val callback = proxy(api.initializeCallback) { method, args ->
            when (method.name) {
                "onSuccess" -> onSuccess(args!![0]!!)
                "onError" -> onError(enumName(args!![0]))
            }
            null
        }
        call { api.initializeWithSessionRequest.invoke(null, context, deviceKeyIdentifier, processor, callback) }
    }

    /** Launches the liveness → ID scan (with NFC) → 3D:2D match session in its own Activity. */
    fun startPhotoIdMatch(instance: Any, activity: Activity, processor: Any) {
        call { api.start3DLivenessThen3D2DPhotoIDMatch.invoke(instance, activity, processor) }
    }

    /**
     * The `FaceTecSessionStatus` constant's name for an `onActivityResult` delivery, or `null`
     * when the result is not a FaceTec session's.
     */
    fun sessionStatus(requestCode: Int, resultCode: Int, data: Intent?): String? {
        val result = call { api.getActivitySessionResult.invoke(null, requestCode, resultCode, data) } ?: return null
        return enumName(call { api.getStatus.invoke(result) })
    }

    /** A `FaceTecSessionRequestProcessor` that hands every request to [relay]. */
    fun newSessionRequestProcessor(relay: FaceTecSessionRequestRelay): Any =
        proxy(api.processor) { method, args ->
            if (method.name == "onSessionRequest") {
                val requestBlob = args!![0] as String
                val callback = args[1]!!
                val responseBlob = relay.onSessionRequest(requestBlob)
                if (responseBlob != null) {
                    call { api.processResponse.invoke(callback, responseBlob) }
                } else {
                    call { api.abortOnCatastrophicError.invoke(callback) }
                }
            }
            null
        }

    /**
     * Implements [iface] with [handler], answering `Object`'s own methods itself (a FaceTec
     * class may put the proxy in a map or log it).
     */
    private fun proxy(iface: Class<*>, handler: (Method, Array<out Any?>?) -> Any?): Any {
        lateinit var self: Any
        self = Proxy.newProxyInstance(iface.classLoader, arrayOf(iface), InvocationHandler { _, method, args ->
            when (method.name) {
                "equals" -> if (method.parameterCount == 1) self === args!![0] else handler(method, args)
                "hashCode" -> if (method.parameterCount == 0) System.identityHashCode(self) else handler(method, args)
                "toString" -> if (method.parameterCount == 0) "FaceTec ${iface.simpleName} (SIROS SDK)" else handler(method, args)
                else -> handler(method, args)
            }
        })
        return self
    }

    /**
     * FaceTec's enums override `toString()` with display text, so the constant is identified
     * by [Enum.name].
     */
    private fun enumName(value: Any?): String = (value as? Enum<*>)?.name ?: value.toString()

    /** Unwraps reflection's wrapper so callers see the FaceTec SDK's own exception. */
    private inline fun <T> call(block: () -> T): T =
        try {
            block()
        } catch (e: InvocationTargetException) {
            throw e.targetException ?: e
        }
}
