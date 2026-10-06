// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv.facetec

import android.app.Activity
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject
import org.siros.sdk.idv.BiometricCaptureDelegate
import org.siros.sdk.idv.IDVException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * FaceTec biometric capture delegate.
 *
 * Implements [BiometricCaptureDelegate] by wrapping the FaceTec mobile SDK
 * using the FaceScanProcessor/IDScanProcessor callback pattern. Captured
 * biometric data is returned as a JSONObject for upload to the IDV backend
 * via [RemoteIDVClient].
 *
 * When the FaceTec SDK is not on the classpath, all methods throw
 * [IDVException.Unavailable].
 *
 * This targets the FaceTec **9** API. FaceTec 10 removed `FaceTecSDK.getStatus()`,
 * `FaceTecSession`, `FaceTecFaceScanProcessor`, `FaceTecIDScanSession` and
 * `FaceTecIDScanProcessor`, so with FaceTec 10 [isAvailable] is always `false`
 * (sirosfoundation/siros-sdk-kotlin#246). Use [FaceTecIDVProvider].
 */
@Deprecated(
    "Targets the FaceTec 9 API and cannot run with FaceTec 10. Use FaceTecIDVProvider.",
    ReplaceWith("FaceTecIDVProvider(FaceTecIDVConfig(processRequestUrl, authToken, deviceKeyIdentifier))"),
)
class FaceTecCaptureDelegate : BiometricCaptureDelegate {

    override val name: String = "FaceTec"

    override suspend fun isAvailable(): Boolean {
        return try {
            val sdkClass = Class.forName("com.facetec.sdk.FaceTecSDK")
            val getStatusMethod = sdkClass.getMethod("getStatus")
            val status = getStatusMethod.invoke(null)
            // FaceTecSDKStatus.INITIALIZED == ordinal 1
            status?.toString() == "INITIALIZED"
        } catch (_: Exception) {
            false
        }
    }

    override suspend fun captureLiveness(activity: Activity, sessionToken: String): JSONObject {
        if (!isAvailable()) {
            throw IDVException.Unavailable(
                "FaceTec SDK not available. Ensure com.facetec:facetec-sdk is on the classpath and initialized."
            )
        }

        return suspendCancellableCoroutine { cont ->
            try {
                // Use reflection to avoid compile-time dependency on FaceTec SDK
                val sessionClass = Class.forName("com.facetec.sdk.FaceTecSession")
                val processorClass = Class.forName("com.facetec.sdk.FaceTecFaceScanProcessor")

                val processor = java.lang.reflect.Proxy.newProxyInstance(
                    processorClass.classLoader,
                    arrayOf(processorClass)
                ) { _, method, args ->
                    when (method.name) {
                        "processSessionWhileFaceTecSDKWaits" -> {
                            val sessionResult = args[0]
                            val callback = args[1]

                            // Check status via reflection
                            val statusMethod = sessionResult.javaClass.getMethod("getStatus")
                            val status = statusMethod.invoke(sessionResult)

                            if (status?.toString() != "SESSION_COMPLETED_SUCCESSFULLY") {
                                cont.resumeWithException(
                                    IDVException.Cancelled()
                                )
                                // Call cancel on callback
                                callback.javaClass.getMethod("onFaceScanResultCancel").invoke(callback)
                                return@newProxyInstance null
                            }

                            // Extract biometric data
                            val faceScan = sessionResult.javaClass.getMethod("getFaceScanBase64")
                                .invoke(sessionResult) as? String ?: ""
                            val auditTrail = (sessionResult.javaClass.getMethod("getAuditTrailCompressedBase64")
                                .invoke(sessionResult) as? Array<*>)?.firstOrNull() as? String ?: ""
                            val lowQuality = (sessionResult.javaClass.getMethod("getLowQualityAuditTrailCompressedBase64")
                                .invoke(sessionResult) as? Array<*>)?.firstOrNull() as? String ?: ""
                            val sessionId = sessionResult.javaClass.getMethod("getSessionId")
                                .invoke(sessionResult) as? String ?: ""

                            val payload = JSONObject().apply {
                                put("faceScan", faceScan)
                                put("auditTrailImage", auditTrail)
                                put("lowQualityAuditTrailImage", lowQuality)
                                put("sessionId", sessionId)
                            }

                            cont.resume(payload)
                            // Signal SDK done
                            callback.javaClass.getMethod("onFaceScanGoToNextStep", String::class.java)
                                .invoke(callback, "")
                            null
                        }
                        "onFaceTecSDKCompletelyDone" -> {
                            if (cont.isActive) {
                                cont.resumeWithException(
                                    IDVException.Cancelled()
                                )
                            }
                            null
                        }
                        else -> null
                    }
                }

                // Create session: new FaceTecSession(activity, processor, sessionToken)
                val constructor = sessionClass.getConstructor(
                    Activity::class.java,
                    processorClass,
                    String::class.java
                )
                constructor.newInstance(activity, processor, sessionToken)
            } catch (e: Exception) {
                cont.resumeWithException(
                    IDVException.Unavailable("Failed to start FaceTec session: ${e.message}")
                )
            }
        }
    }

    override suspend fun captureDocument(
        activity: Activity,
        sessionToken: String,
        livenessSessionId: String,
    ): JSONObject {
        if (!isAvailable()) {
            throw IDVException.Unavailable(
                "FaceTec SDK not available. Ensure com.facetec:facetec-sdk is on the classpath and initialized."
            )
        }

        return suspendCancellableCoroutine { cont ->
            try {
                val sessionClass = Class.forName("com.facetec.sdk.FaceTecIDScanSession")
                val processorClass = Class.forName("com.facetec.sdk.FaceTecIDScanProcessor")

                val processor = java.lang.reflect.Proxy.newProxyInstance(
                    processorClass.classLoader,
                    arrayOf(processorClass)
                ) { _, method, args ->
                    when (method.name) {
                        "processIDScanWhileFaceTecSDKWaits" -> {
                            val idScanResult = args[0]
                            val callback = args[1]

                            val statusMethod = idScanResult.javaClass.getMethod("getStatus")
                            val status = statusMethod.invoke(idScanResult)

                            if (status?.toString() != "SUCCESS") {
                                cont.resumeWithException(
                                    IDVException.Cancelled()
                                )
                                callback.javaClass.getMethod("onIDScanResultCancel").invoke(callback)
                                return@newProxyInstance null
                            }

                            val frontImage = (idScanResult.javaClass.getMethod("getFrontImagesCompressedBase64")
                                .invoke(idScanResult) as? Array<*>)?.firstOrNull() as? String ?: ""
                            val backImage = (idScanResult.javaClass.getMethod("getBackImagesCompressedBase64")
                                .invoke(idScanResult) as? Array<*>)?.firstOrNull() as? String ?: ""
                            val sessionId = idScanResult.javaClass.getMethod("getSessionId")
                                .invoke(idScanResult) as? String ?: ""

                            val payload = JSONObject().apply {
                                put("idScanFrontImage", frontImage)
                                put("idScanBackImage", backImage)
                                put("livenessSessionId", livenessSessionId)
                                put("sessionId", sessionId)
                            }

                            cont.resume(payload)
                            callback.javaClass.getMethod("onIDScanResultGoToNextStep", String::class.java)
                                .invoke(callback, "")
                            null
                        }
                        "onFaceTecSDKCompletelyDone" -> {
                            if (cont.isActive) {
                                cont.resumeWithException(
                                    IDVException.Cancelled()
                                )
                            }
                            null
                        }
                        else -> null
                    }
                }

                val constructor = sessionClass.getConstructor(
                    Activity::class.java,
                    processorClass,
                    String::class.java
                )
                constructor.newInstance(activity, processor, sessionToken)
            } catch (e: Exception) {
                cont.resumeWithException(
                    IDVException.Unavailable("Failed to start FaceTec ID scan: ${e.message}")
                )
            }
        }
    }
}
