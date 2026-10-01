// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package com.facetec.sdk;

import android.content.Context;
import android.content.Intent;

/**
 * Test double for the part of the FaceTec SDK 10 API that FaceTecApi calls, with the same
 * names and signatures as com.facetec:facetec-sdk:10.1.17. It records calls and answers
 * synchronously; FaceTec10ApiContractTest checks the real AAR when one is available.
 */
public final class FaceTecSDK {
    public interface InitializeCallback {
        void onSuccess(FaceTecSDKInstance instance);

        void onError(FaceTecInitializationError error);
    }

    public static Context preloadedWith;
    public static String deviceKeyIdentifier;
    public static FaceTecSessionRequestProcessor processor;
    /** When set, initialization fails with this error instead of succeeding. */
    public static FaceTecInitializationError failInitializationWith;
    /** When set, preload throws it. */
    public static RuntimeException preloadThrows;
    /** What getActivitySessionResult returns. */
    public static FaceTecSessionResult sessionResult;

    public static void reset() {
        preloadedWith = null;
        deviceKeyIdentifier = null;
        processor = null;
        failInitializationWith = null;
        sessionResult = null;
        preloadThrows = null;
        FaceTecSDKInstance.startedWith = null;
        FaceTecSDKInstance.startedProcessor = null;
    }

    public static void preload(Context context) {
        if (preloadThrows != null) throw preloadThrows;
        preloadedWith = context;
    }

    public static void initializeWithSessionRequest(
            Context context,
            String deviceKeyIdentifier,
            FaceTecSessionRequestProcessor processor,
            InitializeCallback callback) {
        FaceTecSDK.deviceKeyIdentifier = deviceKeyIdentifier;
        FaceTecSDK.processor = processor;
        if (failInitializationWith != null) {
            callback.onError(failInitializationWith);
        } else {
            callback.onSuccess(new FaceTecSDKInstance());
        }
    }

    public static FaceTecSessionResult getActivitySessionResult(int requestCode, int resultCode, Intent data) {
        return sessionResult;
    }
}
