// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package com.facetec.sdk;

import android.app.Activity;

/** Test double; see FaceTecSDK. */
public class FaceTecSDKInstance {
    public static Activity startedWith;
    public static FaceTecSessionRequestProcessor startedProcessor;

    public void start3DLivenessThen3D2DPhotoIDMatch(Activity activity, FaceTecSessionRequestProcessor processor) {
        startedWith = activity;
        startedProcessor = processor;
    }
}
