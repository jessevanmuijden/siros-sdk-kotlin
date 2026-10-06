// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package com.facetec.sdk;

/** Test double; see FaceTecSDK. */
public interface FaceTecSessionRequestProcessor {
    void onSessionRequest(String sessionRequestBlob, Callback callback);

    interface Callback {
        void processResponse(String responseBlob);

        void updateProgress(float progress);

        void abortOnCatastrophicError();
    }
}
