// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package com.facetec.sdk;

/** Test double; see FaceTecSDK. */
public class FaceTecSessionResult {
    private final FaceTecSessionStatus status;

    public FaceTecSessionResult(FaceTecSessionStatus status) {
        this.status = status;
    }

    public FaceTecSessionStatus getStatus() {
        return status;
    }
}
