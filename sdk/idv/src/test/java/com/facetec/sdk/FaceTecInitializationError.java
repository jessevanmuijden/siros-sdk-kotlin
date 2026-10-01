// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package com.facetec.sdk;

/** Test double; see FaceTecSDK. Like the real enum, toString() returns display text. */
public enum FaceTecInitializationError {
    REJECTED_BY_SERVER,
    REQUEST_ABORTED,
    DEVICE_NOT_SUPPORTED;

    @Override
    public final String toString() {
        return "Initialization error: " + name().toLowerCase().replace('_', ' ');
    }
}
