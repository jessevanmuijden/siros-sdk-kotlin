// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package com.facetec.sdk;

/**
 * Test double; see FaceTecSDK. Like the real enum, toString() returns display text rather than
 * the constant's name.
 */
public enum FaceTecSessionStatus {
    SESSION_COMPLETED,
    REQUEST_ABORTED,
    USER_CANCELLED_FACE_SCAN,
    USER_CANCELLED_ID_SCAN,
    LOCKED_OUT,
    CAMERA_ERROR,
    CAMERA_PERMISSIONS_DENIED,
    UNKNOWN_INTERNAL_ERROR;

    @Override
    public final String toString() {
        return "Session status: " + name().toLowerCase().replace('_', ' ');
    }
}
