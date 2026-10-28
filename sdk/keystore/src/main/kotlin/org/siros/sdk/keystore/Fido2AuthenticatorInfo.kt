// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import uniffi.siros_wscd_manager.FfiAuthenticatorInfo
import uniffi.siros_wscd_manager.FfiClientPinState
import uniffi.siros_wscd_manager.FfiEnrolmentSuitability

/** Whether a FIDO2 authenticator has a client PIN. */
enum class Fido2PinState { SET, NOT_SET, UNSUPPORTED }

/**
 * Whether the authenticator can be enrolled as a wallet key. ADVISORY until it has been checked against real hardware:
 * the previewSign extension name the check relies on is not verified on a real key, and a blocked PIN (no retries left)
 * counts as [Unsuitable] on a raw transport.
 */
sealed interface Fido2Suitability {
    data object Suitable : Fido2Suitability

    /** [reason] is the library's English text, for logs and support; it is never a PIN or a secret. */
    data class Unsuitable(val reason: String) : Fido2Suitability
}

/**
 * What a FIDO2 authenticator says about itself (CTAP2 getInfo, plus the PIN retry counter when a PIN is set), read
 * WITHOUT asking for or sending a PIN. The [aaguid] identifies the authenticator MODEL, not the individual key.
 */
class Fido2AuthenticatorInfo(
    val versions: List<String>,
    aaguid: ByteArray,
    val clientPin: Fido2PinState,
    /** The minimum PIN length in characters; 4 when the authenticator does not say. */
    val minPinLength: Int,
    val forcePinChange: Boolean,
    /** Remaining PIN attempts; null unless a PIN is set. */
    val pinRetries: Int?,
    val pinUvAuthProtocols: List<Int>,
    val extensions: List<String>,
    val options: Map<String, Boolean>,
    val suitability: Fido2Suitability,
) {
    private val aaguidBytes: ByteArray = aaguid.copyOf()

    /** The 16-byte AAGUID (a copy). */
    val aaguid: ByteArray get() = aaguidBytes.copyOf()

    /** The AAGUID as a lower-case UUID string. */
    val aaguidString: String
        get() {
            val h = aaguidBytes.joinToString("") { "%02x".format(it) }
            return if (h.length == 32) "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}" else h
        }

    /**
     * Whether [other] is, as far as the enrolment dialog is concerned, the same situation: the same PIN state, the same
     * minimum PIN length and the same AAGUID. Anything else means a different key (or a changed one) and the dialog must be
     * asked again.
     */
    fun sameEnrolmentSituationAs(other: Fido2AuthenticatorInfo): Boolean =
        clientPin == other.clientPin && minPinLength == other.minPinLength && aaguidBytes.contentEquals(other.aaguidBytes)

    override fun toString() = "Fido2AuthenticatorInfo(aaguid=$aaguidString, clientPin=$clientPin, minPinLength=$minPinLength, suitability=$suitability)"
}

internal fun FfiAuthenticatorInfo.toSdk() = Fido2AuthenticatorInfo(
    versions = versions,
    aaguid = aaguid,
    clientPin = when (clientPin) {
        FfiClientPinState.SET -> Fido2PinState.SET
        FfiClientPinState.NOT_SET -> Fido2PinState.NOT_SET
        FfiClientPinState.UNSUPPORTED -> Fido2PinState.UNSUPPORTED
    },
    minPinLength = minPinLength.coerceAtMost(Int.MAX_VALUE.toUInt()).toInt(),
    forcePinChange = forcePinChange,
    pinRetries = pinRetries?.coerceAtMost(Int.MAX_VALUE.toUInt())?.toInt(),
    pinUvAuthProtocols = pinUvAuthProtocols.map { it.coerceAtMost(Int.MAX_VALUE.toUInt()).toInt() },
    extensions = extensions,
    options = options,
    suitability = when (val s = enrolmentSuitability) {
        is FfiEnrolmentSuitability.Suitable -> Fido2Suitability.Suitable
        is FfiEnrolmentSuitability.Unsuitable -> Fido2Suitability.Unsuitable(s.reason)
    },
)
