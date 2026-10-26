package org.siros.sdk.keystore

/**
 * Interface for providing a CTAP2 transport channel to external authenticators.
 *
 * Implementations bridge platform-specific BLE or NFC communication
 * to the WSCD's CTAP2 transport requirements. The wallet application
 * provides a concrete implementation that handles device discovery,
 * pairing, and CBOR message framing over the chosen transport.
 *
 * Usage with WSCD:
 * ```kotlin
 * class BleTransport(private val context: Context) : Ctap2TransportProvider {
 *     override suspend fun send(command: ByteArray): ByteArray {
 *         // BLE GATT write/notify cycle
 *     }
 *     override suspend fun isAvailable(): Boolean {
 *         return context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)
 *     }
 * }
 * ```
 */
interface Ctap2TransportProvider {
    /**
     * Send a CTAP2 command (CBOR-encoded) and return the response.
     *
     * The implementation handles framing (e.g. BLE fragmentation)
     * and waits for the authenticator response.
     *
     * @param command CBOR-encoded CTAP2 command bytes.
     * @return CBOR-encoded CTAP2 response bytes.
     */
    suspend fun send(command: ByteArray): ByteArray

    /** Whether the transport is currently available and connected. */
    suspend fun isAvailable(): Boolean

    /**
     * Attempt to discover and connect to an authenticator.
     *
     * For BLE: starts scanning for FIDO2 service UUID.
     * For NFC: initiates tag polling session.
     */
    suspend fun connect()

    /** Disconnect from the current authenticator. */
    suspend fun disconnect()
}

/** Errors specific to CTAP2 transport operations. */
sealed class Ctap2TransportException(
    /** Machine-readable error code for i18n mapping. */
    val errorCode: String,
    message: String,
) : Exception(message) {
    class NotAvailable : Ctap2TransportException("ctap2_not_available", "CTAP2 transport not available")
    class ConnectionFailed(detail: String) : Ctap2TransportException("ctap2_connection_failed", "Connection failed: $detail")
    class Timeout : Ctap2TransportException("ctap2_timeout", "CTAP2 transport timeout")
    class DeviceDisconnected : Ctap2TransportException("ctap2_device_disconnected", "Authenticator disconnected")
    class InvalidResponse(detail: String) : Ctap2TransportException("ctap2_invalid_response", "Invalid CTAP2 response: $detail")

    /** Neither physical transport produced a usable authenticator; [usb] and [nfc] say, in short words, why each gave up. */
    class TransportsUnavailable(val usb: String, val nfc: String) :
        Ctap2TransportException("ctap2_not_available", "No security key found (NFC: $nfc; USB: $usb)")
}

/**
 * A short, user-presentable reason for [this] failure of a CTAP2 transport (no stack trace, no payload, no device identifiers):
 * what a caller may show or put in an error message. The full cause belongs in a log, never in this text.
 */
fun Throwable.shortTransportReason(): String = when (this) {
    is Ctap2TransportException.NotAvailable -> "transport not available"
    is Ctap2TransportException.Timeout -> "timed out waiting for the key"
    is Ctap2TransportException.DeviceDisconnected -> "key moved away (tag lost)"
    is Ctap2TransportException.TransportsUnavailable -> "no security key found"
    is Ctap2TransportException.ConnectionFailed -> "could not talk to the key"
    is Ctap2TransportException.InvalidResponse -> "unexpected answer from the key"
    else -> "security key communication failed"
}
