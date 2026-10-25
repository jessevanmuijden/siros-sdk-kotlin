package org.siros.sdk.keystore

import android.app.Activity
import android.nfc.TagLostException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeout
import timber.log.Timber
import java.io.IOException

/**
 * NFC CTAP2 transport for FIDO2 authenticators (e.g. YubiKey) presented as
 * an ISO-DEP (ISO 14443-4) tag.
 *
 * Implements the SDK-level [Ctap2TransportProvider] - same division of
 * responsibility as [UsbCtap2Transport]: all previewSign CBOR
 * request-building and response-parsing lives in Rust
 * (`siros-wscd-manager`'s `preview_sign_protocol` module). This class only
 * owns the physical transport below that - CTAP2's NFC framing (FIDO
 * CTAP2.1 §8.2.9): select the FIDO applet by AID, then wrap each raw CTAP2
 * command (leading command byte + CBOR params) in an extended-length ISO
 * 7816-4 APDU and return the response with its trailing SW1SW2 stripped.
 *
 * Unlike USB's CTAPHID (channel handshake + KEEPALIVE polling while waiting
 * for a physical touch), NFC has no separate "user presence" signal - the
 * user tapping/holding the authenticator to the reader IS presence, so
 * there's no keepalive loop to handle, just a single blocking APDU
 * exchange per command. The user must keep the authenticator in the NFC
 * field for the whole session (every [send] call), not just the initial
 * tap - lifting it early surfaces as [Ctap2TransportException.DeviceDisconnected]
 * via [TagLostException], which [Ctap2TransportBridge] already retries
 * once by reconnecting.
 *
 * Takes an [Activity] rather than a plain [android.content.Context] -
 * `NfcAdapter.enableReaderMode` requires one; this is a real Android API
 * constraint, not a design choice, so a host app must supply its current
 * foreground Activity when constructing this transport.
 */
class NfcCtap2Transport internal constructor(
    private val reader: NfcReader,
    private val tagWaitTimeoutMs: Long = TAG_WAIT_TIMEOUT_MS,
) : Ctap2TransportProvider {

    constructor(activity: Activity) : this(AndroidNfcReader(activity))

    private var isoDep: NfcTagHandle? = null

    companion object {
        private const val TAG = "NfcCtap2Transport"

        // FIDO2 CTAP2 applet AID (FIDO CTAP2.1 §8.2.9.1).
        private val FIDO_AID = byteArrayOf(
            0xA0.toByte(), 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
        )

        private const val SW_SUCCESS = 0x9000
        internal const val TAG_WAIT_TIMEOUT_MS = 30_000L
        private const val ISODEP_TIMEOUT_MS = 20_000

    }

    override suspend fun isAvailable(): Boolean = reader.isEnabled

    /**
     * Waits for the key to be presented and selects its FIDO applet.
     *
     * Reader mode is armed ONCE and stays armed for the whole wait: a first presentation that fails (the tag moved away during
     * the SELECT, an ISO-DEP error, the key re-presented) is logged (type and short reason, never payload bytes) and the next
     * presentation is handled here too, so Android's own tag dispatcher (the YubiKey OTP "Web link" prompt) never gets the key
     * while an enrollment is waiting. Reader mode is disarmed only on a timeout or cancellation (a connected session keeps it
     * until [disconnect]).
     */
    override suspend fun connect() {
        if (!reader.isEnabled) throw Ctap2TransportException.NotAvailable()
        val tags = Channel<NfcTagHandle>(Channel.UNLIMITED)
        reader.enableReaderMode { tag -> tags.trySend(tag) }
        var lastFailure: Throwable? = null
        // The tag whose session this call opened: published to [isoDep] only when the wait ended in success, so a connect/SELECT
        // that finishes AFTER the timeout or a cancellation fired never leaves a connected session behind.
        var opened: NfcTagHandle? = null
        try {
            Timber.i("$TAG: waiting for NFC tap - present the security key")
            withTimeout(tagWaitTimeoutMs) {
                while (true) {
                    val tag = tags.receive()
                    try {
                        tag.connect(ISODEP_TIMEOUT_MS)
                        selectFidoApplet(tag)
                        opened = tag
                        return@withTimeout
                    } catch (e: kotlinx.coroutines.CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        runCatching { tag.close() }
                        lastFailure = e
                        // The cause, for the log only: type and message, never APDU bytes.
                        Timber.w("$TAG: tag connection failed (${e.javaClass.simpleName}: ${e.message?.take(80)}); waiting for the next tap")
                    }
                }
            }
            isoDep = opened
            Timber.i("$TAG: FIDO2 applet selected over NFC")
        } catch (e: TimeoutCancellationException) {
            runCatching { opened?.close() }
            reader.disableReaderMode()
            throw lastFailure?.let { mapFailure(it) } ?: Ctap2TransportException.Timeout()
        } catch (e: kotlinx.coroutines.CancellationException) {
            runCatching { opened?.close() }
            reader.disableReaderMode()
            throw e
        } finally {
            tags.close()
        }
    }

    /** A tag-level failure as a typed transport error with a short, payload-free reason. */
    private fun mapFailure(e: Throwable): Ctap2TransportException = when (e) {
        is Ctap2TransportException -> e
        is TagLostException -> Ctap2TransportException.DeviceDisconnected()
        is IOException -> Ctap2TransportException.DeviceDisconnected()
        else -> Ctap2TransportException.ConnectionFailed(e.javaClass.simpleName)
    }

    override suspend fun disconnect() {
        runCatching { isoDep?.close() }
        isoDep = null
        reader.disableReaderMode()
    }

    /**
     * Send a raw CTAP2 command (already CBOR-encoded with its leading
     * command byte, built by Rust's `preview_sign_protocol` module) and
     * return the raw response bytes exactly as received (leading status
     * byte + CBOR body) - same shape [UsbCtap2Transport.send] returns. No
     * CBOR knowledge here - Rust does all encoding/decoding on both sides.
     */
    override suspend fun send(command: ByteArray): ByteArray {
        val tech = isoDep ?: throw Ctap2TransportException.DeviceDisconnected()
        Timber.d("$TAG: CTAP2 command (${command.size}B)")
        val response = try {
            tech.transceive(buildApdu(command))
        } catch (e: TagLostException) {
            isoDep = null
            throw Ctap2TransportException.DeviceDisconnected()
        } catch (e: IOException) {
            throw Ctap2TransportException.DeviceDisconnected()
        }
        val unwrapped = unwrapApduResponse(response)
        Timber.d("$TAG: CTAP2 response (${unwrapped.size}B)")
        return unwrapped
    }

    /** ISO 7816-4 SELECT (by name) for the FIDO2 applet AID. */
    private fun selectFidoApplet(tech: NfcTagHandle) {
        val selectApdu = byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, FIDO_AID.size.toByte()) +
            FIDO_AID + byteArrayOf(0x00)
        val response = tech.transceive(selectApdu)
        val sw = statusWord(response)
        if (sw != SW_SUCCESS) {
            throw Ctap2TransportException.ConnectionFailed(
                "SELECT FIDO applet failed: SW=0x${sw.toString(16)}",
            )
        }
    }

    /**
     * Wrap a raw CTAP2 command in a CTAP2-over-NFC APDU (FIDO CTAP2.1
     * §8.2.9.2): CLA=0x80, INS=0x10, P1=P2=0x00, extended-length Lc/data,
     * extended Le=0x0000 (accept up to the protocol maximum back).
     */
    private fun buildApdu(command: ByteArray): ByteArray {
        val lc = command.size
        val header = byteArrayOf(0x80.toByte(), 0x10, 0x00, 0x00)
        val lcBytes = byteArrayOf(0x00, ((lc shr 8) and 0xFF).toByte(), (lc and 0xFF).toByte())
        val le = byteArrayOf(0x00, 0x00)
        return header + lcBytes + command + le
    }

    private fun unwrapApduResponse(response: ByteArray): ByteArray {
        val sw = statusWord(response)
        if (sw != SW_SUCCESS) {
            throw Ctap2TransportException.InvalidResponse("APDU status 0x${sw.toString(16)}")
        }
        return response.copyOfRange(0, response.size - 2)
    }

    private fun statusWord(response: ByteArray): Int {
        if (response.size < 2) {
            throw Ctap2TransportException.InvalidResponse("APDU response too short")
        }
        return ((response[response.size - 2].toInt() and 0xFF) shl 8) or
            (response[response.size - 1].toInt() and 0xFF)
    }
}
