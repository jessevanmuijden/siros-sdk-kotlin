// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import timber.log.Timber

/** One discovered ISO-DEP tag, as [NfcCtap2Transport] needs it (a seam over `Tag`/`IsoDep` so the transport is testable). */
interface NfcTagHandle {
    /** Opens the ISO-DEP session with the given exchange timeout; throws when the tag is gone or is not ISO-DEP. */
    fun connect(timeoutMs: Int)

    /** One APDU exchange; throws [android.nfc.TagLostException] / [java.io.IOException] when the tag went away. */
    fun transceive(apdu: ByteArray): ByteArray

    fun close()
}

/** The reader side of NFC, as [NfcCtap2Transport] needs it (a seam over `NfcAdapter` reader mode). */
interface NfcReader {
    /** False when the device has no NFC or it is switched off. */
    val isEnabled: Boolean

    /** Arms reader mode: every tag the key presents (again) is delivered to [onTag] until [disableReaderMode]. */
    fun enableReaderMode(onTag: (NfcTagHandle) -> Unit)

    /** Disarms reader mode. Never throws: an activity that is gone or paused has nothing left to disarm. */
    fun disableReaderMode()
}

/** The real [NfcReader] over the default [NfcAdapter] and [activity] (reader mode needs a foreground Activity). */
internal class AndroidNfcReader(private val activity: Activity) : NfcReader {
    private val adapter: NfcAdapter? get() = NfcAdapter.getDefaultAdapter(activity)

    override val isEnabled: Boolean get() = adapter?.isEnabled == true

    override fun enableReaderMode(onTag: (NfcTagHandle) -> Unit) {
        val nfc = adapter ?: throw Ctap2TransportException.NotAvailable()
        nfc.enableReaderMode(
            activity,
            { tag: Tag -> onTag(IsoDepHandle(tag)) },
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            null,
        )
    }

    override fun disableReaderMode() {
        val nfc = adapter ?: return
        try {
            nfc.disableReaderMode(activity)
        } catch (e: IllegalStateException) {
            // The activity is already destroyed (or not resumed): there is nothing left to disarm.
            Timber.d("NFC reader mode not disabled: ${e.javaClass.simpleName}")
        }
    }
}

internal class IsoDepHandle(private val tag: Tag) : NfcTagHandle {
    private var isoDep: IsoDep? = null

    override fun connect(timeoutMs: Int) {
        val tech = IsoDep.get(tag) ?: throw Ctap2TransportException.ConnectionFailed("Tag does not support ISO-DEP")
        // Held BEFORE the timeout and the connect, so close() reaches the real IsoDep when either of them throws.
        isoDep = tech
        tech.timeout = timeoutMs
        tech.connect()
    }

    override fun transceive(apdu: ByteArray): ByteArray = (isoDep ?: throw Ctap2TransportException.DeviceDisconnected()).transceive(apdu)

    override fun close() {
        runCatching { isoDep?.close() }
        isoDep = null
    }
}
