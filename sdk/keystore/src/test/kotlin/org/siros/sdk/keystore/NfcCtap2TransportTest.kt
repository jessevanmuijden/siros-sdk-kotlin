// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import android.nfc.NfcAdapter
import android.nfc.TagLostException
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import java.io.IOException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class NfcCtap2TransportTest {
    class FakeReader(override var isEnabled: Boolean = true) : NfcReader {
        var enabled = 0
        var disabled = 0
        var armed = false
        private var onTag: ((NfcTagHandle) -> Unit)? = null
        override fun enableReaderMode(onTag: (NfcTagHandle) -> Unit) { enabled++; armed = true; this.onTag = onTag }
        override fun disableReaderMode() { disabled++; armed = false; onTag = null }

        /** The key is presented: delivered only while reader mode is armed; otherwise Android's own dispatcher would have it. */
        fun present(tag: NfcTagHandle): Boolean = onTag?.also { it(tag) } != null
    }

    private val ok = byteArrayOf(0x90.toByte(), 0x00)

    class FakeTag(private val connectFailure: Exception? = null, private val selectAnswer: ByteArray = byteArrayOf(0x90.toByte(), 0x00)) : NfcTagHandle {
        var closed = false
        override fun connect(timeoutMs: Int) { connectFailure?.let { throw it } }
        override fun transceive(apdu: ByteArray): ByteArray = if (apdu[1] == 0xA4.toByte()) selectAnswer else byteArrayOf(0x01, 0x02, 0x90.toByte(), 0x00)
        override fun close() { closed = true }
    }

    @Test
    fun aFirstTapThatFails_isFollowedByASecondTapThatSucceeds_withReaderModeNeverDisarmedBetween() = runTest {
        val reader = FakeReader()
        val transport = NfcCtap2Transport(reader, tagWaitTimeoutMs = 30_000)
        val connecting = async { transport.connect() }
        runCurrent()
        assertTrue(reader.armed)
        val first = FakeTag(connectFailure = TagLostException("gone"))
        assertTrue(reader.present(first))
        runCurrent()
        assertTrue("the failed tag was closed", first.closed)
        assertTrue("still waiting, still armed: the second tap is ours, not the OS dispatcher's", reader.armed)
        assertEquals(0, reader.disabled)
        assertEquals("armed once, not re-enabled per tap", 1, reader.enabled)
        assertTrue(reader.present(FakeTag()))
        runCurrent()
        connecting.await()
        assertArrayEquals(byteArrayOf(0x01, 0x02), transport.send(byteArrayOf(0x04)))
    }

    @Test
    fun aSelectThatFailsIsAlsoRetriedOnTheNextTap() = runTest {
        val reader = FakeReader()
        val transport = NfcCtap2Transport(reader, 30_000)
        val connecting = async { transport.connect() }
        runCurrent()
        reader.present(FakeTag(selectAnswer = byteArrayOf(0x6A.toByte(), 0x82.toByte())))
        runCurrent()
        assertTrue(reader.armed)
        reader.present(FakeTag())
        runCurrent()
        connecting.await()
        assertEquals(0, reader.disabled)
    }

    @Test
    fun whenNoTapWorksBeforeTheTimeout_readerModeIsDisarmedOnce_andTheErrorSaysWhy() = runTest {
        val reader = FakeReader()
        val transport = NfcCtap2Transport(reader, 5_000)
        val connecting = async { runCatching { transport.connect() } }
        runCurrent()
        repeat(3) { reader.present(FakeTag(connectFailure = TagLostException("gone"))); runCurrent() }
        assertTrue(reader.armed)
        advanceTimeBy(6_000)
        runCurrent()
        val failure = connecting.await().exceptionOrNull()
        assertTrue(failure.toString(), failure is Ctap2TransportException.DeviceDisconnected)
        assertEquals(1, reader.disabled)
        assertFalse(reader.armed)
    }

    @Test
    fun noTapAtAll_isATimeout() = runTest {
        val reader = FakeReader()
        val transport = NfcCtap2Transport(reader, 5_000)
        val connecting = async { runCatching { transport.connect() } }
        runCurrent()
        advanceTimeBy(6_000)
        runCurrent()
        assertTrue(connecting.await().exceptionOrNull() is Ctap2TransportException.Timeout)
        assertEquals(1, reader.disabled)
    }

    @Test
    fun noNfc_isNotAvailable_andNeverArms() = runTest {
        val reader = FakeReader(isEnabled = false)
        try {
            NfcCtap2Transport(reader).connect()
            fail("connected without NFC")
        } catch (_: Ctap2TransportException.NotAvailable) {
        }
        assertEquals(0, reader.enabled)
    }

    @Test
    fun disarmingReaderModeOnADestroyedActivityDoesNotThrow() {
        mockkStatic(NfcAdapter::class)
        try {
            val adapter = mockk<NfcAdapter>(relaxed = true)
            every { NfcAdapter.getDefaultAdapter(any()) } returns adapter
            every { adapter.disableReaderMode(any()) } throws IllegalStateException("Cannot disable reader mode: activity is already destroyed")
            AndroidNfcReader(mockk(relaxed = true)).disableReaderMode() // must not throw
        } finally {
            unmockkStatic(NfcAdapter::class)
        }
    }

    // ---- the composite keeps the failure of each branch and does not end one because the other is absent ----

    private class FakeBranch(val result: suspend () -> Unit) : Ctap2TransportProvider {
        override suspend fun send(command: ByteArray) = byteArrayOf()
        override suspend fun isAvailable() = true
        override suspend fun connect() = result()
        override suspend fun disconnect() {}
    }

    @Test
    fun theCompositeNamesWhichBranchFailedAndWhy_notJustThatBothFailed() = runTest {
        val composite = CompositeCtap2Transport(
            usb = FakeBranch { throw Ctap2TransportException.NotAvailable() },
            nfc = FakeBranch { throw Ctap2TransportException.DeviceDisconnected() },
            requestChoice = { null },
        )
        val failure = runCatching { composite.connect() }.exceptionOrNull()
        failure as Ctap2TransportException.TransportsUnavailable
        assertEquals("transport not available", failure.usb)
        assertEquals("key moved away (tag lost)", failure.nfc)
        assertTrue(failure.message!!.contains("NFC") && failure.message!!.contains("USB"))
    }

    @Test
    fun anAbsentUsbDoesNotEndTheNfcWait() = runTest {
        val composite = CompositeCtap2Transport(
            usb = FakeBranch { throw Ctap2TransportException.NotAvailable() }, // fails at once
            nfc = FakeBranch { kotlinx.coroutines.delay(20_000) }, // the user taps late and it works
            requestChoice = { null },
        )
        composite.connect() // no exception: NFC was still waited for
    }

    // ---- the callback boundary: a short typed error, never a stack trace ----

    @Test
    fun theUniffiCallbackBoundaryMapsEveryTransportFailureToAShortTypedError() {
        for (failure in listOf<Exception>(
            Ctap2TransportException.NotAvailable(),
            Ctap2TransportException.DeviceDisconnected(),
            Ctap2TransportException.Timeout(),
            Ctap2TransportException.ConnectionFailed("x"),
            Ctap2TransportException.TransportsUnavailable("not attached", "tag lost"),
            IllegalStateException("something internal with a long message ".repeat(20)),
            IOException("io"),
        )) {
            val bridge = Ctap2TransportBridge(FakeBranch { throw failure })
            val thrown = runCatching { bridge.ctap2SendCommand(byteArrayOf(1)) }.exceptionOrNull()
            thrown as uniffi.siros_wscd_manager.FfiWscdException.Callback
            val text = thrown.msg
            assertTrue(text, text.length <= 60)
            assertFalse("no stack trace in the message: $text", text.contains("\n") || text.contains("at org.") || text.contains("Exception"))
        }
        // The reason is the short mapped one.
        val tagLost = runCatching { Ctap2TransportBridge(FakeBranch { throw Ctap2TransportException.DeviceDisconnected() }).ctap2SendCommand(byteArrayOf(1)) }.exceptionOrNull()
        assertEquals("key moved away (tag lost)", (tagLost as uniffi.siros_wscd_manager.FfiWscdException.Callback).msg)
    }

    // ---- a connect that finishes after the timeout leaves nothing connected ----

    @Test
    fun aConnectThatFinishesAfterTheTimeoutIsClosedAndNeverPublished() {
        val reader = FakeReader()
        val transport = NfcCtap2Transport(reader, tagWaitTimeoutMs = 150)
        val slow = object : NfcTagHandle {
            var closed = false
            override fun connect(timeoutMs: Int) { Thread.sleep(500) } // blocking: not cancellable, finishes after the timeout
            override fun transceive(apdu: ByteArray) = byteArrayOf(0x90.toByte(), 0x00)
            override fun close() { closed = true }
        }
        val failure = kotlinx.coroutines.runBlocking {
            val connecting = kotlinx.coroutines.GlobalScope.async(kotlinx.coroutines.Dispatchers.Default) { runCatching { transport.connect() } }
            kotlinx.coroutines.delay(30)
            reader.present(slow)
            connecting.await().exceptionOrNull()
        }
        assertTrue(failure.toString(), failure is Ctap2TransportException)
        assertTrue("the late session was closed", slow.closed)
        assertFalse("and reader mode disarmed", reader.armed)
        // Nothing was published: a send has no session.
        val sendFailure = runCatching { kotlinx.coroutines.runBlocking { transport.send(byteArrayOf(1)) } }.exceptionOrNull()
        assertTrue(sendFailure is Ctap2TransportException.DeviceDisconnected)
    }

    // ---- the real ISO-DEP handle closes the IsoDep even when the timeout or the connect throws ----

    @Test
    fun theRealIsoDepHandleClosesTheIsoDepWhenSettingTheTimeoutOrConnectingThrows() {
        mockkStatic(android.nfc.tech.IsoDep::class)
        try {
            for (failAt in listOf("timeout", "connect")) {
                val iso = mockk<android.nfc.tech.IsoDep>(relaxed = true)
                every { android.nfc.tech.IsoDep.get(any()) } returns iso
                if (failAt == "timeout") every { iso.timeout = any() } throws IllegalStateException("tag lost") else every { iso.connect() } throws IOException("tag lost")
                val handle = IsoDepHandle(mockk(relaxed = true))
                try {
                    handle.connect(1000)
                    fail("connected")
                } catch (_: Exception) {
                }
                handle.close() // what the transport's retry loop does
                io.mockk.verify(exactly = 1) { iso.close() }
            }
        } finally {
            unmockkStatic(android.nfc.tech.IsoDep::class)
        }
    }

    // ---- the pre-seam constructor still exists for compiled consumers ----

    @Test
    fun theCompositeKeepsItsOldJvmConstructor() {
        CompositeCtap2Transport::class.java.getConstructor(UsbCtap2Transport::class.java, NfcCtap2Transport::class.java, kotlin.jvm.functions.Function1::class.java)
    }
}
