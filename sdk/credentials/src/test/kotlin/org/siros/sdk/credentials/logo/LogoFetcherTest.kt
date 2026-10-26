// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.logo

import android.graphics.Bitmap
import android.graphics.Color
import java.io.ByteArrayOutputStream
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.Buffer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class LogoFetcherTest {
    private val server = MockWebServer()
    private val plain = MockWebServer()
    private lateinit var client: OkHttpClient

    @Before
    fun setUp() {
        val cert = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
        val serverTls = HandshakeCertificates.Builder().heldCertificate(cert).build()
        val clientTls = HandshakeCertificates.Builder().addTrustedCertificate(cert.certificate).build()
        server.useHttps(serverTls.sslSocketFactory(), false)
        server.start()
        plain.start()
        client = OkHttpClient.Builder().sslSocketFactory(clientTls.sslSocketFactory(), clientTls.trustManager).build()
    }

    @After
    fun tearDown() {
        // A throttled-body test leaves the server thread mid-sleep; that is not a failure.
        try {
            server.shutdown()
        } catch (e: java.io.IOException) {
            // ignored
        }
        plain.shutdown()
    }

    private fun png(w: Int = 8, h: Int = 8): ByteArray {
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        bmp.eraseColor(Color.RED)
        return ByteArrayOutputStream().also { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }.toByteArray()
    }

    private fun body(bytes: ByteArray, type: String? = "image/png") =
        MockResponse().setBody(Buffer().write(bytes)).also { r -> type?.let { r.addHeader("Content-Type", it) } }

    private fun url(path: String = "/logo") = server.url(path).toString()
    private fun load(f: LogoFetcher = LogoFetcher(client), u: String = url()) = runBlocking { f.load(u) }

    @Test
    fun `loads a png over https as a clean png`() {
        server.enqueue(body(png()))
        assertTrue(load() is LogoLoad.Loaded)
    }

    @Test
    fun `non https and credentialed urls never reach the network`() {
        assertEquals(LogoLoad.Rejected(LogoRejection.UnsupportedScheme), load(u = plain.url("/l").toString()))
        assertEquals(LogoLoad.Rejected(LogoRejection.InvalidUrl), load(u = "https://u:p@localhost:${server.port}/l"))
        assertEquals(0, plain.requestCount)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `https to https redirect is followed`() {
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", url("/real")))
        server.enqueue(body(png()))
        assertTrue(load() is LogoLoad.Loaded)
    }

    @Test
    fun `redirect downgrade to http is not followed`() {
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", plain.url("/x").toString()))
        assertEquals(LogoLoad.Rejected(LogoRejection.FetchRejected), load())
        assertEquals(0, plain.requestCount)
    }

    @Test
    fun `redirect carrying userinfo is refused`() {
        server.enqueue(
            MockResponse().setResponseCode(302)
                .addHeader("Location", "https://u:p@localhost:${server.port}/real"),
        )
        assertEquals(LogoLoad.Rejected(LogoRejection.InvalidUrl), load())
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `client errors are rejections and server errors are transient and not remembered`() {
        server.enqueue(MockResponse().setResponseCode(404))
        assertEquals(LogoLoad.Rejected(LogoRejection.FetchRejected), load())
        server.enqueue(MockResponse().setResponseCode(503))
        val f = LogoFetcher(client)
        assertTrue(runBlocking { f.load(url("/flaky")) } is LogoLoad.Transient)
        server.enqueue(body(png()))
        assertTrue("a transient failure must not be cached", runBlocking { f.load(url("/flaky")) } is LogoLoad.Loaded)
    }

    @Test
    fun `body is capped while streaming, with no content length to trust`() {
        // Chunked, far larger than the cap, and endless from the client's point of view.
        server.enqueue(
            MockResponse().setChunkedBody(Buffer().write(ByteArray(4 * 1024 * 1024)), 8192)
                .addHeader("Content-Type", "image/png"),
        )
        assertEquals(LogoLoad.Rejected(LogoRejection.TooLarge), load())
    }

    @Test
    fun `declared content length over the cap is refused`() {
        server.enqueue(body(ByteArray(LogoSanitizer.MAX_DECODED_BYTES + 10)))
        assertEquals(LogoLoad.Rejected(LogoRejection.TooLarge), load())
    }

    @Test
    fun `a stalled server times out as transient`() {
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        assertTrue(load(LogoFetcher(client, timeoutMillis = 300)) is LogoLoad.Transient)
    }

    @Test
    fun `svg without a content type is routed by sniffing and still guarded`() {
        val ok = """<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><rect width="8" height="8"/></svg>"""
        server.enqueue(body(ok.toByteArray(), type = null))
        assertTrue(load() is LogoLoad.Loaded)
        val bad = """<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><script>alert(1)</script></svg>"""
        server.enqueue(body(bad.toByteArray(), type = "application/octet-stream"))
        assertEquals(LogoLoad.Rejected(LogoRejection.ActiveContent), load())
    }

    @Test
    fun `a declared png that is really html is rejected`() {
        server.enqueue(body("<html><script>1</script></html>".toByteArray(), "image/png"))
        assertTrue(load() is LogoLoad.Rejected)
    }

    @Test
    fun `concurrent loads of one url share a single request`() = runBlocking {
        server.enqueue(body(png()).setBodyDelay(300, java.util.concurrent.TimeUnit.MILLISECONDS))
        val f = LogoFetcher(client)
        val a = async { f.load(url()) }
        val b = async { f.load(url()) }
        assertTrue(a.await() is LogoLoad.Loaded)
        assertTrue(b.await() is LogoLoad.Loaded)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `cancelling the only waiter aborts the request and a later load starts afresh`() = runBlocking {
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        val f = LogoFetcher(client, timeoutMillis = 30_000)
        val first = async(kotlinx.coroutines.Dispatchers.Default) { f.load(url()) }
        // The request is on the wire (bounded wait, not a sleep).
        assertTrue(server.takeRequest(10, java.util.concurrent.TimeUnit.SECONDS) != null)
        first.cancelAndJoin()
        server.enqueue(body(png()))
        assertTrue(f.load(url()) is LogoLoad.Loaded)
        assertEquals(2, server.requestCount)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `timeout is validated`() {
        LogoFetcher(client, timeoutMillis = 0)
    }

    @Test
    fun `cancelling the last waiter aborts a stalled body read promptly`() = runBlocking {
        val canceled = java.util.concurrent.CountDownLatch(1)
        val listening = client.newBuilder().eventListener(object : okhttp3.EventListener() {
            override fun canceled(call: okhttp3.Call) = canceled.countDown()
        }).build()
        // Headers arrive at once; the body then trickles at 1 byte per 10 s.
        server.enqueue(
            MockResponse().setBody(Buffer().write(ByteArray(4096))).addHeader("Content-Type", "image/png")
                .throttleBody(1, 10, java.util.concurrent.TimeUnit.SECONDS),
        )
        val f = LogoFetcher(listening, timeoutMillis = 60_000)
        val waiter = async(kotlinx.coroutines.Dispatchers.Default) { f.load(url()) }
        assertTrue(server.takeRequest(10, java.util.concurrent.TimeUnit.SECONDS) != null)
        waiter.cancelAndJoin()
        assertTrue("the socket must be aborted, not left to the 60 s timeout", canceled.await(10, java.util.concurrent.TimeUnit.SECONDS))
    }

    @Test
    fun `a waiter cancelled while the lock is held still leaves, so a later load refetches`() = runBlocking {
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        val f = LogoFetcher(client, timeoutMillis = 60_000)
        val lockField = LogoFetcher::class.java.getDeclaredField("lock").apply { isAccessible = true }
        val lock = lockField.get(f) as kotlinx.coroutines.sync.Mutex
        val waiter = async(kotlinx.coroutines.Dispatchers.Default) { f.load(url()) }
        assertTrue(server.takeRequest(10, java.util.concurrent.TimeUnit.SECONDS) != null)
        lock.lock()
        waiter.cancel() // its cleanup now has to wait for the lock
        // The cleanup is non-cancellable, so the waiter cannot finish while the lock is held
        // (a cancellable cleanup would throw at the lock and finish at once, skipping the decrement).
        assertEquals(null, kotlinx.coroutines.withTimeoutOrNull(500) { waiter.join() })
        lock.unlock()
        waiter.join()
        server.enqueue(body(png()))
        val later = kotlinx.coroutines.withTimeoutOrNull(10_000) { f.load(url()) }
        assertTrue("a phantom waiter kept the old flight alive: $later", later is LogoLoad.Loaded)
        assertEquals(2, server.requestCount)
    }

    private fun gzipWithHugeFname(nameBytes: Int, payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x1f, 0x8b.toByte(), 8, 0x08, 0, 0, 0, 0, 0, 0)) // FLG.FNAME
        out.write(ByteArray(nameBytes) { 'a'.code.toByte() })
        out.write(0)
        val deflater = java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION, true)
        deflater.setInput(payload)
        deflater.finish()
        val buf = ByteArray(1024)
        while (!deflater.finished()) out.write(buf, 0, deflater.deflate(buf))
        return out.toByteArray()
    }

    @Test
    fun `a compressed response is refused unread and identity is requested`() {
        val gz = gzipWithHugeFname(8 * 1024 * 1024, png())
        server.enqueue(body(gz).addHeader("Content-Encoding", "gzip"))
        val started = System.nanoTime()
        assertEquals(LogoLoad.Rejected(LogoRejection.FetchRejected), load())
        assertEquals("identity", server.takeRequest().getHeader("Accept-Encoding"))
        assertTrue("must not chew through the gzip header", System.nanoTime() - started < 5_000_000_000L)
        // Same for deflate/br labels.
        server.enqueue(body(png()).addHeader("Content-Encoding", "br"))
        assertEquals(LogoLoad.Rejected(LogoRejection.FetchRejected), load())
    }

    @Test
    fun `a data uri never reaches the sanitizer`() {
        // The sanitizer would answer MalformedDataUri for this; the fetcher must refuse by scheme first.
        assertEquals(LogoLoad.Rejected(LogoRejection.UnsupportedScheme), load(u = "data:image/png;base64,@@@"))
        assertEquals(LogoLoad.Rejected(LogoRejection.UnsupportedScheme), load(u = "  DATA:image/png;base64,@@@"))
    }
}
