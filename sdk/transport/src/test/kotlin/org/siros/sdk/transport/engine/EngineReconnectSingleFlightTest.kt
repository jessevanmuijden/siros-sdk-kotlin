package org.siros.sdk.transport.engine

import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import java.io.IOException

/**
 * The engine socket is single-flight: found live (Pixel run, forced reconnect right after a QR scan) that the failure the
 * replaced socket raised, and a ping timeout, each scheduled its own reconnect, so several sockets were open at once and
 * the flow's replies went to a socket the engine no longer knew.
 */
class EngineReconnectSingleFlightTest {
    private val sockets = mutableListOf<WebSocket>()
    private val listeners = mutableListOf<WebSocketListener>()
    private val response = mockk<Response>(relaxed = true)
    private val client = mockk<OkHttpClient>()
    private val builder = mockk<OkHttpClient.Builder>()

    @Before
    fun setUp() {
        every { client.newWebSocket(any<Request>(), any<WebSocketListener>()) } answers {
            val ws = mockk<WebSocket>(relaxed = true)
            every { ws.send(any<String>()) } returns true
            sockets += ws
            listeners += secondArg<WebSocketListener>()
            ws
        }
        every { client.newBuilder() } returns builder
        every { builder.pingInterval(any(), any()) } returns builder
        every { builder.build() } returns client
    }

    private fun session() = WalletEngineSession(baseUrl = "https://wallet.example.com", tenantId = "t", client = client)

    /** Longer than the first two backoffs (1 s, 2 s), so any reconnect that was going to happen has happened. */
    private fun settle() = Thread.sleep(2600)

    @Test
    fun `the failure a forced reconnect raises on the replaced socket opens no further connection`() {
        val s = session()
        s.connect("tok")
        listeners[0].onOpen(sockets[0], response)
        runBlocking { s.forceReconnect() }
        assertEquals(2, sockets.size)
        listeners[0].onFailure(sockets[0], IOException("Socket closed"), null)
        listeners[0].onClosing(sockets[0], 1006, "gone")
        settle()
        assertEquals("one replacement, not one per callback", 2, sockets.size)
    }

    @Test
    fun `two failures of the current socket schedule one reconnect`() {
        val s = session()
        s.connect("tok")
        listeners[0].onOpen(sockets[0], response)
        listeners[0].onFailure(sockets[0], IOException("ping timeout"), null)
        listeners[0].onClosing(sockets[0], 1006, "gone")
        settle()
        assertEquals(2, sockets.size)
    }

    @Test
    fun `a forced reconnect replaces a pending backoff attempt instead of adding to it`() {
        val s = session()
        s.connect("tok")
        listeners[0].onFailure(sockets[0], IOException("ping timeout"), null)
        runBlocking { s.forceReconnect() }
        settle()
        assertEquals("the initial socket and the forced one only", 2, sockets.size)
    }

    @Test
    fun `a message the socket refuses is an error, not a silent loss`() {
        val s = session()
        s.connect("tok")
        every { sockets[0].send(any<String>()) } returns false
        assertThrows(IllegalStateException::class.java) { s.startPresentation(requestUri = "openid4vp://x") }
    }

    @Test
    fun `the engine's own 3 s ping interval never becomes the client's pong wait`() {
        assertEquals(10_000L, WalletEngineSession.livenessIntervalMs(3000L))
        assertEquals(15_000L, WalletEngineSession.livenessIntervalMs(15_000L))
    }
}
