package org.siros.sdk.transport.engine

import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
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

    @Test
    fun `a forced reconnect whose caller is cancelled during the token refresh does not stop the pending recovery`() {
        val s = session()
        var calls = 0
        s.connect("tok", tokenProvider = { if (calls++ == 0) kotlinx.coroutines.awaitCancellation() else "fresh" })
        listeners[0].onOpen(sockets[0], response)
        listeners[0].onFailure(sockets[0], IOException("ping timeout"), null) // schedules the backoff attempt
        runBlocking {
            // UNDISPATCHED: the forced reconnect runs on this thread up to its first suspension, which is inside tokenProvider,
            // so the cancellation below cannot race the coroutine's start.
            val forced = kotlinx.coroutines.GlobalScope.launch(kotlinx.coroutines.Dispatchers.Default, start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { s.forceReconnect() }
            assertEquals("the forced refresh is parked in tokenProvider", 1, calls)
            forced.cancelAndJoin() // the caller goes away while tokenProvider is suspended
        }
        settle()
        assertEquals("the pending attempt still reconnected", 2, sockets.size)
    }

    @Test
    fun `a forced reconnect cancels an automatic attempt that is parked in the token refresh`() {
        val s = session()
        val entered = kotlinx.coroutines.CompletableDeferred<Unit>()
        val gate = kotlinx.coroutines.CompletableDeferred<String>()
        var calls = 0
        s.connect("tok", tokenProvider = { if (calls++ == 0) { entered.complete(Unit); gate.await() } else "fresh" })
        listeners[0].onOpen(sockets[0], response)
        listeners[0].onFailure(sockets[0], IOException("ping timeout"), null) // the backoff attempt parks in the refresh after 1 s
        runBlocking {
            // The attempt signals that it is inside the refresh; no sleep decides the order.
            assertEquals(Unit, kotlinx.coroutines.withTimeout(10_000) { entered.await() })
            s.forceReconnect() // replaces the parked attempt: installs socket 1
        }
        assertEquals(2, sockets.size)
        gate.complete("late")
        settle()
        assertEquals("the cancelled attempt did not add or replace a socket", 2, sockets.size)
    }

    private fun field(name: String) = WalletEngineSession::class.java.getDeclaredField(name).apply { isAccessible = true }

    @Test
    fun `an automatic attempt past its state check does not publish or cancel a replacement installed before it takes the lock`() {
        val s = session()
        val entered = kotlinx.coroutines.CompletableDeferred<Unit>()
        s.connect("tok", tokenProvider = { entered.complete(Unit); "fresh" })
        listeners[0].onOpen(sockets[0], response)
        val replacement = mockk<WebSocket>(relaxed = true)
        val connLock = field("connLock").get(s)!!
        synchronized(connLock) {
            // Hold the lock BEFORE the attempt can reach doConnect: it passes its state check, then has to wait for the lock.
            listeners[0].onFailure(sockets[0], IOException("ping timeout"), null) // schedules the attempt (RECONNECTING)
            runBlocking { kotlinx.coroutines.withTimeout(10_000) { entered.await() } }
            // While the old attempt is held back, a replacement becomes the live socket (what forceReconnect does under this lock).
            (field("liveGeneration").get(s) as java.util.concurrent.atomic.AtomicInteger).set(99)
            field("webSocket").set(s, replacement)
        }
        runBlocking {
            val job = field("pendingReconnect").get(s) as kotlinx.coroutines.Job
            kotlinx.coroutines.withTimeout(10_000) { job.join() }
        }
        assertEquals("the stale attempt opened no socket", 1, sockets.size)
        io.mockk.verify(exactly = 0) { replacement.cancel() }
        assertEquals("the replacement is still the live socket", replacement, field("webSocket").get(s))
    }

    @Test
    fun `a socket that failed is not reported connected during the backoff`() {
        val s = session()
        s.connect("tok")
        listeners[0].onOpen(sockets[0], response)
        assertEquals(true, s.isConnected)
        listeners[0].onFailure(sockets[0], IOException("ping timeout"), null)
        assertEquals(false, s.isConnected)
        assertThrows(IllegalStateException::class.java) { s.startPresentation(requestUri = "openid4vp://x") }
    }

    @Test
    fun `a credential notification the socket refuses does not throw`() {
        val s = session()
        s.connect("tok")
        every { sockets[0].send(any<String>()) } returns false
        s.sendCredentialNotification("flow", "n1", "credential_accepted", null)
    }

    @Test
    fun `a duplicate callback while the last retry is pending does not exhaust the budget`() {
        val s = session()
        s.connect("tok")
        listeners[0].onOpen(sockets[0], response)
        // Four retries already spent: the next failure schedules the fifth (the last).
        WalletEngineSession::class.java.getDeclaredField("reconnectAttempts").apply { isAccessible = true }.setInt(s, 4)
        listeners[0].onFailure(sockets[0], IOException("ping timeout"), null)
        assertEquals(WalletEngineSession.State.RECONNECTING, s.state.value)
        listeners[0].onClosing(sockets[0], 1006, "gone") // another callback of the same socket
        assertEquals("still retrying, not FAILED", WalletEngineSession.State.RECONNECTING, s.state.value)
    }
}
