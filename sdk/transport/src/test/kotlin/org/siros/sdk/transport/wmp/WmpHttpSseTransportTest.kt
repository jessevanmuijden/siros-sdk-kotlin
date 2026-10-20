package org.siros.sdk.transport.wmp

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.siros.sdk.transport.TransportState
import timber.log.Timber

/** The SSE binding's guarantees for a flow that delivers a secret: connected before anything is sent, no event twice, nothing logged. */
class WmpHttpSseTransportTest {

    private val requests = mutableListOf<Request>()
    private var release: CountDownLatch? = null

    /** A client whose event stream answers with [body] (one frame per call of [bodies]), after [release] if set. */
    private fun client(vararg bodies: String): OkHttpClient {
        var call = 0
        return OkHttpClient.Builder().addInterceptor { chain ->
            requests += chain.request()
            release?.await(10, TimeUnit.SECONDS)
            val text = bodies[minOf(call++, bodies.size - 1)]
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .body(
                    object : ResponseBody() {
                        override fun contentType() = null
                        override fun contentLength() = -1L
                        override fun source() = Buffer().write(text.toByteArray())
                    },
                ).build()
        }.build()
    }

    private val logs = mutableListOf<String>()
    private val tree = object : Timber.Tree() {
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
            logs += message + (t?.let { " " + it.toString() + it.message } ?: "")
        }
    }

    @Before fun plant() = Timber.plant(tree)

    @After fun uproot() = Timber.uproot(tree)

    @Test
    fun connectReturnsOnlyOnceTheStreamIsOpen() = runBlocking {
        release = CountDownLatch(1)
        val transport = WmpHttpSseTransport("https://x.test/send", "https://x.test/events", client("data: {}\n\n"))
        val connected = CompletableDeferred<Unit>()
        val job = launch(Dispatchers.Default) {
            transport.connect()
            connected.complete(Unit)
        }
        delay(300)
        assertFalse("connect() must not return before the stream is open", connected.isCompleted)
        assertEquals(TransportState.CONNECTING, transport.state.value)
        release!!.countDown()
        withTimeout(5_000) { connected.await() }
        job.join()
        assertTrue(transport.state.value == TransportState.CONNECTED || transport.state.value == TransportState.DISCONNECTED)
    }

    @Test
    fun aFailedConnectionReturnsFailedInsteadOfHanging() = runBlocking {
        val http = OkHttpClient.Builder().addInterceptor { chain ->
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(503).message("no")
                .body(ResponseBody.create(null, "")).build()
        }.build()
        val transport = WmpHttpSseTransport("https://x.test/send", "https://x.test/events", http)
        withTimeout(5_000) { transport.connect() }
        assertEquals(TransportState.FAILED, transport.state.value)
    }

    @Test
    fun aReplayedEventIdIsDeliveredOnce() = runBlocking {
        val body = "id: 1\ndata: {\"n\":1}\n\nid: 2\ndata: {\"n\":2}\n\nid: 1\ndata: {\"n\":1}\n\nid: 3\ndata: {\"n\":3}\n\n"
        val transport = WmpHttpSseTransport("https://x.test/send", "https://x.test/events", client(body))
        transport.connect()
        val received = withTimeout(5_000) { transport.incoming().take(3).toList() }.map { it.toString(Charsets.UTF_8) }
        assertEquals(listOf("{\"n\":1}", "{\"n\":2}", "{\"n\":3}"), received)
    }

    @Test
    fun eventsWithoutAnIdAreAllDelivered() = runBlocking {
        val transport = WmpHttpSseTransport("https://x.test/send", "https://x.test/events", client("data: a\n\ndata: a\n\n"))
        transport.connect()
        assertEquals(listOf("a", "a"), withTimeout(5_000) { transport.incoming().take(2).toList() }.map { it.toString(Charsets.UTF_8) })
    }

    @Test
    fun aReconnectAsksForEventsAfterTheLastOneReceived_andDoesNotRedeliverReplays() = runBlocking {
        val transport = WmpHttpSseTransport(
            "https://x.test/send", "https://x.test/events",
            client("id: 1\ndata: a\n\nid: 2\ndata: b\n\n", "id: 2\ndata: b\n\nid: 3\ndata: c\n\n"),
        )
        transport.connect()
        assertNull(requests[0].header("Last-Event-ID"))
        val first = withTimeout(5_000) { transport.incoming().take(2).toList() }
        assertEquals(listOf("a", "b"), first.map { it.toString(Charsets.UTF_8) })
        // The first stream ended; connect again.
        withTimeout(5_000) { while (transport.state.value != TransportState.DISCONNECTED) delay(10) }
        transport.connect()
        assertEquals("2", requests[1].header("Last-Event-ID"))
        // "b" is replayed on the new stream and not delivered again.
        assertEquals(listOf("c"), withTimeout(5_000) { transport.incoming().take(1).toList() }.map { it.toString(Charsets.UTF_8) })
    }

    @Test
    fun noEventDataAndNoDecodeErrorIsLogged() = runBlocking {
        val secret = "SEEDMARK-00112233445566778899aabbccddeeff"
        val transport = WmpHttpSseTransport("https://x.test/send", "https://x.test/events", client("id: 1\ndata: {\"credential_metadata\":\"$secret\"}\n\n"))
        transport.connect()
        withTimeout(5_000) { transport.incoming().take(1).toList() }
        logs.forEach { assertFalse(it, it.contains("SEEDMARK")) }

        // A frame the session cannot decode: the error is logged without quoting the frame.
        val fake = FakeTransport()
        val session = WmpSession(transport = fake, config = WmpSessionConfig(requestTimeoutMs = 2_000))
        val job = launch { session.create("tok") }
        withTimeout(2_000) { while (fake.sentMessages.isEmpty()) delay(10) }
        val req = WmpCodec().decodeRequest(fake.sentMessages.last())
        fake.receiveFromServer("""{"jsonrpc":"2.0","id":"${req.id}","result":{"wmp":{"version":"0.1","session_id":"s"},"resumption_token":"r"}}""".toByteArray())
        job.join()
        fake.receiveFromServer("""{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"result":{"credential_metadata":{"org.siros.secret_seed":{"ns":"$secret"}}} BROKEN""".toByteArray())
        delay(300)
        assertTrue("the decode failure was logged", logs.any { it.contains("Error handling incoming WMP message") })
        logs.forEach { assertFalse(it, it.contains("SEEDMARK")) }
        session.close()
    }
}
