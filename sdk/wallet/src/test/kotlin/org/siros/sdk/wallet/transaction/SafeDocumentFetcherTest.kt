package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.runBlocking
import okhttp3.Authenticator
import okhttp3.CookieJar
import okhttp3.Dns
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.InetAddress

class SafeDocumentFetcherTest {
    private lateinit var server: MockWebServer

    @Before fun setUp() { server = MockWebServer().apply { start() } }
    @After fun tearDown() { server.shutdown() }

    private fun relaxed(maxBytes: Long = 1024) =
        SafeDocumentFetcher(allowInsecureHttp = true, allowNonPublicAddresses = true, maxBytes = maxBytes)

    private fun dnsOf(f: () -> List<InetAddress>) = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> = f()
    }

    private fun addr(literal: String): InetAddress = InetAddress.getByName(literal)

    @Test
    fun `the client carries nothing of the app's and follows no redirects`() {
        val c = SafeDocumentFetcher().buildClient()

        assertTrue(c.interceptors.isEmpty())
        assertTrue(c.networkInterceptors.isEmpty())
        assertTrue(c.cookieJar === CookieJar.NO_COOKIES)
        assertTrue(c.authenticator === Authenticator.NONE)
        assertTrue(c.proxyAuthenticator === Authenticator.NONE)
        assertFalse(c.followRedirects)
        assertFalse(c.followSslRedirects)
        assertTrue("an app-supplied Dns/cache must not leak in", c.cache == null)
    }

    @Test
    fun `no credential-bearing header is sent`() = runBlocking {
        server.enqueue(MockResponse().setBody("{}"))

        relaxed().get(server.url("/d").toString())

        val h = server.takeRequest().headers
        assertNull(h["Authorization"])
        assertNull(h["Cookie"])
        assertNull(h["X-Tenant-ID"])
    }

    @Test
    fun `a redirect is a failure and the target is never requested`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", server.url("/internal").toString()))
        server.enqueue(MockResponse().setBody("secret"))

        assertNull(relaxed().get(server.url("/start").toString()))
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a name that resolves to a non-public address is refused`() = runBlocking {
        for (target in listOf("127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1", "::ffff:10.0.0.1")) {
            val fetcher = SafeDocumentFetcher(dns = dnsOf { listOf(addr(target)) })
            assertNull(target, fetcher.get("https://docs.example.com/schema.json"))
        }
    }

    @Test
    fun `one private address among public ones refuses the whole answer`() = runBlocking {
        val fetcher = SafeDocumentFetcher(dns = dnsOf { listOf(addr("93.184.216.34"), addr("10.0.0.1")) })

        assertNull(fetcher.get("https://docs.example.com/s.json"))
    }

    @Test
    fun `IP literals, userinfo and plain http are refused before any lookup`() = runBlocking {
        var lookups = 0
        val fetcher = SafeDocumentFetcher(dns = dnsOf { lookups++; listOf(addr("93.184.216.34")) })
        for (url in listOf(
            "https://169.254.169.254/latest/meta-data", "https://127.0.0.1/", "https://[::1]/", "https://[fd00::1]/",
            "https://2130706433/", "https://user:pw@docs.example.com/", "https://user@docs.example.com/",
            "http://docs.example.com/", "ftp://docs.example.com/", "not a url",
        )) {
            assertNull(url, fetcher.get(url))
        }
        assertEquals(0, lookups)
    }

    @Test
    fun `address classification`() {
        for (ok in listOf("93.184.216.34", "8.8.8.8", "2606:4700:4700::1111")) assertTrue(ok, SafeDocumentFetcher.isPublic(addr(ok)))
        for (bad in listOf("127.0.0.1", "10.0.0.1", "192.168.0.1", "172.31.255.255", "169.254.169.254", "100.100.100.100", "0.1.2.3", "255.255.255.255", "224.0.0.1", "::1", "::", "fc00::", "fdff::1", "fe80::1", "ff02::1")) {
            assertFalse(bad, SafeDocumentFetcher.isPublic(addr(bad)))
        }
        assertTrue(SafeDocumentFetcher.isIpLiteral("127.0.0.1"))
        assertTrue(SafeDocumentFetcher.isIpLiteral("::1"))
        assertFalse(SafeDocumentFetcher.isIpLiteral("docs.example.com"))
    }

    @Test
    fun `size cap, error status and unreachable host give nothing, exact cap passes`() = runBlocking {
        server.enqueue(MockResponse().setBody("x".repeat(11)))
        assertNull(relaxed(10).get(server.url("/a").toString()))
        server.enqueue(MockResponse().setBody("x".repeat(10)))
        assertEquals(10, relaxed(10).get(server.url("/b").toString())!!.length)
        server.enqueue(MockResponse().setResponseCode(404))
        assertNull(relaxed().get(server.url("/c").toString()))
        val url = server.url("/gone").toString()
        server.shutdown()
        assertNull(relaxed().get(url))
    }

    @Test
    fun `the production client's resolver itself refuses a non-public answer`() {
        for (target in listOf("127.0.0.1", "10.0.0.1", "169.254.169.254", "fc00::1")) {
            val client = SafeDocumentFetcher(dns = dnsOf { listOf(addr(target)) }).buildClient()
            val failure = runCatching { client.dns.lookup("docs.example.com") }.exceptionOrNull()
            assertTrue("$target: $failure", failure is java.net.UnknownHostException)
        }
        val ok = SafeDocumentFetcher(dns = dnsOf { listOf(addr("93.184.216.34")) }).buildClient()
        assertEquals(1, ok.dns.lookup("docs.example.com").size)
    }
}
