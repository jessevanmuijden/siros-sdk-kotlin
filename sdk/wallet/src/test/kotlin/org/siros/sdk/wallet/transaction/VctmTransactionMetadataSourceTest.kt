package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.credential
import java.security.MessageDigest
import java.util.Base64

class VctmTransactionMetadataSourceTest {
    private lateinit var server: MockWebServer

    @Before fun setUp() { server = MockWebServer().apply { start() } }
    @After fun tearDown() { server.shutdown() }

    private val vctmJson = """{"vct":"https://pay.example.com/card","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":{}}"""

    private fun sri(text: String) =
        "sha256-" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(text.toByteArray()))

    /** Registry answers [registryBody]; everything else goes through a (test-relaxed) safe fetcher. */
    private fun source(
        registryBody: String? = vctmJson,
        maxBytes: Long = SafeDocumentFetcher.MAX_DOCUMENT_BYTES,
    ) = VctmTransactionMetadataSource(
        registryUrl = "https://wallet.example.com/registry",
        registryGet = { registryBody },
        fetcher = SafeDocumentFetcher(allowInsecureHttp = true, allowNonPublicAddresses = true, maxBytes = maxBytes),
    )

    private fun cred(extra: String = "", issuer: String? = null) =
        credential(claims = """{"vct":"https://pay.example.com/card"$extra}""").let {
            if (issuer == null) it else it.copy(credentialIssuerIdentifier = issuer)
        }

    @Test
    fun `resolves the type metadata of the credential's vct`() = runBlocking {
        val meta = source().typeMetadata(cred())

        assertEquals("urn:eu:europa:ec:eudi:sua:sca", meta!!["category"]!!.toString().trim('"'))
    }

    @Test
    fun `no metadata, wrong vct, or a credential without vct yields nothing`() = runBlocking {
        assertNull(source(registryBody = null).typeMetadata(cred(issuer = "https://nowhere.invalid")))
        assertNull(source(registryBody = """{"vct":"https://other.example/type"}""").typeMetadata(cred()))
        assertNull(source().typeMetadata(credential(claims = """{"iss":"x"}""")))
        assertNull(source().typeMetadata(credential(claims = "not json")))
    }

    @Test
    fun `a vct#integrity pin is enforced against what was resolved`() = runBlocking {
        assertNotNull(source().typeMetadata(cred(""","vct#integrity":"${sri(vctmJson)}"""")))
        assertNull(source().typeMetadata(cred(""","vct#integrity":"${sri("something else")}"""")))
        assertNull(source().typeMetadata(cred(""","vct#integrity":"garbage"""")))
    }

    @Test
    fun `a vct#integrity that is present but not a string refuses instead of meaning no pin`() = runBlocking {
        for (bad in listOf("null", "{}", "[]", "[\"sha256-x\"]", "5", "true")) {
            assertNull(bad, source().typeMetadata(cred(""","vct#integrity":$bad""")))
        }
    }

    // ── the type-metadata path is bounded, like the document path ──

    @Test
    fun `type metadata from an issuer endpoint over http is not fetched`() = runBlocking {
        server.enqueue(MockResponse().setBody(vctmJson))
        val strict = VctmTransactionMetadataSource(
            registryUrl = "https://wallet.example.com/registry",
            registryGet = { null },
            fetcher = SafeDocumentFetcher(), // production settings: https only, public only
        )

        assertNull(strict.typeMetadata(cred(issuer = server.url("/").toString().trimEnd('/'))))
        assertEquals("never requested", 0, server.requestCount)
    }

    @Test
    fun `type metadata over the size cap is refused, at the cap it is accepted`() = runBlocking {
        val issuer = server.url("/").toString().trimEnd('/')
        server.enqueue(MockResponse().setBody(vctmJson + " ".repeat(200)))
        assertNull(source(registryBody = null, maxBytes = vctmJson.length + 100L).typeMetadata(cred(issuer = issuer)))

        server.enqueue(MockResponse().setBody(vctmJson))
        assertNotNull(source(registryBody = null, maxBytes = vctmJson.length.toLong()).typeMetadata(cred(issuer = issuer)))
    }

    @Test
    fun `the registry is reached through the caller's bounded function, other URLs are not`() = runBlocking {
        val seen = mutableListOf<String>()
        val src = VctmTransactionMetadataSource(
            registryUrl = "https://wallet.example.com/registry",
            registryGet = { seen += it; vctmJson },
            fetcher = SafeDocumentFetcher(),
        )

        assertNotNull(src.typeMetadata(cred()))
        assertEquals(1, seen.size)
        assert(seen.single().startsWith("https://wallet.example.com/registry/type-metadata"))
        Unit
    }

    @Test
    fun `a referenced document goes through the safe fetcher`() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"type":"object"}"""))
        assertEquals("""{"type":"object"}""", source().document(server.url("/schema.json").toString()))
    }
}
