package org.siros.sdk.credentials.interop

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class DidTest {

    private val p256Jwk = Json.parseToJsonElement(
        """{"kty":"EC","crv":"P-256",
            "x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
            "y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"}""",
    ) as JsonObject

    // ── did:jwk ─────────────────────────────────────────────────────

    @Test
    fun `a did jwk round-trips back to the key it was built from`() {
        val did = createDidJwk(p256Jwk)
        assertTrue(did.startsWith("did:jwk:"))

        val resolution = resolveDidJwk(did)
        val document = resolution.documentOrNull
        assertNotNull("did:jwk resolves offline", document)
        assertEquals(did, document!!.id)

        val key = document.findPublicKey("$did#0", DidRelationship.AUTHENTICATION)
        assertNotNull(key)
        assertEquals(
            p256Jwk["x"]!!.jsonPrimitive.content,
            key!!["x"]!!.jsonPrimitive.content,
        )
    }

    @Test
    fun `the only verification method of a did jwk is hash zero`() {
        val did = createDidJwk(p256Jwk)
        assertEquals("$did#0", didJwkKeyId(did))
        val document = resolveDidJwk(did).documentOrNull!!
        assertEquals(listOf("$did#0"), document.authentication)
        assertEquals(listOf("$did#0"), document.assertionMethod)
    }

    @Test
    fun `WebCrypto bookkeeping and private material never reach the identifier`() {
        // A key exported by WebCrypto carries `ext`/`key_ops`, and a private
        // key carries `d`. Including either would make the same key produce
        // two different DIDs - or publish the private key.
        val noisy = Json.parseToJsonElement(
            """{"kty":"EC","crv":"P-256",
                "x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
                "y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE",
                "d":"secret","ext":true,"key_ops":["sign"]}""",
        ) as JsonObject
        assertEquals(createDidJwk(p256Jwk), createDidJwk(noisy))

        val encoded = createDidJwk(noisy).removePrefix("did:jwk:")
        val decoded = String(Base64.getUrlDecoder().decode(encoded), Charsets.UTF_8)
        assertTrue("no private key material in the DID", !decoded.contains("\"d\""))
        assertTrue(!decoded.contains("key_ops"))
    }

    @Test
    fun `optional JWK members do not change the identifier`() {
        // A key that also carries `alg`, `use` or a `kid` is the same key, and
        // must get the same DID - otherwise one client's did:jwk stops
        // matching another's for the same key pair in the shared container.
        val annotated = Json.parseToJsonElement(
            """{"kty":"EC","crv":"P-256",
                "x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
                "y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE",
                "alg":"ES256","use":"sig","kid":"whatever"}""",
        ) as JsonObject
        assertEquals(createDidJwk(p256Jwk), createDidJwk(annotated))
    }

    @Test
    fun `the identifier holds exactly the thumbprint members`() {
        // RFC 7638's required set for the key type, so the mapping from key to
        // DID is one-to-one.
        val encoded = createDidJwk(p256Jwk).removePrefix("did:jwk:")
        val decoded = String(Base64.getUrlDecoder().decode(encoded), Charsets.UTF_8)
        assertEquals(
            """{"crv":"P-256","kty":"EC","x":"${p256Jwk["x"]!!.jsonPrimitive.content}","y":"${p256Jwk["y"]!!.jsonPrimitive.content}"}""",
            decoded,
        )
    }

    @Test
    fun `member order does not change the identifier`() {
        val reordered = Json.parseToJsonElement(
            """{"y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE",
                "x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
                "crv":"P-256","kty":"EC"}""",
        ) as JsonObject
        assertEquals(createDidJwk(p256Jwk), createDidJwk(reordered))
    }

    @Test
    fun `a malformed did jwk fails rather than resolving to nothing`() {
        assertTrue(resolveDidJwk("did:jwk:not-base64url!!") is DidResolution.Failed)
        assertTrue(resolveDidJwk("did:web:example.com") is DidResolution.Failed)
    }

    // ── delegated resolution ────────────────────────────────────────
    //
    // Everything that is not did:jwk is a trust decision - which document is
    // authoritative for an identifier - and belongs to go-trust, reached
    // through the backend. These tests pin that the SDK delegates rather than
    // fetching, because fetching is exactly the bug.

    @Test
    fun `a did web is resolved through the delegate, not fetched`() = runBlocking {
        var asked: String? = null
        val resolver = DidResolver(delegate = { did ->
            asked = did
            Json.parseToJsonElement(
                """
                {
                  "id": "did:web:issuer.example",
                  "verificationMethod": [{
                    "id": "did:web:issuer.example#key-1",
                    "type": "JsonWebKey2020",
                    "controller": "did:web:issuer.example",
                    "publicKeyJwk": {"kty":"EC","crv":"P-256","x":"aa","y":"bb"}
                  }],
                  "assertionMethod": ["did:web:issuer.example#key-1"]
                }
                """.trimIndent(),
            ) as JsonObject
        })
        val document = resolver.resolve("did:web:issuer.example").documentOrNull
        assertEquals("did:web:issuer.example", asked)
        val key = document!!.findPublicKey("did:web:issuer.example#key-1", DidRelationship.ASSERTION_METHOD)
        assertEquals("aa", key!!["x"]!!.jsonPrimitive.content)
    }

    @Test
    fun `a wallet with no resolution authority does not resolve a did web itself`() = runBlocking {
        // Failing is the point: the alternative is the SDK deciding which host
        // to believe, which is go-trust's decision, not the wallet's.
        val resolver = DidResolver(delegate = null)
        val result = resolver.resolve("did:web:example.com")
        assertTrue(result is DidResolution.Failed)
    }

    @Test
    fun `a document naming a different subject is rejected`() = runBlocking {
        // Whoever returned it, it is not this DID's document.
        val resolver = DidResolver(delegate = {
            Json.parseToJsonElement("""{"id":"did:web:evil.example"}""") as JsonObject
        })
        assertTrue(resolver.resolve("did:web:example.com") is DidResolution.Failed)
    }

    @Test
    fun `a delegate that cannot resolve is a failure, not an empty document`() = runBlocking {
        val resolver = DidResolver(delegate = { null })
        assertTrue(resolver.resolve("did:web:example.com") is DidResolution.Failed)
    }

    @Test
    fun `did jwk never reaches the delegate`() = runBlocking {
        // It resolves offline: the key is the identifier, so a round trip
        // would add a dependency and a failure mode for a known answer.
        var called = false
        val resolver = DidResolver(delegate = { called = true; null })
        val did = createDidJwk(p256Jwk)
        assertNotNull(resolver.resolve(did).documentOrNull)
        assertFalse("did:jwk must not be delegated", called)
    }

    @Test
    fun `did webvh is delegated like any other network method`() = runBlocking {
        // A DIIP v6 Future Direction. The SDK does not special-case it: go-trust
        // either resolves it or does not.
        var asked: String? = null
        val resolver = DidResolver(profile = DiipProfile.V6, delegate = { asked = it; null })
        resolver.resolve("did:webvh:scid:example.com")
        assertEquals("did:webvh:scid:example.com", asked)
        assertTrue(DidMethod.WEBVH in DidResolver(profile = DiipProfile.V6).requiredMethods)
    }

    // ── documents and cnf ───────────────────────────────────────────

    @Test
    fun `an inline verification method is registered as well as a referenced one`() {
        val document = parseDidDocument(
            Json.parseToJsonElement(
                """
                {
                  "id": "did:web:x.example",
                  "authentication": [{
                    "id": "#inline",
                    "type": "JsonWebKey2020",
                    "publicKeyJwk": {"kty":"EC","crv":"P-256","x":"cc","y":"dd"}
                  }]
                }
                """.trimIndent(),
            ) as JsonObject,
        )
        // A relative fragment is resolved against the document's own id.
        val key = document.findPublicKey("did:web:x.example#inline", DidRelationship.AUTHENTICATION)
        assertEquals("cc", key!!["x"]!!.jsonPrimitive.content)
    }

    @Test
    fun `a kid is matched by fragment when it is not the full DID URL`() {
        val did = createDidJwk(p256Jwk)
        val document = resolveDidJwk(did).documentOrNull!!
        assertNotNull(document.findPublicKey("#0", DidRelationship.AUTHENTICATION))
    }

    @Test
    fun `cnf kid wins over cnf jwk, and an absent binding is null`() {
        val thumbprint = { _: JsonObject -> "THUMB" }
        assertEquals(
            "did:jwk:abc#0",
            resolveCnfKid(
                Json.parseToJsonElement("""{"kid":"did:jwk:abc#0","jwk":{"kty":"EC"}}""") as JsonObject,
                thumbprint,
            ),
        )
        assertEquals(
            "THUMB",
            resolveCnfKid(Json.parseToJsonElement("""{"jwk":{"kty":"EC"}}""") as JsonObject, thumbprint),
        )
        assertNull(resolveCnfKid(null, thumbprint))
        assertNull(resolveCnfKid(Json.parseToJsonElement("{}") as JsonObject, thumbprint))
    }

    @Test
    fun `a DID's method is read from the identifier`() {
        assertEquals(DidMethod.JWK, DidMethod.of("did:jwk:abc"))
        assertEquals(DidMethod.WEB, DidMethod.of("did:web:example.com"))
        assertEquals(DidMethod.WEBVH, DidMethod.of("did:webvh:scid:example.com"))
        assertNull(DidMethod.of("https://example.com"))
        assertNull(DidMethod.of("did:unknown:x"))
    }

    @Test
    fun `a method name is read even when this SDK does not know it`() {
        assertEquals("unknown", DidMethod.methodName("did:unknown:x"))
        assertEquals("ebsi", DidMethod.methodName("did:ebsi:zABC"))
        assertNull(DidMethod.methodName("https://example.com"))
        // `did:<method>:<id>` - neither half may be missing.
        assertNull(DidMethod.methodName("did:web"))
        assertNull(DidMethod.methodName("did:web:"))
        assertNull(DidMethod.methodName("did::x"))
    }

    @Test
    fun `a method this SDK does not know is still go-trust's to resolve`() = runBlocking {
        // Enumerating methods here would make the SDK the authority on which
        // of them exist. It is not: go-trust is, and a method it learns about
        // must not need an SDK release.
        var asked: String? = null
        val resolver = DidResolver(delegate = { did -> asked = did; null })
        resolver.resolve("did:ebsi:zABC")
        assertEquals("did:ebsi:zABC", asked)
    }

    @Test
    fun `something that is not a DID is not delegated`() = runBlocking {
        var asked: String? = null
        val resolver = DidResolver(delegate = { did -> asked = did; null })
        val result = resolver.resolve("https://issuer.example")
        assertNull(asked)
        assertTrue(result is DidResolution.Failed)
    }
    @Test
    fun `a document with several keys and no kid is ambiguous rather than the first one`() {
        // Taking the first would make verification depend on document order:
        // a token signed by the issuer's other assertion key would be
        // rejected, and a key it never signed with could be accepted.
        val document = parseDidDocument(
            Json.parseToJsonElement(
                """
                {
                  "id": "did:web:issuer.example",
                  "verificationMethod": [
                    {"id":"did:web:issuer.example#a","type":"JsonWebKey2020","controller":"did:web:issuer.example",
                     "publicKeyJwk":{"kty":"EC","crv":"P-256","x":"aa","y":"bb"}},
                    {"id":"did:web:issuer.example#b","type":"JsonWebKey2020","controller":"did:web:issuer.example",
                     "publicKeyJwk":{"kty":"EC","crv":"P-256","x":"cc","y":"dd"}}
                  ],
                  "assertionMethod": ["did:web:issuer.example#a","did:web:issuer.example#b"]
                }
                """.trimIndent(),
            ) as JsonObject,
        )
        assertNull(document.findPublicKey(kid = null, relationship = DidRelationship.ASSERTION_METHOD))
        // Naming one resolves it.
        assertEquals(
            "aa",
            document.findPublicKey("did:web:issuer.example#a", DidRelationship.ASSERTION_METHOD)
                ?.get("x")?.jsonPrimitive?.content,
        )
    }

    @Test
    fun `a sole key still resolves without a kid`() {
        val did = createDidJwk(p256Jwk)
        assertNotNull(
            resolveDidJwk(did).documentOrNull
                ?.findPublicKey(kid = null, relationship = DidRelationship.AUTHENTICATION),
        )
    }
}
