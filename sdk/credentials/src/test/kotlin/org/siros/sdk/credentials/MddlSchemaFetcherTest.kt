// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class MddlSchemaFetcherTest {

    private val sampleMddlSchemaJson = """
        {
          "format": "mso_mdoc",
          "doctype": "org.iso.18013.5.1.mDL",
          "display": [
            { "locale": "en", "name": "Mobile Driving Licence" }
          ],
          "attestation_los": "Tier2"
        }
    """.trimIndent()

    @Test
    fun `fetch returns MDDL schema from type-metadata endpoint`() = runTest {
        val fetcher = MddlSchemaFetcher(httpGet = { url ->
            if (url == "https://issuer.example.com/type-metadata/mdl_scope") {
                sampleMddlSchemaJson
            } else {
                null
            }
        })
        val schema = fetcher.fetch("https://issuer.example.com", "mdl_scope")
        assertNotNull(schema)
        assertEquals("org.iso.18013.5.1.mDL", schema!!.doctype)
        assertEquals("Tier2", schema.requiredKeyStorage)
    }

    @Test
    fun `fetch returns null when strategy fails`() = runTest {
        val fetcher = MddlSchemaFetcher(httpGet = { null })
        val schema = fetcher.fetch("https://issuer.example.com", "missing_scope")
        assertNull(schema)
    }

    @Test
    fun `fetch returns null when httpGet throws`() = runTest {
        val fetcher = MddlSchemaFetcher(httpGet = { throw java.io.IOException("network error") })
        val schema = fetcher.fetch("https://issuer.example.com", "scope")
        assertNull(schema)
    }

    @Test
    fun `fetch trims trailing slash from issuer URL`() = runTest {
        var calledUrl: String? = null
        val fetcher = MddlSchemaFetcher(httpGet = { url ->
            calledUrl = url
            null
        })
        fetcher.fetch("https://issuer.example.com/", "scope")
        assertEquals("https://issuer.example.com/type-metadata/scope", calledUrl)
    }

    @Test
    fun `parseMddlSchema parses valid JSON`() {
        val fetcher = MddlSchemaFetcher()
        val schema = fetcher.parseMddlSchema(sampleMddlSchemaJson)
        assertNotNull(schema)
        assertEquals("mso_mdoc", schema!!.format)
        assertEquals("org.iso.18013.5.1.mDL", schema.doctype)
    }

    @Test
    fun `parseMddlSchema returns null for invalid JSON`() {
        val fetcher = MddlSchemaFetcher()
        assertNull(fetcher.parseMddlSchema("{not valid json"))
    }

    /**
     * Regression test for #229 fix review (mirrors siros-sdk-swift#178's
     * identical Copilot finding): CredentialUtilsTest only constructs
     * MddlSchema/MddlClaimMeta programmatically, so a @SerialName mismatch
     * against real issuer JSON (e.g. svg_templates, color_scheme, svg_id)
     * would never be caught by any test. This decodes the actual raw JSON
     * shape (mirroring `vc`'s pkg/mdoc/schema.go) through the real parse path.
     */
    @Test
    fun `parseMddlSchema decodes svg_templates and svg_id from raw JSON`() {
        val json = """
            {
              "format": "mso_mdoc",
              "doctype": "eu.europa.ec.eudi.photoid.1",
              "display": [
                {
                  "locale": "en",
                  "name": "Photo ID",
                  "rendering": {
                    "svg_templates": [
                      { "uri": "https://issuer.example.com/photoid.svg", "properties": { "color_scheme": "light" } }
                    ]
                  }
                }
              ],
              "claims": {
                "org.iso.23220.photoid.1": {
                  "portrait": { "value_type": "bstr", "svg_id": "portrait" }
                }
              }
            }
        """.trimIndent()
        val fetcher = MddlSchemaFetcher()
        val schema = fetcher.parseMddlSchema(json)

        assertEquals("https://issuer.example.com/photoid.svg", schema?.display?.first()?.rendering?.svgTemplates?.first()?.uri)
        assertEquals("light", schema?.display?.first()?.rendering?.svgTemplates?.first()?.properties?.colorScheme)
        assertEquals("portrait", schema?.claims?.get("org.iso.23220.photoid.1")?.get("portrait")?.svgId)
    }

    @Test
    fun `fetch returns MDDL schema from registry service when registryUrl and vct are known`() = runTest {
        var calledUrl: String? = null
        val fetcher = MddlSchemaFetcher(httpGet = { url ->
            calledUrl = url
            if (url == "https://wallet.example.com/registry/type-metadata?vct=org.iso.18013.5.1.mDL") {
                sampleMddlSchemaJson
            } else {
                null
            }
        })
        val schema = fetcher.fetch(
            issuerUrl = "https://issuer.example.com",
            scope = "mdl_scope",
            vct = "org.iso.18013.5.1.mDL",
            registryUrl = "https://wallet.example.com/registry",
        )
        assertNotNull(schema)
        assertEquals("org.iso.18013.5.1.mDL", schema!!.doctype)
        assertEquals(
            "https://wallet.example.com/registry/type-metadata?vct=org.iso.18013.5.1.mDL",
            calledUrl,
        )
    }

    @Test
    fun `fetch trims trailing slash from registryUrl`() = runTest {
        val calledUrls = mutableListOf<String>()
        val fetcher = MddlSchemaFetcher(httpGet = { url ->
            calledUrls.add(url)
            null
        })
        fetcher.fetch(
            issuerUrl = "https://issuer.example.com",
            scope = "mdl_scope",
            vct = "org.iso.18013.5.1.mDL",
            registryUrl = "https://wallet.example.com/registry/",
        )
        assertEquals(
            "https://wallet.example.com/registry/type-metadata?vct=org.iso.18013.5.1.mDL",
            calledUrls.first(),
        )
    }

    @Test
    fun `fetch falls through to issuer-direct strategy when registry has no entry`() = runTest {
        val fetcher = MddlSchemaFetcher(httpGet = { url ->
            when {
                url.contains("/registry/") -> null // registry 404 / miss
                url == "https://issuer.example.com/type-metadata/mdl_scope" -> sampleMddlSchemaJson
                else -> null
            }
        })
        val schema = fetcher.fetch(
            issuerUrl = "https://issuer.example.com",
            scope = "mdl_scope",
            vct = "org.iso.18013.5.1.mDL",
            registryUrl = "https://wallet.example.com/registry",
        )
        assertNotNull(schema)
        assertEquals("org.iso.18013.5.1.mDL", schema!!.doctype)
    }

    @Test
    fun `fetch skips registry strategy when registryUrl is null`() = runTest {
        var registryQueried = false
        val fetcher = MddlSchemaFetcher(httpGet = { url ->
            if (url.contains("/registry/")) registryQueried = true
            if (url == "https://issuer.example.com/type-metadata/mdl_scope") sampleMddlSchemaJson else null
        })
        val schema = fetcher.fetch(
            issuerUrl = "https://issuer.example.com",
            scope = "mdl_scope",
            vct = "org.iso.18013.5.1.mDL",
            registryUrl = null,
        )
        assertNotNull(schema)
        assertEquals(false, registryQueried)
    }

    @Test
    fun `fetch skips registry strategy when vct is not known`() = runTest {
        var registryQueried = false
        val fetcher = MddlSchemaFetcher(httpGet = { url ->
            if (url.contains("/registry/")) registryQueried = true
            if (url == "https://issuer.example.com/type-metadata/mdl_scope") sampleMddlSchemaJson else null
        })
        val schema = fetcher.fetch(
            issuerUrl = "https://issuer.example.com",
            scope = "mdl_scope",
            vct = null,
            registryUrl = "https://wallet.example.com/registry",
        )
        assertNotNull(schema)
        assertEquals(false, registryQueried)
    }

    // ── Caching ─────────────────────────────────────────────────────

    @Test
    fun `fetch caches successful result and does not hit network again within ttl`() = runTest {
        var callCount = 0
        val fetcher = MddlSchemaFetcher(httpGet = { url ->
            callCount++
            if (url == "https://issuer.example.com/type-metadata/mdl_scope") sampleMddlSchemaJson else null
        })

        val first = fetcher.fetch("https://issuer.example.com", "mdl_scope")
        val second = fetcher.fetch("https://issuer.example.com", "mdl_scope")

        assertNotNull(first)
        assertNotNull(second)
        assertEquals("org.iso.18013.5.1.mDL", second!!.doctype)
        assertEquals(1, callCount)
    }

    @Test
    fun `fetch does not serve a different key from another entry's cache`() = runTest {
        var callCount = 0
        val fetcher = MddlSchemaFetcher(httpGet = { url ->
            callCount++
            when (url) {
                "https://issuer.example.com/type-metadata/mdl_scope" -> sampleMddlSchemaJson
                "https://issuer.example.com/type-metadata/other_scope" ->
                    """{"format": "mso_mdoc", "doctype": "org.example.other"}"""
                "https://other-issuer.example.com/type-metadata/mdl_scope" ->
                    """{"format": "mso_mdoc", "doctype": "org.example.from-other-issuer"}"""
                else -> null
            }
        })

        val mdl = fetcher.fetch("https://issuer.example.com", "mdl_scope")
        val otherScope = fetcher.fetch("https://issuer.example.com", "other_scope")
        val otherIssuer = fetcher.fetch("https://other-issuer.example.com", "mdl_scope")

        assertEquals("org.iso.18013.5.1.mDL", mdl!!.doctype)
        assertEquals("org.example.other", otherScope!!.doctype)
        assertEquals("org.example.from-other-issuer", otherIssuer!!.doctype)
        // Three distinct cache keys, none served from another's entry, so all three hit the network.
        assertEquals(3, callCount)

        // Repeating each is now served from cache: no additional network calls.
        fetcher.fetch("https://issuer.example.com", "mdl_scope")
        fetcher.fetch("https://issuer.example.com", "other_scope")
        fetcher.fetch("https://other-issuer.example.com", "mdl_scope")
        assertEquals(3, callCount)
    }

    @Test
    fun `fetch re-fetches after the cache entry's ttl has expired`() = runTest {
        var callCount = 0
        var now = 0L
        val fetcher = MddlSchemaFetcher(
            httpGet = { url ->
                callCount++
                if (url == "https://issuer.example.com/type-metadata/mdl_scope") sampleMddlSchemaJson else null
            },
            cacheTtlSeconds = 10,
            nowMillis = { now },
        )

        fetcher.fetch("https://issuer.example.com", "mdl_scope")
        assertEquals(1, callCount)

        // Still within the 10s TTL: served from cache.
        now += 5_000
        fetcher.fetch("https://issuer.example.com", "mdl_scope")
        assertEquals(1, callCount)

        // Past the TTL: must hit the network again.
        now += 6_000
        fetcher.fetch("https://issuer.example.com", "mdl_scope")
        assertEquals(2, callCount)
    }

    @Test
    fun `fetch never caches a null result`() = runTest {
        var callCount = 0
        val fetcher = MddlSchemaFetcher(httpGet = { callCount++; null })

        val first = fetcher.fetch("https://issuer.example.com", "missing_scope")
        val second = fetcher.fetch("https://issuer.example.com", "missing_scope")

        assertNull(first)
        assertNull(second)
        // Both calls retried the network - a miss is never cached.
        assertEquals(2, callCount)
    }

    // ── Persistent cache ────────────────────────────────────────────
    // The policy itself is exercised exhaustively in VctmFetcherTest; these
    // confirm the mdoc fetcher is wired to the same layer under its own
    // namespace.

    @Test
    fun `persistent cache suppresses a not-yet-due retry and is namespaced apart from VCTM`() = runTest {
        var now = 0L
        var callCount = 0
        val cache = InMemoryFetchCache()
        val fetcher = MddlSchemaFetcher(httpGet = { callCount++; null }, nowMillis = { now }, persistentCache = cache)

        assertNull(fetcher.fetch("https://issuer.example.com", "mdl_scope"))
        assertEquals(1, callCount)
        val key = cache.snapshot().keys.single()
        assertEquals(true, key.startsWith("mddl:"))
        assertEquals(FetchCacheStatus.MISS, cache.snapshot().getValue(key).status)

        now += 10 * 60 * 1000
        assertNull(MddlSchemaFetcher(httpGet = { callCount++; null }, nowMillis = { now }, persistentCache = cache)
            .fetch("https://issuer.example.com", "mdl_scope"))
        assertEquals(1, callCount)
    }

    @Test
    fun `persisted hit is served across instances without network`() = runTest {
        var now = 0L
        var callCount = 0
        val cache = InMemoryFetchCache()
        val first = MddlSchemaFetcher(
            httpGet = { url ->
                callCount++
                if (url == "https://issuer.example.com/type-metadata/mdl_scope") sampleMddlSchemaJson else null
            },
            nowMillis = { now },
            persistentCache = cache,
        )
        assertNotNull(first.fetch("https://issuer.example.com", "mdl_scope"))

        now += 60 * 60 * 1000
        val second = MddlSchemaFetcher(httpGet = { callCount++; null }, nowMillis = { now }, persistentCache = cache)
        val schema = second.fetch("https://issuer.example.com", "mdl_scope")
        assertEquals("org.iso.18013.5.1.mDL", schema!!.doctype)
        assertEquals(1, callCount)
    }
}
