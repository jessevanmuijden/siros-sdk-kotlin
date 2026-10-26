// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class Ts11CredentialTierCatalogTest {
    private fun entry(id: String, los: String?) = """{"id":"$id","attestationLoS":${if (los == null) "null" else "\"$los\""},"supportedFormats":["mso_mdoc"],"schemaURIs":[]}"""
    private fun page(vararg entries: String) = """{"data":[${entries.joinToString(",")}],"total":${entries.size},"limit":100,"offset":0}"""

    /** A registry whose answer the test controls, and a clock it advances. */
    private class Fixture(var body: String?) {
        var fetches = 0
        var now = 1_000_000L
        val catalog = Ts11CredentialTierCatalog(
            discovery = Ts11CredentialDiscovery(
                registryClient = Ts11RegistryClient(httpGet = { _ -> fetches++; body }),
                httpGet = { null },
            ),
            ttlMillis = 1000,
            maxStaleMillis = 10_000,
            clock = { now },
        )
    }

    @Test
    fun `a listed type has its tier, an unlisted type or one listed without a tier is not listed`() = runTest {
        val f = Fixture(page(entry("pid", "iso_18045_high"), entry("untiered", null)))
        assertEquals(CatalogTier.Known("iso_18045_high"), f.catalog.tierFor("pid"))
        assertEquals(CatalogTier.NotListed, f.catalog.tierFor("untiered"))
        assertEquals(CatalogTier.NotListed, f.catalog.tierFor("other"))
    }

    @Test
    fun `the snapshot is cached for the ttl and refreshed after it`() = runTest {
        val f = Fixture(page(entry("pid", "iso_18045_moderate")))
        f.catalog.tierFor("pid")
        f.catalog.tierFor("pid")
        assertEquals(1, f.fetches)
        f.body = page(entry("pid", "iso_18045_high"))
        f.now += 1001
        assertEquals("a raised tier is picked up after the ttl", CatalogTier.Known("iso_18045_high"), f.catalog.tierFor("pid"))
        assertEquals(2, f.fetches)
    }

    @Test
    fun `a failed refresh serves the last good snapshot until it is too old, then the answer is unavailable`() = runTest {
        val f = Fixture(page(entry("pid", "iso_18045_high")))
        assertEquals(CatalogTier.Known("iso_18045_high"), f.catalog.tierFor("pid"))
        f.body = null
        f.now += 5000
        assertEquals("stale but within the limit", CatalogTier.Known("iso_18045_high"), f.catalog.tierFor("pid"))
        f.now += 6000
        assertEquals("too old: never trusted indefinitely", CatalogTier.Unavailable, f.catalog.tierFor("pid"))
    }

    @Test
    fun `an unreachable or empty registry is unavailable and an empty answer never replaces a good snapshot`() = runTest {
        val none = Fixture(null)
        assertEquals(CatalogTier.Unavailable, none.catalog.tierFor("pid"))
        val f = Fixture(page(entry("pid", "iso_18045_high")))
        f.catalog.tierFor("pid")
        f.body = page()
        f.now += 1001
        assertEquals(CatalogTier.Known("iso_18045_high"), f.catalog.tierFor("pid"))
    }

    @Test
    fun `two entries for one type give the most demanding tier`() = runTest {
        val f = Fixture(page(entry("pid", "iso_18045_basic"), entry("pid", "iso_18045_high")))
        // merged by id in the registry client (later wins), so the registry itself can only say one thing per id
        assertEquals(CatalogTier.Known("iso_18045_high"), f.catalog.tierFor("pid"))
    }
}
