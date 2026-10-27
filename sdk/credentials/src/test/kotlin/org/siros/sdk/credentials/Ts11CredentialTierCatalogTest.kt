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
    fun `a type declared twice gets the most demanding tier, in whichever order the registry lists it`() = runTest {
        for (order in listOf(listOf("iso_18045_high", "iso_18045_basic"), listOf("iso_18045_basic", "iso_18045_high"))) {
            val f = Fixture(page(entry("pid", order[0]), entry("pid", order[1])))
            assertEquals("order $order", CatalogTier.Known("iso_18045_high"), f.catalog.tierFor("pid"))
        }
    }

    @Test
    fun `a declaration with an unknown tier is preserved through the merge so the wallet refuses it, in either order`() = runTest {
        for (order in listOf(listOf("iso_18045_ultra", "iso_18045_basic"), listOf("iso_18045_basic", "iso_18045_ultra"))) {
            val f = Fixture(page(entry("pid", order[0]), entry("pid", order[1])))
            assertEquals("order $order", CatalogTier.Known("iso_18045_ultra"), f.catalog.tierFor("pid"))
        }
        // and a declaration without any tier beside a tiered one cannot be answered
        val none = Fixture(page(entry("pid", "iso_18045_high"), entry("pid", null)))
        assertEquals(CatalogTier.NotListed, none.catalog.tierFor("pid"))
    }

    /** A registry in two pages; [second] is what the second page request returns (null = it fails). */
    private class Paged(var first: String, var second: String?) {
        var now = 1_000_000L
        val catalog = Ts11CredentialTierCatalog(
            discovery = Ts11CredentialDiscovery(
                registryClient = Ts11RegistryClient(httpGet = { url -> if (url.contains("offset=")) second else first }),
                httpGet = { null },
            ),
            ttlMillis = 1000,
            maxStaleMillis = 10_000,
            clock = { now },
        )
    }

    private fun firstPage(vararg e: String) = """{"data":[${e.joinToString(",")}],"total":2,"limit":1,"offset":0}"""
    private fun secondPage(vararg e: String) = """{"data":[${e.joinToString(",")}],"total":2,"limit":1,"offset":1}"""

    @Test
    fun `an incomplete refresh never replaces a snapshot and does not extend its stale deadline`() = runTest {
        val r = Paged(firstPage(entry("pid", "iso_18045_high")), secondPage(entry("other", "iso_18045_basic")))
        assertEquals(CatalogTier.Known("iso_18045_high"), r.catalog.tierFor("pid"))
        // the registry now says basic for pid, but the second page cannot be read: the answer is incomplete
        r.first = firstPage(entry("pid", "iso_18045_basic"))
        r.second = null
        r.now += 2000
        assertEquals("the previous snapshot is kept", CatalogTier.Known("iso_18045_high"), r.catalog.tierFor("pid"))
        r.now += 9000 // 11 s after the ORIGINAL snapshot
        assertEquals("the incomplete refreshes did not renew it", CatalogTier.Unavailable, r.catalog.tierFor("pid"))
    }

    @Test
    fun `an incomplete answer with no snapshot is unavailable, not a partial catalog`() = runTest {
        val r = Paged(firstPage(entry("pid", "iso_18045_basic")), null)
        assertEquals(CatalogTier.Unavailable, r.catalog.tierFor("pid"))
    }

    @Test
    fun `an entry with both an SD-JWT and an mdoc schema is indexed under every identity it states`() = runTest {
        val both = """{"id":"pid-schema","attestationLoS":"iso_18045_high","supportedFormats":["dc+sd-jwt","mso_mdoc"],"schemaURIs":[
            {"formatIdentifier":"dc+sd-jwt","uri":"https://r.example/vctm.json"},{"formatIdentifier":"mso_mdoc","uri":"https://r.example/mddl.json"}]}"""
        val catalog = Ts11CredentialTierCatalog(
            discovery = Ts11CredentialDiscovery(
                registryClient = Ts11RegistryClient(httpGet = { _ -> page(both) }),
                httpGet = { url ->
                    when (url) {
                        "https://r.example/vctm.json" -> """{"vct":"urn:eudi:pid:1"}"""
                        "https://r.example/mddl.json" -> """{"format":"mso_mdoc","doctype":"eu.europa.ec.eudi.pid.1"}"""
                        else -> null
                    }
                },
            ),
        )
        assertEquals(CatalogTier.Known("iso_18045_high"), catalog.tierFor("urn:eudi:pid:1"))
        assertEquals("the mdoc doctype too", CatalogTier.Known("iso_18045_high"), catalog.tierFor("eu.europa.ec.eudi.pid.1"))
    }

    @Test
    fun `a schema document that cannot be read makes the answer incomplete`() = runTest {
        val e = """{"id":"pid-schema","attestationLoS":"iso_18045_high","schemaURIs":[{"formatIdentifier":"dc+sd-jwt","uri":"https://r.example/vctm.json"}]}"""
        val catalog = Ts11CredentialTierCatalog(
            discovery = Ts11CredentialDiscovery(registryClient = Ts11RegistryClient(httpGet = { _ -> page(e) }), httpGet = { null }),
        )
        assertEquals(CatalogTier.Unavailable, catalog.tierFor("pid-schema"))
    }
}
