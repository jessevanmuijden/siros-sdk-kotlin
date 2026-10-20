// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.io.File
import java.security.MessageDigest
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The background catalog refresh: what it keeps, what it expunges, and what it leaves alone when offline. */
@OptIn(ExperimentalCoroutinesApi::class)
class ZkCircuitCatalogRefresherTest {
    private val json = Json { ignoreUnknownKeys = true }

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private val bytesA = ByteArray(10) { 1 }
    private val bytesB = ByteArray(11) { 2 }

    private fun descriptor(
        id: String,
        bytes: ByteArray,
        status: String = "active",
        published: Boolean = true,
        deprecatedAt: String? = null,
        aliases: List<String> = emptyList(),
    ) = ZkCircuitDescriptor(
        id = id, aliases = aliases, system = "longfellow", systemVersion = "8", docTypes = listOf("d"),
        published = published, status = status, deprecatedAt = deprecatedAt,
        artifact = ZkArtifact(url = "/v1/artifacts/sha256/${sha(bytes)}", hash = "sha256:${sha(bytes)}", size = bytes.size.toLong()),
    )

    /** A catalog served from memory: the manifest and each descriptor, with the artifacts by hash. */
    private class Catalog(val json: Json) {
        var circuits: List<ZkCircuitDescriptor> = emptyList()
        var next: String? = null
        var reachable = true
        var manifestFetches = 0
        val artifacts = HashMap<String, ByteArray>()

        fun client(cacheDir: File?) = ZkCircuitClient(
            sources = listOf("https://c.test"),
            httpGet = { url ->
                if (!reachable) return@ZkCircuitClient null
                when {
                    url.endsWith("/v1/manifest.json") -> {
                        manifestFetches++
                        json.encodeToString(ZkManifest.serializer(), ZkManifest(circuits = circuits, next = next))
                    }
                    else -> circuits.firstOrNull { url.endsWith("/v1/circuits/${it.id}.json") }
                        ?.let { json.encodeToString(ZkCircuitDescriptor.serializer(), it) }
                }
            },
            httpGetBytes = { url -> if (reachable) artifacts.entries.firstOrNull { url.endsWith(it.key) }?.value else null },
            cacheDir = cacheDir,
        )
    }

    private fun tempDir() = java.nio.file.Files.createTempDirectory("refresh").toFile().also { it.deleteOnExit() }

    private fun File.names(sub: String) = File(this, sub).listFiles()?.map { it.name }?.sorted().orEmpty()

    /** A catalog with circuits [a] and [b] active, both fetched and downloaded into [dir]. */
    private suspend fun warmed(catalog: Catalog, dir: File?): ZkCircuitClient {
        val a = descriptor("a", bytesA)
        val b = descriptor("b", bytesB)
        catalog.circuits = listOf(a, b)
        catalog.artifacts[sha(bytesA)] = bytesA
        catalog.artifacts[sha(bytesB)] = bytesB
        val client = catalog.client(dir)
        client.downloadArtifact(client.fetchCircuit("a")!!)
        client.downloadArtifact(client.fetchCircuit("b")!!)
        return client
    }

    @Test
    fun `a circuit the manifest now lists as deprecated is expunged, descriptor and artifact, and onRetired hears of it`() = runTest {
        val dir = tempDir()
        val catalog = Catalog(json)
        val client = warmed(catalog, dir)
        assertEquals(listOf("a.json", "b.json"), dir.names("descriptors"))
        catalog.circuits = listOf(descriptor("a", bytesA, status = "deprecated", deprecatedAt = "2026-10-01T00:00:00Z"), descriptor("b", bytesB))
        val retired = mutableListOf<String>()

        val result = ZkCircuitCatalogRefresher(client, { retired += it.id }).refreshOnce() as ZkCircuitCatalogRefresher.Result.Refreshed

        assertEquals(listOf("a"), result.retired.map { it.id })
        assertEquals(listOf("a"), retired)
        assertEquals(listOf("b.json"), dir.names("descriptors"))
        assertEquals(listOf(sha(bytesB)), dir.names("artifacts"))
        // Offline now, "a" is gone and "b" still serves.
        catalog.reachable = false
        assertNull(client.fetchCircuit("a"))
        assertEquals("b", client.fetchCircuit("b")?.id)
        assertTrue(client.isArtifactCached(descriptor("b", bytesB)))
        assertFalse(client.isArtifactCached(descriptor("a", bytesA)))
    }

    @Test
    fun `a circuit absent from a complete manifest is expunged, and so is every unreferenced cached artifact`() = runTest {
        val dir = tempDir()
        val catalog = Catalog(json)
        val client = warmed(catalog, dir)
        File(File(dir, "artifacts"), "f".repeat(64)).writeBytes(byteArrayOf(1)) // an orphan
        catalog.circuits = listOf(descriptor("b", bytesB))
        val retired = mutableListOf<String>()
        ZkCircuitCatalogRefresher(client, { retired += it.id }).refreshOnce()
        assertEquals(listOf("a"), retired)
        assertEquals(listOf("b.json"), dir.names("descriptors"))
        assertEquals(listOf(sha(bytesB)), dir.names("artifacts"))
    }

    @Test
    fun `a stale descriptor copy cached under a name that is no active id or alias is removed`() = runTest {
        val dir = tempDir()
        val catalog = Catalog(json)
        val client = warmed(catalog, dir)
        File(File(dir, "descriptors"), "a.json").copyTo(File(File(dir, "descriptors"), "retired-alias.json"))
        ZkCircuitCatalogRefresher(client).refreshOnce()
        assertEquals(listOf("a.json", "b.json"), dir.names("descriptors"))
    }

    @Test
    fun `an artifact an active circuit still uses is kept when another circuit with the same artifact is retired`() = runTest {
        val dir = tempDir()
        val catalog = Catalog(json)
        val client = warmed(catalog, dir)
        // "b" now ships the same artifact as "a", and "a" is retired.
        catalog.circuits = listOf(descriptor("b", bytesA))
        ZkCircuitCatalogRefresher(client).refreshOnce()
        assertEquals(listOf(sha(bytesA)), dir.names("artifacts"))
    }

    @Test
    fun `offline, nothing is expunged or changed and nothing retires`() = runTest {
        val dir = tempDir()
        val catalog = Catalog(json)
        val client = warmed(catalog, dir)
        catalog.circuits = emptyList() // would retire everything, if it were seen
        catalog.reachable = false
        val retired = mutableListOf<String>()
        val result = ZkCircuitCatalogRefresher(client, { retired += it.id }).refreshOnce()
        assertEquals(ZkCircuitCatalogRefresher.Result.Offline, result)
        assertTrue(retired.isEmpty())
        assertEquals(listOf("a.json", "b.json"), dir.names("descriptors"))
        assertEquals(2, dir.names("artifacts").size)
        assertEquals("a", client.fetchCircuit("a")?.id)
    }

    @Test
    fun `a partial manifest page retires only what it lists as not active`() = runTest {
        val dir = tempDir()
        val catalog = Catalog(json)
        val client = warmed(catalog, dir)
        // The page lists only "b", deprecated, and says there is more: "a" is absent but not thereby retired.
        catalog.circuits = listOf(descriptor("b", bytesB, status = "deprecated", deprecatedAt = "2026-10-01T00:00:00Z"))
        catalog.next = "/v1/manifest.json?page=2"
        val retired = mutableListOf<String>()
        val result = ZkCircuitCatalogRefresher(client, { retired += it.id }).refreshOnce() as ZkCircuitCatalogRefresher.Result.Refreshed
        assertFalse(result.complete)
        assertEquals(listOf("b"), retired)
        assertEquals(listOf("a.json"), dir.names("descriptors"))
        assertEquals(listOf(sha(bytesA)), dir.names("artifacts"))
    }

    @Test
    fun `an active circuit's cached descriptor is replaced by the manifest's copy`() = runTest {
        val dir = tempDir()
        val catalog = Catalog(json)
        val client = warmed(catalog, dir)
        val newer = descriptor("a", bytesB)
        catalog.circuits = listOf(newer, descriptor("b", bytesB))
        catalog.reachable = true
        val result = ZkCircuitCatalogRefresher(client).refreshOnce() as ZkCircuitCatalogRefresher.Result.Refreshed
        assertEquals(2, result.refreshed)
        catalog.reachable = false
        assertEquals("sha256:${sha(bytesB)}", client.fetchCircuit("a")?.artifact?.hash)
    }

    @Test
    fun `a circuit seen retired by the proving path is not kept either`() = runTest {
        val dir = tempDir()
        val catalog = Catalog(json)
        val client = warmed(catalog, dir)
        catalog.circuits = listOf(descriptor("a", bytesA, published = false), descriptor("b", bytesB))
        assertEquals(false, client.fetchCircuit("a")?.published)
        catalog.reachable = false
        assertNull(client.fetchCircuit("a"))
        assertFalse(client.isArtifactCached(descriptor("a", bytesA)))
    }

    @Test
    fun `without a disk cache the circuits fetched in this process are still retired`() = runTest {
        val catalog = Catalog(json)
        val client = warmed(catalog, null)
        catalog.circuits = listOf(descriptor("b", bytesB))
        val retired = mutableListOf<String>()
        ZkCircuitCatalogRefresher(client, { retired += it.id }).refreshOnce()
        assertEquals(listOf("a"), retired)
        assertEquals(setOf("b"), client.knownDescriptors().keys)
    }

    @Test
    fun `refresh is fail-soft, a throwing listener does not stop the others or the refresh`() = runTest {
        val dir = tempDir()
        val catalog = Catalog(json)
        val client = warmed(catalog, dir)
        catalog.circuits = emptyList()
        val seen = mutableListOf<String>()
        val result = ZkCircuitCatalogRefresher(client, { seen += it.id; error("listener broke") }).refreshOnce()
        assertTrue(result is ZkCircuitCatalogRefresher.Result.Refreshed)
        assertEquals(setOf("a", "b"), seen.toSet())
        assertEquals(emptyList<String>(), dir.names("descriptors"))
        // A client that throws (an OutOfMemoryError from a body, say) is Failed, not an exception.
        val boom = ZkCircuitClient(httpGet = { throw OutOfMemoryError("x") })
        assertEquals(ZkCircuitCatalogRefresher.Result.Offline, ZkCircuitCatalogRefresher(boom).refreshOnce())
        val throwingRetire = ZkCircuitCatalogRefresher(client, { throw OutOfMemoryError("x") })
        assertNotNull(throwingRetire.refreshOnce())
    }

    /** The client fetches on a real IO dispatcher, so the virtual-time scheduler cannot wait for it: poll in real time. */
    private suspend fun awaitFetches(catalog: Catalog, n: Int) = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
        repeat(300) { if (catalog.manifestFetches >= n) return@withContext; Thread.sleep(10) }
        assertEquals(n, catalog.manifestFetches)
    }

    @Test
    fun `requestRefresh is debounced and launchIn refreshes at once and then every interval`() = runTest {
        val catalog = Catalog(json)
        catalog.circuits = listOf(descriptor("a", bytesA))
        var now = 1_000_000L
        val refresher = ZkCircuitCatalogRefresher(catalog.client(null), nowMillis = { now }, intervalMillis = 1000, minGapMillis = 500)
        assertNotNull(refresher.requestRefresh())
        assertEquals(1, catalog.manifestFetches)
        assertNull("within the gap", refresher.requestRefresh())
        now += 499
        assertNull(refresher.requestRefresh())
        now += 2
        assertNotNull(refresher.requestRefresh())
        assertEquals(2, catalog.manifestFetches)

        // Real time (the client fetches on a real IO dispatcher, which virtual time cannot wait for).
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default)
        val job = ZkCircuitCatalogRefresher(catalog.client(null), intervalMillis = 400).launchIn(scope)
        awaitFetches(catalog, 3)
        // Not again before the interval: a loop without its delay would have fetched many times by now.
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) { Thread.sleep(150) }
        assertEquals(3, catalog.manifestFetches)
        awaitFetches(catalog, 4)
        job.cancel()
    }
}
