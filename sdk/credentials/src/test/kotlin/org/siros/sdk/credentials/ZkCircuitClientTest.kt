// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import okio.buffer
import org.junit.Test
import java.security.MessageDigest

class ZkCircuitClientTest {

    private val json = Json { ignoreUnknownKeys = true }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun manifestJson(circuitsJson: String): String = """
        {
          "manifestVersion": 1,
          "generatedAt": "2026-08-01T00:00:00Z",
          "catalog": "siros-zk-circuits",
          "circuits": [$circuitsJson],
          "next": null
        }
    """.trimIndent()

    private fun circuitJson(id: String, hash: String = "deadbeef", url: String = "/v1/artifacts/sha256/deadbeef", size: Int = 4): String = """
        {
          "id": "$id",
          "system": "longfellow",
          "systemVersion": "1.0",
          "published": true,
          "status": "active",
          "params": {"num_attributes": 3},
          "artifact": {
            "url": "$url",
            "hash": "$hash",
            "size": $size,
            "compression": "none",
            "mediaType": "application/octet-stream"
          },
          "publishedAt": "2026-08-01T00:00:00Z"
        }
    """.trimIndent()

    // ── fetchManifest ────────────────────────────────────────────────

    @Test
    fun `fetchManifest returns the parsed manifest from the first source`() = runTest {
        val client = ZkCircuitClient(httpGet = { url ->
            if (url == "https://zk-circuits.fly.dev/v1/manifest.json") {
                manifestJson(circuitJson("longfellow-mdl-v1"))
            } else {
                null
            }
        })

        val manifest = client.fetchManifest()

        assertEquals(1, manifest?.circuits?.size)
        assertEquals("longfellow-mdl-v1", manifest?.circuits?.get(0)?.id)
        assertEquals("longfellow", manifest?.circuits?.get(0)?.system)
        assertEquals("siros-zk-circuits", manifest?.catalog)
    }

    @Test
    fun `fetchManifest defaults to a single zk-circuits fly dev source`() = runTest {
        var calledUrl: String? = null
        val client = ZkCircuitClient(httpGet = { url ->
            calledUrl = url
            null
        })

        client.fetchManifest()

        assertEquals("https://zk-circuits.fly.dev/v1/manifest.json", calledUrl)
    }

    @Test
    fun `fetchManifest falls back to the second mirror when the first fails`() = runTest {
        val calledUrls = mutableListOf<String>()
        val client = ZkCircuitClient(
            sources = listOf("https://zk-circuits.fly.dev", "https://api.circuits.siros.org"),
            httpGet = { url ->
                calledUrls.add(url)
                when (url) {
                    "https://zk-circuits.fly.dev/v1/manifest.json" -> null // first mirror down
                    "https://api.circuits.siros.org/v1/manifest.json" -> manifestJson(circuitJson("longfellow-mdl-v1"))
                    else -> null
                }
            },
        )

        val manifest = client.fetchManifest()

        assertEquals(1, manifest?.circuits?.size)
        assertEquals(listOf(
            "https://zk-circuits.fly.dev/v1/manifest.json",
            "https://api.circuits.siros.org/v1/manifest.json",
        ), calledUrls)
    }

    @Test
    fun `fetchManifest does not merge across sources - only the first success is used`() = runTest {
        // Even though the second source would also succeed with a different
        // circuit, ZkCircuitClient's mirror semantics mean only the first
        // successful source's result is returned - never merged, unlike
        // Ts11RegistryClient.
        val client = ZkCircuitClient(
            sources = listOf("https://mirror-a.example.org", "https://mirror-b.example.org"),
            httpGet = { url ->
                when (url) {
                    "https://mirror-a.example.org/v1/manifest.json" -> manifestJson(circuitJson("circuit-a"))
                    "https://mirror-b.example.org/v1/manifest.json" -> manifestJson(circuitJson("circuit-b"))
                    else -> null
                }
            },
        )

        val manifest = client.fetchManifest()

        assertEquals(1, manifest?.circuits?.size)
        assertEquals("circuit-a", manifest?.circuits?.get(0)?.id)
    }

    @Test
    fun `fetchManifest returns null when every source fails`() = runTest {
        val client = ZkCircuitClient(
            sources = listOf("https://mirror-a.example.org", "https://mirror-b.example.org"),
            httpGet = { null },
        )

        assertNull(client.fetchManifest())
    }

    @Test
    fun `fetchManifest returns null for a malformed JSON response`() = runTest {
        val client = ZkCircuitClient(httpGet = { "not valid json" })

        assertNull(client.fetchManifest())
    }

    // ── fetchCircuit ─────────────────────────────────────────────────

    @Test
    fun `fetchCircuit returns the parsed descriptor by id`() = runTest {
        val client = ZkCircuitClient(httpGet = { url ->
            if (url == "https://zk-circuits.fly.dev/v1/circuits/longfellow-mdl-v1.json") {
                circuitJson("longfellow-mdl-v1")
            } else {
                null
            }
        })

        val descriptor = client.fetchCircuit("longfellow-mdl-v1")

        assertEquals("longfellow-mdl-v1", descriptor?.id)
        assertEquals("active", descriptor?.status)
        assertEquals("deadbeef", descriptor?.artifact?.hash)
    }

    @Test
    fun `fetchCircuit falls back to the second mirror when the first fails`() = runTest {
        val client = ZkCircuitClient(
            sources = listOf("https://zk-circuits.fly.dev", "https://api.circuits.siros.org"),
            httpGet = { url ->
                when (url) {
                    "https://api.circuits.siros.org/v1/circuits/longfellow-mdl-v1.json" ->
                        circuitJson("longfellow-mdl-v1")
                    else -> null
                }
            },
        )

        val descriptor = client.fetchCircuit("longfellow-mdl-v1")

        assertEquals("longfellow-mdl-v1", descriptor?.id)
    }

    @Test
    fun `fetchCircuit returns null when every source fails`() = runTest {
        val client = ZkCircuitClient(httpGet = { null })

        assertNull(client.fetchCircuit("unknown"))
    }

    // ── downloadArtifact ─────────────────────────────────────────────

    @Test
    fun `downloadArtifact returns bytes whose sha256 matches the descriptor hash`() = runTest {
        val bytes = "circuit-bytes".toByteArray()
        val hash = sha256Hex(bytes)
        val client = ZkCircuitClient(
            httpGetBytes = { url ->
                if (url == "https://zk-circuits.fly.dev/v1/artifacts/sha256/$hash") bytes else null
            },
        )
        val circuit = json.decodeFromString(ZkCircuitDescriptor.serializer(), circuitJson("longfellow-mdl-v1", hash = hash, url = "/v1/artifacts/sha256/$hash", size = bytes.size))

        val downloaded = client.downloadArtifact(circuit)

        assertTrue(bytes.contentEquals(downloaded))
    }

    @Test
    fun `downloadArtifact matches a real sha256-prefixed descriptor hash, not just a bare hex fixture`() = runTest {
        // Real go-zk-circuits descriptors wire the hash as "sha256:<hex>" (confirmed
        // live against zk-circuits.fly.dev) - unlike this file's other fixtures,
        // which use a bare hex hash and would not have caught the real bug this
        // regression-tests: the comparison used to always fail for a correct
        // download because one side of the comparison never had the prefix
        // stripped.
        val bytes = "circuit-bytes".toByteArray()
        val hash = sha256Hex(bytes)
        val client = ZkCircuitClient(
            httpGetBytes = { url ->
                if (url == "https://zk-circuits.fly.dev/v1/artifacts/sha256/$hash") bytes else null
            },
        )
        val circuit = json.decodeFromString(
            ZkCircuitDescriptor.serializer(),
            circuitJson("longfellow-mdl-v1", hash = "sha256:$hash", url = "/v1/artifacts/sha256/$hash", size = bytes.size),
        )

        val downloaded = client.downloadArtifact(circuit)

        assertTrue(bytes.contentEquals(downloaded))
    }

    @Test
    fun `downloadArtifact falls back to the second mirror when the first fails to fetch`() = runTest {
        val bytes = "circuit-bytes".toByteArray()
        val hash = sha256Hex(bytes)
        val client = ZkCircuitClient(
            sources = listOf("https://zk-circuits.fly.dev", "https://api.circuits.siros.org"),
            httpGetBytes = { url ->
                when (url) {
                    "https://api.circuits.siros.org/v1/artifacts/sha256/$hash" -> bytes
                    else -> null
                }
            },
        )
        val circuit = json.decodeFromString(ZkCircuitDescriptor.serializer(), circuitJson("longfellow-mdl-v1", hash = hash, url = "/v1/artifacts/sha256/$hash", size = bytes.size))

        val downloaded = client.downloadArtifact(circuit)

        assertTrue(bytes.contentEquals(downloaded))
    }

    @Test
    fun `downloadArtifact throws when the downloaded bytes hash does not match`() = runTest {
        val bytes = "tampered-bytes".toByteArray()
        val client = ZkCircuitClient(
            httpGetBytes = { bytes },
        )
        val circuit = json.decodeFromString(
                ZkCircuitDescriptor.serializer(),
                circuitJson("longfellow-mdl-v1", hash = "0000000000000000000000000000000000000000000000000000000000000000"),
            )

        try {
            client.downloadArtifact(circuit)
            fail("expected ZkArtifactException on hash mismatch")
        } catch (e: ZkArtifactException) {
            assertTrue(e.message?.contains("longfellow-mdl-v1") == true)
        }
    }

    @Test
    fun `downloadArtifact throws when the descriptor has no artifact`() = runTest {
        val client = ZkCircuitClient(httpGetBytes = { fail("should never fetch without an artifact"); null })
        val circuit = ZkCircuitDescriptor(
            id = "no-artifact-circuit",
            system = "longfellow",
            systemVersion = "1.0",
            published = true,
            status = "active",
            publishedAt = "2026-08-01T00:00:00Z",
        )

        try {
            client.downloadArtifact(circuit)
            fail("expected ZkArtifactException for a missing artifact")
        } catch (e: ZkArtifactException) {
            assertTrue(e.message?.contains("no-artifact-circuit") == true)
        }
    }

    @Test
    fun `downloadArtifact resolves an absolute artifact url as a single candidate, not mirrored`() = runTest {
        val bytes = "abs-bytes".toByteArray()
        val hash = sha256Hex(bytes)
        val calledUrls = mutableListOf<String>()
        val client = ZkCircuitClient(
            sources = listOf("https://zk-circuits.fly.dev", "https://api.circuits.siros.org"),
            httpGetBytes = { url ->
                calledUrls.add(url)
                if (url == "https://cdn.example.org/blobs/$hash") bytes else null
            },
        )
        val circuit = json.decodeFromString(
                ZkCircuitDescriptor.serializer(),
                circuitJson("longfellow-mdl-v1", hash = hash, url = "https://cdn.example.org/blobs/$hash", size = bytes.size),
            )

        val downloaded = client.downloadArtifact(circuit)

        assertTrue(bytes.contentEquals(downloaded))
        assertEquals(listOf("https://cdn.example.org/blobs/$hash"), calledUrls)
    }

    @Test
    fun `downloadArtifact constructs the artifact path from the hash when url is blank`() = runTest {
        val bytes = "blank-url-bytes".toByteArray()
        val hash = sha256Hex(bytes)
        var calledUrl: String? = null
        val client = ZkCircuitClient(
            httpGetBytes = { url ->
                calledUrl = url
                if (url == "https://zk-circuits.fly.dev/v1/artifacts/sha256/$hash") bytes else null
            },
        )
        val circuit = json.decodeFromString(ZkCircuitDescriptor.serializer(), circuitJson("longfellow-mdl-v1", hash = hash, url = "", size = bytes.size))

        val downloaded = client.downloadArtifact(circuit)

        assertEquals("https://zk-circuits.fly.dev/v1/artifacts/sha256/$hash", calledUrl)
        assertTrue(bytes.contentEquals(downloaded))
    }

    // ── on-device cache ──────────────────────────────────────────────

    @Test
    fun `a stale alias copy that cannot be removed is logged, not ignored and not fatal`() {
        val dir = tempCacheDir()
        val descriptor = json.decodeFromString(ZkCircuitDescriptor.serializer(), circuitJson("longfellow-mdl-v1")).copy(aliases = listOf("old-alias"))
        // A non-empty directory where the alias copy should be: File.delete() fails on it.
        val stuck = java.io.File(java.io.File(dir, "descriptors"), "old-alias.json")
        java.io.File(stuck, "child").apply { parentFile.mkdirs(); writeText("x") }
        val lines = mutableListOf<String>()
        val tree = object : timber.log.Timber.Tree() {
            override fun log(priority: Int, tag: String?, message: String, t: Throwable?) { lines += message }
        }
        timber.log.Timber.plant(tree)
        try {
            ZkCircuitClient(cacheDir = dir).cacheDescriptor(descriptor)
        } finally {
            timber.log.Timber.uproot(tree)
        }
        assertTrue(lines.toString(), lines.any { it.contains("could not remove old-alias.json") })
        // An alias copy that is simply absent logs nothing.
        lines.clear()
        timber.log.Timber.plant(tree)
        try {
            ZkCircuitClient(cacheDir = tempCacheDir()).cacheDescriptor(descriptor)
        } finally {
            timber.log.Timber.uproot(tree)
        }
        assertTrue(lines.toString(), lines.none { it.contains("could not remove") })
    }

    private fun tempCacheDir(): java.io.File =
        java.nio.file.Files.createTempDirectory("zk-circuit-cache").toFile().also { it.deleteOnExit() }

    @Test
    fun `a verified artifact is fetched once per device and served from disk after that`() = runTest {
        val bytes = "circuit-bytes".toByteArray()
        val hash = sha256Hex(bytes)
        val dir = tempCacheDir()
        var fetches = 0
        val client = ZkCircuitClient(
            httpGetBytes = { url -> fetches++; if (url.endsWith("/$hash")) bytes else null },
            cacheDir = dir,
        )
        val circuit = json.decodeFromString(ZkCircuitDescriptor.serializer(), circuitJson("longfellow-mdl-v1", hash = "sha256:$hash", url = "/v1/artifacts/sha256/$hash", size = bytes.size))
        assertTrue(!client.isArtifactCached(circuit))

        assertTrue(bytes.contentEquals(client.downloadArtifact(circuit)))
        assertEquals(1, fetches)
        assertTrue(client.isArtifactCached(circuit))

        // A second client over the same directory - a later process - never touches the network.
        val offline = ZkCircuitClient(httpGetBytes = { fail("must be served from the cache"); null }, cacheDir = dir)
        assertTrue(bytes.contentEquals(offline.downloadArtifact(circuit)))
        assertEquals(1, fetches)
    }

    @Test
    fun `a cached artifact that fails its hash check is discarded and re-fetched, never trusted`() = runTest {
        val bytes = "circuit-bytes".toByteArray()
        val hash = sha256Hex(bytes)
        val dir = tempCacheDir()
        // Poison the cache with the right name and the wrong content.
        java.io.File(java.io.File(dir, "artifacts"), hash).apply { parentFile.mkdirs(); writeBytes("tampered".toByteArray()) }
        var fetches = 0
        val client = ZkCircuitClient(httpGetBytes = { fetches++; bytes }, cacheDir = dir)
        val circuit = json.decodeFromString(ZkCircuitDescriptor.serializer(), circuitJson("longfellow-mdl-v1", hash = hash, url = "/v1/artifacts/sha256/$hash", size = bytes.size))

        assertTrue(bytes.contentEquals(client.downloadArtifact(circuit)))
        assertEquals(1, fetches)
        assertTrue(bytes.contentEquals(java.io.File(java.io.File(dir, "artifacts"), hash).readBytes()))
    }

    @Test
    fun `descriptors are network-first and the cached copy serves only when every source fails`() = runTest {
        val dir = tempCacheDir()
        val online = ZkCircuitClient(
            sources = listOf("https://a.example"),
            httpGet = { url -> if (url == "https://a.example/v1/circuits/longfellow-mdl-v1.json") circuitJson("longfellow-mdl-v1") else null },
            cacheDir = dir,
        )
        assertEquals("longfellow-mdl-v1", online.fetchCircuit("longfellow-mdl-v1")?.id)

        val offline = ZkCircuitClient(sources = listOf("https://a.example"), httpGet = { null }, cacheDir = dir)
        assertEquals("longfellow-mdl-v1", offline.fetchCircuit("longfellow-mdl-v1")?.id)
        assertNull(offline.fetchCircuit("never-fetched"))

        // A fresher descriptor from the network replaces the cached one.
        val updated = ZkCircuitClient(
            sources = listOf("https://a.example"),
            httpGet = { circuitJson("longfellow-mdl-v1").replace("\"status\": \"active\"", "\"status\": \"deprecated\"") },
            cacheDir = dir,
        )
        assertEquals("deprecated", updated.fetchCircuit("longfellow-mdl-v1")?.status)
        // A circuit seen retired is not kept: an offline wallet no longer finds it to prove with.
        assertNull(offline.fetchCircuit("longfellow-mdl-v1"))
    }

    @Test
    fun `without a cache directory nothing is written and every call fetches`() = runTest {
        val bytes = "circuit-bytes".toByteArray()
        val hash = sha256Hex(bytes)
        var fetches = 0
        val client = ZkCircuitClient(httpGetBytes = { fetches++; bytes })
        val circuit = json.decodeFromString(ZkCircuitDescriptor.serializer(), circuitJson("longfellow-mdl-v1", hash = hash, url = "/v1/artifacts/sha256/$hash", size = bytes.size))
        client.downloadArtifact(circuit)
        client.downloadArtifact(circuit)
        assertEquals(2, fetches)
        assertTrue(!client.isArtifactCached(circuit))
    }

    // ── CIRCUIT-3: sizes are bounded and enforced ─────────────────────

    private fun descriptorFor(bytes: ByteArray, declared: Int) = json.decodeFromString(
        ZkCircuitDescriptor.serializer(),
        sha256Hex(bytes).let { circuitJson("longfellow-mdl-v1", hash = it, url = "/v1/artifacts/sha256/$it", size = declared) },
    )

    private suspend fun assertArtifactRefused(client: ZkCircuitClient, d: ZkCircuitDescriptor) {
        try {
            client.downloadArtifact(d)
            fail("expected the artifact to be refused")
        } catch (e: ZkArtifactException) {
            // expected
        }
    }

    @Test
    fun `an artifact whose declared size is missing, over the ceiling or not the served length is refused`() = runTest {
        val bytes = "circuit-bytes".toByteArray()
        var fetches = 0
        val client = ZkCircuitClient(httpGetBytes = { fetches++; bytes }, maxArtifactBytes = 1000)
        assertArtifactRefused(client, descriptorFor(bytes, declared = 0))
        assertArtifactRefused(client, descriptorFor(bytes, declared = 1001))
        assertEquals("refused before any fetch", 0, fetches)
        // The hash matches, but the catalog's size claim is wrong.
        assertArtifactRefused(client, descriptorFor(bytes, declared = bytes.size + 1))
        assertArtifactRefused(client, descriptorFor(bytes, declared = bytes.size - 1))
        assertTrue(bytes.contentEquals(client.downloadArtifact(descriptorFor(bytes, declared = bytes.size))))
    }

    @Test
    fun `a cached artifact of the wrong length is not trusted`() = runTest {
        val bytes = "circuit-bytes".toByteArray()
        val dir = tempCacheDir()
        val d = descriptorFor(bytes, declared = bytes.size)
        val client = ZkCircuitClient(httpGetBytes = { bytes }, cacheDir = dir)
        client.downloadArtifact(d)
        val offline = ZkCircuitClient(httpGetBytes = { null }, cacheDir = dir)
        assertTrue(bytes.contentEquals(offline.downloadArtifact(descriptorFor(bytes, declared = bytes.size))))
        assertArtifactRefused(offline, descriptorFor(bytes, declared = bytes.size + 1))
    }

    @Test
    fun `an oversized or crashing catalog body is a failed fetch, not an exception or an allocation`() = runTest {
        val big = circuitJson("longfellow-mdl-v1") + " ".repeat(200)
        val capped = ZkCircuitClient(httpGet = { big }, maxDescriptorBytes = 100)
        assertNull(capped.fetchCircuit("longfellow-mdl-v1"))
        assertNull(capped.fetchManifest())
        val ok = ZkCircuitClient(httpGet = { big }, maxDescriptorBytes = 100000)
        assertEquals("longfellow-mdl-v1", ok.fetchCircuit("longfellow-mdl-v1")?.id)
        // An OutOfMemoryError (or any Throwable) from a fetch is contained.
        assertNull(ZkCircuitClient(httpGet = { throw OutOfMemoryError("hostile body") }).fetchCircuit("x"))
        val bytes = "circuit-bytes".toByteArray()
        assertArtifactRefused(ZkCircuitClient(httpGetBytes = { throw OutOfMemoryError("hostile body") }), descriptorFor(bytes, bytes.size))
    }

    private fun clientServing(body: ByteArray, contentLength: Long = -1, limitDescriptor: Int = 1000, limitArtifact: Long = 1000): ZkCircuitClient {
        val http = okhttp3.OkHttpClient.Builder().addInterceptor { chain ->
            val source = okio.Buffer().write(body)
            val responseBody = object : okhttp3.ResponseBody() {
                override fun contentType() = null
                override fun contentLength() = contentLength
                override fun source(): okio.BufferedSource = source
            }
            okhttp3.Response.Builder().request(chain.request()).protocol(okhttp3.Protocol.HTTP_1_1)
                .code(200).message("OK").body(responseBody).build()
        }.build()
        return ZkCircuitClient(httpClient = http, maxDescriptorBytes = limitDescriptor, maxArtifactBytes = limitArtifact)
    }

    @Test
    fun `the real http path never reads past the limit, whether or not the server says how long the body is`() = runTest {
        val descriptorBody = circuitJson("longfellow-mdl-v1").toByteArray()
        val tight = descriptorBody.size - 1
        assertNull(clientServing(descriptorBody, limitDescriptor = tight).fetchCircuit("longfellow-mdl-v1"))
        assertNull(clientServing(descriptorBody, contentLength = descriptorBody.size.toLong(), limitDescriptor = tight).fetchCircuit("longfellow-mdl-v1"))
        assertEquals("longfellow-mdl-v1", clientServing(descriptorBody, limitDescriptor = descriptorBody.size).fetchCircuit("longfellow-mdl-v1")?.id)

        // An artifact longer than the size the catalog declared is cut off at that size and refused.
        val artifact = ByteArray(500) { it.toByte() }
        val d = descriptorFor(artifact, declared = 100)
        assertArtifactRefused(clientServing(artifact), d)
        assertTrue(artifact.contentEquals(clientServing(artifact).downloadArtifact(descriptorFor(artifact, declared = artifact.size))))
    }

    /** A body of [total] zero bytes that counts what is actually pulled from it. */
    private class CountingBody(val total: Long, val declared: Long) {
        var pulled = 0L
        val source: okio.BufferedSource = run {
            object : okio.Source {
                override fun read(sink: okio.Buffer, byteCount: Long): Long {
                    if (pulled >= total) return -1
                    val n = minOf(byteCount, total - pulled, 8192)
                    sink.write(ByteArray(n.toInt()))
                    pulled += n
                    return n
                }
                override fun timeout() = okio.Timeout.NONE
                override fun close() {}
            }.buffer()
        }
    }

    private fun clientOver(body: CountingBody, limitDescriptor: Int = 1000, limitArtifact: Long = 1000): ZkCircuitClient {
        val http = okhttp3.OkHttpClient.Builder().addInterceptor { chain ->
            val rb = object : okhttp3.ResponseBody() {
                override fun contentType() = null
                override fun contentLength() = body.declared
                override fun source() = body.source
            }
            okhttp3.Response.Builder().request(chain.request()).protocol(okhttp3.Protocol.HTTP_1_1).code(200).message("OK").body(rb).build()
        }.build()
        return ZkCircuitClient(httpClient = http, maxDescriptorBytes = limitDescriptor, maxArtifactBytes = limitArtifact)
    }

    @Test
    fun `an enormous body is never pulled past the limit, with or without a declared length`() = runTest {
        val unknown = CountingBody(total = 500_000_000L, declared = -1)
        assertNull(clientOver(unknown).fetchCircuit("x"))
        assertTrue("pulled ${unknown.pulled}", unknown.pulled <= 1000 + 2 * 8192)

        val declared = CountingBody(total = 500_000_000L, declared = 500_000_000L)
        assertNull(clientOver(declared).fetchCircuit("x"))
        assertEquals("a declared length over the limit reads nothing", 0L, declared.pulled)

        val artifact = CountingBody(total = 500_000_000L, declared = -1)
        assertArtifactRefused(clientOver(artifact), descriptorFor(ByteArray(10), declared = 10))
        assertTrue("pulled ${artifact.pulled}", artifact.pulled <= 10 + 2 * 8192)
    }
}
