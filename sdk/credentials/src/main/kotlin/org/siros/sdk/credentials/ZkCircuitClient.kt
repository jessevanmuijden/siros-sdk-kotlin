// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import okhttp3.OkHttpClient
import okhttp3.Request
import timber.log.Timber
import java.io.File
import java.security.MessageDigest

/**
 * A single format-specific verification record recorded against a circuit's
 * [ZkSource], mirroring `catalog.VerificationRecord` in
 * `go-zk-circuits/pkg/catalog/types.go` field-for-field. Written exclusively
 * by that service's own tooling (`circuitctl verify-interop`) - never
 * hand-edited, and not itself a trust decision, just descriptive metadata.
 */
@Serializable
data class ZkVerificationRecord(
    val tool: String = "",
    val toolVersion: String = "",
    val verifierIdentity: String = "",
    val date: String = "",
    val result: String = "",
    val notes: String? = null,
)

/**
 * Provenance for a [ZkCircuitDescriptor], mirroring `catalog.Source` in
 * `go-zk-circuits/pkg/catalog/types.go`.
 */
@Serializable
data class ZkSource(
    val origin: String = "",
    val originRef: String? = null,
    val originPath: String? = null,
    val toolchain: String? = null,
    val license: String? = null,
    val openSource: Boolean = false,
    val addedBy: String = "",
    val verifiedBy: List<ZkVerificationRecord> = emptyList(),
)

/**
 * The decompressed-form hash/size of a [ZkArtifact], present when
 * [ZkArtifact.compression] is not `"none"`. Mirrors `catalog.Uncompressed`.
 */
@Serializable
data class ZkUncompressed(
    val hash: String = "",
    val size: Long = 0,
)

/**
 * Describes the downloadable bytes for a circuit, mirroring `catalog.Artifact`
 * in `go-zk-circuits/pkg/catalog/types.go`.
 *
 * NOTE on [url]: in the real deployed service this is a *relative* path (e.g.
 * `/v1/artifacts/sha256/<hex>`, set by `pkg/publish/add.go`'s
 * `entry.Artifact.URL = "/v1/" + catalog.ArtifactFilePath(...)`), not an
 * absolute URL - [ZkCircuitClient.downloadArtifact] resolves it against each
 * configured mirror accordingly. See that method's doc comment.
 *
 * [hash] is over the bytes AS SERVED (compressed, if [compression] != "none");
 * [uncompressed]'s hash is over the decompressed bytes. Neither is the same
 * as the proof system's own circuit identifier that may appear inside
 * [ZkCircuitDescriptor.params].
 */
@Serializable
data class ZkArtifact(
    val url: String = "",
    val hash: String = "",
    val size: Long = 0,
    val compression: String = "",
    val mediaType: String = "",
    val uncompressed: ZkUncompressed? = null,
)

/**
 * One catalog entry - the body of `GET /v1/circuits/{id}.json` and one
 * element of [ZkManifest.circuits] - mirroring `catalog.CircuitDescriptor`
 * in `go-zk-circuits/pkg/catalog/types.go` field-for-field.
 */
@Serializable
data class ZkCircuitDescriptor(
    val id: String,
    val aliases: List<String> = emptyList(),
    val system: String = "",
    val systemVersion: String = "",
    val docTypes: List<String> = emptyList(),
    val published: Boolean = false,
    val status: String = "",
    val params: JsonObject = JsonObject(emptyMap()),
    val artifact: ZkArtifact? = null,
    val source: ZkSource? = null,
    val publishedAt: String = "",
    val deprecatedAt: String? = null,
    val notes: String? = null,
    /** The circuit's structured `capabilities`, when the catalog has them. Passed to the matcher verbatim, never read here. */
    val capabilities: JsonObject? = null,
) {
    /** Published, `active` and not deprecated: the only state in which a circuit may be proved with. */
    fun isActive(): Boolean = published && deprecatedAt == null && status == "active"
}

/**
 * The top-level document served at `GET /v1/manifest.json`, mirroring
 * `catalog.Manifest` in `go-zk-circuits/pkg/catalog/types.go`.
 */
@Serializable
data class ZkManifest(
    val manifestVersion: Int = 1,
    val generatedAt: String = "",
    val catalog: String = "",
    val circuits: List<ZkCircuitDescriptor> = emptyList(),
    val next: String? = null,
)

/**
 * Thrown by [ZkCircuitClient.downloadArtifact] when no configured source (or
 * URL candidate) produced hash-verified artifact bytes - either every fetch
 * attempt failed outright, or the downloaded bytes' SHA-256 digest never
 * matched [ZkArtifact.hash]. Per the service's own API contract, hash
 * verification is the client's responsibility, not something the server
 * guarantees for you - this exception is how that responsibility is enforced.
 */
class ZkArtifactException(message: String) : Exception(message)

/**
 * Client for the go-zk-circuits catalog REST API - the real, deployed
 * read-only service for discovering/downloading ZK-proof circuit artifacts
 * for the Longfellow-ZKP-pseudonym feature (`https://zk-circuits.fly.dev`
 * today, moving to `https://api.circuits.siros.org` once DNS is live - NOT
 * the bare `circuits.siros.org` human-facing website).
 *
 * DELIBERATELY DIFFERENT fallback semantics than [Ts11RegistryClient]: that
 * class's `sources` are *distinct* registries whose entries are merged
 * together. This class's [sources] are *mirrors of the same catalog* - the
 * literal same service, reachable at a different hostname (e.g. a CDN
 * fallback, or the pre-DNS Fly.io URL alongside the eventual
 * `api.circuits.siros.org` one) - so every method here tries each source **in
 * list order** and returns the first one that succeeds, without ever merging
 * results across sources.
 *
 * @param sources mirror base URLs, tried in order until one succeeds.
 *        Defaults to a single entry, [DEFAULT_ZK_CIRCUIT_URL].
 * @param httpGet optional injectable text-fetch function (URL -> response
 *        body string, or null on failure/non-2xx), for tests. When null, a
 *        real OkHttp-backed implementation is used.
 * @param httpGetBytes optional injectable byte-fetch function (URL -> raw
 *        response bytes, or null on failure/non-2xx), for tests (e.g.
 *        artifact downloads). When null, a real OkHttp-backed implementation
 *        is used.
 * @param httpClient the [OkHttpClient] backing the default (non-injected)
 *        fetch implementations. OkHttp follows redirects by default, which
 *        is required for `GET /v1/circuits/{id}.json` when `id` is an alias
 *        (the server responds with a 301 to the canonical id).
 */
class ZkCircuitClient(
    private val sources: List<String> = listOf(DEFAULT_ZK_CIRCUIT_URL),
    private val httpGet: (suspend (String) -> String?)? = null,
    private val httpGetBytes: (suspend (String) -> ByteArray?)? = null,
    private val httpClient: OkHttpClient = OkHttpClient(),
    /**
     * On-device cache of what this client fetches, or null for none.
     *
     * Artifacts are stored under their catalog-published SHA-256, which
     * [downloadArtifact] verifies on every read as well as on every
     * download, so a cached artifact is exactly as trusted as a fresh one
     * and a corrupt file is simply re-fetched. A circuit is tens of
     * megabytes compressed and immutable once published (its identity IS
     * its hash), so there is nothing to expire: fetch and verify happen
     * once per device, and the OS may evict the directory under storage
     * pressure without any correctness consequence.
     *
     * Descriptors are cached too, network-first: a fetched descriptor
     * replaces the cached copy, and the cached copy is used only when every
     * source fails. That is what lets a proof run with no network at all -
     * the case an ISO 18013-5 proximity presentation exists for.
     */
    private val cacheDir: File? = null,
    /** The most a manifest or descriptor body may be: a larger one is refused, not read into memory. */
    private val maxDescriptorBytes: Int = DEFAULT_MAX_DESCRIPTOR_BYTES,
    /** The most an artifact may be, whatever the catalog says it is: a larger artifact is refused unfetched. */
    private val maxArtifactBytes: Long = DEFAULT_MAX_ARTIFACT_BYTES,
) {
    private val json = Json { ignoreUnknownKeys = true }

    companion object {
        /** Default zk-circuits catalog base URL (pre-DNS Fly.io deployment). */
        const val DEFAULT_ZK_CIRCUIT_URL = "https://zk-circuits.fly.dev"

        /** Default [maxDescriptorBytes]: 4 MiB (the real manifest is far smaller). */
        const val DEFAULT_MAX_DESCRIPTOR_BYTES = 4 * 1024 * 1024

        /** Default [maxArtifactBytes]: 256 MiB (the largest real artifact is about 4 MB compressed). */
        const val DEFAULT_MAX_ARTIFACT_BYTES = 256L * 1024 * 1024
    }

    /**
     * `GET /v1/manifest.json` - the full circuit catalog, from the first
     * [sources] entry that serves a parseable manifest (see class docs for
     * the ordered-fallback, non-merging semantics). Returns null if every
     * source failed (network error, non-2xx, or malformed JSON).
     */
    suspend fun fetchManifest(): ZkManifest? = withContext(Dispatchers.IO) {
        for (source in sources) {
            val url = manifestUrl(source)
            val body = fetchRaw(url) ?: continue
            try {
                return@withContext json.decodeFromString(ZkManifest.serializer(), body)
            } catch (e: Exception) {
                Timber.w(e, "Failed to parse zk-circuit manifest from $url")
            }
        }
        if (sources.isNotEmpty()) {
            Timber.w("All ${sources.size} zk-circuit source(s) failed to yield a manifest")
        }
        null
    }

    /**
     * `GET /v1/circuits/{id}.json` - a single circuit descriptor, from the
     * first [sources] entry that serves one, by canonical id or alias (an
     * alias 301-redirects to the canonical id server-side; the default
     * OkHttp-backed fetch follows redirects automatically). Returns null if
     * every source failed.
     */
    suspend fun fetchCircuit(id: String): ZkCircuitDescriptor? = withContext(Dispatchers.IO) {
        for (source in sources) {
            val url = circuitUrl(source, id)
            val body = fetchRaw(url) ?: continue
            try {
                val descriptor = json.decodeFromString(ZkCircuitDescriptor.serializer(), body)
                if (descriptor.isActive()) {
                    writeCached(descriptorFile(id), body.toByteArray(Charsets.UTF_8))
                    seen[descriptor.id] = descriptor
                } else {
                    // Seen retired: it stops being usable now, not at the next refresh (the caller sees the
                    // descriptor and refuses it; nothing of it stays cached to serve an offline wallet).
                    expunge(descriptor)
                    removeCached(descriptorFile(id))
                }
                return@withContext descriptor
            } catch (e: Exception) {
                Timber.w(e, "Failed to parse zk-circuit descriptor '$id' from $url")
            }
        }
        if (sources.isNotEmpty()) {
            Timber.w("All ${sources.size} zk-circuit source(s) failed to yield circuit '$id'")
        }
        readCached(descriptorFile(id))?.let { cached ->
            try {
                Timber.i("Using cached zk-circuit descriptor '$id' (every source failed)")
                return@withContext json.decodeFromString(ZkCircuitDescriptor.serializer(), cached.toString(Charsets.UTF_8))
            } catch (e: Exception) {
                Timber.w(e, "Cached zk-circuit descriptor '$id' is unreadable")
            }
        }
        null
    }

    /**
     * Downloads a circuit's artifact bytes and verifies their SHA-256 digest
     * against [ZkArtifact.hash] before returning them - the API's docs are
     * explicit that this verification is the client's responsibility, never
     * assumed from a successful HTTP fetch alone.
     *
     * Builds an ordered list of URL candidates and tries each in turn (first
     * hash-verified success wins):
     * - if [ZkArtifact.url] is already an absolute URL, it is the only
     *   candidate (it already pins its own host, so there is nothing to
     *   mirror-fallback across);
     * - otherwise (the real service's current behavior - see [ZkArtifact.url]'s
     *   doc comment) it is a relative path, resolved against every configured
     *   [sources] mirror in order;
     * - if [ZkArtifact.url] is blank, the path is instead constructed from
     *   [ZkArtifact.hash] as `v1/artifacts/{alg}/{hex}` (`sha256` is the only
     *   algorithm the service supports today), again resolved against every
     *   mirror.
     *
     * @throws ZkArtifactException if [descriptor] has no [ZkCircuitDescriptor.artifact],
     *   or if every URL candidate either failed to fetch or failed hash
     *   verification.
     */
    suspend fun downloadArtifact(descriptor: ZkCircuitDescriptor): ByteArray = withContext(Dispatchers.IO) {
        val artifact = descriptor.artifact
            ?: throw ZkArtifactException("Circuit '${descriptor.id}' has no artifact")
        // The size is part of the catalog's claim and bounds what is fetched: absent, non-positive or over
        // the ceiling is refused before any byte is read.
        if (artifact.size <= 0 || artifact.size > maxArtifactBytes) {
            throw ZkArtifactException("Circuit '${descriptor.id}' declares an unacceptable artifact size (${artifact.size})")
        }
        val expectedHash = bareHex(artifact.hash)
        val cacheFile = artifactFile(expectedHash)
        readCached(cacheFile)?.let { cached ->
            if (cached.size.toLong() == artifact.size && sha256Hex(cached).equals(expectedHash, ignoreCase = true)) {
                return@withContext cached
            }
            Timber.w("Cached zk-circuit artifact for '${descriptor.id}' failed its hash check - discarding it")
            cacheFile?.delete()
        }

        var lastFailure: String? = null
        for (url in candidateArtifactUrls(artifact)) {
            val bytes = fetchBytes(url, artifact.size)
            if (bytes == null) {
                lastFailure = "fetch failed from $url"
                continue
            }
            if (bytes.size.toLong() != artifact.size) {
                Timber.w("zk-circuit artifact size mismatch for '${descriptor.id}' from $url: expected ${artifact.size}, got ${bytes.size}")
                lastFailure = "size mismatch from $url"
                continue
            }
            val actualHash = sha256Hex(bytes)
            if (!actualHash.equals(expectedHash, ignoreCase = true)) {
                Timber.w(
                    "zk-circuit artifact hash mismatch for '${descriptor.id}' from $url: " +
                        "expected ${artifact.hash}, got $actualHash",
                )
                lastFailure = "hash mismatch from $url"
                continue
            }
            writeCached(cacheFile, bytes)
            seen[descriptor.id] = descriptor
            return@withContext bytes
        }
        throw ZkArtifactException(
            "Failed to download a hash-verified artifact for circuit '${descriptor.id}' " +
                "from any of ${sources.size} source(s)" + (lastFailure?.let { " (last: $it)" } ?: ""),
        )
    }

    /** Circuits fetched in this process, by id: what a refresh may need to expunge when there is no disk cache. */
    private val seen = java.util.concurrent.ConcurrentHashMap<String, ZkCircuitDescriptor>()

    /** Every descriptor this client knows of: the cached ones and those fetched in this process, by id. */
    fun knownDescriptors(): Map<String, ZkCircuitDescriptor> {
        val out = LinkedHashMap<String, ZkCircuitDescriptor>()
        val dir = cacheDir?.let { File(it, "descriptors") }
        dir?.listFiles()?.filter { it.isFile && it.name.endsWith(".json") }?.forEach { f ->
            try {
                val d = json.decodeFromString(ZkCircuitDescriptor.serializer(), f.readText())
                out[d.id] = d
            } catch (e: Exception) {
                Timber.w(e, "Unreadable cached zk-circuit descriptor ${f.name}; removing it")
                f.delete()
            }
        }
        out.putAll(seen)
        return out
    }

    /** Stores [descriptor] as the cached descriptor of its id (a refresh replaces a stale copy with the manifest's). */
    fun cacheDescriptor(descriptor: ZkCircuitDescriptor) {
        writeCached(descriptorFile(descriptor.id), json.encodeToString(ZkCircuitDescriptor.serializer(), descriptor).toByteArray(Charsets.UTF_8))
        // A copy cached under an alias is stale now; the next lookup by alias fetches it afresh.
        descriptor.aliases.forEach { removeCached(descriptorFile(it)) }
        seen[descriptor.id] = descriptor
    }

    /** Removes everything cached for [descriptor]: its descriptor under its id and aliases, and its artifact by hash. */
    fun expunge(descriptor: ZkCircuitDescriptor) = expunge(descriptor, keepArtifactHashes = emptySet())

    /** As [expunge], but an artifact whose (lower-case, bare) hash is in [keepArtifactHashes] stays: another circuit uses it. */
    private fun expunge(descriptor: ZkCircuitDescriptor, keepArtifactHashes: Set<String>) {
        (listOf(descriptor.id) + descriptor.aliases).forEach { descriptorFile(it)?.delete() }
        descriptor.artifact?.hash?.let(::bareHex)?.takeIf { it.lowercase() !in keepArtifactHashes }?.let { artifactFile(it)?.delete() }
        seen.remove(descriptor.id)
    }

    /**
     * Keeps only what [active] (the circuits a COMPLETE catalog manifest lists as published, current and `active`)
     * names: every other cached descriptor and every cached artifact whose hash no active circuit uses is deleted.
     * Returns the known descriptors that were retired by this. Call only with the
     * circuits of a complete catalog.
     */
    fun retainOnly(active: List<ZkCircuitDescriptor>): List<ZkCircuitDescriptor> {
        val activeIds = active.flatMap { listOf(it.id) + it.aliases }.toSet()
        val activeHashes = active.mapNotNull { it.artifact?.hash?.let(::bareHex)?.lowercase() }.toSet()
        val retired = knownDescriptors().values.filter { it.id !in activeIds }
        retired.forEach { expunge(it, activeHashes) }
        // Descriptor files whose id is neither an active id nor an alias (a descriptor cached under a retired alias).
        cacheDir?.let { File(it, "descriptors") }?.listFiles()?.forEach { f ->
            val name = java.net.URLDecoder.decode(f.name.removeSuffix(".json"), "UTF-8")
            if (f.isFile && name !in activeIds) f.delete()
        }
        cacheDir?.let { File(it, "artifacts") }?.listFiles()?.forEach { f ->
            if (f.isFile && f.name.lowercase() !in activeHashes) f.delete()
        }
        return retired
    }

    /** Whether [downloadArtifact] would be served from disk for [descriptor]. Cheap; for diagnostics and tests. */
    fun isArtifactCached(descriptor: ZkCircuitDescriptor): Boolean =
        descriptor.artifact?.let { artifactFile(bareHex(it.hash))?.isFile } == true

    /** Removes everything cached. Artifacts are immutable, so this only ever costs a re-download. */
    fun clearCache() {
        cacheDir?.deleteRecursively()
    }

    private fun artifactFile(hashHex: String): File? =
        cacheDir?.let { File(File(it, "artifacts"), hashHex.lowercase()) }

    private fun descriptorFile(id: String): File? =
        // Ids are catalog-controlled but still go through a filename-safe
        // encoding so a hostile or odd id cannot escape the directory.
        cacheDir?.let { File(File(it, "descriptors"), java.net.URLEncoder.encode(id, "UTF-8") + ".json") }

    /**
     * Removes a cached file. A file that is already absent is fine; one that exists and cannot be removed is logged (the file
     * name only, never contents): the cache is best effort, so this never fails the caller, but a stale copy that stays
     * must be visible.
     */
    private fun removeCached(file: File?) {
        if (file == null || !file.exists()) return
        if (!file.delete()) Timber.w("zk-circuit cache: could not remove ${file.name}")
    }

    private fun readCached(file: File?): ByteArray? =
        try {
            file?.takeIf { it.isFile }?.readBytes()
        } catch (e: Exception) {
            Timber.w(e, "zk-circuit cache read failed for ${file?.name}")
            null
        }

    /** Atomic: written beside the target and renamed, so a crash never leaves a truncated file to be trusted. */
    private fun writeCached(file: File?, bytes: ByteArray) {
        if (file == null) return
        try {
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, "${file.name}.tmp")
            tmp.writeBytes(bytes)
            if (!tmp.renameTo(file)) {
                tmp.delete()
                Timber.w("zk-circuit cache write could not move ${tmp.name} into place")
            }
        } catch (e: Exception) {
            Timber.w(e, "zk-circuit cache write failed for ${file.name}")
        }
    }

    private fun manifestUrl(source: String): String = "${source.trimEnd('/')}/v1/manifest.json"

    private fun circuitUrl(source: String, id: String): String = "${source.trimEnd('/')}/v1/circuits/$id.json"

    /** See [downloadArtifact]'s doc comment for the resolution rules this implements. */
    private fun candidateArtifactUrls(artifact: ZkArtifact): List<String> {
        val url = artifact.url
        if (url.startsWith("http://") || url.startsWith("https://")) {
            return listOf(url)
        }
        val path = if (url.isNotBlank()) url.removePrefix("/") else "v1/artifacts/sha256/${bareHex(artifact.hash)}"
        return sources.map { "${it.trimEnd('/')}/$path" }
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    /**
     * [ZkArtifact.hash]/[ZkUncompressed.hash] are wire-formatted as
     * `"sha256:<hex>"` (matching go-zk-circuits' own hash field convention),
     * but [sha256Hex] returns a bare hex digest with no prefix - comparing
     * the two directly without stripping this prefix always failed, even
     * for a byte-for-byte-correct download (confirmed live: "expected
     * sha256:44c4b98..., got 44c4b98..." - the same digest, just one side
     * prefixed). Strips it if present; leaves the string as-is otherwise, so
     * a legacy unprefixed hash value would still compare correctly too.
     */
    private fun bareHex(hash: String): String = hash.removePrefix("sha256:")

    // Throwable, not Exception: an OutOfMemoryError from a hostile body is a failed fetch, not a crash.
    // Cancellation is the one thing that must propagate.
    private suspend fun fetchRaw(url: String): String? {
        return try {
            val body = if (httpGet != null) httpGet.invoke(url) else fetchTextWithOkHttp(url)
            if (body != null && body.length > maxDescriptorBytes) {
                Timber.w("zk-circuit response from $url exceeds the $maxDescriptorBytes-byte limit; refused")
                null
            } else {
                body
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Throwable) {
            Timber.w(e, "zk-circuit fetch error from $url")
            null
        }
    }

    private suspend fun fetchBytes(url: String, limit: Long): ByteArray? {
        return try {
            val bytes = if (httpGetBytes != null) httpGetBytes.invoke(url) else fetchBytesWithOkHttp(url, limit)
            if (bytes != null && bytes.size.toLong() > limit) {
                Timber.w("zk-circuit artifact from $url exceeds its declared size; refused")
                null
            } else {
                bytes
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Throwable) {
            Timber.w(e, "zk-circuit artifact fetch error from $url")
            null
        }
    }

    private fun fetchTextWithOkHttp(url: String): String? {
        val request = Request.Builder().url(url).get().build()
        httpClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                Timber.w("zk-circuit fetch failed: ${response.code} from $url")
                return null
            }
            val body = response.body ?: return null
            val bytes = readBounded(body, maxDescriptorBytes.toLong()) ?: run {
                Timber.w("zk-circuit response from $url exceeds the $maxDescriptorBytes-byte limit; refused")
                return null
            }
            return bytes.toString(Charsets.UTF_8)
        }
    }

    /** At most [limit] bytes of [body], or null if it is longer: never reads the excess, whatever Content-Length says. */
    private fun readBounded(body: okhttp3.ResponseBody, limit: Long): ByteArray? {
        if (body.contentLength() > limit) return null
        val source = body.source()
        source.request(limit + 1)
        if (source.buffer.size > limit) return null
        return source.buffer.readByteArray()
    }

    private fun fetchBytesWithOkHttp(url: String, limit: Long): ByteArray? {
        val request = Request.Builder().url(url).get().build()
        httpClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                Timber.w("zk-circuit artifact fetch failed: ${response.code} from $url")
                return null
            }
            val body = response.body ?: return null
            return readBounded(body, limit).also {
                if (it == null) Timber.w("zk-circuit artifact from $url exceeds its declared size; refused")
            }
        }
    }
}
