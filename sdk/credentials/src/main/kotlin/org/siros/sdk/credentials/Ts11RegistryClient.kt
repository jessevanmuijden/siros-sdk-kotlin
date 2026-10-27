// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import timber.log.Timber
import java.net.URI

/**
 * A single format-specific URI within a [Ts11SchemaMeta] entry, e.g. the
 * `sd-jwt` VCTM location or the `mso_mdoc` MDDL location for the same
 * logical credential type. Mirrors `TS11SchemaURI` in
 * `go-wallet-backend/internal/registry/fetcher.go`.
 */
@Serializable
data class Ts11SchemaUri(
    val formatIdentifier: String,
    val uri: String,
)

/**
 * Metadata for a single credential-type schema entry from a TS11 registry
 * (`registry.siros.org` or a compatible source), mirroring `TS11SchemaMeta`
 * in `go-wallet-backend/internal/registry/fetcher.go` field-for-field.
 *
 * @property id the schema's registry identifier (not necessarily the same
 *   as the credential's own `vct`/`doctype` - that authoritative identifier
 *   lives inside the fetched VCTM/MDDL document itself; see [VctmFetcher] /
 *   [MddlSchemaFetcher] for resolving the actual document once a
 *   [schemaURIs] entry is chosen).
 * @property attestationLoS the minimum key-storage assurance tier this
 *   credential type requires, in the same ISO 18045 vocabulary as
 *   [Vctm.requiredKeyStorage] / [MddlSchema.requiredKeyStorage]
 *   (`"iso_18045_basic"` / `"iso_18045_moderate"` / `"iso_18045_high"`).
 *   Exposed here, unparsed/uninterpreted, so a later caller can compare it
 *   against `org.siros.sdk.keystore.WscdPluginCapabilities`'s tier table -
 *   this class does not do that comparison itself.
 * @property bindingType the credential's key-binding mechanism (e.g.
 *   `"jwk"`, `"cose_key"`) as declared by the registry.
 * @property supportedFormats the credential formats this schema supports
 *   (e.g. `"dc+sd-jwt"`, `"mso_mdoc"`).
 * @property schemaURIs the format-specific document locations for this
 *   schema; empty when the registry hasn't published any yet.
 */
@Serializable
data class Ts11SchemaMeta(
    val id: String,
    val version: String? = null,
    val attestationLoS: String? = null,
    val bindingType: String? = null,
    val supportedFormats: List<String> = emptyList(),
    val schemaURIs: List<Ts11SchemaUri> = emptyList(),
    val rulebookURI: String? = null,
    val trustedAuthorities: List<String>? = null,
)

/** Every declaration of every registry source, unmerged, and whether all of it was read; see [Ts11RegistryClient.fetchAllDeclarations]. */
data class Ts11Declarations(val entries: List<Ts11SchemaMeta>, val complete: Boolean)

/**
 * Wire shape for the paginated `/api/v1/schemas.json` endpoint. Supports
 * both response formats it may return, mirroring `TS11SchemasResponse` in
 * the Go reference implementation:
 * - Current: `{"data": [...], "total": N, "limit": N, "offset": N}`
 * - Legacy: `{"schemas": [...], "next": "...", "total": N, "page": N, "pageSize": N}`
 */
@Serializable
private data class Ts11SchemasWireResponse(
    val schemas: List<Ts11SchemaMeta>? = null,
    val data: List<Ts11SchemaMeta>? = null,
    val total: Int = 0,
    val page: Int = 0,
    val pageSize: Int = 0,
    val limit: Int = 0,
    val offset: Int = 0,
    val next: String? = null,
) {
    /** Whichever schema array is populated ([data] takes precedence over [schemas]). */
    fun entries(): List<Ts11SchemaMeta> = if (!data.isNullOrEmpty()) data else (schemas ?: emptyList())

    /** True if there are additional pages to fetch, per either pagination style. */
    fun hasMorePages(): Boolean {
        if (!next.isNullOrEmpty()) return true
        if (limit > 0 && offset + entries().size < total) return true
        return false
    }
}

/** Wire shape for the non-paginated `/api/v1/registry.json` endpoint (all credentials, minimal metadata). */
@Serializable
private data class Ts11RegistryWireResponse(
    val total: Int = 0,
    val credentials: List<Ts11RegistryListEntry> = emptyList(),
)

@Serializable
private data class Ts11RegistryListEntry(
    val id: String,
    val version: String? = null,
    val supportedFormats: List<String> = emptyList(),
    val attestationLoS: String? = null,
    val bindingType: String? = null,
    val schemaURIs: List<Ts11SchemaUri>? = null,
)

/**
 * Queries a real TS11 credential-type registry (`registry.siros.org` by
 * default) directly, rather than going through go-wallet-backend's
 * `/type-metadata` proxy endpoint (which is a cache in front of this same
 * registry, not the registry itself - see [VctmFetcher] / [MddlSchemaFetcher]
 * for that proxy-based lookup path).
 *
 * Ports the discovery/pagination/format-detection logic from
 * `go-wallet-backend/internal/registry/fetcher.go`'s `Fetcher.Fetch` /
 * `fetchFromSource` / `processTS11Response` - the confirmed real reference
 * implementation - handling:
 * - the paginated current wire shape: `{"data": [...], "total", "limit", "offset"}`
 * - the legacy wire shape: `{"schemas": [...], "next"}`
 * - the non-paginated `/api/v1/registry.json` "all credentials" shape
 *   (used when a [sources] entry's URL already points at that file)
 *
 * following pagination on each source until exhausted.
 *
 * Supports multiple registry [sources], matching
 * `go-wallet-backend/configs/registry.yaml`'s `sources:` config concept for
 * future multi-registry deployments (defaults to a single entry,
 * [DEFAULT_REGISTRY_URL]). When more than one source is configured, entries
 * are merged by [Ts11SchemaMeta.id] with later sources overwriting earlier
 * ones - the same merge order `Fetcher.Fetch` uses for its `Sources` list.
 *
 * A source URL that already ends in `.json` (e.g. an explicit
 * `.../api/v1/registry.json`) is fetched as-is; otherwise `/api/v1/schemas.json`
 * is appended - mirrors `RemoteSourceConfig.resolveURL()`.
 *
 * KNOWN GAP (inherited from the Go reference implementation, not introduced
 * here): neither this client nor `fetcher.go` performs any JWS/signature
 * verification of the registry response. The response is trusted as-is once
 * fetched over TLS. Fixing this, if ever needed, is a separate, deliberate
 * change - not something to silently add here.
 *
 * Error handling matches this SDK's existing fetcher classes ([VctmFetcher],
 * [MddlSchemaFetcher]): failures (network errors, malformed JSON, non-200
 * responses) are logged and degrade gracefully rather than throwing - a
 * source that fails is skipped, and [fetchSchemas] returns whatever could be
 * gathered from the sources that succeeded (an empty list if all failed).
 *
 * @param sources base registry URLs to query, tried independently and
 *        merged (see class docs). Defaults to [DEFAULT_REGISTRY_URL].
 * @param httpGet optional HTTP GET function for custom HTTP clients. Takes
 *        a URL string, returns the response body string or null on failure.
 *        When null, uses `java.net.HttpURLConnection`.
 */
class Ts11RegistryClient(
    private val sources: List<String> = listOf(DEFAULT_REGISTRY_URL),
    private val httpGet: (suspend (String) -> String?)? = null,
) {
    private val json = Json { ignoreUnknownKeys = true }

    companion object {
        /** Default TS11 registry base URL. */
        const val DEFAULT_REGISTRY_URL = "https://registry.siros.org"

        // Safety valve against a misbehaving/malicious source looping
        // pagination forever (e.g. a "next" URL that always points back to
        // itself). Not present in the Go reference, which relies on Go's
        // context deadline for the equivalent protection - this SDK has no
        // such deadline plumbed through, so a hard page cap stands in for it.
        private const val MAX_PAGES = 1000
    }

    /**
     * Fetch the full schema list across all configured [sources], following
     * pagination on each source until exhausted. See the class docs for
     * merge order, format detection, and error-handling behavior.
     */
    suspend fun fetchSchemas(): List<Ts11SchemaMeta> = withContext(Dispatchers.IO) {
        val merged = linkedMapOf<String, Ts11SchemaMeta>()
        var anySucceeded = false

        for (source in sources) {
            val entries = fetchFromSource(source)
            if (entries != null) {
                anySucceeded = true
                for (entry in entries) merged[entry.id] = entry
            }
        }

        if (!anySucceeded && sources.isNotEmpty()) {
            Timber.w("All ${sources.size} TS11 registry source(s) failed; returning no schemas")
        }

        merged.values.toList()
    }

    private suspend fun fetchFromSource(source: String): List<Ts11SchemaMeta>? = fetchSourceDetailed(source)?.entries

    /** One source's entries, and whether every page of it was read (a page that failed or a page limit reached makes it incomplete). */
    private class SourceResult(val entries: List<Ts11SchemaMeta>, val complete: Boolean)

    private suspend fun fetchSourceDetailed(source: String): SourceResult? {
        val resolvedUrl = resolveUrl(source)
        Timber.d("Fetching TS11 registry source $resolvedUrl")
        val body = fetchRaw(resolvedUrl) ?: return null
        return try {
            parseAndPaginate(resolvedUrl, body)
        } catch (e: Exception) {
            Timber.w(e, "TS11 registry fetch failed for source $resolvedUrl")
            null
        }
    }

    /**
     * EVERY declaration of every source, as the registry published them: no merging by id (two declarations of one type stay two, so a
     * consumer that must be fail-closed can see both), and [Ts11Declarations.complete] says whether every source and every page of it was
     * read. A consumer must not treat an incomplete answer as the registry's state.
     */
    suspend fun fetchAllDeclarations(): Ts11Declarations = withContext(Dispatchers.IO) {
        val all = mutableListOf<Ts11SchemaMeta>()
        var complete = sources.isNotEmpty()
        for (source in sources) {
            val result = fetchSourceDetailed(source)
            if (result == null) {
                complete = false
            } else {
                all += result.entries
                if (!result.complete) complete = false
            }
        }
        Ts11Declarations(all, complete)
    }

    /** Mirrors `RemoteSourceConfig.resolveURL()`: an explicit `.json` URL is used as-is. */
    private fun resolveUrl(source: String): String {
        if (source.endsWith(".json")) return source
        return source.trimEnd('/') + "/api/v1/schemas.json"
    }

    private suspend fun parseAndPaginate(resolvedUrl: String, firstBody: String): SourceResult? {
        if (looksLikeAllCredentialsRegistryResponse(firstBody)) {
            val entries = parseRegistryResponse(resolvedUrl, firstBody) ?: return null
            // A response with fewer entries than it declares (`total`) is a PARTIAL registry: not complete.
            val declared = try {
                json.decodeFromString(Ts11RegistryWireResponse.serializer(), firstBody).total
            } catch (e: Exception) {
                0
            }
            return SourceResult(entries, complete = declared <= 0 || entries.size >= declared)
        }
        var complete = true

        val entries = mutableListOf<Ts11SchemaMeta>()
        var currentBody = firstBody
        var pageCount = 0

        while (true) {
            val page = try {
                // `{}` or an error object decodes with defaults: a page is a page only if it carries `data` or `schemas`.
                val obj = json.parseToJsonElement(currentBody).jsonObject
                require("data" in obj || "schemas" in obj) { "not a schemas page" }
                json.decodeFromString(Ts11SchemasWireResponse.serializer(), currentBody)
            } catch (e: Exception) {
                if (pageCount == 0) {
                    Timber.w(e, "Failed to parse TS11 schemas response from $resolvedUrl")
                    return null
                }
                Timber.w(e, "Failed to parse a subsequent TS11 schemas page from $resolvedUrl; stopping pagination")
                complete = false
                break
            }

            entries += page.entries()
            pageCount++

            if (!page.hasMorePages()) break
            if (pageCount >= MAX_PAGES) {
                complete = false
                break
            }

            val nextUrl = nextPageUrl(page, resolvedUrl)
            val nextBody = fetchRaw(nextUrl)
            if (nextBody == null) {
                Timber.w("Failed to fetch next page of TS11 schemas from $nextUrl; stopping pagination")
                complete = false
                break
            }
            currentBody = nextBody
        }

        return SourceResult(entries, complete)
    }

    /**
     * Detects the `/api/v1/registry.json` "all credentials" shape:
     * `{"credentials": [...], "total": N}` without the `data`/`schemas` keys
     * the paginated schemas.json shape uses - mirrors `fetchFromSource`'s
     * top-level-key format-detector in the Go reference.
     */
    private fun looksLikeAllCredentialsRegistryResponse(body: String): Boolean {
        return try {
            val obj = json.parseToJsonElement(body).jsonObject
            "credentials" in obj && "data" !in obj && "schemas" !in obj
        } catch (_: Exception) {
            false
        }
    }

    private fun parseRegistryResponse(resolvedUrl: String, body: String): List<Ts11SchemaMeta>? {
        return try {
            val resp = json.decodeFromString(Ts11RegistryWireResponse.serializer(), body)
            resp.credentials.map { entry ->
                Ts11SchemaMeta(
                    id = entry.id,
                    version = entry.version,
                    attestationLoS = entry.attestationLoS,
                    bindingType = entry.bindingType,
                    supportedFormats = entry.supportedFormats,
                    schemaURIs = entry.schemaURIs ?: emptyList(),
                )
            }
        } catch (e: Exception) {
            Timber.w(e, "Failed to parse TS11 registry.json response from $resolvedUrl")
            null
        }
    }

    /**
     * Mirrors `TS11SchemasResponse.NextPageURL()`: the legacy `next` field is
     * used directly when present; otherwise an offset-based URL is built
     * against [baseUrl] (the source's originally resolved URL, not the
     * previously fetched page's URL - matching the Go reference, which
     * always recomputes from the fixed base rather than accumulating).
     */
    private fun nextPageUrl(page: Ts11SchemasWireResponse, baseUrl: String): String {
        if (!page.next.isNullOrEmpty()) return page.next

        val nextOffset = page.offset + page.entries().size
        var clean = baseUrl
        val offsetIdx = clean.indexOf("offset=")
        if (offsetIdx > 0) {
            val ampIdx = clean.indexOf('&', offsetIdx)
            clean = if (ampIdx == -1) {
                clean.substring(0, offsetIdx - 1) // strip preceding '?' or '&'
            } else {
                clean.substring(0, offsetIdx) + clean.substring(ampIdx + 1)
            }
        }
        val sep = if (clean.contains("?")) "&" else "?"
        return "$clean${sep}offset=$nextOffset"
    }

    private suspend fun fetchRaw(url: String): String? {
        return try {
            if (httpGet != null) httpGet.invoke(url) else fetchWithUrlConnection(url)
        } catch (e: Exception) {
            Timber.w(e, "TS11 registry fetch error from $url")
            null
        }
    }

    private fun fetchWithUrlConnection(url: String): String? {
        val connection = URI(url).toURL().openConnection() as java.net.HttpURLConnection
        connection.requestMethod = "GET"
        connection.connectTimeout = 10_000
        connection.readTimeout = 10_000
        connection.setRequestProperty("Accept", "application/json")
        return try {
            if (connection.responseCode != 200) {
                Timber.w("TS11 registry fetch failed: ${connection.responseCode} from $url")
                null
            } else {
                connection.inputStream.bufferedReader().use { it.readText() }
            }
        } finally {
            connection.disconnect()
        }
    }
}
