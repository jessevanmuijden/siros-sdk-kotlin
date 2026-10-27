// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.net.URI

/**
 * A single [Ts11RegistryClient]-discovered credential type, enriched with a
 * real display identity - see [Ts11CredentialDiscovery] for how [identifier]/
 * [name]/[description] are resolved.
 *
 * @property schema the original registry entry, unchanged - still needed for
 *   [Ts11SchemaMeta.attestationLoS]/[Ts11SchemaMeta.supportedFormats] tier
 *   filtering (see `WscdPluginCapabilities`), which this class does not
 *   duplicate.
 * @property identifier the credential type's own `vct` (SD-JWT VC) or
 *   `doctype` (mdoc) identifier, resolved from the schema document at one of
 *   [Ts11SchemaMeta.schemaURIs] - the same identifier space
 *   `WscdSelectionPolicy`'s `"issuer|credentialType"` mapping keys already
 *   use elsewhere in this app. Falls back to the registry's own opaque
 *   [Ts11SchemaMeta.id] when no document could be fetched/parsed - this is
 *   the "UUID instead of a real name" gap this class exists to close, but a
 *   registry UUID is still a better fallback than nothing.
 * @property name human-readable display name, when resolved. `null` when
 *   enrichment failed (network error, unparseable document, no recognized
 *   format in [Ts11SchemaMeta.schemaURIs]) - callers should fall back to
 *   [identifier] for display in that case (see [displayName]).
 * @property description human-readable description, when resolved.
 */
data class Ts11DiscoveredCredential(
    val schema: Ts11SchemaMeta,
    val identifier: String,
    val name: String? = null,
    val description: String? = null,
) {
    /** Best available label for display: the resolved [name], else [identifier]. */
    val displayName: String get() = name ?: identifier
}

/**
 * Resolves each [Ts11RegistryClient]-discovered [Ts11SchemaMeta]'s real
 * display identity (`vct`/`doctype` + `name`/`description`), since neither
 * `/api/v1/schemas.json` nor `/api/v1/registry.json` carries a human name or
 * description at the list level - confirmed against the real reference
 * implementation, `go-wallet-backend/internal/registry/fetcher.go`. The
 * ONLY place that identity exists is inside the actual schema document each
 * [Ts11SchemaMeta.schemaURIs] entry points to - mirrors `fetcher.go`'s
 * `fetchSchemaDocument`/`parseDocumentHeader` pattern: for each
 * [Ts11SchemaMeta.schemaURIs] entry, fetch the document, parse out its own
 * `vct`/`doctype`/`name`/`description`, falling back to the raw
 * [Ts11SchemaMeta.id] only if the fetch/parse fails.
 *
 * Picks which [Ts11SchemaMeta.schemaURIs] entry to fetch by
 * [Ts11SchemaUri.formatIdentifier]: anything containing `"sd-jwt"` is parsed
 * as a [VctmFetcher]-shaped document (SD-JWT VC Type Metadata); anything
 * containing `"mso_mdoc"` is parsed as an [MddlSchemaFetcher]-shaped
 * document (mdoc MDDL schema, using `display?.firstOrNull()` for its
 * name/description - [MddlSchema] itself has no top-level name/description).
 * A schema with neither format in its [Ts11SchemaMeta.schemaURIs] - or one
 * whose fetch/parse fails - degrades gracefully to the raw [Ts11SchemaMeta.id]
 * (see [Ts11DiscoveredCredential]'s doc comment), exactly like `fetcher.go`:
 * one bad entry never throws or blocks the rest of the discovery list.
 *
 * Deliberately does its own raw HTTP GET of the chosen [Ts11SchemaUri.uri]
 * (same `java.net.HttpURLConnection` pattern [Ts11RegistryClient]/
 * [VctmFetcher]/[MddlSchemaFetcher] each already use) rather than calling
 * [VctmFetcher.fetch]/[MddlSchemaFetcher.fetch]: those methods resolve a
 * document from an *issuer's* URL via their own issuer-direct/well-known/
 * registry-proxy strategies, which don't apply here - a [Ts11SchemaUri.uri]
 * is already the exact document location, so it's fetched as-is and parsed
 * with [VctmFetcher.parseVctm]/[MddlSchemaFetcher.parseMddlSchema] (reusing
 * those fetchers' existing parsing logic and [Vctm]/[MddlSchema] types,
 * rather than re-declaring another copy of either shape here).
 *
 * @param registryClient supplies the raw discovered schema list.
 * @param vctmFetcher used only for its [VctmFetcher.parseVctm] parsing (its
 *        own [VctmFetcher.fetch] issuer-resolution strategies are unused here).
 * @param mddlSchemaFetcher used only for its [MddlSchemaFetcher.parseMddlSchema]
 *        parsing (same rationale as [vctmFetcher]).
 * @param httpGet optional HTTP GET function for custom HTTP clients/tests.
 *        Takes a URL string, returns the response body string or null on
 *        failure. When null, uses `java.net.HttpURLConnection`.
 */
class Ts11CredentialDiscovery(
    private val registryClient: Ts11RegistryClient = Ts11RegistryClient(),
    private val vctmFetcher: VctmFetcher = VctmFetcher(),
    private val mddlSchemaFetcher: MddlSchemaFetcher = MddlSchemaFetcher(),
    private val httpGet: (suspend (String) -> String?)? = null,
) {

    /** Fetch the schema list and enrich every entry - see class docs for resolution/fallback order. */
    suspend fun discover(): List<Ts11DiscoveredCredential> = withContext(Dispatchers.IO) {
        registryClient.fetchSchemas().map { schema -> enrich(schema) }
    }

    /** What [discoverAll] found: one entry per (declaration, identity), and whether everything was read ([complete]). */
    class Result(val credentials: List<Ts11DiscoveredCredential>, val complete: Boolean)

    /**
     * Every declaration (duplicates kept) with EVERY identity it states: an entry with both an SD-JWT and an mdoc schema URI yields its
     * `vct` AND its `doctype`. Incomplete (`complete == false`) when a registry page or source, or a schema document, could not be
     * read: the identities that could not be resolved still appear under the entry's registry id, but a caller must not take an
     * incomplete answer as the state of the registry.
     */
    suspend fun discoverAll(): Result = withContext(Dispatchers.IO) {
        val declarations = registryClient.fetchAllDeclarations()
        var complete = declarations.complete
        val found = mutableListOf<Ts11DiscoveredCredential>()
        for (schema in declarations.entries) {
            var identified = false
            for (format in listOf("sd-jwt", "mso_mdoc")) {
                val uri = schema.schemaURIs.firstOrNull { it.formatIdentifier.contains(format, ignoreCase = true) } ?: continue
                val body = fetchDocument(uri.uri)
                if (body == null) {
                    complete = false
                    continue
                }
                if (format == "sd-jwt") {
                    vctmFetcher.parseVctm(body)?.let { vctm ->
                        found += Ts11DiscoveredCredential(schema, vctm.vct, vctm.name, vctm.description)
                        identified = true
                    } ?: run { complete = false }
                } else {
                    mddlSchemaFetcher.parseMddlSchema(body)?.let { mddl ->
                        val display = mddl.display?.firstOrNull()
                        found += Ts11DiscoveredCredential(schema, mddl.doctype, display?.name, display?.description)
                        identified = true
                    } ?: run { complete = false }
                }
            }
            if (!identified) found += Ts11DiscoveredCredential(schema, identifier = schema.id)
        }
        Result(found, complete)
    }

    private suspend fun enrich(schema: Ts11SchemaMeta): Ts11DiscoveredCredential {
        val sdJwtUri = schema.schemaURIs.firstOrNull { it.formatIdentifier.contains("sd-jwt", ignoreCase = true) }
        if (sdJwtUri != null) {
            fetchDocument(sdJwtUri.uri)?.let { body ->
                vctmFetcher.parseVctm(body)?.let { vctm ->
                    return Ts11DiscoveredCredential(schema, vctm.vct, vctm.name, vctm.description)
                }
            }
        }

        val mdocUri = schema.schemaURIs.firstOrNull { it.formatIdentifier.contains("mso_mdoc", ignoreCase = true) }
        if (mdocUri != null) {
            fetchDocument(mdocUri.uri)?.let { body ->
                mddlSchemaFetcher.parseMddlSchema(body)?.let { mddl ->
                    val display = mddl.display?.firstOrNull()
                    return Ts11DiscoveredCredential(schema, mddl.doctype, display?.name, display?.description)
                }
            }
        }

        // Graceful fallback (see class docs): no recognized format in
        // schemaURIs, or the fetch/parse of a recognized one failed.
        Timber.d("TS11 schema ${schema.id}: no display identity resolved, falling back to raw id")
        return Ts11DiscoveredCredential(schema, identifier = schema.id)
    }

    private suspend fun fetchDocument(url: String): String? {
        return try {
            if (httpGet != null) httpGet.invoke(url) else fetchWithUrlConnection(url)
        } catch (e: Exception) {
            Timber.w(e, "TS11 schema document fetch failed for $url")
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
                Timber.w("TS11 schema document fetch failed: ${connection.responseCode} from $url")
                null
            } else {
                connection.inputStream.bufferedReader().use { it.readText() }
            }
        } finally {
            connection.disconnect()
        }
    }
}
