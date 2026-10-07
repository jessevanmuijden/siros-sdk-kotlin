// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.VctmFetcher
import timber.log.Timber

/**
 * The production [TransactionMetadataSource]: type metadata through the SDK's
 * [VctmFetcher] strategies (registry, issuer endpoint, well-known path) and
 * referenced documents through [SafeDocumentFetcher].
 *
 * Every network hop of this path is bounded, unlike the wallet's display
 * metadata path: the registry (the wallet's own, configured backend) is read
 * through [registryGet], which the caller bounds; every other URL (an issuer's
 * or verifier's choice) goes through [fetcher] (HTTPS only, public addresses
 * only, no redirects, size cap, time limit, nothing of the app's attached).
 * This instance has no persistent cache.
 *
 * The type metadata is used only if it is the document the credential's
 * `vct#integrity` pins (when it pins one; a present but malformed pin refuses)
 * and if it describes the credential's own `vct`.
 *
 * @param registryGet fetches a URL under [registryUrl] (adding the wallet's own
 *   headers) with a bounded read; `null` on any failure.
 */
internal class VctmTransactionMetadataSource(
    private val registryUrl: String,
    private val registryGet: suspend (String) -> String?,
    private val fetcher: SafeDocumentFetcher = SafeDocumentFetcher(),
) : TransactionMetadataSource {

    private val registryBase = registryUrl.trimEnd('/')

    private val vctmFetcher = VctmFetcher(
        httpGet = { url -> if (url.startsWith(registryBase)) registryGet(url) else fetcher.get(url) },
        cacheTtlSeconds = MEMORY_TTL_SECONDS,
    )

    override suspend fun typeMetadata(credential: StoredCredential): JsonObject? {
        val payload = CredentialUtils.parseJwtPayload(credential.raw) ?: return null
        val vct = (payload["vct"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        val pinnedElement = payload["vct#integrity"]
        val pinned = when {
            pinnedElement == null -> null
            pinnedElement is JsonPrimitive && pinnedElement.isString -> pinnedElement.content
            else -> {
                Timber.w("vct#integrity is present but not a string; refusing")
                return null
            }
        }
        val document = try {
            vctmFetcher.fetchDocument(
                issuerUrl = credential.credentialIssuerIdentifier.orEmpty(),
                scope = credential.credentialConfigurationId.orEmpty(),
                vct = vct,
                registryUrl = registryUrl,
                // The fetcher only returns a document hashing to this.
                expectedIntegrity = pinned,
            )
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.w("Type metadata lookup failed (${e.javaClass.simpleName})")
            null
        } ?: return null
        if (document.vctm.vct != vct) {
            Timber.w("Type metadata does not describe the credential's type")
            return null
        }
        return try {
            Json.parseToJsonElement(document.raw) as? JsonObject
        } catch (_: Exception) {
            null
        }
    }

    override suspend fun document(uri: String): String? = fetcher.get(uri)

    companion object {
        private const val MEMORY_TTL_SECONDS = 300L
    }
}
