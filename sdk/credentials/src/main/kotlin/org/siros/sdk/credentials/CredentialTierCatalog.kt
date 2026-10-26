// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber

/** What the credential catalog says about the key-storage tier of one credential type. */
sealed interface CatalogTier {
    /** The catalog lists the type with this ISO 18045 tier (`iso_18045_basic` / `_moderate` / `_high`). */
    data class Known(val tier: String) : CatalogTier

    /** The catalog is reachable but does not list the type, or lists it without a tier. */
    object NotListed : CatalogTier

    /** The catalog could not be consulted (no usable answer, and nothing fresh enough cached). */
    object Unavailable : CatalogTier
}

/**
 * The credential catalog's answer to "what key-storage tier does this credential type require": the BASELINE the wallet applies at
 * issuance; the issuer's own metadata may only raise it (see `WalletConfig.credentialTierCatalog`).
 */
fun interface CredentialTierCatalog {
    /** The tier for [credentialType] (a `vct` or an mdoc doctype). Never throws: a failure is [CatalogTier.Unavailable]. */
    suspend fun tierFor(credentialType: String): CatalogTier
}

/**
 * A [CredentialTierCatalog] over the TS11 registry ([Ts11CredentialDiscovery]): one fetch builds a map keyed by each type's real
 * identifier (vct / doctype) and by its registry schema id, then answers from it. The snapshot is refreshed after [ttlMillis]
 * (single flight); when a refresh fails the last good snapshot is served until it is [maxStaleMillis] old, after which the answer is
 * [CatalogTier.Unavailable] - a stale catalog is never trusted indefinitely (a tier raised since could be hidden).
 */
class Ts11CredentialTierCatalog(
    private val discovery: Ts11CredentialDiscovery = Ts11CredentialDiscovery(),
    private val ttlMillis: Long = 60 * 60 * 1000L,
    private val maxStaleMillis: Long = 24 * 60 * 60 * 1000L,
    private val clock: () -> Long = System::currentTimeMillis,
) : CredentialTierCatalog {
    private class Snapshot(val at: Long, val tiers: Map<String, String?>)

    private val lock = Mutex()
    private var snapshot: Snapshot? = null

    override suspend fun tierFor(credentialType: String): CatalogTier {
        val current = lock.withLock {
            val now = clock()
            val held = snapshot
            if (held == null || now - held.at >= ttlMillis) {
                val fresh = refresh(now)
                if (fresh != null) snapshot = fresh
            }
            snapshot?.takeIf { clock() - it.at < maxStaleMillis }
        } ?: return CatalogTier.Unavailable
        if (!current.tiers.containsKey(credentialType)) return CatalogTier.NotListed
        val tier = current.tiers[credentialType]
        return if (tier.isNullOrBlank()) CatalogTier.NotListed else CatalogTier.Known(tier)
    }

    private suspend fun refresh(now: Long): Snapshot? {
        val discovered = try {
            discovery.discover()
        } catch (e: Exception) {
            Timber.w("credential tier catalog refresh failed (${e.javaClass.simpleName})")
            return null
        }
        // An empty answer is what a failed fetch of every source looks like: it never replaces a good snapshot.
        if (discovered.isEmpty()) return null
        val tiers = HashMap<String, String?>()
        for (d in discovered) {
            val tier = d.schema.attestationLoS
            // The most demanding tier wins when two entries describe the same type.
            fun put(key: String) {
                val old = tiers[key]
                tiers[key] = when {
                    tier == null -> old
                    old == null -> tier
                    WscdTierOrder.rank(tier) > WscdTierOrder.rank(old) -> tier
                    else -> old
                }
            }
            put(d.identifier)
            put(d.schema.id)
        }
        return Snapshot(now, tiers)
    }
}

/** The ISO 18045 tier order, lowest first; the same vocabulary as `Vctm.requiredKeyStorage` and `Ts11SchemaMeta.attestationLoS`. */
object WscdTierOrder {
    val ORDER: List<String> = listOf("iso_18045_basic", "iso_18045_moderate", "iso_18045_high")

    /** The tier's position (higher = stronger), or -1 for a string that is not a known tier. */
    fun rank(tier: String): Int = ORDER.indexOf(tier)
}
