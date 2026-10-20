// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber

/**
 * Keeps the on-device circuit cache honest, in the background and without any UI: fetches the catalog manifest
 * and makes the cache match it. A circuit the manifest no longer lists as published, current and `active`
 * (deprecated, revoked, unpublished, or gone) is EXPUNGED, so it stops being usable as soon as a refresh sees it.
 *
 * Semantics (the Swift port should match them exactly):
 * - [refreshOnce] fetches `GET /v1/manifest.json` through [ZkCircuitClient.fetchManifest]. No manifest (every
 *   source failed, malformed, over the size limit) is [Result.Offline]: NOTHING is changed, no cached circuit is
 *   expunged and none is refreshed, and the wallet keeps proving with what it has cached. There is no age
 *   limit on that: an offline wallet may use a cached circuit until the first refresh that reaches the catalog
 *   (the proving path itself also asks the catalog first and uses the cache only when it cannot be reached).
 * - With a manifest: the ACTIVE circuits are those with `published`, no `deprecatedAt` and `status == "active"`.
 *   If `manifest.next` is null the manifest is COMPLETE and the cache is reduced to the active circuits
 *   ([ZkCircuitClient.retainOnly]): every cached or process-seen descriptor whose id is not an active id or alias,
 *   its descriptor files, and every cached artifact whose hash no active circuit uses, are deleted, and
 *   [onRetired] is called once per retired known descriptor (so resident prover memory and caches derived from
 *   its prover key are dropped). If `manifest.next` is set the manifest is a PARTIAL page: absence proves nothing,
 *   so only descriptors the page itself lists as not active are expunged.
 * - Every cached descriptor whose circuit is active is replaced by the manifest's copy, so a refreshed
 *   descriptor (new artifact hash) never leaves the old one in use.
 * - Fail-soft and bounded: it never throws (except cancellation), reads at most the client's body limit, and one
 *   refresh runs at a time ([refreshOnce] calls serialise on a lock). [launchIn] runs one refresh at once and then
 *   one every [intervalMillis]; [requestRefresh] (a connectivity change, say) refreshes now unless one finished
 *   less than [minGapMillis] ago.
 */
class ZkCircuitCatalogRefresher(
    private val client: ZkCircuitClient,
    /** Called for each retired circuit this client knew, after its cache is gone. Must not throw (a throw is logged). */
    private val onRetired: suspend (ZkCircuitDescriptor) -> Unit = {},
    /** Called with every manifest a refresh fetched, after the cache was reduced to it: the circuit table follows the catalog. Must not throw (a throw is logged). */
    private val onManifest: (ZkManifest) -> Unit = {},
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val intervalMillis: Long = DEFAULT_INTERVAL_MILLIS,
    private val minGapMillis: Long = DEFAULT_MIN_GAP_MILLIS,
) {
    /** The outcome of one refresh. */
    sealed interface Result {
        /** The catalog was reached. [retired] circuits were expunged, [refreshed] cached descriptors replaced. */
        data class Refreshed(val retired: List<ZkCircuitDescriptor>, val refreshed: Int, val complete: Boolean) : Result

        /** The catalog could not be reached: nothing was changed. */
        object Offline : Result

        /** Something else went wrong; nothing further was done. */
        object Failed : Result
    }

    private val lock = Mutex()
    @Volatile private var lastFinished = Long.MIN_VALUE

    /** One refresh, see the class doc. */
    suspend fun refreshOnce(): Result = lock.withLock {
        try {
            val manifest = client.fetchManifest()
            if (manifest == null) {
                Timber.i("circuit catalog refresh: catalog unreachable; the cache is left as it is")
                return@withLock Result.Offline
            }
            val complete = manifest.next == null
            val active = manifest.circuits.filter { it.isActive() }
            val retired = if (complete) {
                client.retainOnly(active)
            } else {
                // A partial page: only what it lists as not active is retired.
                val inactive = manifest.circuits.filter { !it.isActive() }
                val known = client.knownDescriptors()
                inactive.mapNotNull { known[it.id] ?: it.takeIf { d -> client.isArtifactCached(d) } }
                    .distinct().onEach { client.expunge(it) }
            }
            var refreshed = 0
            val known = client.knownDescriptors()
            for (d in active) {
                val idOrAlias = (listOf(d.id) + d.aliases)
                if (idOrAlias.any { it in known }) {
                    client.cacheDescriptor(d)
                    refreshed++
                }
            }
            retired.forEach { d ->
                try {
                    onRetired(d)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    Timber.w(e, "circuit catalog refresh: dropping resident state of '${d.id}' failed")
                }
            }
            try {
                onManifest(manifest)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                Timber.w(e, "circuit catalog refresh: updating the circuit table failed")
            }
            if (retired.isNotEmpty()) Timber.i("circuit catalog refresh: expunged ${retired.size} retired circuit(s)")
            Result.Refreshed(retired, refreshed, complete)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            Timber.w(e, "circuit catalog refresh failed")
            Result.Failed
        } finally {
            lastFinished = nowMillis()
        }
    }

    /** Refreshes now unless a refresh finished less than the minimum gap ago; returns null when skipped. */
    suspend fun requestRefresh(): Result? {
        val last = lastFinished
        if (last != Long.MIN_VALUE && nowMillis() - last in 0 until minGapMillis) return null
        return refreshOnce()
    }

    /** Refreshes at once and then every interval, until [scope] ends or the job is cancelled. */
    fun launchIn(scope: CoroutineScope): Job = scope.launch {
        while (isActive) {
            refreshOnce()
            delay(intervalMillis)
        }
    }

    companion object {
        /** Default refresh period: six hours. */
        const val DEFAULT_INTERVAL_MILLIS = 6L * 60 * 60 * 1000

        /** Default minimum gap for [requestRefresh]: thirty seconds. */
        const val DEFAULT_MIN_GAP_MILLIS = 30_000L
    }
}
