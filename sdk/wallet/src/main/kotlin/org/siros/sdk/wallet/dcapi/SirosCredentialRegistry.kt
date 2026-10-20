// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.credentials.registry.digitalcredentials.openid4vp.OpenId4VpRegistry
import androidx.credentials.registry.provider.ClearCredentialRegistryRequest
import androidx.credentials.registry.provider.RegistryManager
import androidx.credentials.registry.provider.digitalcredentials.DigitalCredentialRegistry
import com.google.android.gms.identitycredentials.ClearRegistryRequest
import com.google.android.gms.identitycredentials.IdentityCredentialManager
import com.google.android.gms.identitycredentials.RegistrationRequest
import com.google.android.gms.tasks.Task
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.StoredCredential
import timber.log.Timber
import uniffi.siros_dc_matcher_ffi.FfiCapability
import uniffi.siros_dc_matcher_ffi.FfiClaim
import uniffi.siros_dc_matcher_ffi.FfiCredential
import uniffi.siros_dc_matcher_ffi.SirosBlobBuilder

/**
 * Registers this wallet's credentials with the OS credential picker, using a
 * matcher the SDK supplies rather than the one AndroidX ships.
 *
 * The matcher is the WebAssembly module the platform runs inside the picker to
 * decide which credentials to offer. AndroidX's `OpenId4VpRegistry` supplies
 * Google's build, which understands `mso_mdoc` and `dc+sd-jwt` and nothing
 * else - so a verifier asking for `mso_mdoc_zk` gets no entry at all and the
 * ZK presentation path is unreachable from a browser.
 *
 * Swapping it is public API rather than a workaround: [DigitalCredentialRegistry]
 * takes the matcher as a plain `ByteArray`.
 *
 * ## Why this lives in the SDK
 *
 * Registration, blob building and matching are wallet logic that every
 * consumer needs. They lived in the sample app while the swap was being
 * proven; keeping them there would have made every wallet reimplement the one
 * part where a mistake is invisible - a blob the matcher cannot read looks
 * exactly like having no matching credential.
 *
 * ## One artifact, one version
 *
 * The encoder and `matcher.wasm` both come from the `siros-dc-matcher` AAR.
 * Pairing an encoder with a matcher that predates it produces a wallet that
 * matches nothing and reports nothing, so they are deliberately not separable.
 *
 * ## Icons
 *
 * Every entry carries an icon, because the picker host silently drops an
 * entry whose icon is null or empty - learned on a device, not from docs.
 * The floor is a solid tile in the card's colour; when the issuer's logo has
 * been fetched and rendered by [PickerIconCache] that is used instead. The
 * cache is only ever *read* during registration, so registering never waits
 * on the network; missing icons are fetched afterwards in the background
 * and, if any land, the snapshot is registered once more so the picker
 * picks them up (see [fetchMissingIconsThenReregister]).
 */
object SirosCredentialRegistry {

    /** Matches the `intentAction` the wallet's DC API activity declares. */
    const val REGISTRY_ID = "org.siros.sdk.wallet.dcapi.registry"

    /** `credential_format` of an ISO mdoc, the only format with an MSO to parse. */
    private const val MDOC_FORMAT = "mso_mdoc"

    /** Asset path of the matcher, shipped inside the `siros-dc-matcher` AAR. */
    private const val MATCHER_ASSET = "matcher.wasm"

    /**
     * Where background icon fetches run. Process-lifetime, like this object;
     * a SupervisorJob so one failed download can't cancel its siblings.
     */
    private val iconScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** One background icon sweep at a time; a second [refresh] while one runs doesn't stack another. */
    private val iconFetchInFlight = AtomicBoolean(false)

    /**
     * The most recent [refresh] request, or null if the last one cleared the
     * registry. A background icon sweep re-registers *this*, never the
     * snapshot it was started from: a credential may have been added or
     * deleted while the logos downloaded, and re-registering the older set
     * would resurrect it in the picker.
     */
    private val latestRequest = AtomicReference<RefreshRequest?>(null)

    private class RefreshRequest(
        val credentials: List<StoredCredential>,
        val zkSystems: List<ZkSystem>,
        val useStockMatcher: Boolean,
        val claimlessDoctypes: Set<String> = emptySet(),
        val circuitZkCircuits: List<CircuitZkCircuit> = emptyList(),
    )

    /**
     * The pre-standardization Credential Manager type string.
     *
     * [DigitalCredentialRegistry] (via [RegistryManager]) registers under
     * `androidx.credentials.TYPE_DIGITAL_CREDENTIAL` only. multipaz's
     * wallet-side registry code (`DigitalCredentialsExt.android.kt`) and
     * animo's `expo-digital-credentials-api` both register the identical
     * database a second time under this older string via the raw GMS client,
     * for browsers whose dispatch still keys off it. [refresh] does the same;
     * it costs one extra call and reaches whatever still looks here.
     */
    private const val LEGACY_TYPE = "com.credman.IdentityCredential"

    /**
     * Replace the registered snapshot with [credentials].
     *
     * Registration is a whole-snapshot replace rather than an incremental
     * update, so call this whenever the credential set materially changes.
     * An empty set clears the registry: a wallet with nothing to offer should
     * not appear in the picker at all.
     *
     * @param claimlessDoctypes The document types served through `circuit_zk`
     *   (see [SirosWallet.circuitZkDocTypes]): their credentials are registered
     *   with no claims, because they are answered with a proof, never with
     *   claim values. Empty by default.
     * @param circuitZkCircuits The circuits this wallet can prove `circuit_zk`
     *   requests with (see [SirosWallet.circuitZkCircuits]). Each is registered
     *   with the matcher, so the picker shows `circuit_zk` rows and honours the
     *   verifier's circuit lists. Empty by default: such a request then matches
     *   nothing.
     */
    suspend fun refresh(
        context: Context,
        credentials: List<StoredCredential>,
        zkSystems: List<ZkSystem> = emptyList(),
        useStockMatcher: Boolean = false,
        claimlessDoctypes: Set<String> = emptySet(),
        circuitZkCircuits: List<CircuitZkCircuit> = emptyList(),
    ) {
        if (credentials.isEmpty()) {
            clear(context)
            return
        }
        latestRequest.set(RefreshRequest(credentials, zkSystems, useStockMatcher, claimlessDoctypes, circuitZkCircuits))
        try {
            if (useStockMatcher) {
                registerWithStockMatcher(context, credentials)
                return
            }
            val iconCache = PickerIconCache(context)
            // File reads only (PickerIconCache hops to IO itself); no network here.
            val icons = cachedIcons(iconCache, credentials)
            val blob = buildBlob(credentials, zkSystems, icons, debug = context.isDebuggable(), claimlessDoctypes = claimlessDoctypes, circuitZkCircuits = circuitZkCircuits)
            val matcher = context.assets.open(MATCHER_ASSET).use { it.readBytes() }
            RegistryManager.create(context).registerCredentials(
                SirosRegistry(credentials = blob, matcher = matcher),
            )
            registerLegacyType(context, blob, matcher)
            Timber.d(
                "DC API registry updated: ${credentials.size} credentials, ${icons.size} with logo icons, " +
                    "${blob.size}-byte blob",
            )
            fetchMissingIconsThenReregister(context.applicationContext, iconCache, credentials, icons)
        } catch (e: Exception) {
            // Registration failing must never break the rest of the app - on a
            // device without DC API support it simply means these credentials
            // are not offered through the browser.
            Timber.w(e, "Failed to register DC API credentials")
        }
    }

    /**
     * Register the same blob and matcher again under [LEGACY_TYPE], via the
     * raw GMS client rather than [RegistryManager].
     *
     * Best-effort and additive: the [RegistryManager] registration above is
     * the one every current API surface documents, and this is not meant to
     * replace it - only to also reach whatever still dispatches on the old
     * type string, the way multipaz's independently-working implementation
     * does. A failure here must not affect the primary registration, so it
     * is caught and logged rather than propagated.
     *
     * Awaited, not fire-and-forget: [refresh] and [clear] run back to back on
     * login and logout, and a registration still in flight when the next call
     * starts could land after the clear that was meant to remove it.
     */
    private suspend fun registerLegacyType(context: Context, blob: ByteArray, matcher: ByteArray) {
        try {
            IdentityCredentialManager.getClient(context)
                .registerCredentials(
                    RegistrationRequest(
                        credentials = blob,
                        matcher = matcher,
                        type = LEGACY_TYPE,
                        requestType = "",
                        protocolTypes = emptyList(),
                    ),
                )
                .await()
            Timber.d("DC API legacy-type registration succeeded")
        } catch (e: Exception) {
            Timber.w(e, "Failed to register DC API credentials under the legacy type")
        }
    }

    /**
     * Register through AndroidX's matcher instead of ours.
     *
     * Kept reachable deliberately. The platform accepting a wallet-supplied
     * matcher is confirmed on hardware, but it is not ours to guarantee, and
     * the cost of keeping a way back is one function. It understands
     * `mso_mdoc` and `dc+sd-jwt` only - a `mso_mdoc_zk` request produces no
     * entry on this path, which is the whole reason the other one exists.
     */
    private suspend fun registerWithStockMatcher(
        context: Context,
        credentials: List<StoredCredential>,
    ) {
        val entries = StockEntryBuilder.buildEntries(credentials)
        if (entries.isEmpty()) {
            clear(context)
            return
        }
        RegistryManager.create(context).registerCredentials(
            OpenId4VpRegistry(
                credentialEntries = entries,
                id = REGISTRY_ID,
                supportedProtocols = listOf(
                    OpenId4VpRegistry.PROTOCOL_OPENID4VP_1_0_SIGNED,
                    OpenId4VpRegistry.PROTOCOL_OPENID4VP_1_0_MULTISIGNED,
                    OpenId4VpRegistry.PROTOCOL_OPENID4VP_1_0_UNSIGNED,
                ),
            ),
        )
        Timber.d("DC API registry updated via the stock matcher (${entries.size} entries)")
    }

    /** Every credential's on-disk rendered logo icon, keyed by credential id. Reads files only. */
    private suspend fun cachedIcons(
        iconCache: PickerIconCache,
        credentials: List<StoredCredential>,
    ): Map<Long, ByteArray> = buildMap {
        credentials.forEach { cred ->
            val metadata = cred.metadata ?: return@forEach
            val url = metadata.logo?.uri ?: return@forEach
            iconCache.cached(url, metadata.backgroundColor)?.let { put(cred.id, it) }
        }
    }

    /**
     * After a registration went out with placeholders for some entries, try
     * to fetch those logos in the background and, if any landed, register
     * the *latest* snapshot once more so the picker picks them up.
     *
     * Bounded: [PickerIconCache.isDue] skips URLs with a current negative
     * entry, so a dead or SVG logo costs one download per backoff interval,
     * not one per registration. The re-registration's own sweep only starts
     * if it still finds icons that are missing and due - which, for the
     * snapshot just swept, it won't; for a newer snapshot that arrived
     * mid-sweep (and was refused a sweep of its own by [iconFetchInFlight])
     * it will, which is how that snapshot's logos get their turn.
     */
    private fun fetchMissingIconsThenReregister(
        appContext: Context,
        iconCache: PickerIconCache,
        credentials: List<StoredCredential>,
        alreadyCached: Map<Long, ByteArray>,
    ) {
        val missing = credentials
            .filter { it.id !in alreadyCached && it.metadata?.logo?.uri != null }
            .distinctBy { PickerIconCache.key(it.metadata!!.logo!!.uri!!, it.metadata!!.backgroundColor) }
        if (missing.isEmpty()) return
        if (!iconFetchInFlight.compareAndSet(false, true)) return
        iconScope.launch {
            var landed = 0
            try {
                for (cred in missing) {
                    val url = cred.metadata?.logo?.uri ?: continue
                    val colour = cred.metadata?.backgroundColor
                    if (!iconCache.isDue(url, colour)) continue
                    if (iconCache.fetchAndStore(url, colour) != null) landed++
                }
            } catch (e: Exception) {
                Timber.w(e, "Background picker-icon fetch failed")
            } finally {
                iconFetchInFlight.set(false)
            }
            if (landed == 0) return@launch
            val latest = latestRequest.get() ?: run {
                // The registry was cleared while we downloaded (logout). The
                // icons are on disk for whichever registration comes next.
                Timber.d("Picker icons landed ($landed) but the registry was cleared; not re-registering")
                return@launch
            }
            Timber.i("Re-registering DC API credentials with $landed newly rendered logo icon(s)")
            refresh(appContext, latest.credentials, latest.zkSystems, latest.useStockMatcher, latest.claimlessDoctypes, latest.circuitZkCircuits)
        }
    }

    /**
     * Remove this wallet's entries from the picker.
     *
     * Clears both registrations [refresh] makes: the [RegistryManager] one
     * and the [LEGACY_TYPE] one made through the raw GMS client. The AndroidX
     * clear does not reach the latter, so without the second call a wallet
     * that logged out would keep offering its last snapshot under the legacy
     * type until it next logged in.
     *
     * Also forgets the last snapshot, so a background icon sweep that
     * finishes after this does not put it straight back. That has to happen
     * here and not only in [refresh]'s empty-list path: this is public, and
     * logout calls it directly.
     */
    suspend fun clear(context: Context) {
        latestRequest.set(null)
        try {
            RegistryManager.create(context)
                .clearCredentialRegistry(ClearCredentialRegistryRequest(true))
        } catch (e: Exception) {
            Timber.w(e, "Failed to clear DC API credential registry")
        }
        try {
            IdentityCredentialManager.getClient(context)
                .clearRegistry(ClearRegistryRequest())
                .await()
        } catch (e: Exception) {
            Timber.w(e, "Failed to clear DC API legacy-type registry")
        }
    }

    /**
     * Suspend until a Play Services [Task] completes, surfacing failure as an
     * exception. Same shape as `PlayIntegrityProvider`, kept private here
     * rather than shared because a module-wide Task bridge would pull the GMS
     * Tasks API into every module's surface for two call sites.
     *
     * A [Task] cannot be cancelled, so cancellation of the caller only stops
     * it from being resumed; the request itself still reaches the host.
     */
    private suspend fun <T> Task<T>.await(): T = suspendCancellableCoroutine { continuation ->
        addOnCompleteListener { task ->
            if (!continuation.isActive) return@addOnCompleteListener
            val error = task.exception
            when {
                task.isCanceled -> continuation.cancel()
                error != null -> continuation.resumeWithException(error)
                else -> continuation.resume(task.result)
            }
        }
    }

    /**
     * A zero-knowledge proof system this wallet can actually produce.
     *
     * [params] is optional, and the choice is a real one.
     *
     * Supply parameters only for a system whose circuits this wallet knows
     * ahead of time. They are then enforced: a request naming the right
     * [system] with a different `num_attributes` will not be offered, because
     * a ZK circuit is built for a fixed attribute count and the proof could
     * not be produced.
     *
     * Leave them empty for a system that supports any shape and only
     * discovers at proof time whether a specific circuit is available - which
     * is how [org.siros.sdk.credentials.ZkProofSystem.matchingSpec] is
     * defined, and why this SDK's own systems register with no parameters.
     * Declaring a count such a system cannot honour would refuse requests it
     * can in fact satisfy.
     *
     * A parameter neither side names is not a constraint.
     */
    data class ZkSystem(val system: String, val params: Map<String, String>)

    /**
     * The matcher capabilities that register [circuit]: one per id the circuit
     * answers to (its id, then each alias), because the matcher compares a
     * verifier's `system_id_values` with one registered `system_id` and knows
     * nothing of aliases. `functions` is declared only when the catalog says
     * which functions the circuit supports; a circuit that declares none is
     * not filtered by function. `credential_type` and `capabilities` are
     * registered when the circuit carries them, as given: the matcher reads
     * them, the SDK does not.
     */
    internal fun circuitCapabilities(circuit: CircuitZkCircuit): List<FfiCapability> =
        org.siros.sdk.credentials.SharedCircuitZkServing.capabilities(circuit)

    /**
     * Encode the blob to register.
     *
     * Built by the Rust encoder rather than assembled here: the matcher reads
     * this with the decoder from the same artifact, and a second hand-written
     * encoder is exactly the kind of thing that drifts silently.
     */
    internal fun buildBlob(
        credentials: List<StoredCredential>,
        zkSystems: List<ZkSystem>,
        icons: Map<Long, ByteArray> = emptyMap(),
        debug: Boolean = false,
        claimlessDoctypes: Set<String> = emptySet(),
        circuitZkCircuits: List<CircuitZkCircuit> = emptyList(),
    ): ByteArray {
        // `use`, not a bare call: the builder holds a native handle, and
        // leaving it to the Cleaner means the handle survives until a GC that
        // may never come under memory pressure. Registration runs on every
        // credential change, so a leak here accumulates.
        return SirosBlobBuilder().use { builder -> buildWith(builder, credentials, zkSystems, icons, debug, claimlessDoctypes, circuitZkCircuits) }
    }

    private fun buildWith(
        builder: SirosBlobBuilder,
        credentials: List<StoredCredential>,
        zkSystems: List<ZkSystem>,
        icons: Map<Long, ByteArray>,
        debug: Boolean,
        claimlessDoctypes: Set<String>,
        circuitZkCircuits: List<CircuitZkCircuit>,
    ): ByteArray {
        // With this on, a request that matches nothing gets one picker entry
        // naming why (see the matcher's `Diagnostics`). Only ever for a
        // debuggable build: an end user cannot act on "not satisfiable", and
        // selecting the entry hands this wallet a credential id that does not
        // exist.
        builder.setDebug(debug)
        zkSystems.forEach { builder.addZkSystem(FfiCapability(it.system, it.params)) }
        circuitZkCircuits.forEach { circuit -> circuitCapabilities(circuit).forEach(builder::addZkpReqSystem) }

        credentials.forEach { cred ->
            val iconId = cred.id.toString()
            // Never null, never empty: the host drops such entries outright.
            // A rendered logo when the cache has one, the colour tile if not.
            val icon = icons[cred.id]?.takeIf { it.isNotEmpty() } ?: placeholderIcon(cred)
            builder.addIcon(iconId, icon)
            builder.addCredential(
                FfiCredential(
                    id = cred.id.toString(),
                    format = cred.format,
                    doctype = docTypeFor(cred),
                    // The credential's own vct, not the metadata copy - the
                    // OS picker matches on this, and a credential whose
                    // metadata has not been built yet would otherwise be
                    // registered with no type at all and match nothing.
                    vct = CredentialUtils.vctOf(cred),
                    title = cred.metadata?.name ?: cred.format,
                    subtitle = cred.metadata?.issuer?.name ?: "",
                    iconId = iconId,
                    // A type served through circuit_zk is answered with a proof, never
                    // with claims, so it registers none.
                    claims = if (CredentialUtils.isOfDocTypes(cred, claimlessDoctypes)) emptyList() else CredentialUtils.extractClaims(cred).map { claim ->
                        FfiClaim(
                            // A list, not a dotted string. ISO mdoc namespaces
                            // contain dots themselves (org.iso.18013.5.1), so
                            // flattening and re-splitting mis-parses every one
                            // of them - splitting on the LAST dot is what makes
                            // "org.iso.18013.5.1.family_name" come back as the
                            // namespace and element it actually is.
                            path = splitClaimKey(cred.format, claim.key),
                            value = claim.value,
                            display = claim.label,
                            // Only when it differs. Repeating the value here
                            // would put every claim value in the registered
                            // blob twice, for a string the matcher would
                            // render identically.
                            displayValue = null,
                        )
                    },
                ),
            )
        }
        return builder.build()
    }

    /**
     * The docType a registry entry carries.
     *
     * For an mdoc this is read from the credential's own MSO rather than from
     * issuer metadata, which is only populated when the issuer happens to
     * expose a SIROS-internal schema endpoint. A standards-conformant
     * third-party issuer has no reason to, and relying on it leaves every such
     * credential unmatchable while looking perfectly valid.
     *
     * Only an mdoc has an MSO, though. An SD-JWT's raw value is a compact
     * serialization, and its `.` separators are not base64url, so handing it
     * to [CredentialUtils.parseMdocDocument] throws - caught there, but logged
     * at warn with a full stack trace, once per SD-JWT credential per refresh,
     * and the registry refreshes on every credential change and every flow.
     * The guard lives here rather than inside `parseMdocDocument` because that
     * warning is worth keeping for a *genuine* mdoc that fails to parse.
     */
    internal fun docTypeFor(cred: StoredCredential): String? =
        if (cred.format.equals(MDOC_FORMAT, ignoreCase = true)) {
            CredentialUtils.parseMdocDocument(cred)?.docType ?: cred.metadata?.doctype
        } else {
            cred.metadata?.doctype
        }

    /**
     * Split a display-claim key into the path components DCQL matches against.
     *
     * mdoc element identifiers never contain dots while namespaces routinely
     * do, so the split is on the last one. JSON-based credentials keep the key
     * whole - their claim keys are not dotted paths.
     */
    internal fun splitClaimKey(format: String, key: String): List<String> =
        if (format.equals(MDOC_FORMAT, ignoreCase = true) && key.contains('.')) {
            listOf(key.substringBeforeLast('.'), key.substringAfterLast('.'))
        } else {
            listOf(key)
        }

    /**
     * A flat card-coloured placeholder - the floor for every entry.
     *
     * Used whenever [PickerIconCache] has no rendered logo yet (first
     * registration, logo not yet downloaded, logo is an SVG this SDK can't
     * rasterise, or the URL is dead). Showing nothing is not an option: the
     * picker drops iconless entries.
     */
    private fun placeholderIcon(cred: StoredCredential): ByteArray =
        PickerIconRenderer.placeholder(cred.metadata?.backgroundColor)

    private fun Context.isDebuggable(): Boolean =
        applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    /** The registration request itself. */
    private class SirosRegistry(credentials: ByteArray, matcher: ByteArray) :
        DigitalCredentialRegistry(
            id = REGISTRY_ID,
            credentials = credentials,
            matcher = matcher,
        )
}
