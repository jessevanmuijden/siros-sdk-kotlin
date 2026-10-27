// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import org.siros.sdk.keystore.WscdPluginCapabilities
import timber.log.Timber

/**
 * How long a [WscdChoiceResult.Chosen] answer should be remembered, chosen by
 * the user alongside the plugin itself (see [WscdChoiceDialog] in the
 * sample app for the corresponding UI):
 * - [ONCE]: use the chosen plugin for this credential-issuance batch only -
 *   no persistence at all, the very next resolution for the same
 *   (issuer, credentialType) starts over from [WscdSelectionPolicy.resolve]'s
 *   top.
 * - [THIS_ISSUER]: persist via the existing per-(issuer, credentialType) TOFU
 *   mechanism - unchanged from this feature's original "always remember"
 *   behavior.
 * - [ALL_ISSUERS]: persist as the single global user override (see
 *   [WscdSelectionPolicy.setGlobalUserOverride]), which from then on wins for
 *   every (issuer, credentialType) pair that doesn't have a more specific
 *   per-(issuer, credentialType) user override set.
 */
enum class RememberScope { ONCE, THIS_ISSUER, ALL_ISSUERS }

/** The host app's answer to a [RequestWscdChoice] prompt. */
sealed interface WscdChoiceResult {
    /**
     * @param rememberScope defaults to [RememberScope.THIS_ISSUER], matching
     *   this feature's original behavior (every [Chosen] answer was persisted
     *   as a TOFU entry) for callers/tests that predate [RememberScope].
     */
    data class Chosen(val pluginId: String, val rememberScope: RememberScope = RememberScope.THIS_ISSUER) : WscdChoiceResult
    data object Cancelled : WscdChoiceResult
}

/**
 * Asks the host app to pick which registered WSCD plugin to use for an
 * upcoming credential-issuance key batch, when [WscdSelectionPolicy] can't
 * resolve it unambiguously on its own (see that class's doc comment for the
 * full resolution order this is one step of).
 *
 * Mirrors [org.siros.sdk.keystore.mdoc.RequestProximityConsent]'s shape
 * exactly: a suspending bridge to the host app's own UI, implemented by the
 * host app and supplied via [WalletConfig.requestWscdChoice].
 *
 * Only a plugin ID is returned, not a `KeystoreManager` instance - the SDK
 * already holds the concrete instance via [WalletConfig.availableKeystores],
 * since that map is how the host app registers what's available in the
 * first place.
 *
 * @param issuer the credential issuer identifier.
 * @param credentialType the credential type identifier (`vct` or mdoc
 *   `doctype`) about to be issued.
 * @param eligiblePluginIds every plugin ID whose static nominal tier (see
 *   [WscdPluginCapabilities]) meets the credential type's required tier
 *   (never empty or a singleton - [WscdSelectionPolicy] only invokes this
 *   when there's a genuine choice to make).
 */
typealias RequestWscdChoice = suspend (
    issuer: String,
    credentialType: String,
    eligiblePluginIds: List<String>,
) -> WscdChoiceResult

/**
 * Common supertype for every hard-failure [WscdSelectionPolicy.resolve] can
 * throw, so a caller (see `SirosWallet.requestBackendKeyAttestation`) can
 * catch/propagate both the same way: neither "zero eligible plugins" nor
 * "several eligible plugins but no way to pick one" may ever be treated as
 * "fall back to the default keystore" - both mean issuance must not silently
 * proceed against a plugin that doesn't meet the credential type's declared
 * requirement.
 */
sealed class WscdSelectionException(message: String) : Exception(message)

/**
 * Thrown by [WscdSelectionPolicy.resolve] when zero of the host app's
 * [WalletConfig.availableKeystores] entries have a static nominal tier
 * ([WscdPluginCapabilities]) meeting a credential type's declared
 * `requiredTier` - a distinct signal from "no requirement" (which resolves
 * to `null`, a no-op) so a caller can surface a clear "no available
 * authenticator meets this credential's requirement" error instead of
 * silently proceeding with an insufficient plugin.
 */
class NoEligibleWscdPluginException(
    val issuer: String,
    val credentialType: String,
    val requiredTier: String,
) : WscdSelectionException(
    "No available WSCD plugin meets required key-storage tier '$requiredTier' for issuer=$issuer credentialType=$credentialType"
)

/**
 * Thrown by `SirosWallet` when no WSCD able to serve the credential has been ONBOARDED (enrolled: a
 * token-backed plugin such as FIDO2 holds no enrolled key), or onboarding could not be determined,
 * which is treated the same. Raised BEFORE any PIN request: a PIN for a token nobody onboarded is
 * meaningless. Distinct from [NoEligibleWscdPluginException] (no registered plugin has a sufficient
 * tier): here a plugin of sufficient tier exists but none is onboarded. The message is suitable to
 * show the user.
 *
 * @param issuer null when the wallet was using its default keystore with no credential type in scope.
 * @param requiredTier null when the credential type declared no tier requirement.
 * @param pluginIds the plugins that were candidates and are not onboarded.
 */
class NoOnboardedWscdException(
    val issuer: String?,
    val credentialType: String?,
    val requiredTier: String?,
    val pluginIds: List<String>,
) : WscdSelectionException(
    "No applicable WSCD is available: none of $pluginIds has been onboarded" +
        (if (requiredTier != null) " for required key-storage tier '$requiredTier'" else "") +
        (if (issuer != null) " (issuer=$issuer credentialType=$credentialType)" else "")
)

/**
 * Issuance is refused because the credential type's required key-storage tier cannot be determined: a credential catalog is
 * configured ([WalletConfig.credentialTierCatalog]) and it does not list the type, could not be consulted, or a tier it (or the
 * issuer) states is not a known ISO 18045 tier. Nothing falls back to a weaker keystore.
 *
 * @param reason a short, fixed description (never a value from the issuer or the catalog).
 */
class KeyStorageTierUndeterminedException(
    val issuer: String?,
    val credentialType: String?,
    val reason: String,
) : WscdSelectionException(
    "The required key-storage tier cannot be determined ($reason)" +
        (if (issuer != null) " (issuer=$issuer credentialType=$credentialType)" else ""),
)

/**
 * Thrown by [WscdSelectionPolicy.resolve] when two or more of the host app's
 * registered plugins meet the credential type's declared `requiredTier`, but
 * there was no way to have the user pick which one: either no
 * [RequestWscdChoice] callback was configured at all, the user cancelled the
 * prompt, or the host app's callback answered with something outside the
 * offered [eligiblePluginIds] list. Distinct from [NoEligibleWscdPluginException]:
 * here at least one plugin WOULD be sufficient, so this is "ambiguous,
 * unresolved" rather than "nothing usable at all" - but the caller must treat
 * both the same way (never silently fall back to a possibly-insufficient
 * default keystore), since resolving the ambiguity is the entire point of
 * asking in the first place.
 */
class AmbiguousWscdPluginException(
    val issuer: String,
    val credentialType: String,
    val eligiblePluginIds: List<String>,
) : WscdSelectionException(
    "Multiple WSCD plugins ($eligiblePluginIds) meet the required key-storage tier for issuer=$issuer " +
        "credentialType=$credentialType, but no user choice was made to pick one"
)

/**
 * Trust-on-first-use persistence for [WscdSelectionPolicy]'s per-
 * (issuer, credentialType) plugin choice, so the host app/user is asked at
 * most once unless the persisted choice stops being sufficient for a
 * (possibly later, stricter) required tier. Abstracted behind an interface
 * so tests can supply an in-memory fake instead of an Android
 * `EncryptedSharedPreferences`-backed [SessionStore].
 */
interface WscdTofuStore {
    /** The persisted plugin ID for `"$issuer|$credentialType"`, or `null` if none yet. */
    fun get(issuer: String, credentialType: String): String?

    /** Persist `pluginId` as the TOFU choice for `"$issuer|$credentialType"`. */
    fun put(issuer: String, credentialType: String, pluginId: String)

    /**
     * Every persisted mapping, keyed by `"$issuer|$credentialType"` -> plugin
     * ID - for host-app settings UI that wants to show/clear the TOFU state
     * (see [WscdSelectionPolicy.tofuMapping]). Defaults to empty so existing
     * [WscdTofuStore] implementations (e.g. test fakes) don't have to
     * implement it just to keep compiling.
     */
    fun getAll(): Map<String, String> = emptyMap()

    /**
     * Remove the persisted mapping for `"$issuer|$credentialType"`, if any -
     * a "forget this choice" host-app affordance (see
     * [WscdSelectionPolicy.clearTofuMapping]). No-op by default.
     */
    fun remove(issuer: String, credentialType: String) {}

    /**
     * Remove every persisted mapping (see [WscdSelectionPolicy.clearAllTofuMappings]).
     * No-op by default.
     */
    fun clearAll() {}
}

/**
 * [WscdTofuStore] backed by [SessionStore.wscdTofuMappingJson] - the whole
 * mapping is kept as a single serialized `Map<String, String>` JSON blob
 * (matching [SessionStore.privateDataJwe]'s "one opaque string" precedent)
 * rather than one `SessionStore` property per (issuer, credentialType) pair,
 * since that set is open-ended and account-scoped storage already handles
 * multi-account isolation for us.
 */
internal class SessionStoreWscdTofuStore(private val sessionStore: SessionStore) : WscdTofuStore {
    private val json = Json { ignoreUnknownKeys = true }
    private val mapSerializer = MapSerializer(String.serializer(), String.serializer())

    private fun key(issuer: String, credentialType: String) = "$issuer|$credentialType"

    private fun readAll(): Map<String, String> {
        val raw = sessionStore.wscdTofuMappingJson ?: return emptyMap()
        return try {
            json.decodeFromString(mapSerializer, raw)
        } catch (e: Exception) {
            Timber.w(e, "Failed to decode WSCD TOFU mapping, treating as empty")
            emptyMap()
        }
    }

    override fun get(issuer: String, credentialType: String): String? = readAll()[key(issuer, credentialType)]

    // Read-modify-write on the whole JSON blob, so concurrent resolve() calls
    // for two different (issuer, credentialType) pairs (e.g. two credential
    // types being issued near-simultaneously) must be serialized here -
    // otherwise the second writer's readAll() can miss the first writer's
    // not-yet-visible update and clobber it (last writer wins, dropping an
    // entry). Locks on `sessionStore` itself (shared across every
    // [SessionStoreWscdTofuStore]/[SessionStoreWscdUserOverrideStore]
    // instance that wraps the same [SessionStore]) rather than `this`, since
    // a fresh store instance per call site would otherwise defeat the lock.
    override fun put(issuer: String, credentialType: String, pluginId: String) {
        synchronized(sessionStore) {
            val updated = readAll() + (key(issuer, credentialType) to pluginId)
            sessionStore.wscdTofuMappingJson = json.encodeToString(mapSerializer, updated)
        }
    }

    override fun getAll(): Map<String, String> = readAll()

    override fun remove(issuer: String, credentialType: String) {
        synchronized(sessionStore) {
            val updated = readAll() - key(issuer, credentialType)
            sessionStore.wscdTofuMappingJson = if (updated.isEmpty()) null else json.encodeToString(mapSerializer, updated)
        }
    }

    override fun clearAll() {
        synchronized(sessionStore) {
            sessionStore.wscdTofuMappingJson = null
        }
    }
}

/**
 * Persistence for [WscdSelectionPolicy]'s explicit, deliberate user
 * overrides - distinct from [WscdTofuStore], which is an auto-remembered
 * outcome of an *ambiguous* resolution the user (or [WscdSelectionPolicy]
 * itself) never explicitly asked to lock in. A user override always wins
 * over TOFU/[WalletConfig.defaultWscdMapping] (see [WscdSelectionPolicy.resolve]),
 * since it exists specifically to let a user raise the effective tier above
 * what a credential type actually requires - e.g. "always use my YubiKey for
 * this issuer/every issuer, even though software-key would suffice."
 *
 * Two independent scopes, both abstracted here since both are simple opaque
 * state a host-app settings UI wants to read/write:
 * - per-(issuer, credentialType): [get]/[put]/[getAll]/[remove]/[clearAll],
 *   same shape as [WscdTofuStore].
 * - global (every issuer/credential type not covered by a more specific
 *   per-(issuer, credentialType) override): [getGlobal]/[setGlobal]/[clearGlobal].
 */
interface WscdUserOverrideStore {
    /** The persisted user-override plugin ID for `"$issuer|$credentialType"`, or `null` if none set. */
    fun get(issuer: String, credentialType: String): String?

    /** Persist `pluginId` as the user override for `"$issuer|$credentialType"`. */
    fun put(issuer: String, credentialType: String, pluginId: String)

    /**
     * Every persisted per-(issuer, credentialType) user override, keyed by
     * `"$issuer|$credentialType"` -> plugin ID - for a host-app settings
     * screen (see [WscdSelectionPolicy.currentUserOverrides]). Defaults to
     * empty so existing implementations don't have to implement it just to
     * keep compiling.
     */
    fun getAll(): Map<String, String> = emptyMap()

    /** Remove the persisted user override for `"$issuer|$credentialType"`, if any. No-op by default. */
    fun remove(issuer: String, credentialType: String) {}

    /** Remove every persisted per-(issuer, credentialType) user override. No-op by default. */
    fun clearAll() {}

    /** The persisted single global user-override plugin ID, or `null` if none set. */
    fun getGlobal(): String?

    /** Persist `pluginId` as the global user override. */
    fun setGlobal(pluginId: String)

    /** Remove the persisted global user override, if any. No-op by default. */
    fun clearGlobal() {}
}

/**
 * [WscdUserOverrideStore] backed by [SessionStore.wscdUserOverrideMappingJson]
 * (per-(issuer, credentialType)) and [SessionStore.wscdGlobalOverridePluginId]
 * (global) - mirrors [SessionStoreWscdTofuStore]'s exact "one opaque JSON
 * blob" shape for the per-pair map, plus the same read-modify-write locking
 * fix (see [SessionStoreWscdTofuStore.put]'s doc comment) since it's the
 * identical class of bug.
 */
internal class SessionStoreWscdUserOverrideStore(private val sessionStore: SessionStore) : WscdUserOverrideStore {
    private val json = Json { ignoreUnknownKeys = true }
    private val mapSerializer = MapSerializer(String.serializer(), String.serializer())

    private fun key(issuer: String, credentialType: String) = "$issuer|$credentialType"

    private fun readAll(): Map<String, String> {
        val raw = sessionStore.wscdUserOverrideMappingJson ?: return emptyMap()
        return try {
            json.decodeFromString(mapSerializer, raw)
        } catch (e: Exception) {
            Timber.w(e, "Failed to decode WSCD user-override mapping, treating as empty")
            emptyMap()
        }
    }

    override fun get(issuer: String, credentialType: String): String? = readAll()[key(issuer, credentialType)]

    override fun put(issuer: String, credentialType: String, pluginId: String) {
        synchronized(sessionStore) {
            val updated = readAll() + (key(issuer, credentialType) to pluginId)
            sessionStore.wscdUserOverrideMappingJson = json.encodeToString(mapSerializer, updated)
        }
    }

    override fun getAll(): Map<String, String> = readAll()

    override fun remove(issuer: String, credentialType: String) {
        synchronized(sessionStore) {
            val updated = readAll() - key(issuer, credentialType)
            sessionStore.wscdUserOverrideMappingJson = if (updated.isEmpty()) null else json.encodeToString(mapSerializer, updated)
        }
    }

    override fun clearAll() {
        synchronized(sessionStore) {
            sessionStore.wscdUserOverrideMappingJson = null
        }
    }

    override fun getGlobal(): String? = sessionStore.wscdGlobalOverridePluginId

    override fun setGlobal(pluginId: String) {
        sessionStore.wscdGlobalOverridePluginId = pluginId
    }

    override fun clearGlobal() {
        sessionStore.wscdGlobalOverridePluginId = null
    }
}

/** No-op [WscdUserOverrideStore] for callers that don't wire up user-override persistence at all. */
private object NoopWscdUserOverrideStore : WscdUserOverrideStore {
    override fun get(issuer: String, credentialType: String): String? = null
    override fun put(issuer: String, credentialType: String, pluginId: String) {}
    override fun getGlobal(): String? = null
    override fun setGlobal(pluginId: String) {}
}

/**
 * Resolves which WSCD plugin should back key generation for one
 * credential-issuance key batch, given the credential type's declared
 * key-storage assurance requirement (`Vctm.requiredKeyStorage` /
 * `MddlSchema.requiredKeyStorage`, wire field `attestation_los`) and the set
 * of plugins the host app has actually registered
 * (`WalletConfig.availableKeystores`).
 *
 * **Phase 1 scope**: no changes to `siros-wscd-manager` (Rust/UniFFI) - no
 * live plugin enumeration, no live per-plugin capability query. Resolution
 * uses only [WscdPluginCapabilities]'s static table and picks among
 * `KeystoreManager` instances the host app has already constructed and
 * handed to the SDK via `availableKeystores` - never by asking the SDK to
 * build or mutate a plugin instance itself (only the host app can wire up
 * the platform transports real plugins like fido2/r2ps need).
 *
 * Resolution order for [resolve]:
 * 1. `requiredTier == null` (credential type declared no requirement) ->
 *    `null` (no-op: caller keeps using its existing default keystore).
 * 2. A [WscdUserOverrideStore]-persisted per-(issuer, credentialType) user
 *    override that's still available and still meets `requiredTier` -> use
 *    it. Deliberate, explicit user state (set via [setUserOverride], e.g.
 *    from a settings screen) - NOT written to TOFU, since it's already its
 *    own stable, separately-tracked preference.
 * 3. Else a [WscdUserOverrideStore]-persisted *global* user override (every
 *    issuer/credential type, [setGlobalUserOverride]) that's still available
 *    and still sufficient -> use it.
 * 4. A [WscdTofuStore]-persisted choice for (issuer, credentialType) that's
 *    still available and still meets `requiredTier` -> reuse it.
 * 5. [defaultMapping]'s entry for (issuer, credentialType), if available and
 *    sufficient -> persist as the new TOFU entry, return it.
 * 6. Exactly one plugin among `availablePluginIds` meets `requiredTier` ->
 *    persist as TOFU, return it. Otherwise, if [currentDefaultPluginId] (the
 *    plugin already active before this resolution) is itself among
 *    `availablePluginIds` and meets `requiredTier`, prefer it - avoids an
 *    unnecessary plugin switch when the current default is already good
 *    enough, even though other eligible plugins exist.
 * 7. More than one eligible plugin and the current default isn't one of
 *    them (or is unknown) -> ask the host app via [requestChoice]. A
 *    `Chosen` result is used according to its `rememberScope` (see
 *    [RememberScope]: [RememberScope.ONCE] persists nothing,
 *    [RememberScope.THIS_ISSUER] persists as TOFU,
 *    [RememberScope.ALL_ISSUERS] persists as the new global user override).
 *    `Cancelled`, no [requestChoice] callback configured at all, or a
 *    `Chosen` answer outside the offered eligible list, all throw
 *    [AmbiguousWscdPluginException] - unlike steps 1-6, there is no safe
 *    "no-op" here: silently falling back to the default keystore when
 *    several sufficient plugins exist but none was picked would defeat this
 *    whole feature's purpose.
 * 8. Zero eligible plugins -> [NoEligibleWscdPluginException], a distinct
 *    signal from every other branch above so the caller does NOT silently
 *    proceed with an insufficient plugin.
 */
class WscdSelectionPolicy(
    private val tofuStore: WscdTofuStore,
    private val defaultMapping: Map<String, String>? = null,
    private val requestChoice: RequestWscdChoice? = null,
    private val userOverrideStore: WscdUserOverrideStore = NoopWscdUserOverrideStore,
) {
    companion object {
        /**
         * Issuer placeholder meaning "any issuer" in [setUserOverride] and
         * `defaultMapping` entries (`"$WILDCARD_ISSUER|credentialType"`) -
         * lets a caller express "always use plugin X for credential type Y"
         * without enumerating every issuer that offers it. Checked in
         * [resolve] as a fallback when no issuer-specific entry matches.
         * Real-world need: TS11 registry discovery (see the sample app's
         * `Ts11CredentialDiscovery`) knows a credential *type* but has no
         * issuer of its own to key an entry by - this constant is what
         * makes those discovered mappings actually resolve, rather than
         * silently never matching any real issuance.
         */
        const val WILDCARD_ISSUER = "*"
    }

    /**
     * Every persisted TOFU mapping, keyed by `"issuer|credentialType"` ->
     * plugin ID - for a host-app settings screen to display (and, via
     * [clearTofuMapping]/[clearAllTofuMappings], let the user forget).
     */
    fun tofuMapping(): Map<String, String> = tofuStore.getAll()

    /**
     * Forget one persisted TOFU choice, so the next [resolve] call for that
     * (issuer, credentialType) pair re-evaluates from scratch (falling back
     * to [defaultMapping], auto-pick, or [requestChoice] again).
     */
    fun clearTofuMapping(issuer: String, credentialType: String) = tofuStore.remove(issuer, credentialType)

    /** Forget every persisted TOFU choice. */
    fun clearAllTofuMappings() = tofuStore.clearAll()

    /**
     * Explicitly set a per-(issuer, credentialType) user override -
     * distinct from TOFU: this is a deliberate, "always use this plugin for
     * this issuer/credential type" preference (typically a settings-screen
     * affordance, or "remember for this issuer" in [WscdChoiceDialog]-style
     * UI), not an auto-remembered outcome of an ambiguous resolution. Wins
     * over TOFU and [defaultMapping] in [resolve] as long as it remains
     * available and sufficient for the required tier.
     */
    fun setUserOverride(issuer: String, credentialType: String, pluginId: String) =
        userOverrideStore.put(issuer, credentialType, pluginId)

    /** Forget one persisted per-(issuer, credentialType) user override. */
    fun clearUserOverride(issuer: String, credentialType: String) = userOverrideStore.remove(issuer, credentialType)

    /**
     * Every persisted per-(issuer, credentialType) user override, keyed by
     * `"issuer|credentialType"` -> plugin ID - for a host-app settings
     * screen to display separately from [tofuMapping] (see that function's
     * doc comment for why the two are kept distinct).
     */
    fun currentUserOverrides(): Map<String, String> = userOverrideStore.getAll()

    /**
     * Explicitly set the single global user override - "always use this
     * plugin for every issuer/credential type", unless a more specific
     * per-(issuer, credentialType) [setUserOverride] is also set (which wins
     * first in [resolve]'s precedence).
     */
    fun setGlobalUserOverride(pluginId: String) = userOverrideStore.setGlobal(pluginId)

    /** Forget the persisted global user override, if any. */
    fun clearGlobalUserOverride() = userOverrideStore.clearGlobal()

    /** The persisted global user override, or `null` if none set. */
    fun currentGlobalUserOverride(): String? = userOverrideStore.getGlobal()

    suspend fun resolve(
        issuer: String,
        credentialType: String,
        requiredTier: String?,
        availablePluginIds: Set<String>,
        currentDefaultPluginId: String? = null,
    ): String? {
        // A null requiredTier (the credential's own VCTM/MDDL declares no
        // key-storage requirement at all - confirmed to happen with a real
        // demo issuer, wwwallet.org's PID) means there is nothing to
        // eligibility-gate a plugin against, so a plugin is trivially
        // "eligible" - it's up to steps 2/3 below (an explicit user choice)
        // whether to actually use one.
        fun isEligible(pluginId: String): Boolean {
            if (requiredTier == null) return true
            val tier = WscdPluginCapabilities.tierOf(pluginId) ?: return false
            return WscdPluginCapabilities.meets(tier, requiredTier)
        }

        // 2. Per-(issuer, credentialType) user override - checked exactly
        // like TOFU/defaultMapping below (must still be registered AND still
        // meet requiredTier, e.g. in case the requirement was raised since
        // the override was set, or the overridden plugin was unregistered) -
        // if either check fails, fall through to the rest of the chain
        // rather than erroring, since a stale override is not itself a hard
        // failure. Falls back to a WILDCARD_ISSUER entry (any issuer, this
        // credentialType) when no issuer-specific one matches. Deliberately
        // evaluated BEFORE the requiredTier==null short-circuit below: an
        // explicit user override ("always use this plugin", per
        // PreferredWscdCard's own UI copy) must apply "even for credentials
        // that don't require" a specific tier - a real bug found via live
        // testing, where a global override set for exactly this reason was
        // silently ignored because the null-tier check used to return early
        // before either user-override step ever ran.
        (userOverrideStore.get(issuer, credentialType) ?: userOverrideStore.get(WILDCARD_ISSUER, credentialType))?.let { override ->
            if (override in availablePluginIds && isEligible(override)) return override
        }

        // 3. Global user override, same validity checks and same rationale
        // for running before the requiredTier==null short-circuit.
        userOverrideStore.getGlobal()?.let { override ->
            if (override in availablePluginIds && isEligible(override)) return override
        }

        // No override matched, and there's no declared requirement to
        // satisfy - TOFU/default-mapping/auto-pick below all exist to
        // resolve an actual requirement (or its resulting ambiguity), which
        // doesn't apply here. Unlike the two override steps above, none of
        // these represent an explicit "use this regardless" user choice.
        if (requiredTier == null) return null

        // 4. TOFU.
        tofuStore.get(issuer, credentialType)?.let { persisted ->
            if (persisted in availablePluginIds && isEligible(persisted)) return persisted
        }

        // 5. Host-app default mapping. Falls back to a WILDCARD_ISSUER entry
        // the same way step 2 does, for the same reason.
        val mappingKey = "$issuer|$credentialType"
        val wildcardMappingKey = "$WILDCARD_ISSUER|$credentialType"
        (defaultMapping?.get(mappingKey) ?: defaultMapping?.get(wildcardMappingKey))?.let { mapped ->
            if (mapped in availablePluginIds && isEligible(mapped)) {
                tofuStore.put(issuer, credentialType, mapped)
                return mapped
            }
        }

        // 6/7/8. Compute eligibility over what's actually registered.
        val eligibleIds = availablePluginIds.filter { isEligible(it) }
        return when {
            eligibleIds.isEmpty() ->
                throw NoEligibleWscdPluginException(issuer, credentialType, requiredTier)

            eligibleIds.size == 1 ->
                eligibleIds.first().also { tofuStore.put(issuer, credentialType, it) }

            currentDefaultPluginId != null && currentDefaultPluginId in availablePluginIds && isEligible(currentDefaultPluginId) ->
                currentDefaultPluginId.also { tofuStore.put(issuer, credentialType, it) }

            else -> when (val choice = requestChoice?.invoke(issuer, credentialType, eligibleIds) ?: WscdChoiceResult.Cancelled) {
                is WscdChoiceResult.Chosen -> {
                    if (choice.pluginId !in eligibleIds) {
                        // Host app returned something outside the list it was
                        // offered - this is exactly as unresolved as a
                        // cancellation: an answer that wasn't actually one of
                        // the options offered can't be trusted to be
                        // sufficient, so it must not be silently used either.
                        Timber.w(
                            "RequestWscdChoice returned '${choice.pluginId}' which wasn't in the offered " +
                                "eligible list $eligibleIds for issuer=$issuer credentialType=$credentialType; ignoring"
                        )
                        throw AmbiguousWscdPluginException(issuer, credentialType, eligibleIds)
                    }
                    when (choice.rememberScope) {
                        RememberScope.ONCE -> { /* use for this call only, no persistence */ }
                        RememberScope.THIS_ISSUER -> tofuStore.put(issuer, credentialType, choice.pluginId)
                        RememberScope.ALL_ISSUERS -> userOverrideStore.setGlobal(choice.pluginId)
                    }
                    choice.pluginId
                }
                WscdChoiceResult.Cancelled -> throw AmbiguousWscdPluginException(issuer, credentialType, eligibleIds)
            }
        }
    }
}
