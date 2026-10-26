package org.siros.sdk.keystore

import timber.log.Timber
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import org.siros.sdk.credentials.CertificationInfo
import org.siros.sdk.credentials.SignerSecurityProperties
import uniffi.siros_wscd_manager.FfiActivateLifecycleRequest
import uniffi.siros_wscd_manager.FfiActivationOutcome
import uniffi.siros_wscd_manager.FfiAlgorithm
import uniffi.siros_wscd_manager.FfiAuthCallback
import uniffi.siros_wscd_manager.FfiCertificationLevel
import uniffi.siros_wscd_manager.FfiDestroyLifecycleRequest
import uniffi.siros_wscd_manager.FfiDestroyMode
import uniffi.siros_wscd_manager.FfiDestructionOutcome
import uniffi.siros_wscd_manager.FfiFactorKind
import uniffi.siros_wscd_manager.FfiGeneratedKey
import uniffi.siros_wscd_manager.FfiHttpTransport
import uniffi.siros_wscd_manager.FfiKeyStorageType
import uniffi.siros_wscd_manager.FfiLifecycleState
import uniffi.siros_wscd_manager.FfiLifecycleStatus
import uniffi.siros_wscd_manager.FfiMigrationResult
import uniffi.siros_wscd_manager.FfiOperationProgress
import uniffi.siros_wscd_manager.FfiProgressCallback
import uniffi.siros_wscd_manager.FfiCtap2Transport
import uniffi.siros_wscd_manager.FfiR2psConfig
import uniffi.siros_wscd_manager.FfiRegisterLifecycleRequest
import uniffi.siros_wscd_manager.FfiRegistrationOutcome
import uniffi.siros_wscd_manager.FfiRotateLifecycleRequest
import uniffi.siros_wscd_manager.FfiRotationOutcome
import uniffi.siros_wscd_manager.FfiWscdConfig
import uniffi.siros_wscd_manager.FfiWscdException
import uniffi.siros_wscd_manager.FfiWscdManager

/**
 * The manager's name for a BLS12-381 Schnorr key-binding key
 * (`Algorithm::as_str` in siros-wscd-manager), used as the SDK-side
 * algorithm string since JOSE has none for it.
 */
internal const val BLS12381_G1_SCHNORR_NAME: String = "EcsdsaBls12381Bp1Sha256Sec1"

/**
 * [UniFFISigner] wraps the Rust `siros-wscd-manager` UniFFI bindings
 * into the SDK's [Signer] interface.
 *
 * This enables the native SDK to use any WSCD plugin (softkey, R2PS,
 * FIDO2) through the same interface used by the software [JweKeystore].
 *
 * @param config WSCD manager configuration.
 * @param authProvider Callback invoked when user authentication is needed
 *   (e.g. PIN entry for R2PS signing). If null, auth callbacks will throw.
 */
class UniFFISigner(
    config: FfiWscdConfig,
    private val authProvider: AuthProvider? = null,
) : Signer, WscdManager {

    private val ffi: FfiWscdManager = FfiWscdManager(config)

    private companion object {
        /** Plugins whose keys live on a token the user must onboard (enroll) before use. */
        val ONBOARDED_KEY_PLUGIN_IDS = setOf("fido2")
    }

    /**
     * Which plugin this instance was constructed to back by default (e.g.
     * "softkey", "fido2", "r2ps"). Every instance also self-registers a
     * softkey plugin in [init] regardless of this value (see there), but
     * the softkey private-key export/import round-trip (below) must only
     * ever run for the instance that IS actually the softkey plugin - see
     * [exportPrivateKeypairs]'s doc comment for why.
     */
    private val defaultPluginId: String = config.defaultPlugin

    /** Map of key ID → JWK JSON bytes, populated during generateKey. */
    private val publicKeyCache = mutableMapOf<String, ByteArray>()

    init {
        ffi.registerSoftkeyPlugin()
    }

    override fun registerR2psPlugin(config: R2psConfig, transport: R2psTransportProvider) {
        val authMode = config.authMode
        val ffiConfig = FfiR2psConfig(
            serverUrl = config.serverUrl,
            clientId = config.clientId,
            context = config.context,
            authMode = if (authMode is R2psAuthMode.WebAuthn) "webauthn" else "opaque",
            rpId = (authMode as? R2psAuthMode.WebAuthn)?.rpId ?: "",
            allowedCredentialIds = (authMode as? R2psAuthMode.WebAuthn)?.allowedCredentialIds ?: emptyList(),
            clientKeyPem = config.clientKeyPem,
            serverPublicKeyPem = config.serverPublicKeyPem,
        )
        ffi.registerR2psPlugin(ffiConfig, R2psTransportBridge(transport))
    }


    override fun registerFido2Plugin(transport: Ctap2TransportProvider) {
        ffi.registerFido2Plugin(Ctap2TransportBridge(transport))
    }

    override fun registerFido2PluginWithState(transport: Ctap2TransportProvider, state: ByteArray) {
        ffi.registerFido2PluginWithState(Ctap2TransportBridge(transport), state)
    }

    /**
     * Onboarding is the plugin holding at least one enrolled key: enrolling a token generates its
     * first key, restoring from synced state (`registerFido2PluginWithState`) brings the keys back,
     * and destroying the lifecycle removes them. A token plugin that is not registered, holds no
     * key, or cannot be queried is not onboarded (fail closed).
     */
    override suspend fun isWscdOnboarded(): Boolean {
        if (defaultPluginId !in ONBOARDED_KEY_PLUGIN_IDS) return true
        return try {
            withContext(Dispatchers.IO) { ffi.listKeys().any { it.pluginId == defaultPluginId } }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
    }

    override fun exportFido2State(): ByteArray = ffi.exportFido2State()

    override suspend fun generateKey(algorithm: String): String = withContext(Dispatchers.IO) {
        val ffiAlgorithm = algorithm.toFfiAlgorithm()
        val result: FfiGeneratedKey = withPinAuth { auth ->
            ffi.generateKey(ffiAlgorithm, auth, noOpProgress())
        }
        publicKeyCache[result.kid] = result.publicKeyJwk.toByteArray(Charsets.UTF_8)
        result.kid
    }

    override suspend fun sign(keyId: String, data: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        val result = withPinAuth { auth ->
            ffi.sign(
                keyId,
                data,
                FfiAlgorithm.ES256, // algorithm is inferred from the key by the manager
                auth,
                noOpProgress(),
            )
        }
        result.data
    }

    private val factorSigning: FactorSigning by lazy {
        FactorSigning(
            object : FactorSigningBackend {
                override fun capability(kid: String) = ffi.authenticationCapability(kid)
                override fun pluginIdOf(kid: String): String? =
                    ffi.listKeys().firstOrNull { it.kid == kid }?.pluginId
                override fun signWithFactors(
                    kid: String,
                    data: ByteArray,
                    options: uniffi.siros_wscd_manager.FfiSignOptions,
                    auth: FfiAuthCallback,
                ) = ffi.signWithFactors(kid, data, FfiAlgorithm.ES256, options, auth, noOpProgress())
            },
            authCallbackBridge(),
            canAskForPin = authProvider != null,
        )
    }

    override suspend fun scaAuthenticationCapability(keyId: String): ScaAuthenticationCapability =
        withContext(Dispatchers.IO) { factorSigning.capability(keyId) }

    override suspend fun beginScaSign(keyId: String): ScaSignSession {
        // The session may hold a PIN typed ahead of the sign. If the caller is cancelled
        // after it was acquired on the IO dispatcher, withContext throws and the session
        // never reaches the caller, so it is closed here rather than left holding the PIN.
        var acquired: ScaSignSession? = null
        var handedOver = false
        try {
            val session = withContext(Dispatchers.IO) {
                factorSigning.begin(keyId).also { acquired = it }
            }
            handedOver = true
            return object : ScaSignSession by session {
                override suspend fun sign(data: ByteArray): ScaSignature =
                    withContext(Dispatchers.IO) { session.sign(data) }
            }
        } finally {
            if (!handedOver) acquired?.close()
        }
    }

    override suspend fun listKeys(): List<SignerKeyInfo> = withContext(Dispatchers.IO) {
        ffi.listKeys().map { keyInfo ->
            SignerKeyInfo(
                keyId = keyInfo.kid,
                algorithm = keyInfo.algorithm.toSdkAlgorithm(),
            )
        }
    }

    /**
     * The softkey plugin only ever holds its keys in Rust-process memory
     * (see [FfiWscdManager.exportSoftkeyContainer]'s doc comment) - this
     * bulk-exports them (raw `d` scalar + kid + algorithm) and pairs each
     * with its cached public JWK half (from [generateKey] or a prior
     * [importPrivateKeypairs] call) to produce full, spec-compliant private
     * JWKs the caller can fold into privatedata's `S.keypairs`.
     *
     * A key with no cached public half (impossible in practice - every key
     * this signer knows about got there via [generateKey] or
     * [importPrivateKeypairs], both of which populate the cache) is skipped
     * rather than failing the whole export.
     *
     * No-op (matches [Signer.exportPrivateKeypairs]'s documented default)
     * unless [defaultPluginId] is "softkey" - found via live hardware
     * testing: every instance also registers its own internal softkey
     * plugin regardless of [defaultPluginId] (see [init]), so without this
     * guard a fido2- or r2ps-default instance would export/import THAT
     * internal softkey copy too, even though it isn't the one actually
     * meant to carry the wallet's persisted softkey material.
     */
    override suspend fun exportPrivateKeypairs(): List<ExportedPrivateKeypair> = withContext(Dispatchers.IO) {
        if (defaultPluginId != "softkey") return@withContext emptyList()
        // The container's top level is an OBJECT ({"keys": [...], "lifecycle":
        // {...}}, per SoftkeyPlugin's Rust-side ContainerData), not a bare
        // array - confirmed live via a diagnostic log of the raw bytes. Every
        // key was previously silently dropped here (the `as? JsonArray` cast
        // of the whole object always failed, falling through to emptyList()),
        // meaning a softkey-plugin credential's key never actually survived
        // into privatedata's S.keypairs despite generateKey() succeeding -
        // the credential looked "shadow" (no available key) on the very next
        // app restart, 100% of the time.
        val container = Json.parseToJsonElement(
            String(ffi.exportSoftkeyContainer(), Charsets.UTF_8)
        ) as? JsonObject ?: return@withContext emptyList()
        val rawKeys = container["keys"] as? JsonArray ?: return@withContext emptyList()

        rawKeys.mapNotNull { element ->
            val obj = element as? JsonObject ?: return@mapNotNull null
            val kid = obj["kid"]?.let { (it as? JsonPrimitive)?.contentOrNull } ?: return@mapNotNull null
            val algorithm = obj["algorithm"]?.let { (it as? JsonPrimitive)?.contentOrNull } ?: return@mapNotNull null
            val d = obj["d"]?.let { (it as? JsonPrimitive)?.contentOrNull } ?: return@mapNotNull null
            val cachedPublicJwk = publicKeyCache[kid] ?: return@mapNotNull null
            val publicJwk = Json.parseToJsonElement(
                String(cachedPublicJwk, Charsets.UTF_8)
            ) as? JsonObject ?: return@mapNotNull null

            val privateJwk = buildJsonObject {
                publicJwk.forEach { (key, value) -> put(key, value) }
                put("d", JsonPrimitive(d))
                put("kid", JsonPrimitive(kid))
            }
            ExportedPrivateKeypair(keyId = kid, algorithm = algorithm, privateJwk = privateJwk.toString())
        }
    }

    /**
     * Restores keys previously returned by [exportPrivateKeypairs] into the
     * softkey plugin, so they survive this signer's own process restarting
     * (see that method's doc comment). Must be called before any
     * [generateKey] call in this session -
     * [FfiWscdManager.importSoftkeyContainer] replaces the whole softkey
     * plugin registration, so calling it after keys already exist in this
     * session would discard them.
     *
     * Also re-populates [publicKeyCache] for each restored key (from the
     * JWK's own public parameters) so a later [exportPrivateKeypairs] call
     * in this same session can still find it - it didn't go through
     * [generateKey], which is the only other path that populates the cache.
     *
     * No-op unless [defaultPluginId] is "softkey" - see
     * [exportPrivateKeypairs]'s doc comment for why. Found via live
     * hardware testing: without this guard, unlocking a fido2-default
     * instance imported the wallet's softkey key(s) into that instance's
     * own internal softkey plugin, which then got wrongly picked up by
     * [WscdKeystoreAdapter.generateProof]'s "reuse any existing key" logic
     * instead of a real fido2 key, and failed to sign at all (the imported
     * copy was reachable via [listKeys] but not by the underlying signing
     * call - "Signing failed" with no PIN prompt, since the wrong key/plugin
     * combination never got that far).
     */
    override suspend fun importPrivateKeypairs(keypairs: List<ExportedPrivateKeypair>) = withContext(Dispatchers.IO) {
        if (defaultPluginId != "softkey" || keypairs.isEmpty()) return@withContext

        val rawKeys = buildJsonArray {
            keypairs.forEach { kp ->
                val jwk = Json.parseToJsonElement(kp.privateJwk) as JsonObject
                val d = jwk["d"]?.let { (it as? JsonPrimitive)?.contentOrNull }
                    ?: throw IllegalArgumentException("Keypair ${kp.keyId} has no 'd' (private scalar)")

                add(buildJsonObject {
                    put("kid", JsonPrimitive(kp.keyId))
                    put("algorithm", JsonPrimitive(kp.algorithm))
                    put("d", JsonPrimitive(d))
                    put("created_at", JsonPrimitive(0L))
                })

                val publicOnlyJwk = buildJsonObject {
                    jwk.forEach { (key, value) -> if (key != "d") put(key, value) }
                }
                publicKeyCache[kp.keyId] = publicOnlyJwk.toString().toByteArray(Charsets.UTF_8)
            }
        }
        ffi.importSoftkeyContainer(rawKeys.toString().toByteArray(Charsets.UTF_8))
    }

    /**
     * List keys with plugin and creation metadata.
     * Intended for developer/diagnostic UIs — not part of the [Signer] interface.
     */
    suspend fun listKeysDetailed(): List<DetailedKeyInfo> = withContext(Dispatchers.IO) {
        ffi.listKeys().map { keyInfo ->
            DetailedKeyInfo(
                keyId = keyInfo.kid,
                algorithm = keyInfo.algorithm.toSdkAlgorithm(),
                pluginId = keyInfo.pluginId,
                // Rust's created_at is Unix seconds, not millis - see
                // toSdkLifecycleStatus's identical conversion for why.
                createdAt = keyInfo.createdAt * 1000,
            )
        }
    }

    override suspend fun deleteKey(keyId: String) = withContext(Dispatchers.IO) {
        ffi.deleteKey(keyId)
        publicKeyCache.remove(keyId)
        Unit
    }

    override suspend fun attestationChain(keyId: String): AttestationChain? = withContext(Dispatchers.IO) {
        ffi.attestationChain(keyId)?.let { AttestationChain(it.certificates, it.clientDataHash) }
    }

    override suspend fun exportPublicKey(keyId: String): ByteArray = withContext(Dispatchers.IO) {
        publicKeyCache[keyId]?.let { return@withContext it }
        // Cache miss: the key may have been created via a path other than
        // this Signer's own generateKey() (e.g. the WSCD lifecycle
        // register/activate calls used for enrollment), which never
        // populates publicKeyCache. Fall back to asking the manager
        // directly - it can look up any key it currently holds regardless
        // of which call created it - and cache the result for next time.
        val jwkBytes = try {
            ffi.exportPublicKey(keyId).toByteArray(Charsets.UTF_8)
        } catch (e: FfiWscdException) {
            throw IllegalStateException(
                "Public key not cached for $keyId. Key was generated before this session or on another device.",
                e,
            )
        }
        publicKeyCache[keyId] = jwkBytes
        jwkBytes
    }

    override suspend fun migrateKey(keyId: String, targetPlugin: String): MigrationResult =
        withContext(Dispatchers.IO) {
            when (val result = withPinAuth { auth -> ffi.migrateKey(keyId, targetPlugin, auth) }) {
                is FfiMigrationResult.Migrated -> MigrationResult.Migrated(result.newKid)
                is FfiMigrationResult.ReEnrollmentRequired -> MigrationResult.ReEnrollmentRequired(result.oldKid)
            }
        }

    override suspend fun securityProperties(keyId: String): SignerSecurityProperties =
        withContext(Dispatchers.IO) {
            val props = ffi.securityProperties(keyId)
            SignerSecurityProperties(
                keyStorage = listOf(props.keyStorage.toSdkKeyStorage()),
                userAuthentication = props.userAuthentication,
                certification = props.certification.toSdkCertification(),
                amr = props.amr,
            )
        }

    override suspend fun lifecycleStatus(pluginId: String, contextId: String): LifecycleStatus =
        withContext(Dispatchers.IO) {
            ffi.lifecycleStatus(pluginId, contextId).toSdkLifecycleStatus()
        }

    override suspend fun registerLifecycle(request: RegisterLifecycleRequest): RegistrationOutcome =
        withContext(Dispatchers.IO) {
            withPinAuth { auth -> ffi.registerLifecycle(request.toFfiRequest(), auth, noOpProgress()) }.toSdkRegistrationOutcome()
        }

    override suspend fun activateLifecycle(request: ActivateLifecycleRequest): ActivationOutcome =
        withContext(Dispatchers.IO) {
            withPinAuth { auth -> ffi.activateLifecycle(request.toFfiRequest(), auth, noOpProgress()) }.toSdkActivationOutcome()
        }

    override suspend fun rotateLifecycle(request: RotateLifecycleRequest): RotationOutcome =
        withContext(Dispatchers.IO) {
            withPinAuth { auth -> ffi.rotateLifecycle(request.toFfiRequest(), auth, noOpProgress()) }.toSdkRotationOutcome()
        }

    override suspend fun destroyLifecycle(request: DestroyLifecycleRequest): DestructionOutcome =
        withContext(Dispatchers.IO) {
            withPinAuth { auth -> ffi.destroyLifecycle(request.toFfiRequest(), auth, noOpProgress()) }.toSdkDestructionOutcome()
        }

    /**
     * Export the softkey plugin container as JSON bytes for encrypted backup.
     * The caller is responsible for JWE-wrapping the result.
     */
    fun exportSoftkeyContainer(): ByteArray = ffi.exportSoftkeyContainer()

    /**
     * Import a softkey container (JSON bytes) to restore keys from backup.
     */
    fun importSoftkeyContainer(container: ByteArray) {
        ffi.importSoftkeyContainer(container)
    }

    // ─── Auth callback bridge ────────────────────────────────────────────────

    private fun authCallbackBridge(): FfiAuthCallback = AuthCallbackBridge(authProvider)

    /**
     * One WSCD call that may ask for a PIN: runs it with a fresh [AuthCallbackBridge] and re-runs it (bounded by
     * [PinPrompter.MAX_PIN_ATTEMPTS]) after a PIN the authenticator refused for a reason the user can fix; a blocked key or one
     * that needs replugging ends it with [WscdPinException].
     */
    private fun <T> withPinAuth(call: (FfiAuthCallback) -> T): T {
        val bridge = AuthCallbackBridge(authProvider)
        return bridge.prompter.run { call(bridge) }
    }

    private fun noOpProgress(): FfiProgressCallback = object : FfiProgressCallback {
        override fun onProgress(progress: FfiOperationProgress) { /* no-op */ }
    }

    // ─── Type mapping helpers ────────────────────────────────────────────────

    private fun String.toFfiAlgorithm(): FfiAlgorithm = when (this.uppercase()) {
        "ES256" -> FfiAlgorithm.ES256
        "EDDSA", "ED25519" -> FfiAlgorithm.ED_DSA
        // The manager's own name for it (`Algorithm::as_str`), since there
        // is no JOSE `alg` for a BLS12-381 Schnorr key. Blind BBS key
        // binding, COSE -65609; only the fido2 plugin serves it, and only on
        // YubiKey 5.8 alpha firmware.
        BLS12381_G1_SCHNORR_NAME.uppercase() -> FfiAlgorithm.BLS12381_G1_SCHNORR
        else -> throw IllegalArgumentException("Unsupported algorithm: $this")
    }

    private fun FfiAlgorithm.toSdkAlgorithm(): String = when (this) {
        FfiAlgorithm.ES256 -> "ES256"
        FfiAlgorithm.ED_DSA -> "EdDSA"
        FfiAlgorithm.BLS12381_G1_SCHNORR -> BLS12381_G1_SCHNORR_NAME
    }

    private fun FfiKeyStorageType.toSdkKeyStorage(): String = when (this) {
        FfiKeyStorageType.SOFTWARE -> "software"
        FfiKeyStorageType.HARDWARE -> "hardware"
        FfiKeyStorageType.REMOTE_HSM -> "remote_hsm"
        FfiKeyStorageType.TRUSTED_EXECUTION -> "trusted_execution"
    }

    private fun FfiCertificationLevel.toSdkCertification(): CertificationInfo = when (this) {
        FfiCertificationLevel.NONE -> CertificationInfo.None
        FfiCertificationLevel.BASELINE -> CertificationInfo.Certified("EUCC", "baseline")
        FfiCertificationLevel.SUBSTANTIAL -> CertificationInfo.Certified("EUCC", "substantial")
        FfiCertificationLevel.HIGH -> CertificationInfo.Certified("EUCC", "high")
    }

    private fun FactorKind.toFfiFactorKind(): FfiFactorKind = when (this) {
        FactorKind.Opaque -> FfiFactorKind.OPAQUE
        FactorKind.WebAuthn -> FfiFactorKind.WEB_AUTHN
        FactorKind.RawSign -> FfiFactorKind.RAW_SIGN
    }

    private fun FfiFactorKind.toSdkFactorKind(): FactorKind = when (this) {
        FfiFactorKind.OPAQUE -> FactorKind.Opaque
        FfiFactorKind.WEB_AUTHN -> FactorKind.WebAuthn
        FfiFactorKind.RAW_SIGN -> FactorKind.RawSign
    }

    private fun FfiLifecycleState.toSdkLifecycleState(): LifecycleState = when (this) {
        FfiLifecycleState.UNINITIALIZED -> LifecycleState.Uninitialized
        FfiLifecycleState.REGISTERED -> LifecycleState.Registered
        FfiLifecycleState.ACTIVE -> LifecycleState.Active
        FfiLifecycleState.SUSPENDED -> LifecycleState.Suspended
        FfiLifecycleState.DESTROYED -> LifecycleState.Destroyed
    }

    private fun DestroyMode.toFfiDestroyMode(): FfiDestroyMode = when (this) {
        DestroyMode.LocalOnly -> FfiDestroyMode.LOCAL_ONLY
        DestroyMode.RemoteRevokeIfSupported -> FfiDestroyMode.REMOTE_REVOKE_IF_SUPPORTED
        DestroyMode.Strict -> FfiDestroyMode.STRICT
    }

    private fun RegisterLifecycleRequest.toFfiRequest(): FfiRegisterLifecycleRequest =
        FfiRegisterLifecycleRequest(
            pluginId = pluginId,
            contextId = contextId,
            factorKind = factorKind.toFfiFactorKind(),
        )

    private fun ActivateLifecycleRequest.toFfiRequest(): FfiActivateLifecycleRequest =
        FfiActivateLifecycleRequest(
            pluginId = pluginId,
            contextId = contextId,
        )

    private fun RotateLifecycleRequest.toFfiRequest(): FfiRotateLifecycleRequest =
        FfiRotateLifecycleRequest(
            pluginId = pluginId,
            contextId = contextId,
        )

    private fun DestroyLifecycleRequest.toFfiRequest(): FfiDestroyLifecycleRequest =
        FfiDestroyLifecycleRequest(
            pluginId = pluginId,
            contextId = contextId,
            mode = mode.toFfiDestroyMode(),
            reason = reason,
        )

    private fun FfiLifecycleStatus.toSdkLifecycleStatus(): LifecycleStatus = LifecycleStatus(
        contextId = contextId,
        pluginId = pluginId,
        factorKind = factorKind.toSdkFactorKind(),
        state = state.toSdkLifecycleState(),
        // Rust's `updated_at` (siros-wscd-manager's `timeutil::now_unix()`) is
        // Unix seconds, not millis - found via live testing (the Developer
        // screen showed "1970-01-21" for a fresh enrollment). [LifecycleStatus.updatedAt]
        // is epoch-millis everywhere else in this SDK (matches
        // WscdScreen.kt's formatTimestamp(epochMs: Long) using Date(Long)),
        // so convert at this FFI boundary rather than push the unit
        // mismatch onto every caller.
        updatedAt = updatedAt * 1000,
    )

    private fun FfiRegistrationOutcome.toSdkRegistrationOutcome(): RegistrationOutcome = RegistrationOutcome(
        contextId = contextId,
        state = state.toSdkLifecycleState(),
    )

    private fun FfiActivationOutcome.toSdkActivationOutcome(): ActivationOutcome = ActivationOutcome(
        contextId = contextId,
        state = state.toSdkLifecycleState(),
    )

    private fun FfiRotationOutcome.toSdkRotationOutcome(): RotationOutcome = RotationOutcome(
        contextId = contextId,
        state = state.toSdkLifecycleState(),
    )

    private fun FfiDestructionOutcome.toSdkDestructionOutcome(): DestructionOutcome = DestructionOutcome(
        contextId = contextId,
        state = state.toSdkLifecycleState(),
        remotePerformed = remotePerformed,
    )
}

/**
 * Bridges the suspend-based [Ctap2TransportProvider] to the synchronous
 * [FfiCtap2Transport] callback interface UniFFI generates. `runBlocking` is
 * safe here - this callback is invoked from Rust's own background FFI
 * thread pool, never the Android main thread.
 *
 * Lazily connects on first use and stays connected, matching this
 * codebase's other WSCD callback bridges' lifecycle - EXCEPT that a
 * ceremony now sends several commands per attempt (ClientPin's
 * getInfo/getKeyAgreement/getPinUvAuthToken round trips ahead of the
 * actual command, see `preview_sign_protocol::make_credential`), so a
 * connection that died between UI interactions (the physical
 * authenticator was unplugged/replugged, e.g. to clear a transient
 * `CTAP2_ERR_PIN_AUTH_BLOCKED` lockout) previously wedged every
 * subsequent attempt with `DeviceDisconnected` until the whole app was
 * restarted - `connected` never got reset, so [ctap2SendCommand] never
 * called [Ctap2TransportProvider.connect] again. On any [send] failure,
 * drop the stale connection and reconnect once before giving up.
 */
internal class Ctap2TransportBridge(private val provider: Ctap2TransportProvider) : FfiCtap2Transport {
    // Read and written from Rust's own background FFI thread pool (per this
    // class's own doc comment) - @Volatile so a genuinely concurrent
    // invocation can't observe a stale value cached in another thread's
    // register/cache.
    @Volatile
    private var connected = false

    override fun ctap2SendCommand(command: ByteArray): ByteArray = try {
        runBlocking { exchange(command) }
    } catch (e: uniffi.siros_wscd_manager.FfiWscdException) {
        throw e
    } catch (e: Exception) {
        // The callback boundary: an exception of any other type would be sent to Rust as `UnexpectedUniFFICallbackError` whose
        // message is the WHOLE Kotlin stack trace (what a user saw as "a very long error"). A typed error with a short message
        // goes instead; the cause is logged here, separately.
        Timber.w("Ctap2 transport failed: ${e.javaClass.simpleName}: ${e.message?.take(120)}")
        throw uniffi.siros_wscd_manager.FfiWscdException.Callback(e.shortTransportReason())
    }

    private suspend fun exchange(command: ByteArray): ByteArray {
        if (!connected) {
            provider.connect()
            connected = true
        }
        return try {
            provider.send(command)
        } catch (e: Exception) {
            connected = false
            runCatching { provider.disconnect() }
            provider.connect()
            connected = true
            provider.send(command)
        }
    }
}

/** Bridges the suspend-based [R2psTransportProvider] to [FfiHttpTransport]. */
private class R2psTransportBridge(private val provider: R2psTransportProvider) : FfiHttpTransport {
    override fun send(body: ByteArray): ByteArray = runBlocking { provider.send(body) }
}
