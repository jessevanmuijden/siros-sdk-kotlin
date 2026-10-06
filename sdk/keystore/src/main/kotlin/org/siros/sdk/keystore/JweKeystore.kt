package org.siros.sdk.keystore

import org.siros.sdk.credentials.KeystoreException
import org.siros.sdk.credentials.interop.createDidJwk
import org.siros.sdk.credentials.interop.HolderBinding
import org.siros.sdk.credentials.interop.didJwkKeyId
import org.siros.sdk.credentials.interop.InteropProfile
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.AESDecrypter
import com.nimbusds.jose.crypto.AESEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Date
import java.util.UUID
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * A durable OID4VCI renewal candidate for one credential batch - see
 * privatedata-spec SPEC.md §6.2 "S.credentialRefreshTokens". [dpopJwk] MUST
 * be presented back unchanged on every renewal of the same [batchId] (RFC
 * 9449/ARF ISSU_65 key-binding), never regenerated client-side.
 */
@Serializable
data class CredentialRefreshTokenEntry(
    val refreshToken: String,
    val dpopJwk: String? = null,
    val credentialIssuerIdentifier: String,
    val credentialConfigurationId: String,
    /**
     * Identifier of the client-held DPoP key the token is bound to when this
     * wallet signed the DPoP proofs itself (`sign_client_auth`,
     * go-wallet-backend#317) - [dpopJwk] is null in that case. Presented back
     * as `dpop_key_id` on renewal so the engine asks this wallet to sign with
     * the same key.
     */
    val dpopKeyId: String? = null,
)

/**
 * JWE-based keystore implementation fully compatible with the wallet-frontend
 * encrypted container format.
 *
 * Uses the same key hierarchy as the TypeScript web wallet:
 *   PRF output → HKDF(SHA-256, salt, info="eDiplomas PRF") → prfKey (AES-GCM-256)
 *   prfKey → unwrap ECDH private key → ECDH key agreement → AES-KW → unwrap mainKey
 *   mainKey → decrypt JWE (alg=A256GCMKW, enc=A256GCM) → WalletStateContainer
 *
 * This enables cross-device portability: the same encrypted private data
 * can be used by both the Android native wallet and the web wallet,
 * provided the same passkey PRF is used on the same authenticator.
 */
class JweKeystore(
    private val json: Json = Json { ignoreUnknownKeys = true },
    /**
     * The interoperability profile this keystore signs for - see
     * [InteropProfile]. It decides how a new key pair is named and, unless a
     * caller overrides it per issuance, how the Holder's key is named in an
     * OID4VCI proof. Defaults to HAIP, which is what this SDK has always
     * sent.
     */
    private val profile: InteropProfile = InteropProfile.DEFAULT,
    /**
     * How a newly generated key pair is named - see [DidKeyVersion]. Follows
     * [profile] unless a wallet needs something else: a `did:jwk` for DIIP, a
     * JWK thumbprint for HAIP. Keys already in the container keep whatever id
     * they were stored with regardless of this setting, so changing it never
     * orphans a credential.
     */
    private val didKeyVersion: DidKeyVersion = DidKeyVersion.forProfile(profile),
) : KeystoreManager, ExtensionStore {

    /**
     * The pre-DIIP constructor shape, kept so existing Java and already-compiled
     * consumers still link: Kotlin default arguments only help callers
     * recompiled against the new primary constructor, and adding `profile`
     * changed its JVM descriptor. Behaves exactly as before - HAIP, keys named
     * by JWK thumbprint.
     */
    constructor(json: Json) : this(json, InteropProfile.DEFAULT)

    private val mutex = Mutex()
    private var keys: MutableMap<String, ECKey> = mutableMapOf()

    // kid -> the DID that key pair is published under. Kept alongside [keys]
    // rather than recomputed on export, because a key read back from the
    // container must round-trip the DID it was stored with: recomputing it
    // under a different [didKeyVersion] would silently re-identify a key
    // that credentials are already bound to.
    private var keyDids: MutableMap<String, String> = mutableMapOf()
    private var credentials: MutableMap<Long, String> = mutableMapOf()
    private var presentationRecords: MutableMap<Long, String> = mutableMapOf()
    @Volatile private var mainKey: SecretKey? = null
    @Volatile private var containerMetadata: ContainerData? = null
    // Preserve full WalletStateContainer for round-trip fidelity
    private var preservedWalletState: kotlinx.serialization.json.JsonObject? = null
    // Hardware-backed WSCD plugins' exported key metadata (kid ->
    // credential_handle/pubkey mappings, never private key material), keyed
    // by plugin ID - see privatedata-spec SPEC.md §6.1 "S.wscdCredentials".
    // This is what makes a FIDO2 (or future R2PS) hardware key addressable
    // again from ANY device sharing this account, not just the one that
    // enrolled it - a roaming CTAP2 authenticator can be tapped/plugged into
    // a different device entirely, and every device needs the same mapping.
    private var wscdCredentials: MutableMap<String, String> = mutableMapOf()

    // Namespaced client-defined state - privatedata-spec SPEC.md §6.1
    // "S.extensions", the normative replacement for one-off top-level fields
    // like `wscdCredentials` above.
    //
    // namespace -> entry key -> opaque value. Both levels are opaque to this
    // class: it stores and round-trips them and never interprets a value,
    // which is what lets a client carry a namespace it does not implement.
    //
    // Entry keys name an ENTITY - a kid, a credential id, a batch id - never
    // a subsystem (§6.1.1). That is a correctness rule, not a style one:
    // resolution is last-write-wins per (namespace, key), so one aggregate
    // entry per subsystem loses data whenever two devices write concurrently.
    private var extensions: MutableMap<String, MutableMap<String, String>> = mutableMapOf()
    // OID4VCI renewal (credential re-issuance/renewal plan, Phase 2) -
    // refresh_token + the DPoP key it's bound to, keyed by the credential
    // batch's batchId - see privatedata-spec SPEC.md §6.2
    // "S.credentialRefreshTokens". The issuer binds refresh_token to the
    // exact DPoP key used at initial issuance (RFC 9449/ARF ISSU_65), so
    // dpopJwk must be presented back unchanged on every renewal of the same
    // batch, never regenerated - the backend never persists this key
    // itself (see feedback_backend_key_persistence_principle), only the
    // client does, via this field.
    private var credentialRefreshTokens: MutableMap<Long, CredentialRefreshTokenEntry> = mutableMapOf()

    override val isUnlocked: Boolean get() = mainKey != null

    override suspend fun unlock(
        prfOutput: ByteArray,
        encryptedContainer: ByteArray,
        hkdfSalt: ByteArray,
        hkdfInfo: ByteArray,
    ) = mutex.withLock {
        if (encryptedContainer.isNotEmpty()) {
            // Parse the full container format from the wallet-frontend
            val container = EncryptedContainer.parse(encryptedContainer)
            val mainKeyInfo = container.mainKey
                ?: throw KeystoreException("Container missing mainKey")

            // Find the matching PRF key entry by credentialId (passed via wallet layer)
            // Fallback to first entry only if no credentialId match (legacy compat)
            val prfKeyInfo = container.prfKeys.firstOrNull { it.credentialId.isNotEmpty() && it.hkdfSalt.contentEquals(hkdfSalt) }
                ?: container.prfKeys.firstOrNull { it.hkdfSalt.contentEquals(hkdfSalt) }
                ?: container.prfKeys.firstOrNull()
                ?: throw KeystoreException("No PRF key entries in container")

            // Derive the PRF wrapping key: HKDF(PRF output, salt, info)
            val prfKey = EncryptedContainer.derivePrfKey(prfOutput, prfKeyInfo.hkdfSalt, prfKeyInfo.hkdfInfo)

            // Unwrap the main key through ECDH encapsulation
            val unwrappedMainKey = EncryptedContainer.unwrapMainKey(prfKey, prfKeyInfo, mainKeyInfo)
            mainKey = unwrappedMainKey

            // Decrypt the JWE using the main key (A256GCMKW / A256GCM)
            val jweObject = JWEObject.parse(container.jwe)
            jweObject.decrypt(AESDecrypter(unwrappedMainKey))

            // Parse the WalletStateContainer plaintext and preserve for round-trip
            val plaintextJson = json.parseToJsonElement(jweObject.payload.toString())
            if (plaintextJson is kotlinx.serialization.json.JsonObject) {
                preservedWalletState = plaintextJson
            }
            loadWalletState(plaintextJson)

            // Preserve container metadata for re-export
            containerMetadata = container
        } else {
            // First-time setup: generate a fresh main key and container structure
            val (newMainKey, newMainKeyInfo) = EncryptedContainer.generateMainKey()
            mainKey = newMainKey

            // Build a PRF key entry for this authenticator
            val prfKey = EncryptedContainer.derivePrfKey(prfOutput, hkdfSalt, hkdfInfo)
            val encapsulation = EncryptedContainer.wrapMainKey(prfKey, newMainKey, newMainKeyInfo)

            containerMetadata = ContainerData(
                jwe = "", // will be set on export
                mainKey = newMainKeyInfo,
                prfKeys = listOf(
                    PrfKeyInfo(
                        credentialId = ByteArray(0), // will be set by SirosWallet
                        transports = null,
                        prfSalt = ByteArray(32).also { SecureRandom().nextBytes(it) },
                        hkdfSalt = hkdfSalt,
                        hkdfInfo = hkdfInfo,
                        algorithm = AesGcmKeyAlgorithm("AES-GCM", 256),
                        keypair = encapsulation.keypair,
                        unwrapKey = encapsulation.unwrapKey,
                    )
                ),
            )
        }

        Timber.i("Keystore unlocked with ${keys.size} keys, ${credentials.size} credentials, ${presentationRecords.size} presentation records")
    }

    /**
     * Set the credential ID on the PRF key entry (called after registration
     * when the credential ID is known).
     */
    override fun setCredentialId(credentialId: ByteArray) {
        val meta = containerMetadata ?: return
        if (meta.prfKeys.isNotEmpty() && meta.prfKeys[0].credentialId.isEmpty()) {
            containerMetadata = meta.copy(
                prfKeys = listOf(meta.prfKeys[0].copy(credentialId = credentialId)) + meta.prfKeys.drop(1)
            )
        }
    }

    private fun loadWalletState(element: kotlinx.serialization.json.JsonElement) {
        val obj = element as? kotlinx.serialization.json.JsonObject ?: return

        // Parse V3 WalletStateContainer: { events: [...], S: { keypairs, credentials, ... }, lastEventHash }
        val state = obj["S"]?.let { it as? kotlinx.serialization.json.JsonObject }
        if (state != null) {
            // V3 format: keypairs and credentials are in the "S" field
            loadFromWalletStateV3(state)
        } else if (obj.containsKey("keys")) {
            // Legacy Kotlin-only format: { keys: [...], credentials: {...} }
            // predates numeric credential ids entirely - defaults any
            // unparseable (pre-migration UUID-string) key to 0, since this
            // path is only reachable from a container exported before the
            // privatedata-spec numeric-id alignment.
            val legacyState = json.decodeFromString(KeystoreState.serializer(), element.toString())
            keys = legacyState.keys.associate { stored ->
                val ecKey = ECKey.parse(stored.jwk)
                stored.keyId to ecKey
            }.toMutableMap()
            credentials = legacyState.credentials.mapKeys { it.key.toLongOrNull() ?: 0L }.toMutableMap()
        }
    }

    private fun loadFromWalletStateV3(state: kotlinx.serialization.json.JsonObject) {
        // Parse keypairs: [{ kid, keypair: { kid, did, alg, publicKey, privateKey } }]
        val keypairsArray = state["keypairs"]
        if (keypairsArray is kotlinx.serialization.json.JsonArray) {
            for (entry in keypairsArray) {
                val entryObj = entry as? kotlinx.serialization.json.JsonObject ?: continue
                val keypairObj = entryObj["keypair"] as? kotlinx.serialization.json.JsonObject ?: continue
                val kid = keypairObj["kid"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content } ?: continue
                val privateKeyJwk = keypairObj["privateKey"] as? kotlinx.serialization.json.JsonObject ?: continue

                try {
                    val ecKey = ECKey.parse(privateKeyJwk.toString())
                    // Ensure the key has the correct kid set
                    val keyWithId = ECKey.Builder(ecKey).keyID(kid).build()
                    keys[kid] = keyWithId
                    (keypairObj["did"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull
                        ?.let { keyDids[kid] = it }
                } catch (e: Exception) {
                    Timber.w(e, "Failed to parse keypair $kid")
                }
            }
        }

        // Parse credentials: [{ credentialId, format, data, kid, batchId, instanceId, ... }]
        // Store as serialized StoredCredential to preserve kid binding and format.
        // credentialId/batchId are privatedata-spec `number`s on the wire
        // (matching wallet-frontend's WalletStateCredential exactly) - read
        // via .content.toLongOrNull() rather than a strict numeric accessor
        // so a value that arrives quoted (e.g. from a not-yet-migrated
        // container) still parses instead of silently dropping the entry.
        val credsArray = state["credentials"]
        if (credsArray is kotlinx.serialization.json.JsonArray) {
            for (entry in credsArray) {
                val credObj = entry as? kotlinx.serialization.json.JsonObject ?: continue
                val credId = credObj["credentialId"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() }
                    ?: continue
                val data = credObj["data"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                    ?: continue
                val credKid = credObj["kid"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                val credFormat = credObj["format"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull } ?: ""
                val credIssuerIdent = credObj["credentialIssuerIdentifier"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                val credConfigId = credObj["credentialConfigurationId"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                val batchId = credObj["batchId"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() } ?: 0L
                val instanceId = credObj["instanceId"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content?.toIntOrNull() } ?: 0

                // Store as serialized StoredCredential JSON to preserve metadata.
                // credentialIssuerIdentifier/credentialConfigurationId are part
                // of privatedata-spec's normative fields (already written by
                // buildWalletStateV3() below) - reconstructing them here too
                // is what lets SirosWallet re-fetch VCTM display metadata
                // after a fresh login (see SirosWallet.hydrateReloadedCredentials).
                val storedJson = kotlinx.serialization.json.buildJsonObject {
                    put("id", kotlinx.serialization.json.JsonPrimitive(credId))
                    put("format", kotlinx.serialization.json.JsonPrimitive(credFormat))
                    put("raw", kotlinx.serialization.json.JsonPrimitive(data))
                    put("batch_id", kotlinx.serialization.json.JsonPrimitive(batchId))
                    put("instance_id", kotlinx.serialization.json.JsonPrimitive(instanceId))
                    if (!credKid.isNullOrEmpty()) {
                        put("kid", kotlinx.serialization.json.JsonPrimitive(credKid))
                    }
                    if (!credIssuerIdent.isNullOrEmpty()) {
                        put("credential_issuer_identifier", kotlinx.serialization.json.JsonPrimitive(credIssuerIdent))
                    }
                    if (!credConfigId.isNullOrEmpty()) {
                        put("credential_configuration_id", kotlinx.serialization.json.JsonPrimitive(credConfigId))
                    }
                }
                credentials[credId] = storedJson.toString()
            }
        }

        // Parse presentations: [{ presentationId, transactionId, data,
        // usedCredentialIds, presentationTimestampSeconds, audience }] -
        // privatedata-spec's normative shape (wallet-frontend's
        // WalletStatePresentation). transactionId/data have no PresentationRecord
        // counterpart (see PresentationRecord's KDoc) and are intentionally
        // dropped on reload, not round-tripped.
        val presentationsArray = state["presentations"]
        if (presentationsArray is kotlinx.serialization.json.JsonArray) {
            for (entry in presentationsArray) {
                val presObj = entry as? kotlinx.serialization.json.JsonObject ?: continue
                val presId = presObj["presentationId"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() }
                    ?: continue
                val usedCredentialIds = (presObj["usedCredentialIds"] as? kotlinx.serialization.json.JsonArray)
                    ?.mapNotNull { (it as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() }
                    ?: emptyList()
                val timestampSeconds = presObj["presentationTimestampSeconds"]
                    ?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() } ?: 0L
                val audience = presObj["audience"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }

                val recordJson = kotlinx.serialization.json.buildJsonObject {
                    put("id", kotlinx.serialization.json.JsonPrimitive(presId))
                    put("flow_id", kotlinx.serialization.json.JsonPrimitive(""))
                    put("credential_ids", kotlinx.serialization.json.JsonArray(
                        usedCredentialIds.map { kotlinx.serialization.json.JsonPrimitive(it) }
                    ))
                    put("timestamp", kotlinx.serialization.json.JsonPrimitive(timestampSeconds * 1000))
                    if (!audience.isNullOrEmpty()) {
                        put("verifier_name", kotlinx.serialization.json.JsonPrimitive(audience))
                    }
                }
                presentationRecords[presId] = recordJson.toString()
            }
        }

        // Parse wscdCredentials: { [pluginId]: "<opaque exported state>" } -
        // privatedata-spec §6.1, a native-SDK-only extension (see
        // wscdCredentials field's own doc comment above).
        val wscdCredsObj = state["wscdCredentials"] as? kotlinx.serialization.json.JsonObject
        if (wscdCredsObj != null) {
            for ((pluginId, value) in wscdCredsObj) {
                (value as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull?.let {
                    wscdCredentials[pluginId] = it
                }
            }
        }

        // Parse extensions: { [namespace]: { [key]: "<opaque>" } } -
        // privatedata-spec §6.1. Anything that is not a JSON string is
        // skipped rather than rejected: a namespace this build does not
        // implement may legitimately hold a shape it has never seen, and
        // failing to load the whole container over it would be worse than
        // carrying it.
        //
        // Skipped, specifically, rather than coerced: §6.1 makes an entry
        // value a string, and [exportEncryptedContainer] writes every entry
        // back as one. Taking a number or a boolean here would hand the
        // peer that wrote it a re-typed value on the next round trip -
        // quietly changing another client's data is worse than declining to
        // carry a value the spec does not allow in the first place, and it
        // treats primitives the same way objects and arrays are already
        // treated.
        //
        // The map is cleared first because this is a load, not a merge: the
        // same instance unlocked against a second container (a different
        // account, or a re-unlock after entries were dropped) must not carry
        // the first one's entries into it and write them back on export.
        extensions.clear()
        val extensionsObj = state["extensions"] as? kotlinx.serialization.json.JsonObject
        if (extensionsObj != null) {
            for ((namespace, nsValue) in extensionsObj) {
                val entries = nsValue as? kotlinx.serialization.json.JsonObject ?: continue
                val target = extensions.getOrPut(namespace) { mutableMapOf() }
                for ((key, value) in entries) {
                    val primitive = value as? kotlinx.serialization.json.JsonPrimitive ?: continue
                    if (!primitive.isString) continue
                    target[key] = primitive.content
                }
                if (target.isEmpty()) extensions.remove(namespace)
            }
        }

        // Parse credentialRefreshTokens: { [batchId]: {refreshToken, dpopJwk,
        // credentialIssuerIdentifier, credentialConfigurationId} } -
        // privatedata-spec §6.2, a native-SDK-only extension (see
        // credentialRefreshTokens field's own doc comment above).
        val refreshTokensObj = state["credentialRefreshTokens"] as? kotlinx.serialization.json.JsonObject
        if (refreshTokensObj != null) {
            for ((batchIdStr, value) in refreshTokensObj) {
                val batchId = batchIdStr.toLongOrNull() ?: continue
                (value as? kotlinx.serialization.json.JsonObject)?.let { entryObj ->
                    try {
                        credentialRefreshTokens[batchId] = json.decodeFromJsonElement(
                            CredentialRefreshTokenEntry.serializer(),
                            entryObj,
                        )
                    } catch (e: Exception) {
                        Timber.w(e, "Failed to parse credentialRefreshTokens entry for batch $batchId")
                    }
                }
            }
        }
    }

    override fun lock() {
        keys.clear()
        credentials.clear()
        presentationRecords.clear()
        keyDids.clear()
        wscdCredentials.clear()
        extensions.clear()
        credentialRefreshTokens.clear()
        mainKey = null
        containerMetadata = null
        preservedWalletState = null
        Timber.i("Keystore locked")
    }

    override suspend fun generateKey(algorithm: String): String = mutex.withLock {
        requireUnlocked()
        val keyWithId = registerNewKey()
        Timber.d("Generated key: ${keyWithId.keyID}")
        keyWithId.keyID
    }

    /**
     * All currently-loaded keypairs as full private JWK JSON strings, keyed
     * by kid - lets a WSCD-backed [KeystoreManager] (see
     * [WscdKeystoreAdapter]) fold its own signer's keys into this
     * keystore's `S.keypairs` on export, and read them back on unlock, so a
     * software-backed signer's keys round-trip through privatedata instead
     * of only living in that signer's own process memory.
     */
    suspend fun exportKeypairJwks(): Map<String, String> = mutex.withLock {
        keys.mapValues { it.value.toJSONString() }
    }

    /**
     * Every hardware-backed WSCD plugin's persisted key metadata, keyed by
     * plugin ID (see [wscdCredentials]'s doc comment) - read after [unlock]
     * to restore a previously-enrolled key (e.g. via
     * `WscdManager.registerFido2PluginWithState`).
     */
    suspend fun exportWscdCredentials(): Map<String, String> = mutex.withLock {
        wscdCredentials.toMap()
    }

    /**
     * Record a WSCD plugin's freshly-exported key metadata so the next
     * [exportEncryptedContainer] call folds it into `S.wscdCredentials` and
     * it survives to the next [unlock] (on this device or any other sharing
     * this account).
     */
    suspend fun setWscdCredentials(pluginId: String, state: String) = mutex.withLock {
        wscdCredentials[pluginId] = state
    }

    /**
     * One namespace's entries - privatedata-spec §6.1 `S.extensions`.
     *
     * Returns an empty map for a namespace this container does not carry,
     * which is not an error: a namespace only exists once something writes
     * to it.
     *
     * Deliberately readable while locked, unlike [setExtensionEntry] and
     * [removeExtensionEntry]. A locked keystore holds no entries, so the
     * answer is the same empty map a never-written namespace gives, and the
     * caller's contract for that answer is already "this cannot be
     * presented" - see [BbsHolderStateVault.get]. Throwing would turn a
     * credential that cannot be presented right now into a crash on the
     * presentation path.
     */
    override suspend fun extensionEntries(namespace: String): Map<String, String> = mutex.withLock {
        extensions[namespace]?.toMap() ?: emptyMap()
    }

    /**
     * Write one entry, so the next [exportEncryptedContainer] folds it into
     * `S.extensions` and it survives to the next [unlock] on this device or
     * any other sharing this account.
     *
     * @param key MUST name a single entity the wallet already tracks - a
     *   kid, a credential id, a batch id - and MUST NOT name a subsystem or
     *   plugin (§6.1.1). See the [extensions] field comment for why that is
     *   a correctness rule.
     * @throws KeystoreException if the keystore is locked. A write to a
     *   locked keystore has nowhere to go: [lock] has already dropped the
     *   in-memory map, and the next [unlock] loads the container it is
     *   given rather than merging into what is there, so the entry would be
     *   silently discarded. Failing loudly matters more here than for most
     *   state, because for BBS the value being written cannot be
     *   reconstructed after the fact.
     */
    override suspend fun setExtensionEntry(namespace: String, key: String, value: String) = mutex.withLock {
        requireUnlocked()
        extensions.getOrPut(namespace) { mutableMapOf() }[key] = value
    }

    /**
     * Remove one entry.
     *
     * §6.1.2 requires that deleting the entity an entry names deletes the
     * entry; this is how a caller honours that. An emptied namespace is
     * dropped rather than left as an empty object, so a container carries no
     * trace of a namespace nothing uses.
     *
     * @throws KeystoreException if the keystore is locked - same reason as
     *   [setExtensionEntry]. A deletion that appears to succeed while locked
     *   would leave the entry in the container it was meant to be removed
     *   from.
     */
    override suspend fun removeExtensionEntry(namespace: String, key: String) = mutex.withLock {
        requireUnlocked()
        val ns = extensions[namespace] ?: return@withLock
        ns.remove(key)
        if (ns.isEmpty()) extensions.remove(namespace)
    }

    /**
     * Every credential batch's durable renewal candidate, keyed by batchId
     * (see [CredentialRefreshTokenEntry]'s doc comment) - read after
     * [unlock] to look up the refresh_token/DPoP key for a renewal request
     * without depending on in-memory state surviving a restart.
     */
    suspend fun exportCredentialRefreshTokens(): Map<Long, CredentialRefreshTokenEntry> = mutex.withLock {
        credentialRefreshTokens.toMap()
    }

    /**
     * Record (or overwrite) a credential batch's renewal candidate so the
     * next [exportEncryptedContainer] call folds it into
     * `S.credentialRefreshTokens` and it survives to the next [unlock].
     */
    suspend fun setCredentialRefreshToken(batchId: Long, entry: CredentialRefreshTokenEntry) = mutex.withLock {
        credentialRefreshTokens[batchId] = entry
    }

    /**
     * Remove a batch's renewal candidate - MUST be called whenever that
     * batch's credentials are deleted (e.g. superseded by a successful
     * renewal, or the user removes the credential), per
     * privatedata-spec §6.2's requirement that a stale entry pointing at a
     * no-longer-existing batch never lingers.
     */
    suspend fun removeCredentialRefreshToken(batchId: Long) = mutex.withLock {
        credentialRefreshTokens.remove(batchId)
    }

    /**
     * Insert an externally-sourced keypair (e.g. one just generated by a
     * WSCD signer) into this keystore's own key map, so it's included the
     * next time this keystore is exported - see [exportKeypairJwks].
     */
    suspend fun importKeypairJwk(kid: String, jwk: String) = mutex.withLock {
        keys[kid] = ECKey.Builder(ECKey.parse(jwk)).keyID(kid).build()
    }

    override suspend fun sign(keyId: String, payload: ByteArray, algorithm: String): ByteArray = mutex.withLock {
        requireUnlocked()
        val key = keys[keyId] ?: throw KeystoreException("Key not found: $keyId")
        val signer = ECDSASigner(key)
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId).build()
        val jwsObject = com.nimbusds.jose.JWSObject(header, Payload(payload))
        jwsObject.sign(signer)
        jwsObject.serialize().toByteArray(Charsets.UTF_8)
    }

    /** The pre-DIIP call shape: this keystore's own profile decides. */
    override suspend fun generateProof(audience: String, nonce: String, freshKey: Boolean): String =
        generateProof(audience, nonce, freshKey, holderBinding = null)

    override suspend fun generateProof(
        audience: String,
        nonce: String,
        freshKey: Boolean,
        holderBinding: HolderBinding?,
    ): String = mutex.withLock {
        requireUnlocked()
        // `freshKey` means batch issuance: each credential in the batch must
        // be bound to its own key, or every copy shares one holder key and
        // presenting them is linkable. Honouring it also keeps the recorded
        // per-credential `kid` meaningful.
        val key = if (freshKey) {
            registerNewKey()
        } else {
            keys.values.firstOrNull() ?: run {
                Timber.i("No keys available, generating a new key for proof")
                registerNewKey()
            }
        }

        Timber.d("generateProof: building claims for audience=$audience")
        // DIIP requires the `jwt` proof type to carry the Holder's did:jwk as
        // `iss` and to name the key with a `kid` from that DID document; HAIP
        // carries the key in the header instead. The caller may know which
        // this issuer speaks; when it does not, this keystore's own profile
        // decides.
        //
        // The DID is derived from the key rather than read from [keyDids],
        // exactly as WscdKeystoreAdapter does it. A did:jwk *is* its public
        // key, so any key pair has one whether or not it was created under
        // [DidKeyVersion.JWK]. Requiring a stored did:jwk here made the whole
        // negotiation inert for the default wallet: the key version follows
        // the interop profile, which defaults to HAIP, so a negotiated
        // DID_JWK could never be satisfied and every proof fell back to the
        // HAIP shape that a DIIP-only Issuer rejects. What a key was
        // *created* as is a storage question; how this issuance names its
        // holder is not.
        //
        // For a keystore already on [DidKeyVersion.JWK] this is the same
        // value it stored - createDidJwk is deterministic over the canonical
        // public JWK - so nothing changes there.
        val binding = holderBinding ?: profile.holderBinding
        val publicJwk = key.toPublicJWK()
        val did = if (binding == HolderBinding.DID_JWK) {
            // No fallback: DID_JWK is what this issuance negotiated, and the
            // embedded-jwk shape is a different profile the Issuer did not
            // agree to. Failing here says so; falling back would send a proof
            // the Issuer cannot verify and report it as success.
            runCatching { createDidJwk(publicJwk.toJSONString()) }.getOrElse {
                throw KeystoreException("Could not derive a did:jwk for the negotiated DIIP holder binding", it)
            }
        } else {
            null
        }
        val claimsBuilder = JWTClaimsSet.Builder()
            .audience(audience)
            .issueTime(Date())
            .claim("nonce", nonce)
        did?.let { claimsBuilder.issuer(it) }
        val claims = claimsBuilder.build()

        val headerBuilder = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(com.nimbusds.jose.JOSEObjectType("openid4vci-proof+jwt"))
        if (did != null) {
            headerBuilder.keyID(didJwkKeyId(did))
        } else {
            headerBuilder.jwk(publicJwk)
        }
        val header = headerBuilder.build()

        Timber.d("generateProof: signing JWT with key ${key.keyID}")
        val jwt = SignedJWT(header, claims)
        jwt.sign(ECDSASigner(key))
        Timber.d("generateProof: JWT signed successfully")
        jwt.serialize()
    }

    override suspend fun generateKeyProof(
        keyId: String,
        typ: String,
        issuer: String,
        audience: String,
        extraClaims: Map<String, String>,
    ): String = mutex.withLock {
        requireUnlocked()
        val key = keys[keyId] ?: throw KeystoreException("Key not found: $keyId")

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(com.nimbusds.jose.JOSEObjectType(typ))
            .jwk(key.toPublicJWK())
            .build()

        val claimsBuilder = JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(audience)
            .issueTime(Date())
            .expirationTime(Date(System.currentTimeMillis() + 5 * 60 * 1000))
            .jwtID(UUID.randomUUID().toString())
        extraClaims.forEach { (k, v) -> claimsBuilder.claim(k, v) }

        val jwt = SignedJWT(header, claimsBuilder.build())
        jwt.sign(ECDSASigner(key))
        jwt.serialize()
    }

    override suspend fun generateDPoPProof(
        keyId: String,
        htm: String,
        htu: String,
        nonce: String?,
        accessTokenHash: String?,
    ): String = mutex.withLock {
        requireUnlocked()
        val key = keys[keyId] ?: throw KeystoreException("Key not found: $keyId")

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(com.nimbusds.jose.JOSEObjectType("dpop+jwt"))
            .jwk(key.toPublicJWK())
            .build()
        val jwt = SignedJWT(header, dpopClaims(htm, htu, nonce, accessTokenHash))
        jwt.sign(ECDSASigner(key))
        jwt.serialize()
    }

    override suspend fun signPresentation(nonce: String, audience: String, credentialIds: List<Long>, kid: String?): String = mutex.withLock {
        requireUnlocked()
        val key = selectSigningKey(kid)

        val claims = JWTClaimsSet.Builder()
            .audience(audience)
            .issueTime(Date())
            .claim("nonce", nonce)
            .jwtID(UUID.randomUUID().toString())
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(key.keyID)
            .build()

        val jwt = SignedJWT(header, claims)
        jwt.sign(ECDSASigner(key))
        jwt.serialize()
    }

    override suspend fun signVpToken(
        credential: String,
        disclosedClaims: List<String>?,
        nonce: String,
        audience: String,
        kid: String?,
    ): String = mutex.withLock {
        requireUnlocked()
        // The credential's own `cnf` is authoritative about which key it is
        // bound to and how that key is named. An issuer may bind by `cnf.jwk`
        // even when this wallet names its keys by did:jwk URL (and vice
        // versa), so both the lookup and the KB-JWT header follow the
        // credential rather than this wallet's configuration.
        val cnf = cnfOf(credential)
        val cnfKid = resolveCnfKid(cnf)
        val key = selectSigningKey(kid ?: cnfKid)

        // Split the SD-JWT into parts: IssuerJWT~disclosure1~disclosure2~...~
        val parts = credential.split("~")
        val issuerJwt = parts[0]
        val disclosures = parts.drop(1).filter { it.isNotEmpty() }

        // Filter disclosures if specific claims are requested
        val selectedDisclosures = if (disclosedClaims.isNullOrEmpty()) {
            disclosures
        } else {
            filterDisclosures(disclosures, disclosedClaims)
        }

        // Build the SD-JWT presentation string (with trailing ~)
        val sdJwtPresentation = buildString {
            append(issuerJwt)
            for (d in selectedDisclosures) {
                append("~")
                append(d)
            }
            append("~")
        }

        // Compute sd_hash = base64url(SHA-256(sdJwtPresentation))
        val sdHashBytes = java.security.MessageDigest.getInstance("SHA-256")
            .digest(sdJwtPresentation.toByteArray(Charsets.US_ASCII))
        val sdHash = Base64.getUrlEncoder().withoutPadding().encodeToString(sdHashBytes)

        // KB-JWT header: `typ: "kb+jwt"`, `alg: "ES256"`, and the holder key.
        // When the credential binds the holder by value (`cnf.jwk`) the key
        // goes in the header as a JWK with any private material stripped -
        // RFC 9901 plus real-world interop. When it binds by name (`cnf.kid`,
        // which is what DIIP requires), the KB-JWT names the same
        // verification method instead of re-embedding the key.
        val bindsByKid = cnf?.get("jwk") == null && cnfKid != null
        val kbHeaderBuilder = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(com.nimbusds.jose.JOSEObjectType("kb+jwt"))
        if (bindsByKid) {
            kbHeaderBuilder.keyID(cnfKid)
        } else {
            kbHeaderBuilder.jwk(key.toPublicJWK())
        }
        val kbHeader = kbHeaderBuilder.build()

        val kbClaims = JWTClaimsSet.Builder()
            .audience(audience)
            .issueTime(Date())
            .claim("nonce", nonce)
            .claim("sd_hash", sdHash)
            .build()

        val kbJwt = SignedJWT(kbHeader, kbClaims)
        kbJwt.sign(ECDSASigner(key))

        // Assemble: sdJwtPresentation + KB-JWT (no separator — presentation already ends with ~)
        sdJwtPresentation + kbJwt.serialize()
    }

    /**
     * The `cnf` claim of an SD-JWT credential, or null if it has none (or is
     * not parseable - a credential this wallet cannot read is one it cannot
     * sign a presentation for either, and [selectSigningKey] will say so).
     */
    private fun cnfOf(credential: String): kotlinx.serialization.json.JsonObject? = runCatching {
        val payload = credential.substringBefore('~').split('.').getOrNull(1) ?: return@runCatching null
        val padded = payload.padEnd((payload.length + 3) / 4 * 4, '=')
        val decoded = Base64.getUrlDecoder().decode(padded).toString(Charsets.UTF_8)
        (json.parseToJsonElement(decoded) as? kotlinx.serialization.json.JsonObject)
            ?.get("cnf") as? kotlinx.serialization.json.JsonObject
    }.getOrNull()

    /**
     * Filter SD-JWT disclosures to only those matching the requested claim names.
     *
     * Each disclosure is a base64url-encoded JSON array: ["salt", "claim_name", "value"].
     * We decode each, extract the claim name (index 1), and keep only those in [claimNames].
     */
    private fun filterDisclosures(disclosures: List<String>, claimNames: List<String>): List<String> {
        val requested = claimNames.toSet()
        return disclosures.filter { disclosure ->
            try {
                val decoded = Base64.getUrlDecoder().decode(disclosure)
                val arr = json.parseToJsonElement(String(decoded, Charsets.UTF_8))
                val claimName = arr.jsonArray.getOrNull(1)?.jsonPrimitive?.contentOrNull
                claimName != null && claimName in requested
            } catch (e: Exception) {
                // If we can't parse a disclosure, include it to be safe
                Timber.w(e, "Could not parse SD-JWT disclosure, including it")
                true
            }
        }
    }

    override suspend fun exportEncryptedContainer(): ByteArray = mutex.withLock {
        requireUnlocked()
        val currentMainKey = mainKey!!

        // Build the WalletStateContainer V3 plaintext
        val walletState = buildWalletStateV3()
        val payload = json.encodeToString(
            kotlinx.serialization.json.JsonObject.serializer(),
            walletState
        )

        // Encrypt the JWE with A256GCMKW / A256GCM using the main key
        val header = JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256GCM)
        val jweObject = JWEObject(header, Payload(payload))
        jweObject.encrypt(AESEncrypter(currentMainKey))
        val jweString = jweObject.serialize()

        // Build the full container with the updated JWE
        val meta = containerMetadata ?: throw KeystoreException("No container metadata")
        val updatedContainer = meta.copy(jwe = jweString)
        containerMetadata = updatedContainer

        EncryptedContainer.serialize(updatedContainer)
    }

    private fun buildWalletStateV3(): kotlinx.serialization.json.JsonObject {
        // Preserve existing state if available, otherwise initialize fresh.
        // NOTE: this must NOT short-circuit and return existingState verbatim -
        // credentials/keys added via saveCredential()/generateKey() since unlock()
        // only live in the `keys`/`credentials` maps below, not in
        // preservedWalletState, so an early return here would silently drop
        // any credential added by a returning user (preservedWalletState is
        // only ever non-null when unlock() loaded an existing container).
        val existingState = preservedWalletState
        return kotlinx.serialization.json.buildJsonObject {
            val lastEventHash = existingState?.get("lastEventHash")
                ?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull } ?: ""
            put("lastEventHash", kotlinx.serialization.json.JsonPrimitive(lastEventHash))
            val events = existingState?.get("events") as? kotlinx.serialization.json.JsonArray
                ?: kotlinx.serialization.json.JsonArray(emptyList())
            put("events", events)
            put("S", kotlinx.serialization.json.buildJsonObject {
                put("schemaVersion", kotlinx.serialization.json.JsonPrimitive(3))
                put("keypairs", kotlinx.serialization.json.JsonArray(
                    keys.map { (kid, ecKey) ->
                        kotlinx.serialization.json.buildJsonObject {
                            put("kid", kotlinx.serialization.json.JsonPrimitive(kid))
                            put("keypair", kotlinx.serialization.json.buildJsonObject {
                                put("kid", kotlinx.serialization.json.JsonPrimitive(kid))
                                // Preserve DID from original state if available; only compute for fresh keys
                                val preservedDid = existingState?.let { state ->
                                    (state["S"] as? kotlinx.serialization.json.JsonObject)?.let { s ->
                                        (s["keypairs"] as? kotlinx.serialization.json.JsonArray)?.find { entry ->
                                            (entry as? kotlinx.serialization.json.JsonObject)?.let { e ->
                                                ((e["keypair"] as? kotlinx.serialization.json.JsonObject)?.get("kid") as? kotlinx.serialization.json.JsonPrimitive)?.content == kid
                                            } ?: false
                                        }?.let { matchedEntry ->
                                            (matchedEntry as? kotlinx.serialization.json.JsonObject)?.let { e ->
                                                ((e["keypair"] as? kotlinx.serialization.json.JsonObject)?.get("did") as? kotlinx.serialization.json.JsonPrimitive)?.content
                                            }
                                        }
                                    }
                                }
                                // The last fallback follows [didKeyVersion],
                                // not did:key unconditionally. A key folded in
                                // by importKeypairJwk has no keyDids entry, so
                                // a DIIP wallet would otherwise publish it
                                // under the legacy did:key and every client
                                // reading this container afterwards would see
                                // the wrong holder identity for it.
                                put(
                                    "did",
                                    kotlinx.serialization.json.JsonPrimitive(
                                        keyDids[kid]
                                            ?: preservedDid
                                            ?: defaultDidFor(ecKey),
                                    ),
                                )
                                put("alg", kotlinx.serialization.json.JsonPrimitive("ES256"))
                                // Export public key as JWK
                                val pubJwk = json.parseToJsonElement(ecKey.toPublicJWK().toJSONString())
                                put("publicKey", pubJwk)
                                // Export private key as JWK (inside the encrypted JWE)
                                val privJwk = json.parseToJsonElement(ecKey.toJSONString())
                                put("privateKey", privJwk)
                            })
                        }
                    }
                ))
                put("credentials", kotlinx.serialization.json.JsonArray(
                    credentials.map { (id, data) ->
                        // Parse StoredCredential to extract metadata
                        val parsed = try {
                            json.parseToJsonElement(data) as? kotlinx.serialization.json.JsonObject
                        } catch (_: Exception) { null }

                        // Try to find and preserve original credential entry from preserved state.
                        // credentialId is a privatedata-spec number on the wire (matching
                        // wallet-frontend), so compare it numerically rather than as a string.
                        val originalCred = existingState?.let { state ->
                            (state["S"] as? kotlinx.serialization.json.JsonObject)?.let { s ->
                                (s["credentials"] as? kotlinx.serialization.json.JsonArray)?.find { entry ->
                                    (entry as? kotlinx.serialization.json.JsonObject)?.let { e ->
                                        ((e["credentialId"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() == id)
                                    } ?: false
                                }
                            }
                        } as? kotlinx.serialization.json.JsonObject

                        // Preserve all metadata fields from original; use stored/parsed values as fallback
                        val credKid = originalCred?.get("kid")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                            ?: parsed?.get("kid")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull } ?: ""
                        val credFormat = originalCred?.get("format")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                            ?: parsed?.get("format")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull } ?: ""
                        val credData = originalCred?.get("data")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                            ?: parsed?.get("raw")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull } ?: data
                        // Fall back to the credential's own saved JSON (parsed) for a
                        // credential added THIS session (saveCredential() then export,
                        // with no matching entry in the previously-imported container
                        // yet) - without this fallback, a freshly-saved batch
                        // credential's batchId/instanceId would silently reset to 0 on
                        // every export until the container is reloaded once.
                        val instanceId = originalCred?.get("instanceId")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content?.toIntOrNull() }
                            ?: parsed?.get("instance_id")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content?.toIntOrNull() }
                            ?: 0
                        val batchId = originalCred?.get("batchId")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() }
                            ?: parsed?.get("batch_id")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() }
                            ?: 0L
                        val issuerIdent = originalCred?.get("credentialIssuerIdentifier")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                            ?: parsed?.get("credential_issuer_identifier")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull } ?: ""
                        val configId = originalCred?.get("credentialConfigurationId")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                            ?: parsed?.get("credential_configuration_id")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull } ?: ""

                        kotlinx.serialization.json.buildJsonObject {
                            put("credentialId", kotlinx.serialization.json.JsonPrimitive(id))
                            put("format", kotlinx.serialization.json.JsonPrimitive(credFormat))
                            put("data", kotlinx.serialization.json.JsonPrimitive(credData))
                            put("kid", kotlinx.serialization.json.JsonPrimitive(credKid))
                            put("instanceId", kotlinx.serialization.json.JsonPrimitive(instanceId))
                            put("batchId", kotlinx.serialization.json.JsonPrimitive(batchId))
                            put("credentialIssuerIdentifier", kotlinx.serialization.json.JsonPrimitive(issuerIdent))
                            put("credentialConfigurationId", kotlinx.serialization.json.JsonPrimitive(configId))
                        }
                    }
                ))
                // presentations is privatedata-spec's normative S.presentations[]
                // (wallet-frontend's WalletStatePresentation) - genuinely built
                // from the in-memory presentationRecords map, not passed through
                // verbatim, so a presentation recorded THIS session actually
                // survives export/reload (see savePresentationRecord). transactionId
                // has no PresentationRecord counterpart (see its KDoc) - each
                // Android-recorded presentation is treated as its own
                // single-VP transaction, reusing the same id for both fields.
                // `data` (the raw VP) isn't captured at PresentationRecord
                // construction time (recorded at credential-selection time,
                // before the VP is actually signed) - written as "" rather than
                // restructuring that flow, a known, deliberate gap.
                put("presentations", kotlinx.serialization.json.JsonArray(
                    presentationRecords.map { (id, data) ->
                        val parsed = try {
                            json.parseToJsonElement(data) as? kotlinx.serialization.json.JsonObject
                        } catch (_: Exception) { null }
                        val usedCredentialIds = (parsed?.get("credential_ids") as? kotlinx.serialization.json.JsonArray)
                            ?.mapNotNull { (it as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() }
                            ?: emptyList()
                        val timestampMillis = parsed?.get("timestamp")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() } ?: 0L
                        val audience = parsed?.get("verifier_name")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull } ?: ""

                        kotlinx.serialization.json.buildJsonObject {
                            put("presentationId", kotlinx.serialization.json.JsonPrimitive(id))
                            put("transactionId", kotlinx.serialization.json.JsonPrimitive(id))
                            put("data", kotlinx.serialization.json.JsonPrimitive(""))
                            put("usedCredentialIds", kotlinx.serialization.json.JsonArray(
                                usedCredentialIds.map { kotlinx.serialization.json.JsonPrimitive(it) }
                            ))
                            put("presentationTimestampSeconds", kotlinx.serialization.json.JsonPrimitive(timestampMillis / 1000))
                            put("audience", kotlinx.serialization.json.JsonPrimitive(audience))
                        }
                    }
                ))

                put("settings", kotlinx.serialization.json.buildJsonObject {
                    // Preserve settings from original state; use "0" as normative default for new state
                    val refreshTokenAge = existingState?.let { state ->
                        (state["S"] as? kotlinx.serialization.json.JsonObject)?.get("settings")?.let { s ->
                            (s as? kotlinx.serialization.json.JsonObject)?.get("openidRefreshTokenMaxAgeInSeconds")
                                ?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                        }
                    } ?: "0"
                    put("openidRefreshTokenMaxAgeInSeconds", kotlinx.serialization.json.JsonPrimitive(refreshTokenAge))
                })
                
                val credIssuanceSessions = existingState?.let { state ->
                    (state["S"] as? kotlinx.serialization.json.JsonObject)?.get("credentialIssuanceSessions")
                        ?: kotlinx.serialization.json.JsonArray(emptyList())
                } ?: kotlinx.serialization.json.JsonArray(emptyList())
                put("credentialIssuanceSessions", credIssuanceSessions)

                // wscdCredentials (privatedata-spec §6.1, native-SDK-only
                // extension) - wscdCredentials the in-memory map IS the
                // source of truth once loaded (see loadFromWalletStateV3),
                // no need to merge against existingState separately.
                if (wscdCredentials.isNotEmpty()) {
                    put("wscdCredentials", kotlinx.serialization.json.buildJsonObject {
                        for ((pluginId, state) in wscdCredentials) {
                            put(pluginId, kotlinx.serialization.json.JsonPrimitive(state))
                        }
                    })
                }

                // extensions (privatedata-spec §6.1) - written before the
                // legacy fields below so a reader sees the normative shape
                // first. Namespaces this build does not implement are
                // written back exactly as they were read.
                if (extensions.isNotEmpty()) {
                    put("extensions", kotlinx.serialization.json.buildJsonObject {
                        for ((namespace, entries) in extensions) {
                            if (entries.isEmpty()) continue
                            put(namespace, kotlinx.serialization.json.buildJsonObject {
                                for ((key, value) in entries) {
                                    put(key, kotlinx.serialization.json.JsonPrimitive(value))
                                }
                            })
                        }
                    })
                }

                // credentialRefreshTokens (privatedata-spec §6.2,
                // native-SDK-only extension) - same "in-memory map IS the
                // source of truth once loaded" rationale as wscdCredentials
                // above.
                if (credentialRefreshTokens.isNotEmpty()) {
                    put("credentialRefreshTokens", kotlinx.serialization.json.buildJsonObject {
                        for ((batchId, entry) in credentialRefreshTokens) {
                            put(batchId.toString(), json.encodeToJsonElement(CredentialRefreshTokenEntry.serializer(), entry))
                        }
                    })
                }
            })
        }
    }

    override fun listKeys(): List<KeyInfo> {
        return keys.map { (id, _) ->
            KeyInfo(keyId = id, algorithm = "ES256", createdAt = 0)
        }
    }

    // ── Credential storage ──────────────────────────────────────────

    override suspend fun saveCredential(id: Long, json: String) = mutex.withLock {
        requireUnlocked()
        credentials[id] = json
    }

    override suspend fun getCredential(id: Long): String? = mutex.withLock {
        requireUnlocked()
        credentials[id]
    }

    override suspend fun getAllCredentials(): Map<Long, String> = mutex.withLock {
        requireUnlocked()
        credentials.toMap()
    }

    override suspend fun deleteCredential(id: Long): Unit = mutex.withLock {
        requireUnlocked()
        credentials.remove(id)
        Unit
    }

    override suspend fun clearCredentials(): Unit = mutex.withLock {
        requireUnlocked()
        credentials.clear()
    }

    // ── Presentation-history storage ────────────────────────────────

    override suspend fun savePresentationRecord(id: Long, json: String) = mutex.withLock {
        requireUnlocked()
        presentationRecords[id] = json
    }

    override suspend fun getAllPresentationRecords(): Map<Long, String> = mutex.withLock {
        requireUnlocked()
        presentationRecords.toMap()
    }

    override suspend fun clearPresentationRecords(): Unit = mutex.withLock {
        requireUnlocked()
        presentationRecords.clear()
    }

    override suspend fun generateKeypairs(count: Int): List<KeypairInfo> = mutex.withLock {
        requireUnlocked()
        require(count >= 1) { "count must be >= 1" }
        (1..count).map {
            val keyWithId = registerNewKey()
            val pubJwk = kotlinx.serialization.json.Json.parseToJsonElement(
                keyWithId.toPublicJWK().toJSONString()
            ) as kotlinx.serialization.json.JsonObject
            KeypairInfo(keyId = keyWithId.keyID, publicKeyJWK = pubJwk)
        }
    }

    override suspend fun generateKeyAttestation(nonce: String, count: Int): String = mutex.withLock {
        requireUnlocked()
        require(count >= 1) { "count must be >= 1" }
        // Inlined key generation (not generateKeypairs(), which also takes
        // this mutex - Mutex isn't reentrant).
        val generated = (1..count).map { registerNewKey() }
        // Self-attestation: this is a pure in-memory software keystore with
        // no hardware backing or user-authentication gate, so the only
        // truthful claim is the baseline "basic" attack-potential level.
        val signingKey = generated.first()

        val claims = JWTClaimsSet.Builder()
            .issueTime(Date())
            .claim("nonce", nonce)
            .claim("attested_keys", generated.map { it.toPublicJWK().toJSONObject() })
            .claim("key_storage", listOf("iso_18045_basic"))
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(com.nimbusds.jose.JOSEObjectType("key-attestation+jwt"))
            .jwk(signingKey.toPublicJWK())
            .build()

        val jwt = SignedJWT(header, claims)
        jwt.sign(ECDSASigner(signingKey))
        jwt.serialize()
    }

    private fun requireUnlocked() {
        if (!isUnlocked) throw KeystoreException("Keystore is locked")
    }

    /**
     * Pick the key to sign a presentation with. See
     * [WscdKeystoreAdapter.selectSigningKey]'s doc comment for why, when
     * [kid] is given (the credential being presented has a known bound key -
     * see [StoredCredential.kid]), that EXACT key must be used - throwing
     * rather than silently falling back to an arbitrary one if it's
     * missing. [kid] is null only for genuinely credential-less call shapes,
     * where "first available key" (generating one if none exist yet) is the
     * only meaningful choice.
     */
    private fun selectSigningKey(kid: String?): ECKey {
        if (kid != null) {
            return findKeypairByKid(kid)
                ?: throw KeystoreException("Signing key '$kid' not found - this credential's bound key is unavailable")
        }
        return keys.values.firstOrNull() ?: run {
            Timber.i("No keys available, generating a new key for VP signing")
            registerNewKey()
        }
    }

    /**
     * Find a stored key pair by the `kid` a credential refers to it by.
     *
     * Matches on the stored id first, then falls back to comparing JWK
     * thumbprints - see [keypairMatchesKid] for why a wallet naming its keys
     * by `did:jwk` URL still has to answer to a thumbprint.
     */
    private fun findKeypairByKid(kid: String): ECKey? {
        keys[kid]?.let { return it }
        return keys.entries.firstOrNull { (storedKid, key) ->
            keypairMatchesKid(storedKid, key, kid)
        }?.value
    }

    /**
     * Generate a key pair, name it per [didKeyVersion], and add it to the
     * in-memory state. The caller is already holding [mutex].
     */
    private fun registerNewKey(): ECKey {
        val ecKey = ECKeyGenerator(Curve.P_256).generate()
        val publicJwk = json.parseToJsonElement(ecKey.toPublicJWK().toJSONString())
            as kotlinx.serialization.json.JsonObject
        val identity = deriveKeypairIdentity(
            publicJwk = publicJwk,
            version = didKeyVersion,
            legacyDid = { computeDidKey(ecKey) },
            thumbprint = { ecKey.computeThumbprint().toString() },
        )
        val keyWithId = ECKey.Builder(ecKey).keyID(identity.kid).build()
        keys[identity.kid] = keyWithId
        keyDids[identity.kid] = identity.did
        return keyWithId
    }

    /** The DID a stored key pair is published under, if it has one. */
    internal fun didForKid(kid: String): String? = keyDids[kid]

    /**
     * Compute the did:key identifier for a P-256 EC key.
     * Format: did:key:zDn... (Multicodec 0x1200 for P-256 public key, base58btc).
     */
    /**
     * The DID a key pair is published under when nothing has recorded one -
     * whichever identifier [didKeyVersion] names keys by.
     */
    private fun defaultDidFor(key: com.nimbusds.jose.jwk.ECKey): String =
        if (didKeyVersion.namesKeysByDidUrl) {
            runCatching { createDidJwk(key.toPublicJWK().toJSONString()) }.getOrElse { computeDidKey(key) }
        } else {
            computeDidKey(key)
        }

    private fun computeDidKey(ecKey: ECKey): String {
        val pub = ecKey.toECPublicKey()
        // Compressed point: 0x02/0x03 prefix + 32-byte x coordinate
        val xBytes = unsignedBigIntBytes(pub.w.affineX, 32)
        val prefix: Byte = if (pub.w.affineY.testBit(0)) 0x03 else 0x02
        val compressed = byteArrayOf(prefix) + xBytes
        // Multicodec varint for P-256 public key: 0x80, 0x24
        val multicodec = byteArrayOf(0x80.toByte(), 0x24) + compressed
        return "did:key:z${base58Btc(multicodec)}"
    }

    /** Convert BigInteger to fixed-size unsigned byte array (big-endian, zero-padded). */
    private fun unsignedBigIntBytes(value: java.math.BigInteger, size: Int): ByteArray {
        val bytes = value.toByteArray()
        return when {
            bytes.size == size -> bytes
            bytes.size > size -> bytes.copyOfRange(bytes.size - size, bytes.size)
            else -> ByteArray(size - bytes.size) + bytes
        }
    }

    /** Base58 Bitcoin encoding (no checksum). */
    private fun base58Btc(input: ByteArray): String {
        val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var bi = java.math.BigInteger(1, input)
        val sb = StringBuilder()
        val base = java.math.BigInteger.valueOf(58)
        while (bi > java.math.BigInteger.ZERO) {
            val (quotient, remainder) = bi.divideAndRemainder(base)
            sb.append(alphabet[remainder.toInt()])
            bi = quotient
        }
        // Preserve leading zeros
        for (b in input) {
            if (b.toInt() == 0) sb.append('1') else break
        }
        return sb.reverse().toString()
    }

    @Serializable
    private data class KeystoreState(
        val keys: List<StoredKey>,
        val credentials: Map<String, String> = emptyMap(),
    )

    @Serializable
    private data class StoredKey(
        val keyId: String,
        val jwk: String,
        val algorithm: String,
        val createdAt: Long,
    )
}

/**
 * The claims of an RFC 9449 §4.2 DPoP proof: `jti`, `htm`, `htu`, `iat`, plus
 * `nonce` (§8) and `ath` (§4.2, resource requests) when given. Deliberately
 * no `iss`/`aud`/`exp` - those are PoP claims, not DPoP ones. Shared by every
 * [KeystoreManager] implementation in this module.
 */
internal fun dpopClaims(htm: String, htu: String, nonce: String?, accessTokenHash: String?): JWTClaimsSet {
    val b = JWTClaimsSet.Builder()
        .jwtID(UUID.randomUUID().toString())
        .claim("htm", htm)
        .claim("htu", htu)
        .issueTime(Date())
    nonce?.takeIf { it.isNotEmpty() }?.let { b.claim("nonce", it) }
    accessTokenHash?.takeIf { it.isNotEmpty() }?.let { b.claim("ath", it) }
    return b.build()
}
