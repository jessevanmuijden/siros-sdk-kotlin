package org.siros.sdk.keystore

import org.siros.sdk.credentials.KeystoreException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.siros.sdk.credentials.interop.DidRelationship
import org.siros.sdk.credentials.interop.HolderBinding
import org.siros.sdk.credentials.interop.InteropProfile
import org.siros.sdk.credentials.interop.createDidJwk
import org.siros.sdk.credentials.interop.didJwkKeyId
import org.siros.sdk.credentials.interop.resolveDidJwk
import timber.log.Timber
import java.security.MessageDigest
import java.util.Base64
import java.util.Date
import java.util.UUID

/**
 * Transaction data item for TS12 payment SCA.
 *
 * Each item represents one entry from the `transaction_data` array in an
 * OID4VP authorization request. The [rawJson] is the canonical JSON
 * serialization used for hashing into `transaction_data_hashes`.
 */
data class TransactionDataItem(
    /** Transaction type (e.g. "payment", "login_risk", "account_access", "e_mandate"). */
    val type: String,
    /** Canonical JSON serialization of this transaction data item. */
    val rawJson: String,
)

/**
 * Adapts a [Signer] (e.g. backed by WSCD/UniFFI bindings) into the
 * full [KeystoreManager] interface expected by [SirosWallet].
 *
 * Delegates raw key operations (generate, sign, list) to the underlying
 * [Signer] implementation while handling higher-level operations
 * (JWT construction, SD-JWT VP tokens, credential storage) locally.
 *
 * Usage:
 * ```kotlin
 * val wscdSigner: Signer = ... // UniFFI-generated WSCD binding
 * val keystore = WscdKeystoreAdapter(wscdSigner)
 * val wallet = SirosWallet.create(activity, config.copy(keystore = keystore))
 * ```
 */
class WscdKeystoreAdapter private constructor(
    private val signer: Signer,
    /**
     * Owns the PRF-protected container (mainKey/prfKeys/jwe → V3
     * WalletStateContainer) for this adapter's *credentials* - the
     * WSCD manages its own signing-key protection, but SIROS ID's core tenet
     * is that private data, including issued credentials, is always
     * protected by the passkey's PRF-derived secret independent of whichever
     * WSCD backs key signing. Reusing [JweKeystore] here (rather than a
     * WSCD-adapter-local format) guarantees byte-for-byte compatibility with
     * wallet-frontend and JweKeystore-backed native clients per
     * privatedata-spec - the SAME passkey must unlock the SAME credentials
     * on any client.
     *
     * For a hardware-backed or remote-HSM-backed [signer] (FIDO2/CTAP2,
     * R2PS), private key material never leaves that plugin - it persists on
     * its own (a secure element, a remote server), so this instance's own
     * `keypairs` legitimately stays empty forever. For the software
     * ("softkey") plugin, though, there IS real private key material that
     * only ever lives in that plugin's own process memory (see
     * [Signer.exportPrivateKeypairs]'s doc comment) - without folding it in
     * here too, on [unlock]/[exportEncryptedContainer], those keys would be
     * silently lost every time the app process restarts, even though the
     * credentials they're bound to persist fine. [Signer.exportPrivateKeypairs]/
     * [Signer.importPrivateKeypairs] default to a no-op for plugins that
     * don't support this, so this round-trip is harmless for those.
     *
     * A constructor parameter rather than a body property only so the
     * [ExtensionStore] half can be `by`-delegated to it in the class
     * header; the primary constructor is private so no caller can hand this
     * adapter a container it does not own.
     */
    private val credentialsKeystore: JweKeystore,
    /**
     * The interoperability profile this keystore signs for - see
     * [InteropProfile]. Unlike [JweKeystore], the key ids themselves come from
     * the WSCD (which assigns RFC 7638 thumbprints) and are not changed by
     * this setting; what it controls is the identifier presented to Issuers.
     * A `did:jwk` carries the public key inside the identifier, so a
     * `cnf.kid` naming one can always be mapped back to the WSCD key that
     * signs for it - see [resolveSignerKey].
     */
    private val profile: InteropProfile = InteropProfile.DEFAULT,
) : KeystoreManager,
    WscdManager,
    // Extension state has to land in the same blob the credentials do, or
    // it does not reach the account's other devices - and [credentialsKeystore]
    // is the JweKeystore that owns this adapter's container.
    ExtensionStore by credentialsKeystore {

    constructor(signer: Signer) : this(signer, JweKeystore())

    constructor(signer: Signer, profile: InteropProfile) :
        this(signer, JweKeystore(profile = profile), profile)

    /**
     * Non-null only when [signer] is itself WSCD-backed (i.e. a
     * [UniFFISigner]) - a plain software [Signer] has no lifecycle or
     * plugin-registration concept.
     */
    private val wscdManager: WscdManager? = signer as? WscdManager

    private fun requireWscdManager(): WscdManager = wscdManager
        ?: throw UnsupportedOperationException(
            "WSCD lifecycle/plugin registration not supported - this keystore's signer is not WSCD-backed"
        )

    override suspend fun lifecycleStatus(pluginId: String, contextId: String): LifecycleStatus =
        requireWscdManager().lifecycleStatus(pluginId, contextId)

    override suspend fun registerLifecycle(request: RegisterLifecycleRequest): RegistrationOutcome =
        requireWscdManager().registerLifecycle(request)

    override suspend fun activateLifecycle(request: ActivateLifecycleRequest): ActivationOutcome =
        requireWscdManager().activateLifecycle(request)

    override suspend fun rotateLifecycle(request: RotateLifecycleRequest): RotationOutcome =
        requireWscdManager().rotateLifecycle(request)

    override suspend fun destroyLifecycle(request: DestroyLifecycleRequest): DestructionOutcome =
        requireWscdManager().destroyLifecycle(request)

    override fun registerFido2Plugin(transport: Ctap2TransportProvider) =
        requireWscdManager().registerFido2Plugin(transport)

    override fun registerFido2PluginWithState(transport: Ctap2TransportProvider, state: ByteArray) =
        requireWscdManager().registerFido2PluginWithState(transport, state)

    override fun exportFido2State(): ByteArray =
        requireWscdManager().exportFido2State()

    /**
     * The persisted (privatedata-synced) copy of every hardware-backed WSCD
     * plugin's key metadata - see [JweKeystore.exportWscdCredentials]'s doc
     * comment. Read this after [unlock] to restore a previously-enrolled
     * key via e.g. [registerFido2PluginWithState], rather than
     * [exportFido2State] which only reflects the CURRENT process's live
     * plugin state.
     */
    suspend fun exportWscdCredentialsState(): Map<String, String> =
        credentialsKeystore.exportWscdCredentials()

    /**
     * Record a WSCD plugin's freshly-exported key metadata so it round-trips
     * through privatedata on the next [exportEncryptedContainer] - see
     * [JweKeystore.setWscdCredentials].
     */
    suspend fun setWscdCredentialsState(pluginId: String, state: String) =
        credentialsKeystore.setWscdCredentials(pluginId, state)

    /**
     * The persisted (privatedata-synced) renewal candidates for every
     * credential batch - see [JweKeystore.exportCredentialRefreshTokens]'s
     * doc comment.
     */
    suspend fun exportCredentialRefreshTokens(): Map<Long, CredentialRefreshTokenEntry> =
        credentialsKeystore.exportCredentialRefreshTokens()

    /** See [JweKeystore.setCredentialRefreshToken]. */
    suspend fun setCredentialRefreshToken(batchId: Long, entry: CredentialRefreshTokenEntry) =
        credentialsKeystore.setCredentialRefreshToken(batchId, entry)

    /** See [JweKeystore.removeCredentialRefreshToken]. */
    suspend fun removeCredentialRefreshToken(batchId: Long) =
        credentialsKeystore.removeCredentialRefreshToken(batchId)

    override fun registerR2psPlugin(config: R2psConfig, transport: R2psTransportProvider) =
        requireWscdManager().registerR2psPlugin(config, transport)

    override val isUnlocked: Boolean get() = credentialsKeystore.isUnlocked

    override suspend fun unlock(
        prfOutput: ByteArray,
        encryptedContainer: ByteArray,
        hkdfSalt: ByteArray,
        hkdfInfo: ByteArray,
    ) {
        credentialsKeystore.unlock(prfOutput, encryptedContainer, hkdfSalt, hkdfInfo)
        // Restore the signer's own private keys (if it has any exportable -
        // see the class doc comment) from what credentialsKeystore just
        // parsed out of privatedata's own S.keypairs. Must happen before any
        // signer.generateKey() call in this session, since some plugins'
        // import replaces their whole registration.
        val restorable = credentialsKeystore.exportKeypairJwks().map { (kid, jwk) ->
            ExportedPrivateKeypair(keyId = kid, algorithm = "ES256", privateJwk = jwk)
        }
        if (restorable.isNotEmpty()) {
            signer.importPrivateKeypairs(restorable)
        }
    }

    override fun lock() {
        credentialsKeystore.lock()
    }

    /**
     * Attach the passkey's credential ID to a first-time (just-created) PRF
     * key entry once it's known after registration - see
     * [SirosWallet.finishRegistration].
     */
    override fun setCredentialId(credentialId: ByteArray) {
        credentialsKeystore.setCredentialId(credentialId)
    }

    override suspend fun generateKey(algorithm: String): String {
        checkUnlocked()
        return signer.generateKey(algorithm)
    }

    override suspend fun sign(keyId: String, payload: ByteArray, algorithm: String): ByteArray {
        checkUnlocked()
        return signer.sign(keyId, payload)
    }

    /** The pre-DIIP call shape: this keystore's own profile decides. */
    override suspend fun generateProof(audience: String, nonce: String, freshKey: Boolean): String =
        generateProof(audience, nonce, freshKey, holderBinding = null)

    override suspend fun generateProof(
        audience: String,
        nonce: String,
        freshKey: Boolean,
        holderBinding: HolderBinding?,
    ): String {
        checkUnlocked()
        var keys = signer.listKeys()
        if (keys.isEmpty() || freshKey) {
            // Auto-generate a key for VCI proof-of-possession
            val newKeyId = signer.generateKey("ES256")
            keys = if (freshKey) {
                // Use only the freshly generated key
                signer.listKeys().filter { it.keyId == newKeyId }
            } else {
                signer.listKeys()
            }
        }
        val key = keys.firstOrNull()
            ?: throw IllegalStateException("No keys available")
        val pubKeyJson = String(signer.exportPublicKey(key.keyId), Charsets.UTF_8)

        // DIIP requires the `jwt` proof type to carry the Holder's did:jwk as
        // `iss` and to name the key with a `kid` from that DID document; HAIP
        // carries the key in the header instead. The caller may know which
        // this issuer speaks; when it does not, this keystore's own profile
        // decides. The DID is derived from the public key rather than stored:
        // a did:jwk *is* its key, so it needs no bookkeeping and cannot drift
        // out of sync with the WSCD.
        val did = holderDidFor(pubKeyJson, holderBinding ?: profile.holderBinding)

        val headerBuilder = JWSHeader.Builder(jwsAlgorithm(key.algorithm))
            .type(com.nimbusds.jose.JOSEObjectType("openid4vci-proof+jwt"))
        if (did != null) {
            headerBuilder.keyID(didJwkKeyId(did))
        } else {
            headerBuilder.jwk(com.nimbusds.jose.jwk.JWK.parse(pubKeyJson))
        }
        val header = headerBuilder.build()

        val claimsBuilder = JWTClaimsSet.Builder()
            .audience(audience)
            .issueTime(Date())
            .claim("nonce", nonce)
        did?.let { claimsBuilder.issuer(it) }
        val claims = claimsBuilder.build()

        val signingInput = "${base64Url(header.toJSONObject())}.${base64Url(claims.toJSONObject())}"
        val signature = signer.sign(key.keyId, signingInput.toByteArray(Charsets.UTF_8))
        return "$signingInput.${base64UrlEncode(signature)}"
    }

    override suspend fun generateKeyProof(
        keyId: String,
        typ: String,
        issuer: String,
        audience: String,
        extraClaims: Map<String, String>,
    ): String {
        checkUnlocked()
        val key = signer.listKeys().firstOrNull { it.keyId == keyId }
            ?: throw IllegalStateException("Key not found: $keyId")
        val pubKeyJson = String(signer.exportPublicKey(keyId), Charsets.UTF_8)
        val pubJwk = com.nimbusds.jose.jwk.JWK.parse(pubKeyJson)

        val header = JWSHeader.Builder(jwsAlgorithm(key.algorithm))
            .type(com.nimbusds.jose.JOSEObjectType(typ))
            .jwk(pubJwk)
            .build()

        val claimsBuilder = JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(audience)
            .issueTime(Date())
            .expirationTime(Date(System.currentTimeMillis() + 5 * 60 * 1000))
            .jwtID(UUID.randomUUID().toString())
        extraClaims.forEach { (k, v) -> claimsBuilder.claim(k, v) }
        val claims = claimsBuilder.build()

        val signingInput = "${base64Url(header.toJSONObject())}.${base64Url(claims.toJSONObject())}"
        val signature = signer.sign(keyId, signingInput.toByteArray(Charsets.UTF_8))
        return "$signingInput.${base64UrlEncode(signature)}"
    }

    override suspend fun generateDPoPProof(
        keyId: String,
        htm: String,
        htu: String,
        nonce: String?,
        accessTokenHash: String?,
    ): String {
        checkUnlocked()
        val key = signer.listKeys().firstOrNull { it.keyId == keyId }
            ?: throw IllegalStateException("Key not found: $keyId")
        val pubJwk = com.nimbusds.jose.jwk.JWK.parse(String(signer.exportPublicKey(keyId), Charsets.UTF_8))

        val header = JWSHeader.Builder(jwsAlgorithm(key.algorithm))
            .type(com.nimbusds.jose.JOSEObjectType("dpop+jwt"))
            .jwk(pubJwk)
            .build()
        val claims = dpopClaims(htm, htu, nonce, accessTokenHash)

        val signingInput = "${base64Url(header.toJSONObject())}.${base64Url(claims.toJSONObject())}"
        val signature = signer.sign(keyId, signingInput.toByteArray(Charsets.UTF_8))
        return "$signingInput.${base64UrlEncode(signature)}"
    }

    override suspend fun signPresentation(nonce: String, audience: String, credentialIds: List<Long>, kid: String?): String {
        checkUnlocked()
        val keys = signer.listKeys()
        val key = selectSigningKey(keys, kid)

        val header = JWSHeader.Builder(jwsAlgorithm(key.algorithm))
            .keyID(key.keyId)
            .build()

        val claims = JWTClaimsSet.Builder()
            .audience(audience)
            .issueTime(Date())
            .claim("nonce", nonce)
            .jwtID(UUID.randomUUID().toString())
            .build()

        val signingInput = "${base64Url(header.toJSONObject())}.${base64Url(claims.toJSONObject())}"
        val signature = signer.sign(key.keyId, signingInput.toByteArray(Charsets.UTF_8))
        return "$signingInput.${base64UrlEncode(signature)}"
    }

    override suspend fun signVpToken(
        credential: String,
        disclosedClaims: List<String>?,
        nonce: String,
        audience: String,
        kid: String?,
    ): String {
        return signVpToken(credential, disclosedClaims, nonce, audience, null, kid)
    }

    /** Extended VP token signing with transaction data (Phase I: TS12 payment SCA). */
    suspend fun signVpToken(
        credential: String,
        disclosedClaims: List<String>?,
        nonce: String,
        audience: String,
        transactionData: List<TransactionDataItem>?,
        kid: String? = null,
    ): String {
        checkUnlocked()
        val keys = signer.listKeys()
        // The credential's own `cnf` is authoritative about which key it is
        // bound to and how that key is named - an issuer may bind by
        // `cnf.jwk` even when this wallet presents did:jwk identifiers, and
        // vice versa.
        val cnf = cnfOf(credential)
        val cnfKid = resolveCnfKid(cnf)
        val key = selectSigningKey(keys, kid ?: cnfKid)

        // Split SD-JWT
        val parts = credential.split("~")
        val issuerJwt = parts[0]
        val disclosures = parts.drop(1).filter { it.isNotEmpty() }

        // Filter disclosures
        val selected = if (!disclosedClaims.isNullOrEmpty()) {
            disclosures.filter { disclosure ->
                try {
                    val decoded = String(Base64.getUrlDecoder().decode(disclosure), Charsets.UTF_8)
                    val decodedArray = Json.parseToJsonElement(decoded)
                    // SD-JWT disclosures are JSON arrays [salt, name, value]
                    if (decodedArray is kotlinx.serialization.json.JsonArray && decodedArray.size >= 2) {
                        val name = decodedArray[1].toString().trim('"')
                        disclosedClaims.contains(name)
                    } else false
                } catch (_: Exception) { false }
            }
        } else disclosures

        // Build SD-JWT presentation
        val sdJwtPresentation = buildString {
            append(issuerJwt)
            selected.forEach { append("~$it") }
            append("~")
        }

        // sd_hash
        val sdHash = base64UrlEncode(
            MessageDigest.getInstance("SHA-256")
                .digest(sdJwtPresentation.toByteArray(Charsets.UTF_8))
        )

        // KB-JWT
        val pubKeyJson = String(signer.exportPublicKey(key.keyId), Charsets.UTF_8)
        // When the credential binds the holder by name (`cnf.kid`, which is
        // what DIIP requires), the KB-JWT names the same verification method
        // rather than re-embedding the key. A `cnf.jwk` binding keeps the
        // embedded-key form it was issued under.
        val bindsByKid = cnf?.get("jwk") == null && cnfKid != null
        val headerBuilder = JWSHeader.Builder(jwsAlgorithm(key.algorithm))
            .type(com.nimbusds.jose.JOSEObjectType("kb+jwt"))
        if (bindsByKid) {
            headerBuilder.keyID(cnfKid)
        } else {
            headerBuilder.jwk(com.nimbusds.jose.jwk.JWK.parse(pubKeyJson))
        }
        val header = headerBuilder.build()

        val claims = JWTClaimsSet.Builder()
            .audience(audience)
            .issueTime(Date())
            .claim("nonce", nonce)
            .claim("sd_hash", sdHash)

        // Include amr from WSCD security properties (E7: TS12 compliance).
        // NOTE: amr reflects the auth method from the *previous* sign operation
        // since we query it before signing the KB-JWT. This is acceptable because
        // WSCD-backed signing requires prior authentication, and the amr is
        // updated during that authentication phase (not during the sign itself).
        try {
            val props = signer.securityProperties(key.keyId)
            if (props.amr.isNotEmpty()) {
                claims.claim("amr", props.amr)
            }
        } catch (_: Exception) {
            // Security properties not available — omit amr
        }

        // Phase I: Transaction data hashes (TS12 payment SCA)
        if (!transactionData.isNullOrEmpty()) {
            val md = MessageDigest.getInstance("SHA-256")
            val hashes = transactionData.map { item ->
                base64UrlEncode(md.digest(item.rawJson.toByteArray(Charsets.UTF_8)))
            }
            claims.claim("transaction_data_hashes", hashes)
            claims.claim("transaction_data_hashes_alg", "sha-256")
            claims.jwtID(UUID.randomUUID().toString())
        }

        val claimsSet = claims.build()

        val signingInput = "${base64Url(header.toJSONObject())}.${base64Url(claimsSet.toJSONObject())}"
        val signature = signer.sign(key.keyId, signingInput.toByteArray(Charsets.UTF_8))
        val kbJwt = "$signingInput.${base64UrlEncode(signature)}"

        return sdJwtPresentation + kbJwt
    }

    override suspend fun signMdocPresentation(
        credentialBytes: ByteArray,
        disclosedClaims: List<String>?,
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        kid: String?,
    ): ByteArray {
        checkUnlocked()
        val keys = signer.listKeys()
        val key = selectSigningKey(keys, kid)

        val builder = MdocDeviceResponseBuilder(
            credentialBytes = credentialBytes,
            algorithm = key.algorithm,
        )

        return builder.build(
            nonce = nonce,
            audience = audience,
            responseUri = responseUri,
            verifierJwkThumbprint = verifierJwkThumbprint,
            disclosedClaims = disclosedClaims,
            signer = { data -> signer.sign(key.keyId, data) },
        )
    }

    override suspend fun signMdocPresentationForDCAPI(
        credentialBytes: ByteArray,
        disclosedClaims: List<String>?,
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        kid: String?,
    ): ByteArray {
        checkUnlocked()
        val keys = signer.listKeys()
        val key = selectSigningKey(keys, kid)

        val builder = MdocDeviceResponseBuilder(
            credentialBytes = credentialBytes,
            algorithm = key.algorithm,
        )

        return builder.buildForDCAPI(
            nonce = nonce,
            origin = origin,
            encryptionPublicJwkThumbprint = encryptionPublicJwkThumbprint,
            disclosedClaims = disclosedClaims,
            signer = { data -> signer.sign(key.keyId, data) },
        )
    }

    override suspend fun signMdocPresentationForProximity(
        credentialBytes: ByteArray,
        disclosedClaims: List<String>?,
        sessionTranscriptBytes: ByteArray,
        kid: String?,
    ): ByteArray {
        checkUnlocked()
        val keys = signer.listKeys()
        val key = selectSigningKey(keys, kid)

        val builder = MdocDeviceResponseBuilder(
            credentialBytes = credentialBytes,
            algorithm = key.algorithm,
        )

        return builder.buildForProximity(
            sessionTranscriptBytes = sessionTranscriptBytes,
            disclosedClaims = disclosedClaims,
            signer = { data -> signer.sign(key.keyId, data) },
        )
    }

    override suspend fun exportEncryptedContainer(): ByteArray {
        // Fold the signer's own private keys (if any are exportable - see
        // the class doc comment) into credentialsKeystore's own keypairs
        // before serializing, so they round-trip through privatedata
        // instead of only living in that signer's process memory.
        for (kp in signer.exportPrivateKeypairs()) {
            credentialsKeystore.importKeypairJwk(kp.keyId, kp.privateJwk)
        }
        return credentialsKeystore.exportEncryptedContainer()
    }

    override fun listKeys(): List<KeyInfo> {
        return runBlocking {
            signer.listKeys().map { KeyInfo(it.keyId, it.algorithm, 0L) }
        }
    }

    // ── Attestation (WSCD-specific) ─────────────────────────────────

    /**
     * Returns the attestation certificate chain for a key, if available.
     * For hardware-backed keys (FIDO2/CTAP2), this provides attestation
     * proving key provenance for OID4VCI proof of possession.
     */
    override suspend fun attestationChain(keyId: String): AttestationChain? {
        return signer.attestationChain(keyId)
    }

    /**
     * Export the public key in JWK format.
     */
    suspend fun exportPublicKey(keyId: String): ByteArray {
        return signer.exportPublicKey(keyId)
    }

    // ── Migration ───────────────────────────────────────────────────

    /**
     * Migrate a key to a different WSCD plugin.
     *
     * If the result is [MigrationResult.ReEnrollmentRequired], the wallet
     * should trigger credential re-issuance with the issuer.
     */
    suspend fun migrateKey(keyId: String, targetPlugin: String): MigrationResult {
        return signer.migrateKey(keyId, targetPlugin)
    }

    /**
     * Return the security properties for a key.
     */
    override suspend fun securityProperties(keyId: String): SignerSecurityProperties {
        return signer.securityProperties(keyId)
    }

    // ── Credential storage (delegated to credentialsKeystore) ───────

    override suspend fun saveCredential(id: Long, json: String) {
        credentialsKeystore.saveCredential(id, json)
    }

    override suspend fun getCredential(id: Long): String? {
        return credentialsKeystore.getCredential(id)
    }

    override suspend fun getAllCredentials(): Map<Long, String> {
        return credentialsKeystore.getAllCredentials()
    }

    override suspend fun deleteCredential(id: Long) {
        credentialsKeystore.deleteCredential(id)
    }

    override suspend fun clearCredentials() {
        credentialsKeystore.clearCredentials()
    }

    // ── Presentation-history storage (delegated to credentialsKeystore) ─

    override suspend fun savePresentationRecord(id: Long, json: String) {
        credentialsKeystore.savePresentationRecord(id, json)
    }

    override suspend fun getAllPresentationRecords(): Map<Long, String> {
        return credentialsKeystore.getAllPresentationRecords()
    }

    override suspend fun clearPresentationRecords() {
        credentialsKeystore.clearPresentationRecords()
    }

    override suspend fun generateKeypairs(count: Int): List<KeypairInfo> {
        checkUnlocked()
        require(count >= 1) { "count must be >= 1" }
        return (1..count).map {
            val keyId = generateKey("ES256")
            val pubData = signer.exportPublicKey(keyId)
            val pubJwk = kotlinx.serialization.json.Json.parseToJsonElement(
                String(pubData, Charsets.UTF_8)
            ) as kotlinx.serialization.json.JsonObject
            KeypairInfo(keyId = keyId, publicKeyJWK = pubJwk)
        }
    }

    override suspend fun generateKeyAttestation(nonce: String, count: Int): String {
        checkUnlocked()
        val keypairs = generateKeypairs(count)
        // Self-attestation: signed by one of the freshly generated keys
        // itself, matching the spec's "issued... by the Wallet's key
        // storage component itself" option - there's no separate wallet
        // provider or hardware attestation authority in this WSCD plugin.
        val signingKey = keypairs.first()
        val securityProps = try {
            signer.securityProperties(signingKey.keyId)
        } catch (_: Exception) {
            null
        }

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(com.nimbusds.jose.JOSEObjectType("key-attestation+jwt"))
            .jwk(com.nimbusds.jose.jwk.JWK.parse(signingKey.publicKeyJWK.toString()))
            .build()

        val claimsBuilder = JWTClaimsSet.Builder()
            .issueTime(Date())
            .claim("nonce", nonce)
            .claim(
                "attested_keys",
                keypairs.map { com.nimbusds.jose.jwk.JWK.parse(it.publicKeyJWK.toString()).toJSONObject() },
            )
        val keyStorage = securityProps?.keyStorage
            ?.takeIf { it.isNotEmpty() }
            ?.map { toIso18045AttackPotential(it) }
            ?.distinct()
            ?: listOf("iso_18045_basic")
        claimsBuilder.claim("key_storage", keyStorage)
        securityProps?.userAuthentication
            ?.takeIf { it.isNotEmpty() }
            ?.mapNotNull { toIso18045AttackPotential(it, omitIfNone = true) }
            ?.distinct()
            ?.takeIf { it.isNotEmpty() }
            ?.let { claimsBuilder.claim("user_authentication", it) }
        val claims = claimsBuilder.build()

        val signingInput = "${base64Url(header.toJSONObject())}.${base64Url(claims.toJSONObject())}"
        val signature = signer.sign(signingKey.keyId, signingInput.toByteArray(Charsets.UTF_8))
        return "$signingInput.${base64UrlEncode(signature)}"
    }

    // ── Private helpers ─────────────────────────────────────────────

    private fun checkUnlocked() {
        if (!isUnlocked) throw IllegalStateException("Keystore is locked")
    }

    /**
     * Pick the key to sign a presentation with. When [kid] is given (the
     * credential being presented has a known bound key - see
     * [StoredCredential.kid]), that EXACT key must be used - a wallet
     * holding more than one key (e.g. after a batch issuance where each
     * credential instance is bound to its own device key) would otherwise
     * silently sign every credential with whichever key happens to be
     * first, producing a structurally valid but cryptographically wrong
     * signature for every credential except that one. Throws rather than
     * silently falling back if the specified key isn't found, since signing
     * with a different key is never a safe substitute. [kid] is null only
     * for genuinely credential-less call shapes (e.g. [signPresentation]'s
     * legacy no-credential form), where "first available key" is the only
     * meaningful choice.
     */
    private suspend fun selectSigningKey(keys: List<SignerKeyInfo>, kid: String?): SignerKeyInfo {
        if (kid != null) {
            return resolveSignerKey(keys, kid)
                ?: throw IllegalStateException("Signing key '$kid' not found - this credential's bound key is unavailable")
        }
        return keys.firstOrNull() ?: throw IllegalStateException("No keys available for signing")
    }

    /**
     * Map the `kid` a credential names its holder key by onto the WSCD key
     * that signs for it.
     *
     * The WSCD assigns its own key ids (RFC 7638 thumbprints), but a
     * credential may name the key any of three ways: by that id, by a
     * `did:jwk` verification method, or by a thumbprint computed elsewhere
     * (an mdoc device key, an SD-JWT `cnf.jwk`). A `did:jwk` resolves
     * offline - the key is the identifier - so all three reduce to a
     * thumbprint comparison, and no mapping needs to be persisted.
     */
    private suspend fun resolveSignerKey(keys: List<SignerKeyInfo>, kid: String): SignerKeyInfo? {
        keys.firstOrNull { it.keyId == kid }?.let { return it }

        val wanted = thumbprintOfDidJwk(kid) ?: kid
        keys.firstOrNull { it.keyId == wanted }?.let { return it }

        return keys.firstOrNull { key ->
            runCatching {
                val jwk = com.nimbusds.jose.jwk.JWK.parse(
                    String(signer.exportPublicKey(key.keyId), Charsets.UTF_8),
                )
                jwk.toPublicJWK().computeThumbprint().toString() == wanted
            }.getOrDefault(false)
        }
    }

    /**
     * The JWK thumbprint of the key a `did:jwk` embeds, or null if [kid] is
     * not one of its verification methods - see
     * [org.siros.sdk.keystore.thumbprintOfDidJwk], which this mirrors for the
     * WSCD path. A did:jwk document has only `#0`, so any other fragment names
     * nothing and must not select a key.
     */
    private fun thumbprintOfDidJwk(kid: String): String? =
        org.siros.sdk.keystore.thumbprintOfDidJwk(kid)

    /**
     * The `did:jwk` for a public key, when this issuance identifies the
     * holder that way. Null for [HolderBinding.EMBEDDED_JWK], where the proof
     * carries the key instead of naming it.
     */
    private fun holderDidFor(publicKeyJson: String, binding: HolderBinding): String? {
        if (binding != HolderBinding.DID_JWK) return null
        return runCatching {
            createDidJwk(Json.parseToJsonElement(publicKeyJson) as kotlinx.serialization.json.JsonObject)
        }.getOrElse {
            // No fallback: DID_JWK is what this issuance negotiated, and the
            // embedded-jwk shape is a different profile the Issuer did not
            // agree to. Falling back would send a proof the Issuer cannot
            // verify and report it as success.
            throw KeystoreException("Could not derive a did:jwk for the negotiated DIIP holder binding", it)
        }
    }

    /**
     * The `cnf` claim of an SD-JWT credential, or null if it has none.
     */
    private fun cnfOf(credential: String): kotlinx.serialization.json.JsonObject? = runCatching {
        val payload = credential.substringBefore('~').split('.').getOrNull(1) ?: return@runCatching null
        val padded = payload.padEnd((payload.length + 3) / 4 * 4, '=')
        val decoded = String(Base64.getUrlDecoder().decode(padded), Charsets.UTF_8)
        (Json.parseToJsonElement(decoded) as? kotlinx.serialization.json.JsonObject)
            ?.get("cnf") as? kotlinx.serialization.json.JsonObject
    }.getOrNull()

    /**
     * Translate SIROS's internal WSCD key-storage/user-authentication
     * vocabulary (`software`/`hardware`/`trusted_execution`/`remote_hsm`,
     * see [SignerSecurityProperties]) into the OID4VCI Key Attestation JWT's
     * registered `iso_18045_*` attack-potential-resistance values.
     *
     * Confirmed via a real conformance-test issuer that passing the raw
     * internal string through unmapped (e.g. `"software"`) produces a
     * `key_storage`/`user_authentication` value the issuer doesn't
     * recognize - independently verified that our attestation JWT's
     * signature itself is cryptographically valid, so an unrecognized enum
     * value reaching a strict validator is the far more likely explanation
     * for a rejection than the signature math.
     *
     * Mappings are necessarily approximate (SIROS's vocabulary is coarser
     * than the ISO 18045 scale) - conservative/lower tiers are preferred
     * over overclaiming resistance we can't actually back up.
     */
    private fun toIso18045AttackPotential(raw: String, omitIfNone: Boolean = false): String? {
        if (raw.startsWith("iso_18045_")) return raw // already spec-compliant, pass through
        return when (raw.lowercase()) {
            "none" -> if (omitIfNone) null else "iso_18045_basic"
            "software" -> "iso_18045_basic"
            "hardware" -> "iso_18045_moderate"
            "trusted_execution" -> "iso_18045_enhanced-basic"
            "remote_hsm" -> "iso_18045_high"
            else -> "iso_18045_basic"
        }
    }

    private fun jwsAlgorithm(algorithm: String): JWSAlgorithm {
        return when (algorithm.uppercase()) {
            "ES256", "P-256" -> JWSAlgorithm.ES256
            "EDDSA", "ED25519" -> JWSAlgorithm.EdDSA
            else -> JWSAlgorithm.parse(algorithm)
        }
    }

    private fun base64Url(obj: Map<String, Any>): String {
        val jsonObj = kotlinx.serialization.json.JsonObject(
            obj.mapValues { (_, v) -> toJsonElement(v) }
        )
        val json = Json.encodeToString(
            kotlinx.serialization.json.JsonObject.serializer(),
            jsonObj
        )
        return base64UrlEncode(json.toByteArray(Charsets.UTF_8))
    }

    private fun toJsonElement(value: Any?): kotlinx.serialization.json.JsonElement {
        return when (value) {
            null -> kotlinx.serialization.json.JsonNull
            is Number -> kotlinx.serialization.json.JsonPrimitive(value)
            is Boolean -> kotlinx.serialization.json.JsonPrimitive(value)
            is String -> kotlinx.serialization.json.JsonPrimitive(value)
            is Map<*, *> -> kotlinx.serialization.json.JsonObject(
                (value as Map<String, Any?>).mapValues { (_, v) -> toJsonElement(v) }
            )
            is List<*> -> kotlinx.serialization.json.JsonArray(value.map { toJsonElement(it) })
            else -> kotlinx.serialization.json.JsonPrimitive(value.toString())
        }
    }

    private fun base64UrlEncode(data: ByteArray): String {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data)
    }
}
