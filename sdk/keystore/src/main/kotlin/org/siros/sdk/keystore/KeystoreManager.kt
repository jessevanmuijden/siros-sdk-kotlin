package org.siros.sdk.keystore

import org.siros.sdk.credentials.KeystoreException
import org.siros.sdk.credentials.interop.HolderBinding

/**
 * Manages encrypted credential key storage.
 *
 * The keystore is unlocked using a PRF-derived key (from WebAuthn)
 * and contains private keys for credential signing operations.
 * The encrypted container is synchronized with the backend for
 * cross-device portability.
 *
 * This interface intentionally does NOT bind to platform-native key storage.
 * A future Signer abstraction layer will enable hardware-backed keys.
 */
interface KeystoreManager {
    /** Whether the keystore is currently unlocked and usable. */
    val isUnlocked: Boolean

    /**
     * Unlock the keystore using PRF-derived key material.
     *
     * @param prfOutput   raw PRF output from the WebAuthn authenticator.
     * @param encryptedContainer the JWE container (may be empty for first-time setup).
     * @param hkdfSalt    HKDF extraction salt (32 bytes).
     * @param hkdfInfo    HKDF expansion info (e.g. "eDiplomas PRF").
     */
    suspend fun unlock(
        prfOutput: ByteArray,
        encryptedContainer: ByteArray,
        hkdfSalt: ByteArray = ByteArray(32),
        hkdfInfo: ByteArray = "eDiplomas PRF".toByteArray(Charsets.UTF_8),
    )

    /** Lock the keystore, clearing key material from memory. */
    fun lock()

    /**
     * Attach the passkey's credential ID to a first-time (just-created) PRF
     * key entry once it's known, immediately after registration - see
     * `SirosWallet.finishRegistration`. No-op by default; only implementations
     * that maintain a PRF-keyed container (e.g. [JweKeystore],
     * [WscdKeystoreAdapter]) need to act on this.
     */
    fun setCredentialId(credentialId: ByteArray) {}

    /** Generate a new keypair and return the key ID. */
    suspend fun generateKey(algorithm: String = "ES256"): String

    /**
     * Sign a payload with the specified key.
     * @param keyId the key identifier
     * @param payload the data to sign
     * @param algorithm signing algorithm (e.g. "ES256")
     * @return the signature bytes
     */
    suspend fun sign(keyId: String, payload: ByteArray, algorithm: String = "ES256"): ByteArray

    /**
     * Generate a proof JWT for credential issuance (c_nonce binding).
     *
     * @param audience the credential issuer URL
     * @param nonce the c_nonce value from the issuer
     * @param holderBinding how to name the Holder's key - see
     *   [HolderBinding]. This is the one place HAIP and DIIP genuinely
     *   disagree, and OID4VCI allows only one of `jwk` and `kid` in a proof
     *   header, so it has to be decided per issuance: an Issuer that does not
     *   resolve DIDs cannot verify a DIIP-shaped proof, and a DIIP
     *   conformance suite will not accept a HAIP-shaped one. Null (the
     *   default) uses whatever profile this keystore was built for, which is
     *   the right answer whenever the caller has nothing more specific to go
     *   on.
     * @return the signed proof JWT
     */
    suspend fun generateProof(
        audience: String,
        nonce: String,
        freshKey: Boolean = false,
    ): String

    /**
     * [generateProof] with the Holder binding decided per issuance.
     *
     * Open with a default rather than abstract so that an implementation
     * written before DIIP - including a host's own [KeystoreManager] - keeps
     * compiling and linking. `null` and [HolderBinding.EMBEDDED_JWK] forward
     * to the three-argument [generateProof] unchanged, since an
     * implementation written before DIIP existed can only ever have
     * produced the HAIP/`EMBEDDED_JWK` shape - forwarding is exactly
     * honouring the request. [HolderBinding.DID_JWK] is different: this
     * conformer has no way to produce a did:jwk-shaped proof, and silently
     * emitting the HAIP shape instead is not a safe fallback - it is a
     * proof a DIIP-only Issuer will reject, sent as if it had been
     * negotiated correctly. The keystores in this SDK override this method
     * and handle [HolderBinding.DID_JWK] for real (see
     * [JweKeystore]/[WscdKeystoreAdapter], including over a hardware-backed
     * WSCD key: a did:jwk is a pure function of the public key, so no WSCD
     * plugin needs special-casing); only a third-party conformer that
     * hasn't gets this default.
     */
    suspend fun generateProof(
        audience: String,
        nonce: String,
        freshKey: Boolean,
        holderBinding: HolderBinding?,
    ): String {
        if (holderBinding == HolderBinding.DID_JWK) {
            throw KeystoreException(
                "This KeystoreManager does not implement generateProof(..., holderBinding) " +
                    "and so cannot produce a did:jwk-shaped (DIIP) proof - refusing rather than " +
                    "silently emitting a HAIP-shaped proof a DIIP-only Issuer would reject.",
            )
        }
        return generateProof(audience, nonce, freshKey)
    }

    /**
     * Sign a verifiable presentation for OID4VP.
     * @param nonce the verifier nonce
     * @param audience the verifier URL
     * @param credentialIds the credential identifiers to include
     * @param kid the key ID bound to the credential(s) being presented (see
     *   [StoredCredential.kid]) - when non-null, signing MUST use exactly
     *   this key (throwing if it isn't available) rather than an arbitrary
     *   one, since a wallet holding more than one key (e.g. after a batch
     *   issuance where each credential instance is bound to its own device
     *   key) would otherwise silently sign with the wrong key for every
     *   credential except whichever one happens to be first. Null (the
     *   legacy no-credential-context call shape) preserves the old
     *   first-available-key behavior.
     * @return the signed VP JWT
     */
    suspend fun signPresentation(nonce: String, audience: String, credentialIds: List<Long>, kid: String? = null): String

    /**
     * Build a complete SD-JWT VP token with Key Binding JWT.
     *
     * Takes the raw SD-JWT credential, filters disclosures to only those
     * matching [disclosedClaims], computes the `sd_hash`, and signs a
     * KB-JWT with `typ: "kb+jwt"` and the holder's public key in `jwk`.
     *
     * The returned string is the full VP token:
     * `IssuerJWT~disclosure1~...~disclosureN~KB-JWT`
     *
     * @param credential the raw SD-JWT credential string.
     * @param disclosedClaims claim names to selectively disclose (null = all).
     * @param nonce the verifier-provided nonce.
     * @param audience the verifier's client_id.
     * @param kid the key ID bound to this credential (see
     *   [StoredCredential.kid]) - see [signPresentation]'s doc comment for
     *   why this must be the exact key, not an arbitrary available one.
     * @return the assembled VP token string.
     */
    suspend fun signVpToken(
        credential: String,
        disclosedClaims: List<String>?,
        nonce: String,
        audience: String,
        kid: String? = null,
    ): String

    /**
     * As [signVpToken], for an SCA presentation that binds OpenID4VP
     * `transaction_data` (EC TS12): the KB-JWT additionally carries the
     * claims of [transaction] and no other `amr`.
     *
     * The default refuses: a keystore that does not override it cannot
     * produce a compliant SCA key binding JWT, and must not fall back to
     * signing one without the transaction hashes.
     *
     * @throws KeystoreException from the default implementation.
     */
    suspend fun signVpToken(
        credential: String,
        disclosedClaims: List<String>?,
        nonce: String,
        audience: String,
        kid: String?,
        transaction: TransactionBinding,
    ): String = throw KeystoreException(
        "This keystore cannot bind transaction_data to a presentation",
        errorCode = "transaction_data_unsupported_keystore",
    )

    /**
     * Build an mDoc DeviceResponse (ISO 18013-5) for OID4VP presentation.
     *
     * @param credentialBytes Raw CBOR bytes of the IssuerSigned structure.
     * @param disclosedClaims Claim names to disclose (null = all).
     * @param nonce Verifier-provided nonce.
     * @param audience Verifier client_id.
     * @param responseUri Verifier response endpoint URI.
     * @param verifierJwkThumbprint Optional JWK thumbprint for session transcript.
     * @param kid the key ID bound to this credential (see
     *   [StoredCredential.kid]) - the DeviceResponse's `deviceSignature` MUST
     *   be produced with the exact device key this credential's MSO
     *   `deviceKeyInfo.deviceKey` embeds; see [signPresentation]'s doc
     *   comment for why signing with an arbitrary available key is unsafe.
     * @return Base64url-encoded DeviceResponse CBOR bytes.
     */
    suspend fun signMdocPresentation(
        credentialBytes: ByteArray,
        disclosedClaims: List<String>?,
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        kid: String? = null,
    ): ByteArray {
        throw UnsupportedOperationException("mDoc presentation not supported by this keystore")
    }

    /**
     * Build an mDoc DeviceResponse (ISO 18013-5) for OID4VP presentation via
     * the W3C Digital Credentials API, using the `OpenID4VPDCAPIHandover`
     * session transcript (OpenID4VP 1.0 Appendix B.2.6) instead of
     * [signMdocPresentation]'s redirect-flow `OpenID4VPHandover`.
     *
     * @param credentialBytes Raw CBOR bytes of the IssuerSigned structure.
     * @param disclosedClaims Claim names to disclose (null = all).
     * @param nonce Verifier-provided nonce.
     * @param origin The verified browser/page origin that called `navigator.credentials.get()`.
     * @param encryptionPublicJwkThumbprint JWK thumbprint of the verifier's response-encryption
     *   key (present when `response_mode=dc_api.jwt`), null otherwise.
     * @param kid the key ID bound to this credential (see [signMdocPresentation]'s doc comment).
     * @return Base64url-encoded DeviceResponse CBOR bytes.
     */
    suspend fun signMdocPresentationForDCAPI(
        credentialBytes: ByteArray,
        disclosedClaims: List<String>?,
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        kid: String? = null,
    ): ByteArray {
        throw UnsupportedOperationException("mDoc DC API presentation not supported by this keystore")
    }

    /**
     * Build an mDoc DeviceResponse (ISO 18013-5) for a proximity (BLE)
     * presentation, using the caller-supplied proximity `SessionTranscript`
     * bytes (§9.1.5.1) instead of [signMdocPresentation]'s redirect-flow
     * `OpenID4VPHandover` or [signMdocPresentationForDCAPI]'s
     * `OpenID4VPDCAPIHandover` - see `ProximitySessionTranscript`'s doc
     * comment for how that transcript is built from the device engagement,
     * reader key, and handover context.
     *
     * @param credentialBytes Raw CBOR bytes of the IssuerSigned structure.
     * @param disclosedClaims Claim names to disclose (null = all).
     * @param sessionTranscriptBytes CBOR-encoded proximity `SessionTranscript`.
     * @param kid the key ID bound to this credential (see [signMdocPresentation]'s doc comment).
     * @return CBOR-encoded DeviceResponse bytes.
     */
    suspend fun signMdocPresentationForProximity(
        credentialBytes: ByteArray,
        disclosedClaims: List<String>?,
        sessionTranscriptBytes: ByteArray,
        kid: String? = null,
    ): ByteArray {
        throw UnsupportedOperationException("mDoc proximity presentation not supported by this keystore")
    }

    /** Export the encrypted container for backend sync. */
    suspend fun exportEncryptedContainer(): ByteArray

    /** List all key IDs in the keystore. */
    fun listKeys(): List<KeyInfo>

    // ── Credential storage (PRF-encrypted alongside keys) ───────────

    /**
     * Store a credential's raw JSON inside the encrypted container. [id] is
     * privatedata-spec's `credentialId` (a uint32-range number, see
     * `StoredCredential.id`) - a real JSON number on the wire, not a string.
     */
    suspend fun saveCredential(id: Long, json: String)

    /** Get a stored credential's raw JSON by ID. Returns null if not found. */
    suspend fun getCredential(id: Long): String?

    /** Get all stored credential JSON blobs (id → json). */
    suspend fun getAllCredentials(): Map<Long, String>

    /** Remove a credential by ID. */
    suspend fun deleteCredential(id: Long)

    /** Remove all stored credentials. */
    suspend fun clearCredentials()

    // ── Presentation-history storage (PRF-encrypted alongside keys) ─

    /**
     * Store a presentation record's raw JSON inside the encrypted container.
     * [id] is privatedata-spec's `presentationId` (a uint32-range number,
     * see `PresentationRecord.id`).
     */
    suspend fun savePresentationRecord(id: Long, json: String)

    /** Get all stored presentation-record JSON blobs (id → json). */
    suspend fun getAllPresentationRecords(): Map<Long, String>

    /** Remove all stored presentation records. */
    suspend fun clearPresentationRecords()

    /**
     * Generate [count] keypairs and return their public JWKs.
     * Used for key attestation requests.
     *
     * Default implementation throws [UnsupportedOperationException] so
     * existing implementations continue to compile without attestation support.
     */
    suspend fun generateKeypairs(count: Int): List<KeypairInfo> {
        throw UnsupportedOperationException("generateKeypairs not supported by this keystore")
    }

    /**
     * Get the security properties for this keystore's signing keys.
     * Used to populate KA JWT claims (CS-04 §7.1.3, Annex C §C.3.1).
     *
     * Default returns null (security properties not available).
     */
    suspend fun securityProperties(): SignerSecurityProperties? = null

    /**
     * Get the security properties for a specific key, as reported by the
     * underlying WSCD/signer. Used to populate a real backend-issued Key
     * Attestation request's `security_properties` (CS-04 §7.1.3, Annex C
     * §C.3.1) with the properties of the actual freshly-generated
     * attestation keys, rather than the batch-agnostic [securityProperties]
     * above.
     *
     * Default returns null (security properties not available).
     */
    suspend fun securityProperties(keyId: String): SignerSecurityProperties? = null

    /**
     * Return the attestation certificate chain for a key, if available -
     * see [Signer.attestationChain]. Default returns null (attestation not
     * available); only a WSCD-backed keystore with a hardware-attesting
     * plugin (e.g. FIDO2/CTAP2) actually has one to return.
     */
    suspend fun attestationChain(keyId: String): AttestationChain? = null

    /**
     * Generate [count] fresh keypairs and build a single OID4VCI `attestation`
     * proof-type Key Attestation JWT (spec: "Key Attestation in JWT format",
     * proof type Appendix "attestation Proof Type") covering all of them via
     * the `attested_keys` claim.
     *
     * Unlike the `jwt` proof type (one proof of possession per credential in
     * the batch), the spec requires exactly one Key Attestation JWT per
     * request regardless of [count] - the issuer is expected to mint one
     * credential per entry in `attested_keys`.
     *
     * Default implementation throws [UnsupportedOperationException] so
     * existing implementations continue to compile without attestation support.
     */
    suspend fun generateKeyAttestation(nonce: String, count: Int): String {
        throw UnsupportedOperationException("generateKeyAttestation not supported by this keystore")
    }

    /**
     * Build a self-signed JWT proof for an existing key: header `{typ, jwk =
     * that key's own public JWK}`, claims `{iss, aud, iat, exp, jti, ...extraClaims}`.
     *
     * Used for OAuth Client Attestation PoP JWTs (draft-ietf-oauth-attestation-based-client-auth-10
     * §3.1) - both the one-time proof sent to this wallet's own backend to
     * obtain a Wallet Instance Attestation (WIA) (`audience` = the wallet
     * provider/backend, `extraClaims = {"nonce": <challenge>}`), and the
     * per-issuance-flow proof sent (via the backend, forwarded as an HTTP
     * header) to a credential issuer's authorization server alongside that
     * WIA (`audience` = the issuer's AS, `extraClaims = {"challenge": ...}`
     * when the AS publishes a `challenge_endpoint`).
     *
     * [issuer] is the caller's choice, not derived from the key - per the
     * spec, `iss` should be the same OAuth `client_id` this wallet uses in
     * the flow (matching the WIA's own `sub` claim, see
     * `BackendApiClient.generateWIA`'s `clientId` param), not an instance
     * identifier (that's what `cnf.jkt`, computed server-side from this
     * proof's `jwk` header, is for).
     *
     * Deliberately takes an existing [keyId] rather than managing "the
     * instance key" internally - callers are responsible for generating one
     * persistent key (via [generateKey]) and remembering its ID across app
     * restarts (the backend's WIA tracks/revokes wallet instances by this
     * key's JWK thumbprint, so reusing a different key each time would
     * silently register a new "instance" every call).
     *
     * Default implementation throws [UnsupportedOperationException] so
     * existing implementations continue to compile without attestation support.
     */
    suspend fun generateKeyProof(
        keyId: String,
        typ: String,
        issuer: String,
        audience: String,
        extraClaims: Map<String, String> = emptyMap(),
    ): String {
        throw UnsupportedOperationException("generateKeyProof not supported by this keystore")
    }

    /**
     * Sign an RFC 9449 DPoP proof JWT (`typ: dpop+jwt`, public key in the
     * `jwk` header) with [keyId] over the HTTP method [htm] and URL [htu].
     * [nonce] is the server-provided DPoP nonce (§8) and [accessTokenHash]
     * the `ath` claim for resource requests, both omitted when null. Fresh
     * `jti` and `iat` per call. Answers the engine's `sign_client_auth` sign
     * request (go-wallet-backend#317), where the same key is the WIA `cnf`
     * key so the sender-constrained token is bound to the attested key.
     */
    suspend fun generateDPoPProof(
        keyId: String,
        htm: String,
        htu: String,
        nonce: String? = null,
        accessTokenHash: String? = null,
    ): String {
        throw UnsupportedOperationException("generateDPoPProof not supported by this keystore")
    }
}

data class KeyInfo(
    val keyId: String,
    val algorithm: String,
    val createdAt: Long,
)

data class KeypairInfo(
    val keyId: String,
    val publicKeyJWK: kotlinx.serialization.json.JsonObject,
)
