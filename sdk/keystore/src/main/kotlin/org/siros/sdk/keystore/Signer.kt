package org.siros.sdk.keystore

/**
 * Minimal signing interface for raw key operations.
 *
 * Represents the cryptographic backend (WSCD) layer that performs
 * key generation, signing, and attestation. Implementations may use
 * software keys, hardware tokens (FIDO2/CTAP2), or remote HSMs (R2PS/PKCS#11).
 */
interface Signer {
    /**
     * Generate a new keypair.
     * @param algorithm Algorithm identifier (e.g. "ES256", "EdDSA").
     * @return The key ID of the generated key.
     */
    suspend fun generateKey(algorithm: String): String

    /**
     * Sign raw data with the specified key.
     * @param keyId ID of the key to use.
     * @param data Raw bytes to sign.
     * @return The signature bytes.
     */
    suspend fun sign(keyId: String, data: ByteArray): ByteArray

    /**
     * Whether an SCA sign (EC TS12 v1.0.1) with [keyId] could reach two
     * authentication categories. Never prompts. The default says it cannot: a
     * signer that does not report authentication factors must not be offered
     * for SCA.
     */
    suspend fun scaAuthenticationCapability(keyId: String): ScaAuthenticationCapability =
        ScaAuthenticationCapability.cannot("This signer does not report the authentication it applies")

    /**
     * Starts one SCA sign with [keyId]: a fresh user authentication whose factors
     * are reported by the signature itself (see [ScaSignSession]). The default refuses.
     *
     * @throws org.siros.sdk.credentials.TransactionDataError with
     *   `INSUFFICIENT_AUTHENTICATION_FACTORS` when two categories cannot be established.
     */
    suspend fun beginScaSign(keyId: String): ScaSignSession =
        throw ScaSignSession.insufficient("This signer does not report the authentication it applies")

    /** List all keys managed by this signer. */
    suspend fun listKeys(): List<SignerKeyInfo>

    /** Delete a key by ID. */
    suspend fun deleteKey(keyId: String)

    /**
     * Return the attestation certificate chain for a key, if available.
     *
     * For hardware-backed keys (FIDO2, CTAP2), this returns the
     * attestation statement certificate chain proving key provenance,
     * plus the client data hash the attestation signature was computed
     * over. For software keys, returns null.
     */
    suspend fun attestationChain(keyId: String): AttestationChain?

    /**
     * Export the public key in JWK format (JSON-encoded bytes).
     */
    suspend fun exportPublicKey(keyId: String): ByteArray

    /**
     * Migrate a key from one WSCD plugin to another.
     *
     * @param keyId the key to migrate.
     * @param targetPlugin the target plugin identifier.
     * @return the migration result.
     */
    suspend fun migrateKey(keyId: String, targetPlugin: String): MigrationResult

    /**
     * Return the security properties for a key.
     *
     * Reports key storage type, certification level, user authentication
     * methods, and AMR values. The [amr] field reflects the authentication
     * methods used in the most recent [sign] operation.
     */
    suspend fun securityProperties(keyId: String): SignerSecurityProperties

    /**
     * Export this signer's own private keys as spec-compliant JWKs
     * (privatedata-spec §6, `S.keypairs[].keypair.privateKey`), so a
     * software-backed signer's keys can be persisted through the same
     * PRF-protected container as everything else instead of being lost
     * whenever this signer's own backing process restarts.
     *
     * Only meaningful for plugins that hold exportable private key material
     * in the first place - there is nothing to export from a hardware-backed
     * or remote-HSM-backed key (their whole point is that the private key
     * never leaves the secure element/server). Default: unsupported, returns
     * empty - only the software ("softkey") plugin overrides this.
     */
    suspend fun exportPrivateKeypairs(): List<ExportedPrivateKeypair> = emptyList()

    /**
     * Restore keys previously returned by [exportPrivateKeypairs] - the
     * counterpart used after a fresh unlock to rehydrate a software-backed
     * signer's in-memory key store from privatedata's own `S.keypairs`.
     * Default: no-op, since only [exportPrivateKeypairs]'s overriders need
     * to accept keys back.
     */
    suspend fun importPrivateKeypairs(keypairs: List<ExportedPrivateKeypair>) {}
}

/**
 * A signer's own private key, exported as a full JWK (including the private
 * `d` parameter) so it can round-trip through privatedata's `S.keypairs`
 * array (privatedata-spec §6) - see [Signer.exportPrivateKeypairs].
 */
data class ExportedPrivateKeypair(
    val keyId: String,
    val algorithm: String,
    /** Full private JWK JSON, e.g. `{"kty":"EC","crv":"P-256","x":...,"y":...,"d":...}`. */
    val privateJwk: String,
)

/** Result of a key migration operation. */
sealed class MigrationResult {
    /** Key migrated successfully; contains the new key ID. */
    data class Migrated(val newKeyId: String) : MigrationResult()
    /** Migration requires full re-enrollment with the issuer. */
    data class ReEnrollmentRequired(val oldKeyId: String) : MigrationResult()
}

data class SignerKeyInfo(
    val keyId: String,
    val algorithm: String,
)

/**
 * A hardware-backed key's attestation evidence, as returned by
 * [Signer.attestationChain]. For the FIDO2/CTAP2 (previewSign) plugin -
 * currently the only plugin that returns non-null here - [certificates]
 * is a single-element list holding the *raw CBOR attestationObject* from
 * `authenticatorMakeCredential` (fmt/authData/attStmt), not a decoded
 * X.509 certificate chain; the backend does the CBOR decoding and x5c
 * extraction itself (see siros-wscd-manager's `AttestationChain` and
 * `FIDO2AttestationService.Verify` in go-wallet-backend). [clientDataHash]
 * is the client data hash the attestation signature was computed over.
 * Both are needed to register the attestation with the backend (see
 * BackendApiClient.registerFido2Attestation in the auth module).
 */
data class AttestationChain(
    val certificates: List<ByteArray>,
    val clientDataHash: ByteArray,
)

/**
 * Extended key metadata including plugin association and creation timestamp.
 * Intended for developer/diagnostic UIs.
 */
data class DetailedKeyInfo(
    val keyId: String,
    val algorithm: String,
    val pluginId: String,
    val createdAt: Long,
)

/**
 * Certification information for the WSCD (CS-04 §7.1.3, Annex C §C.3.1).
 * Either the string "none" for uncertified devices, or a structured object
 * with scheme and assurance level.
 *
 * Re-exported from credentials module for backward compatibility.
 */
typealias CertificationInfo = org.siros.sdk.credentials.CertificationInfo

/** Security properties reported by a [Signer] for a given key.
 *
 * Re-exported from credentials module for backward compatibility.
 */
typealias SignerSecurityProperties = org.siros.sdk.credentials.SignerSecurityProperties
