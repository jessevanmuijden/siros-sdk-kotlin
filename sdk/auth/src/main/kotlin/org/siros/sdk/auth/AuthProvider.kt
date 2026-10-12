package org.siros.sdk.auth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Authenticator abstraction for FIDO2/WebAuthn operations.
 * SDK consumers can provide their own implementation or use the
 * platform default ([CredentialManagerAuthProvider]).
 */
interface AuthProvider {
    /** Create a new passkey credential (registration). */
    suspend fun register(options: RegisterOptions): RegisterResult

    /** Authenticate with an existing passkey (assertion). */
    suspend fun authenticate(options: AuthenticateOptions): AuthenticateResult

    /**
     * Obtain PRF output for keystore key derivation via a standalone
     * assertion against [credentialId]. [rpId] is required, not optional or
     * inferred from the credential: a platform assertion request with an
     * empty rpId is rejected outright by some authenticator UIs (confirmed:
     * Google Play Services' FIDO2 full-screen UI crashes on it with
     * `IllegalArgumentException: rpId cannot be empty`) rather than falling
     * back to whatever RP the credential itself was created under.
     */
    suspend fun getPrfOutput(credentialId: ByteArray, salt: ByteArray, rpId: String): PrfOutput
}

data class RegisterOptions(
    val rpId: String,
    val rpName: String,
    val userId: ByteArray,
    val userName: String,
    val userDisplayName: String,
    val challenge: ByteArray,
    val attestation: String = "none",
    val authenticatorSelection: AuthenticatorSelection? = null,
    val prfSalt: ByteArray? = null,
)

data class AuthenticatorSelection(
    val authenticatorAttachment: String? = null,
    val residentKey: String = "required",
    val userVerification: String = "preferred",
)

data class RegisterResult(
    val credentialId: ByteArray,
    val attestationObject: ByteArray,
    val clientDataJSON: ByteArray,
    val prfOutput: PrfOutput? = null,
)

data class AuthenticateOptions(
    val rpId: String,
    val challenge: ByteArray,
    val allowCredentials: List<AllowCredential>? = null,
    val userVerification: String = "preferred",
    val prfSalt: ByteArray? = null,
    /**
     * Per-credential PRF salts, keyed by credential ID - mirrors WebAuthn's
     * `prf.evalByCredential` extension. Use this (instead of [prfSalt]) for a
     * discoverable-credential login where multiple candidate credentials
     * (different accounts, or multiple passkeys on one account) are in
     * play: which credential the user actually picks - and therefore which
     * salt applies - is only known once the ceremony resolves, so a single
     * fixed [prfSalt] can't work here. If both [allowCredentials] and this
     * are null/empty when this is non-empty, implementations should build
     * `allowCredentials` from this list's credential IDs. Takes priority
     * over [prfSalt] when non-empty.
     */
    val prfSaltsByCredential: List<Pair<ByteArray, ByteArray>>? = null,
)

data class AllowCredential(
    val id: ByteArray,
    val type: String = "public-key",
)

data class AuthenticateResult(
    val credentialId: ByteArray,
    val authenticatorData: ByteArray,
    val clientDataJSON: ByteArray,
    val signature: ByteArray,
    val userHandle: ByteArray?,
    val prfOutput: PrfOutput? = null,
)

data class PrfOutput(
    val first: ByteArray,
    val second: ByteArray? = null,
)

/** Session tokens returned after successful authentication. */
@Serializable
data class AuthSession(
    @SerialName("appToken") val appToken: String,
    val uuid: String,
    val displayName: String? = null,
    val username: String? = null,
    @SerialName("refreshToken") val refreshToken: String? = null,
    val did: String? = null,
    @SerialName("privateData") val privateData: String? = null,
    @SerialName("tenantId") val tenantId: String? = null,
)
