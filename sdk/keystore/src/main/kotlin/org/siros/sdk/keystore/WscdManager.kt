package org.siros.sdk.keystore

/**
 * Hardware-key-specific WSCD operations not part of the generic [Signer]/
 * [KeystoreManager] surface: additional-plugin registration (FIDO2
 * rawSign, R2PS remote HSM) and hardware-key lifecycle
 * (enroll/rotate/destroy).
 *
 * Only a WSCD-backed keystore (one wrapping a [UniFFISigner]) supports
 * this - obtain it via `SirosWallet.wscdManager`, which is `null` for the
 * default JWE-encrypted keystore or any other [KeystoreManager] that
 * isn't WSCD-backed.
 */
interface WscdManager : SignerLifecycleManager {
    /**
     * Register the FIDO2 previewSign (rawSign) plugin for hardware
     * authenticators (e.g. a YubiKey). All CTAP2 CBOR request-building/
     * response-parsing happens in Rust - [transport] only needs to move
     * raw command/response bytes over USB/BLE/NFC.
     */
    fun registerFido2Plugin(transport: Ctap2TransportProvider)

    /**
     * Register the FIDO2 plugin restored from a previously
     * [exportFido2State]-exported blob (credential handles + public keys,
     * no private material) - use instead of [registerFido2Plugin] when
     * restoring a wallet whose keys were enrolled in an earlier process,
     * so those keys stay addressable. Without this, an enrolled key's
     * `kid` still exists in credential/session metadata after an app
     * restart, but the plugin has no record of the credential handle
     * needed to sign with it again.
     */
    fun registerFido2PluginWithState(transport: Ctap2TransportProvider, state: ByteArray)

    /**
     * Export the FIDO2 plugin's current key state, to persist and later
     * restore via [registerFido2PluginWithState]. Throws if the fido2
     * plugin isn't registered.
     */
    fun exportFido2State(): ByteArray

    /**
     * Read-only description of the FIDO2 authenticator behind the registered `fido2` plugin: what it is, whether it has a PIN,
     * the minimum PIN length, the remaining PIN attempts and whether it can be enrolled. Never asks for or sends a PIN, never
     * changes the key, and uses the registered transport as it is (an already-open USB connection is reused; an NFC key
     * must be held to the phone for it). Throws if the fido2 plugin is not registered.
     */
    suspend fun describeFido2Authenticator(): Fido2AuthenticatorInfo

    /** Register the R2PS remote HSM plugin. */
    fun registerR2psPlugin(config: R2psConfig, transport: R2psTransportProvider)
}

/**
 * R2PS server connection parameters.
 *
 * @param clientKeyPem PEM-encoded P-256 client private key for the R2PS
 *   message envelope's JWS signing. Required for every session regardless
 *   of [authMode] - this identifies the client's own message channel, not
 *   the user-level authentication factor.
 * @param serverPublicKeyPem PEM-encoded P-256 server public key for JWE
 *   envelope encryption. Required for every session regardless of
 *   [authMode].
 */
data class R2psConfig(
    val serverUrl: String,
    val clientId: String,
    val context: String,
    val clientKeyPem: String,
    val serverPublicKeyPem: String,
    val authMode: R2psAuthMode,
)

/**
 * R2PS user-authentication mode. OPAQUE (RFC 9807) PAKE crypto is handled
 * entirely in Rust (`r2ps-client`) - no PAKE client is needed here.
 */
sealed class R2psAuthMode {
    /** Password-based OPAQUE authentication. */
    data object Opaque : R2psAuthMode()

    /** WebAuthn/FIDO2-based authentication (SCAL2-compliant SAD binding). */
    data class WebAuthn(
        val rpId: String,
        val allowedCredentialIds: List<String>,
    ) : R2psAuthMode()
}

/** HTTP transport for R2PS protocol messages. */
fun interface R2psTransportProvider {
    suspend fun send(body: ByteArray): ByteArray
}
