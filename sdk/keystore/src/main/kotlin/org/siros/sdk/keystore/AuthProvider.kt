package org.siros.sdk.keystore

/**
 * Provides user authentication credentials when requested by the WSCD.
 *
 * Implement this interface in the wallet application to handle
 * PIN entry prompts and WebAuthn assertion ceremonies during
 * signing operations that require 2FA (e.g. R2PS remote signing).
 *
 * Note: These methods are called synchronously from a background thread.
 * Implementations that show UI should use platform mechanisms to
 * block until the user completes the interaction (e.g. runBlocking on Main).
 */
interface AuthProvider {
    /**
     * Request the user's PIN (e.g. for OPAQUE authentication, or a CTAP2
     * authenticator's ClientPin).
     *
     * @param pluginId Which registered WSCD plugin (e.g. "fido2", "r2ps")
     *   is asking - a single [AuthProvider] can back multiple plugins with
     *   very different PIN semantics (a real hardware secret vs. a fixed
     *   debug-only test value), so implementations MUST dispatch on this
     *   rather than guessing from ambient UI/app state. Confirmed via live
     *   hardware testing: guessing from a "currently selected dev-screen
     *   tab" signal silently sent the wrong plugin's PIN to a real YubiKey
     *   for an entire session, which the authenticator correctly rejected
     *   every time with no indication of the real cause.
     * @return The PIN as raw bytes (UTF-8 encoded).
     * @throws Exception if the user cancels.
     */
    fun requestPin(pluginId: String): ByteArray

    /**
     * The WSCD's PIN question with its context: ENTER the PIN of an authenticator that has one ([PinRequest.Enter]) or
     * CHOOSE one for an authenticator that has none ([PinRequest.Choose], asked twice by the SDK - once with `confirm`
     * false, once true - and compared by the SDK). Also carries why the user is asked again ([PinRequest.notice]).
     *
     * The default answers [PinRequest.Enter] through [requestPin] (so an existing implementation keeps working for every
     * authenticator that already has a PIN) and refuses [PinRequest.Choose]: an app that does not override this cannot set a
     * PIN, and enrolling a fresh authenticator fails with a cancelled-authentication error instead of sending a guess.
     * Return the PIN as UTF-8 bytes; throw to cancel.
     */
    fun requestPin(request: PinRequest): ByteArray = when (request) {
        is PinRequest.Enter -> requestPin(request.pluginId)
        is PinRequest.Choose -> throw UnsupportedOperationException("This AuthProvider cannot ask the user to choose a PIN")
    }

    /**
     * Request a WebAuthn assertion for the given parameters.
     *
     * @param pluginId Which registered WSCD plugin is asking - see
     *   [requestPin]'s doc comment for why implementations must dispatch on
     *   this rather than guessing.
     * @param challenge The authentication challenge bytes.
     * @param rpId The Relying Party ID.
     * @param allowedCredentials List of allowed credential IDs.
     * @return The CBOR-encoded authenticator assertion response.
     * @throws Exception if the user cancels or no credential is available.
     */
    fun requestWebauthnAssertion(
        pluginId: String,
        challenge: ByteArray,
        rpId: String,
        allowedCredentials: List<ByteArray>,
    ): ByteArray
}
