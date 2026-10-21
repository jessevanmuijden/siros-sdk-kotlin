// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

/**
 * Base exception type for the SIROS Wallet SDK.
 *
 * All SDK-specific exceptions extend this class, allowing integrators
 * to catch every SDK error uniformly:
 *
 * ```kotlin
 * try {
 *     wallet.login()
 * } catch (e: SirosException) {
 *     // handle any SDK error
 * }
 * ```
 *
 * Subtypes enable fine-grained recovery:
 * ```kotlin
 * try { wallet.login() }
 * catch (e: NetworkException) { /* retry later */ }
 * catch (e: AuthException)    { /* re-authenticate */ }
 * catch (e: KeystoreException) { /* keystore corrupt / locked */ }
 * catch (e: SirosException)   { /* generic fallback */ }
 * ```
 *
 * Each exception carries a machine-readable [errorCode] that consuming
 * applications can map to localized user-facing messages:
 * ```kotlin
 * val resId = when (e.errorCode) {
 *     "network_timeout" -> R.string.error_network_timeout
 *     "auth_failed" -> R.string.error_auth_failed
 *     else -> R.string.error_generic
 * }
 * ```
 */
open class SirosException(
    message: String,
    cause: Throwable? = null,
    /** Machine-readable error code for i18n mapping. */
    val errorCode: String = "unknown_error",
) : Exception(message, cause)

/** Raised when a network request fails (timeout, DNS, connection refused). */
class NetworkException(
    message: String,
    cause: Throwable? = null,
    errorCode: String = "network_error",
) : SirosException(message, cause, errorCode)

/** Raised when authentication or authorization fails (401, token expired, WebAuthn error). */
class AuthException @JvmOverloads constructor(
    message: String,
    cause: Throwable? = null,
    errorCode: String = "auth_failed",
    /** HTTP status code when the failure came from an AS/Backend HTTP response. */
    val code: Int? = null,
    /**
     * The server's own user-facing explanation (`message` in the error body),
     * when it sent one - e.g. the text a SID-AUTH-06 `WALLET_SUSPENDED` /
     * `WALLET_REVOKED` refusal carries to tell the two cases apart for the
     * user. [message] stays the developer-facing diagnostic.
     */
    val serverMessage: String? = null,
) : SirosException(message, cause, errorCode) {

    /**
     * The `scope` of a SID-AUTH-06 lifecycle refusal (`instance` or `wallet`),
     * when the server sent one. It is the only machine-readable way to tell a
     * revoked wallet instance from a deactivated wallet, because both answer
     * with `WALLET_REVOKED`; see
     * [org.siros.sdk.auth.WalletLifecycleRefusal.fromRefusal]. Null against a
     * backend that does not send it yet, which must be read as the
     * per-instance case.
     */
    var serverScope: String? = null
        private set

    /**
     * As the primary constructor, plus [serverScope].
     *
     * Deliberately a *secondary* constructor taking every parameter with no
     * defaults, rather than a sixth parameter on the primary one. Appending to
     * the primary constructor would have broken this published module twice
     * over: it removes the five-argument JVM descriptor that Java callers
     * bind to, and it renumbers the synthetic descriptor that Kotlin callers
     * bind to when they rely on default arguments. Either leaves an
     * already-compiled consumer with a NoSuchMethodError instead of a
     * recompile. Having no defaults of its own, this overload adds a
     * descriptor without disturbing any existing one.
     */
    constructor(
        message: String,
        cause: Throwable?,
        errorCode: String,
        code: Int?,
        serverMessage: String?,
        serverScope: String?,
    ) : this(message, cause, errorCode, code, serverMessage) {
        this.serverScope = serverScope
    }
}

/** Raised when keystore operations fail (locked, corrupt container, decryption error). */
class KeystoreException(
    message: String,
    cause: Throwable? = null,
    errorCode: String = "keystore_error",
) : SirosException(message, cause, errorCode)

/**
 * Raised when the private-data container carries a version this SDK does not implement, so it
 * REFUSES to rewrite it (privatedata-spec 2.8, section 6): rewriting would drop or corrupt what a
 * newer (or older, unmigrated) client wrote. It is not a failed merge and not a corrupt container;
 * nothing was changed, nothing was uploaded, and the remedy is to update the SDK (or, for
 * [Kind.STATE_VERSION] below 3, to open the wallet once in a client that migrates it).
 *
 * Reading is unaffected: the container is still unlocked and its credentials are readable.
 */
class UnsupportedSchemaVersionException(
    message: String,
    /** What the SDK does not implement. */
    val kind: Kind,
    /** The `schemaVersion` found (of `S` or of the event), or null when absent or not an integer. */
    val schemaVersion: Int?,
    /** The unknown event type, for [Kind.EVENT_TYPE]; otherwise null. */
    val eventType: String? = null,
) : SirosException(message, null, "unsupported_schema_version") {
    enum class Kind {
        /** `S.schemaVersion` is not one this SDK rewrites. */
        STATE_VERSION,

        /** An event carries a `schemaVersion` this SDK does not implement. */
        EVENT_VERSION,

        /** An event has a `type` that the schema versions this SDK implements do not define. */
        EVENT_TYPE,
    }
}

/** Raised for wallet-level orchestration errors. */
open class WalletException(
    message: String,
    cause: Throwable? = null,
    errorCode: String = "wallet_error",
) : SirosException(message, cause, errorCode)

/** Raised when the backend returns an HTTP error. */
class BackendApiException(
    val code: Int,
    message: String,
    val body: String? = null,
) : SirosException(message, errorCode = "backend_api_$code")
