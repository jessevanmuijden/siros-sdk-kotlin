// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

/**
 * Why a request carrying OpenID4VP `transaction_data` (EC TS12 payment SCA)
 * was not answered with a presentation.
 *
 * The names and the [code] strings are shared, one for one, with the Swift
 * SDK (`TransactionDataError.Reason`), so a host app and the orchestrator see
 * the same reason whichever SDK produced it.
 *
 * @property code The cross-SDK reason code (lower camel case).
 * @property verifierError The OpenID4VP error the verifier is told:
 *   `invalid_transaction_data` for every refusal of the request itself, and
 *   `access_denied` when the user declined to confirm it.
 */
enum class TransactionDataReason(val code: String, val verifierError: String) {
    /** TS12 handling is off, or cannot run (no consent handler); the request is refused, never ignored. */
    DISABLED("disabled", INVALID_TRANSACTION_DATA),

    /** An entry is not a base64url-encoded JSON object, or lacks a usable `type` / `credential_ids`. */
    INVALID_ENTRY("invalidEntry", INVALID_TRANSACTION_DATA),

    /** The orchestrator's decoded copy of an entry disagrees with the entry's own `raw` encoding. */
    INCONSISTENT_WITH_ORCHESTRATOR("inconsistentWithOrchestrator", INVALID_TRANSACTION_DATA),

    /** The credential the entry is bound to is not an SD-JWT VC (TS12 v1.0.1 covers SD-JWT VC only). */
    UNSUPPORTED_FORMAT("unsupportedFormat", INVALID_TRANSACTION_DATA),

    /** The credential's type metadata does not carry the SCA category. */
    NOT_SCA_ATTESTATION("notScaAttestation", INVALID_TRANSACTION_DATA),

    /** The entry's `type` is neither declared by the type metadata nor a built-in TS12 type. */
    UNSUPPORTED_TYPE("unsupportedType", INVALID_TRANSACTION_DATA),

    /** The entry's `payload` does not satisfy the JSON Schema of its type. */
    SCHEMA_VIOLATION("schemaViolation", INVALID_TRANSACTION_DATA),

    /** The type metadata (or what it references) could not be obtained within bounds. */
    METADATA_UNAVAILABLE("metadataUnavailable", INVALID_TRANSACTION_DATA),

    /** None of the hash algorithms the verifier listed is supported. */
    UNSUPPORTED_HASH_ALGORITHM("unsupportedHashAlgorithm", INVALID_TRANSACTION_DATA),

    /** Fewer than two distinct authentication factor categories were established for this operation. */
    INSUFFICIENT_AUTHENTICATION_FACTORS("insufficientAuthenticationFactors", INVALID_TRANSACTION_DATA),

    /** No consent handler is registered, so the transaction cannot be shown to the user. */
    NO_CONSENT_HANDLER("noConsentHandler", INVALID_TRANSACTION_DATA),

    /** The user declined the transaction. */
    DECLINED("declined", ACCESS_DENIED),
}

private const val INVALID_TRANSACTION_DATA = "invalid_transaction_data"
private const val ACCESS_DENIED = "access_denied"

/**
 * Raised when a `transaction_data` request is refused or declined. Nothing
 * has been signed when this is thrown.
 *
 * [reason] is the machine-readable cause; the host app words it for the user
 * in its own language, and [verifierError] is what the verifier is told.
 */
class TransactionDataError(
    val reason: TransactionDataReason,
    message: String,
    cause: Throwable? = null,
) : SirosException(message, cause, errorCode = "transaction_data_${reason.name.lowercase()}") {
    /** The OpenID4VP error code to answer the verifier with. */
    val verifierError: String get() = reason.verifierError
}
