// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.nimbusds.jwt.JWTClaimsSet
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import java.util.UUID

/**
 * Authentication category of an EC TS12 `amr` entry (TS12 v1.0.1 3.6).
 *
 * @property wire the key of the single-key `amr` object.
 */
enum class AuthenticationCategory(val wire: String) {
    KNOWLEDGE("knowledge"),
    POSSESSION("possession"),
    INHERENCE("inherence"),
}

/**
 * One authentication factor applied to authorise a presentation, as an `amr`
 * entry of an SCA key binding JWT: `{"possession": "key_in_remote_wscd"}`.
 *
 * [method] must be one of the values TS12 v1.0.1 3.6 defines for [category];
 * anything else is rejected at construction, because an `amr` the verifier
 * cannot interpret is worse than none.
 */
class AuthenticationFactor(val category: AuthenticationCategory, val method: String) {
    init {
        require(method in METHODS.getValue(category)) {
            "'$method' is not a TS12 ${category.wire} method"
        }
    }

    /** The `amr` entry: a JSON object with this factor's single key. */
    internal fun toAmrEntry(): Map<String, String> = mapOf(category.wire to method)

    override fun equals(other: Any?): Boolean =
        other is AuthenticationFactor && other.category == category && other.method == method

    override fun hashCode(): Int = 31 * category.hashCode() + method.hashCode()

    override fun toString(): String = "${category.wire}:$method"

    companion object {
        /** The methods TS12 v1.0.1 3.6 defines, by category. */
        val METHODS: Map<AuthenticationCategory, Set<String>> = mapOf(
            AuthenticationCategory.KNOWLEDGE to setOf(
                "pin_less_than_6_digits", "pin_6_or_more_digits", "passphrase_less_than_8_chars",
                "passphrase_8_to_11_chars", "passphrase_12_or_more_chars", "pattern", "other",
            ),
            AuthenticationCategory.POSSESSION to setOf(
                "key_in_remote_wscd", "key_in_local_external_wscd", "key_in_local_internal_wscd",
                "key_in_local_native_wscd", "other",
            ),
            AuthenticationCategory.INHERENCE to setOf(
                "fingerprint_device", "fingerprint_external", "face_device", "face_external", "other",
            ),
        )
    }
}

/**
 * What an SCA presentation adds to the key binding JWT (EC TS12 v1.0.1 3.6):
 * `transaction_data_hashes`, `transaction_data_hashes_alg` (a **string**),
 * a fresh `jti`, `response_mode`, and an `amr` of at least two different
 * authentication categories.
 *
 * Built by the wallet after it has validated and obtained consent for the
 * transaction; the keystore only signs what it is given. [hashes] are
 * `base64url(HASH(ASCII bytes of the request's raw entry))` in the verifier's
 * order (OpenID4VP 1.0 Appendix B), computed by the caller.
 *
 * @throws TransactionDataError with `INSUFFICIENT_AUTHENTICATION_FACTORS`
 *   when [authenticationFactors] do not span two categories.
 * @throws IllegalArgumentException for an empty [hashes], an unknown
 *   [hashAlg] or a blank [responseMode].
 */
class TransactionBinding(
    hashes: List<String>,
    val hashAlg: String,
    val responseMode: String,
    authenticationFactors: List<AuthenticationFactor>,
) {
    /** Copied on construction: the caller's list cannot change what gets signed. */
    val hashes: List<String> = hashes.toList()

    /** The factors, copied on construction. */
    val authenticationFactors: List<AuthenticationFactor> = authenticationFactors.toList()

    init {
        require(hashes.isNotEmpty() && hashes.none { it.isEmpty() }) { "transaction_data_hashes must be non-empty" }
        require(hashAlg in HASH_ALGS) { "unsupported transaction_data_hashes_alg '$hashAlg'" }
        require(responseMode.isNotBlank()) { "response_mode is required" }
        if (authenticationFactors.map { it.category }.toSet().size < 2) {
            throw TransactionDataError(
                TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS,
                "An SCA presentation needs at least two different authentication categories; " +
                    "got ${authenticationFactors.map { it.category.wire }.distinct()}",
            )
        }
    }

    /** Adds this binding's claims to a key binding JWT under construction. */
    internal fun applyTo(claims: JWTClaimsSet.Builder) {
        claims.claim("transaction_data_hashes", hashes)
        claims.claim("transaction_data_hashes_alg", hashAlg)
        // A random (v4) UUID: 122 bits from SecureRandom, fresh per presentation.
        claims.jwtID(UUID.randomUUID().toString())
        claims.claim("response_mode", responseMode)
        claims.claim("amr", authenticationFactors.map { it.toAmrEntry() })
    }

    companion object {
        /** `transaction_data_hashes_alg` names the SDK can produce. */
        val HASH_ALGS: List<String> = listOf("sha-256", "sha-384", "sha-512")
    }
}
