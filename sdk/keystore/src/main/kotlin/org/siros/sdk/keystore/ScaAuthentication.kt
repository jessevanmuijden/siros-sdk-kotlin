// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason

/**
 * Whether a key's signer could reach two authentication categories for an SCA
 * sign (EC TS12 v1.0.1 3.6), asked BEFORE the user is shown the transaction.
 * Asking never prompts and never signs.
 *
 * Only a signer that reaches two categories by its own means (a PIN it asks
 * for) is possible. A signer that reaches possession alone and would need the
 * host to vouch for a second factor is reported as [cannot]: the manager
 * refuses a fresh-authentication sign for exactly those signers, so offering
 * them would let the user consent and verify before a certain refusal.
 *
 * @property canReachTwoCategories the signer's own means reach two categories.
 * @property reason why not, when it cannot.
 */
class ScaAuthenticationCapability(
    val canReachTwoCategories: Boolean,
    val reason: String? = null,
) {
    /** Whether an SCA sign can possibly follow. */
    val isPossible: Boolean get() = canReachTwoCategories

    companion object {
        /** No two-category authentication can be established, for [reason]. */
        fun cannot(reason: String) = ScaAuthenticationCapability(false, reason)
    }
}

/** A signature and the factors the signer reports it applied to produce THIS signature. */
class ScaSignature(val signature: ByteArray, val factors: List<AuthenticationFactor>)

/**
 * One SCA sign: [declaredFactors] are what the KB-JWT will claim as its `amr`,
 * known before signing because the JWS covers the claims; [sign] performs the
 * signature with a fresh user authentication and reports the factors that were
 * ACTUALLY applied. The caller must discard the signature unless they match
 * ([requireMatching]): a claim the sign did not back is never emitted.
 *
 * Single use. [close] wipes anything secret held for the sign (a PIN typed
 * ahead of it); always call it.
 */
interface ScaSignSession : AutoCloseable {
    val declaredFactors: List<AuthenticationFactor>
    suspend fun sign(data: ByteArray): ScaSignature
    override fun close() {
        // Nothing secret is held by default; a session that holds a PIN overrides this to wipe it.
    }

    companion object {
        /**
         * Fails closed unless [applied], reported by the sign itself, is exactly
         * [declared] (as a set) and spans two categories.
         */
        fun requireMatching(declared: List<AuthenticationFactor>, applied: List<AuthenticationFactor>) {
            if (applied.map { it.category }.toSet().size < 2) {
                throw insufficient("The signing operation applied fewer than two authentication categories")
            }
            if (applied.toSet() != declared.toSet()) {
                throw insufficient("The authentication applied to the signing operation differs from the one claimed")
            }
        }

        fun insufficient(message: String) =
            TransactionDataError(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, message)
    }
}
