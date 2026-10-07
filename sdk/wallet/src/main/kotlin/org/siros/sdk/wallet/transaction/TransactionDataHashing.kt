// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import java.security.MessageDigest
import java.util.Base64

/** `transaction_data_hashes` (OpenID4VP 1.0 Appendix B; EC TS12 v1.0.1 3.6). */
internal object TransactionDataHashing {
    /** The `transaction_data_hashes_alg` names the SDK can compute, as IANA hash names. */
    val SUPPORTED: List<String> = org.siros.sdk.keystore.TransactionBinding.HASH_ALGS

    private const val SHA_256 = "sha-256"

    /** The algorithm when the verifier lists none (OpenID4VP 1.0 Appendix B). */
    const val DEFAULT = SHA_256

    private fun digest(alg: String): MessageDigest = MessageDigest.getInstance(
        when (alg) {
            SHA_256 -> "SHA-256"
            "sha-384" -> "SHA-384"
            "sha-512" -> "SHA-512"
            else -> throw IllegalArgumentException("unsupported hash algorithm '$alg'")
        },
    )

    /**
     * `base64url(HASH(ASCII bytes of raw))`, no padding.
     *
     * [raw] is hashed exactly as the verifier sent it: never decoded first
     * ("base64url decoding is not performed before hashing") and never
     * re-serialised, which key order, whitespace, escapes and number
     * formatting would change.
     */
    fun hash(raw: String, alg: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(digest(alg).digest(raw.toByteArray(Charsets.US_ASCII)))
}
