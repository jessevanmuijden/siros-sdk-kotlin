// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORObject
import java.security.MessageDigest
import org.siros.sdk.credentials.mdoc.DocumentMdoc

/**
 * The `nym_auth` commitment `ssc = SHA256(secret_seed)`: sizes, the opening check and the mdoc element lookup. The
 * commitment claim of a credential is read by Credential Auxiliary Data v0.1 ([AuxiliaryDataV01.claimStatus]).
 *
 * Every read is strict and fails closed: a value that is absent, duplicated, of the wrong type or of
 * the wrong length is `null`, never a best guess. Nothing here logs or returns a seed.
 */
object SecretSeedCommitment {
    /** `secret_seed` length in bytes (rulebook). */
    const val SEED_BYTES = 16

    /** `ssc` length in bytes: a SHA-256 digest. */
    const val COMMITMENT_BYTES = 32

    /**
     * The value of the element [name] in the credential's own doctype namespace (the one a nym_auth
     * credential carries its claims in, and the one the circuit binds), or null when that namespace or
     * element is absent or the element occurs more than once there. The same element name in another
     * namespace is never consulted.
     */
    fun doctypeElement(document: DocumentMdoc, name: String): CBORObject? {
        val matches = document.issuerSigned.nameSpaces[document.docType].orEmpty().filter { it.item.elementIdentifier == name }
        return matches.singleOrNull()?.item?.elementValue
    }

    /** Whether `SHA256(seed) == ssc`, compared in constant time. False for any wrong length. */
    fun opens(seed: ByteArray, ssc: ByteArray): Boolean {
        if (seed.size != SEED_BYTES || ssc.size != COMMITMENT_BYTES) return false
        val digest = MessageDigest.getInstance("SHA-256").digest(seed)
        return try {
            MessageDigest.isEqual(digest, ssc)
        } finally {
            digest.fill(0)
        }
    }

}
