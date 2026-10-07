// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.keystore.AuthenticationFactor

/**
 * Reports which authentication factors authorised the signing operation that
 * is about to produce an SCA presentation (EC TS12 v1.0.1 3.6 `amr`), for the
 * credential [operation] names.
 *
 * Only factors that can be justified **for this operation** may be returned:
 * a PIN or biometric verified earlier for something else does not count. The
 * wallet refuses the presentation (`insufficientAuthenticationFactors`) unless
 * the answer spans two categories.
 *
 * The WSCD manager does not yet report TS12 factors (siros-wscd-manager#101
 * and #102), so the SDK's default ([ConservativeAuthenticationFactorsProvider])
 * establishes none and SCA presentations are refused until a provider that
 * can is registered with [SirosWallet.authenticationFactorsProvider].
 */
fun interface AuthenticationFactorsProvider {
    /** The factors applied to authorise signing with [operation]'s key; empty when none can be established. */
    suspend fun factorsFor(operation: SigningOperation): List<AuthenticationFactor>

    /**
     * Whether two categories can possibly be established for [operation]. Asked
     * BEFORE the user is shown the transaction, so a wallet that could never
     * satisfy TS12 does not make the user read and confirm a payment it will
     * then refuse. Return `true` if authentication will be prompted for after
     * consent (a PIN or biometric dialog); the default is `true` so a provider
     * that only implements [factorsFor] keeps working.
     */
    suspend fun canEstablish(operation: SigningOperation): Boolean = true
}

/** The signing operation an [AuthenticationFactorsProvider] is asked about. */
class SigningOperation(
    /** The credential whose key signs the key binding JWT. */
    val credential: StoredCredential,
)

/**
 * The default: claims no factor, and says up front that none can be established.
 *
 * Nothing in the current signing path tells the SDK whether a PIN, passphrase
 * or biometric was verified for this particular operation (the software
 * keystore verifies nothing; the WSCD adapter only knows the previous
 * operation's methods, in RFC 8176 vocabulary), and TS12 forbids guessing. A
 * possession factor alone never reaches two categories, so SCA is refused,
 * before consent.
 */
object ConservativeAuthenticationFactorsProvider : AuthenticationFactorsProvider {
    override suspend fun factorsFor(operation: SigningOperation): List<AuthenticationFactor> = emptyList()

    override suspend fun canEstablish(operation: SigningOperation): Boolean = false
}
