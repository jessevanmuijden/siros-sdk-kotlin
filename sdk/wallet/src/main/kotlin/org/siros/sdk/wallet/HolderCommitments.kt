// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.WalletException

/**
 * The holder commitments an issuer asks for in the OpenID4VCI proof JWT
 * (tracking issue https://github.com/SUNET/vc/issues/823).
 *
 * The engine's `generate_proof` sign request carries `holder_commitments`
 * (names only, today `["psc"]`), `credential_type` and `credential_issuer`
 * (the exact `credential_issuer` string of the issuer metadata). The wallet adds
 * `org.siros.psc` = base64url-without-padding (RFC 7515 section 2) of the
 * 32-byte commitment to the proof payload before signing, so the proof of
 * possession covers it.
 *
 * Fail-closed throughout: an unknown commitment name, a missing type or issuer,
 * a keystore that is not a [org.siros.sdk.keystore.HolderWitnessSource], or a value that is not 32
 * bytes refuses the proof. Nothing here ever logs or puts a commitment value in
 * a message.
 */
internal object HolderCommitments {
    const val PSC = "psc"

    /** The proof JWT claim carrying the `psc`. */
    const val PSC_CLAIM = "org.siros.psc"

    private const val PSC_BYTES = 32

    /** The extra proof claims for [requested]; empty when nothing was requested. */
    fun proofClaims(
        requested: List<String>?,
        credentialType: String?,
        credentialIssuer: String?,
        derive: ((credentialType: String, issuer: String) -> ByteArray)?,
    ): Map<String, String> {
        if (requested.isNullOrEmpty()) return emptyMap()
        val unknown = requested.filter { it != PSC }
        if (unknown.isNotEmpty()) {
            throw WalletException(
                "The issuer asked for holder commitments this wallet does not support: $unknown",
                errorCode = "holder_commitment_unsupported",
            )
        }
        if (credentialType.isNullOrEmpty() || credentialIssuer.isNullOrEmpty()) {
            throw WalletException(
                "The issuer asked for a holder commitment but the request names no credential type or issuer",
                errorCode = "holder_commitment_unavailable",
            )
        }
        if (derive == null) {
            throw WalletException(
                "The issuer asked for a holder commitment but this wallet's keystore cannot derive one",
                errorCode = "holder_commitment_unavailable",
            )
        }
        val psc = derive(credentialType, credentialIssuer)
        try {
            if (psc.size != PSC_BYTES) {
                throw WalletException(
                    "The holder commitment derived for this issuer is not $PSC_BYTES bytes",
                    errorCode = "holder_commitment_unavailable",
                )
            }
            return mapOf(PSC_CLAIM to java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(psc))
        } finally {
            psc.fill(0)
        }
    }
}

/**
 * The issuer refused the holder's pseudonym commitment: it already holds a
 * different one for this subject (flow error code `PSC_CONFLICT`, an issuer
 * `invalid_request` whose description starts `org.siros.psc_conflict:`).
 *
 * Terminal and clean: the issuer refuses before issuing, so nothing was stored
 * and no refresh token was captured. The user is told to ask the issuer for an
 * operator-approved reset; [userMessageRes] is the localised sentence.
 *
 * @property issuerMessage The issuer's own text, for logs and support; may be shown but is not the user message.
 */
class PseudonymCommitmentConflictException(
    val issuerMessage: String,
) : org.siros.sdk.credentials.SirosException(
    "The issuer already has a different pseudonym commitment on record for this holder",
    errorCode = ERROR_CODE,
) {
    /** The string resource with the plain-language sentence for the user. */
    val userMessageRes: Int get() = R.string.siros_psc_conflict

    companion object {
        /** The engine's flow error code. */
        const val FLOW_ERROR_CODE = "PSC_CONFLICT"
        const val ERROR_CODE = "psc_conflict"
    }
}
