package org.siros.sdk.wallet

import org.siros.sdk.transport.engine.CredentialResult

/**
 * The single issuance trust policy: a credential is stored only if its issuer's
 * trust has been established. Fails closed - anything short of an affirmative
 * result refuses the whole issuance.
 *
 * - The engine's server-side issuer evaluation ("trust_evaluated" progress)
 *   said `trusted=false` for this flow: refuse. (The engine already errors the
 *   flow in that case; this is the wallet's own defence in depth.)
 * - Every `mso_mdoc` credential must have a verifiable `issuerAuth` and
 *   [mdocTrust] must return `trusted=true` for it. `null` (no x5chain, bad
 *   signature, unparseable) refuses. [mdocTrust] is
 *   [SirosWallet.evaluateIssuerTrust], whose own rule already restricts local
 *   fallback to a genuinely unreachable backend.
 * - No cached positive ever stands in for an evaluation here.
 *
 * @return null when issuance may proceed, else a short non-secret reason for
 *   logs and the host.
 */
internal suspend fun issuanceTrustRefusal(
    credentials: List<CredentialResult>,
    engineTrust: TrustResult?,
    mdocTrust: suspend (CredentialResult) -> TrustResult?,
): String? {
    if (engineTrust != null && !engineTrust.trusted) {
        return "issuer trust evaluation by the wallet backend was negative" +
            (engineTrust.reason?.let { ": $it" } ?: "")
    }
    for (credential in credentials) {
        if (credential.format != "mso_mdoc") continue
        val trust = mdocTrust(credential)
            ?: return "mdoc issuerAuth is missing or could not be verified"
        if (!trust.trusted) {
            return "mdoc issuer is not trusted" + (trust.reason?.let { ": $it" } ?: "")
        }
    }
    return null
}

/** Default, host-resolvable English wording; the SDK string key is `siros_issuer_not_trusted`. */
internal const val ISSUER_NOT_TRUSTED_MESSAGE =
    "This issuer could not be verified as trusted, so the credential was not added."
