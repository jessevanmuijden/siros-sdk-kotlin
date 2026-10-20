// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.siros.sdk.credentials.SirosException
import org.siros.sdk.credentials.WalletException
import org.siros.sdk.wallet.R

/**
 * How strictly the wallet enforces a signed request's `expected_origins`
 * (OpenID4VP 1.0 Appendix A) for the formats other than `circuit_zk`.
 * `circuit_zk` always requires it and is not affected by this setting.
 */
enum class ExpectedOriginsMode {
    /** Ignore `expected_origins`, as the SDK always has. The default. */
    OFF,

    /** Enforce `expected_origins` on a signed request that has the member; one without it is accepted. */
    IF_PRESENT,

    /** A signed request without a valid `expected_origins` is rejected. */
    REQUIRED,
}

/**
 * Chooses which entry of a request's `requests[]` the wallet answers:
 * [DCAPIRequestParser.parse] evaluates the entries in order and takes the
 * first one this accepts.
 */
fun interface DCAPIEntryPolicy {
    /** Whether [request], one parsed entry, is acceptable. */
    fun accepts(request: DCAPIRequest): Boolean

    companion object {
        /** Accept the first entry: the behaviour of the parser before there was a policy. */
        val FIRST_ENTRY = DCAPIEntryPolicy { true }
    }
}

/**
 * Why the wallet refused a DC API request, in terms coarse enough to tell the
 * USER and nothing else. It never reaches the verifier: the verifier is always
 * answered with a bare `access_denied`. It also never carries request
 * content, the verifier id, a pseudonym or a seed - the user is shown a fixed
 * localised sentence per value (see [userMessageRes]).
 */
enum class DCAPIRefusalReason {
    /** The verifier is not trusted (the policy decision point said no). */
    NOT_TRUSTED,

    /** Trust could not be established right now (policy decision point unreachable or failing). */
    TRUST_UNAVAILABLE,

    /** No credential in the wallet satisfies the request. */
    NO_MATCHING_CREDENTIAL,

    /** The credential the user picked cannot be used for this request, or no usable copy of one is left. */
    SELECTED_CREDENTIAL_UNAVAILABLE,

    /** The request is not one this wallet can or will answer (wrong shape, feature off, missing key). */
    UNSUPPORTED_REQUEST,

    /** The request was not delivered the way the wallet requires (unsigned, or not from the page's origin). */
    REQUEST_NOT_VERIFIED,

    /** The identifier the pseudonym is scoped to could not be determined. */
    VERIFIER_ID_UNAVAILABLE,

    /** Building the proof failed. */
    PROOF_FAILED,

    /** The wallet has no way to ask the user for consent (no consent handler is registered), so it cannot answer. */
    CONSENT_UNAVAILABLE,

    /** The user did not approve (declined, dismissed, or did not answer in time). */
    USER_DECLINED,
    ;

    /** The string resource with the plain-language sentence shown to the user. */
    val userMessageRes: Int
        get() = when (this) {
            NOT_TRUSTED -> R.string.siros_dcapi_refused_not_trusted
            TRUST_UNAVAILABLE -> R.string.siros_dcapi_refused_trust_unavailable
            NO_MATCHING_CREDENTIAL -> R.string.siros_dcapi_refused_no_matching_credential
            SELECTED_CREDENTIAL_UNAVAILABLE -> R.string.siros_dcapi_refused_selected_unavailable
            UNSUPPORTED_REQUEST -> R.string.siros_dcapi_refused_unsupported_request
            REQUEST_NOT_VERIFIED -> R.string.siros_dcapi_refused_request_not_verified
            VERIFIER_ID_UNAVAILABLE -> R.string.siros_dcapi_refused_verifier_id_unavailable
            PROOF_FAILED -> R.string.siros_dcapi_refused_proof_failed
            CONSENT_UNAVAILABLE -> R.string.siros_dcapi_refused_consent_unavailable
            USER_DECLINED -> R.string.siros_dcapi_refused_user_declined
        }
}

/**
 * Raised when the wallet refuses a DC API request (no entry of `requests[]` is
 * acceptable under the wallet's [DCAPIRequestRules], or a `circuit_zk` request
 * cannot be answered). The wallet answers the verifier with `access_denied` and
 * no description; [reason] is for the user only. The message names only the
 * protocol of the entry that was refused, never any request content.
 */
class DCAPIRequestRefused(
    val protocol: String,
    val reason: DCAPIRefusalReason = DCAPIRefusalReason.REQUEST_NOT_VERIFIED,
) : SirosException("DC API request refused (protocol=$protocol)", errorCode = "dcapi_request_refused")

/**
 * A DC API presentation the wallet declines on the existing-format paths (untrusted
 * verifier, no matching credential, no eligible copy left, no encryption key). The
 * verifier is answered exactly as it always was: `access_denied` with this
 * exception's message as the description. [reason] is for the USER only: the
 * activity shows the fixed sentence of [DCAPIRefusalReason.userMessageRes] so the
 * decline is never silent. It is a [WalletException], so existing handlers still catch it.
 */
class DCAPIPresentationDeclined(
    message: String,
    val reason: DCAPIRefusalReason,
) : WalletException(message)

/**
 * The wallet's rules for a DC API request: whether a request must be signed
 * and carry the calling origin in `expected_origins`.
 *
 * - For a request that needs a signed one, the protocol must be
 *   exactly `openid4vp-v1-signed` (so `openid4vp-v1-multisigned` is
 *   refused), and [origin] must equal, as an exact string, an entry of a
 *   non-empty `expected_origins`. A missing or malformed `expected_origins`
 *   fails. Every credential query with `format: "zkp_req"` needs it
 *   ([DEFAULT_REQUIRES_SIGNED_REQUEST]) and nothing can lift that:
 *   [requiresSignedRequest] is a hook that may only ADD requests to the
 *   set (its `false` never exempts a `circuit_zk` request).
 * - Any other request follows [mode].
 *
 * [origin] is what the OS reports for the calling page. The wallet compares
 * it; it does not authenticate it.
 */
class DCAPIRequestRules(
    private val origin: String,
    private val mode: ExpectedOriginsMode = ExpectedOriginsMode.OFF,
    private val requiresSignedRequest: (JsonObject?) -> Boolean = DEFAULT_REQUIRES_SIGNED_REQUEST,
) : DCAPIEntryPolicy {

    override fun accepts(request: DCAPIRequest): Boolean {
        // The mandatory rule always applies; the hook can only add to it.
        if (DEFAULT_REQUIRES_SIGNED_REQUEST(request.dcqlQuery) || requiresSignedRequest(request.dcqlQuery)) {
            return request.protocol == SIGNED_PROTOCOL &&
                request.keyMaterial != null &&
                originListed(request)
        }
        if (request.keyMaterial == null) return true
        return when (mode) {
            ExpectedOriginsMode.OFF -> true
            ExpectedOriginsMode.IF_PRESENT -> !request.hasExpectedOrigins || originListed(request)
            ExpectedOriginsMode.REQUIRED -> originListed(request)
        }
    }

    private fun originListed(request: DCAPIRequest): Boolean {
        val listed = request.expectedOrigins
        return listed != null && listed.isNotEmpty() && origin in listed
    }

    companion object {
        /** The only protocol a `circuit_zk` request may use. */
        const val SIGNED_PROTOCOL = "openid4vp-v1-signed"

        /** The mandatory rule, and the hook's default: any credential query with `format: "zkp_req"`. */
        val DEFAULT_REQUIRES_SIGNED_REQUEST: (JsonObject?) -> Boolean = { query ->
            ((query?.get("credentials") as? JsonArray) ?: JsonArray(emptyList())).any {
                (it as? JsonObject)?.get("format")?.jsonPrimitive?.contentOrNull == "zkp_req"
            }
        }
    }
}
