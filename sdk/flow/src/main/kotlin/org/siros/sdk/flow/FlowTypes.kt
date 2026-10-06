package org.siros.sdk.flow

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import org.siros.sdk.credentials.interop.AuthorizationDetail

/** Events emitted during a credential flow. SDK consumer handles UI. */
sealed class FlowEvent {
    /** Flow has started and is in progress. */
    data class Progress(
        val flowId: String,
        val step: String,
        val payload: JsonObject?,
    ) : FlowEvent()

    /** Backend requests the client to sign (proof generation or VP). */
    data class SignRequest(
        val flowId: String,
        val messageId: String,
        val action: SignAction,
        val params: SignParams,
    ) : FlowEvent()

    /** Backend requests credential matching (DCQL query). */
    data class MatchRequest(
        val flowId: String,
        val messageId: String,
        val dcqlQuery: JsonObject,
    ) : FlowEvent()

    /** Flow completed successfully. */
    data class Complete(
        val flowId: String,
        val result: JsonObject?,
    ) : FlowEvent()

    /** Flow failed with an error. */
    data class Error(
        val flowId: String,
        val code: String?,
        val message: String?,
    ) : FlowEvent()
}

enum class SignAction {
    @SerialName("generate_proof") GENERATE_PROOF,
    @SerialName("sign_presentation") SIGN_PRESENTATION,
}

@Serializable
data class SignParams(
    val audience: String? = null,
    val nonce: String? = null,
    val issuer: String? = null,
    val count: Int? = null,
    @SerialName("response_uri") val responseUri: String? = null,
    @SerialName("proof_types_supported") val proofTypesSupported: JsonObject? = null,
    @SerialName("credentials_to_include") val credentialsToInclude: List<JsonObject>? = null,
)

@Serializable
data class SignResponse(
    @SerialName("proof_jwt") val proofJwt: String? = null,
    val proofs: List<String>? = null,
    @SerialName("vp_token") val vpToken: String? = null,
    val attestation: String? = null,
    @SerialName("proof_type") val proofType: String? = null,
)

@Serializable
data class MatchResponse(
    @SerialName("credential_ids") val credentialIds: List<String>,
)

/** Parameters for starting an OID4VCI flow. */
data class OID4VCIFlowParams(
    val credentialOfferUri: String? = null,
    val credentialOffer: JsonObject? = null,
    val issuerUrl: String? = null,
    /**
     * The OID4VCI `authorization_details` to ask the Issuer with - see
     * [org.siros.sdk.credentials.interop.AuthorizationDetails].
     *
     * Sent on flow start because the engine, not this SDK, builds the
     * Authorization Request; the wallet states the intent and the engine
     * forwards it. Null omits the field entirely, which the engine reads as
     * "do not ask this way" and leaves the `scope` path untouched.
     */
    val authorizationDetails: List<AuthorizationDetail>? = null,
)

/** Parameters for starting an OID4VP flow. */
data class OID4VPFlowParams(
    val requestUri: String? = null,
    val request: JsonObject? = null,
)
