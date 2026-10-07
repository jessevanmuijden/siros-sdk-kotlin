// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.transport.wmp.openid4x

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.transport.StringOrStringListSerializer
import org.siros.sdk.transport.engine.CredentialRef
import org.siros.sdk.transport.wmp.*
import timber.log.Timber

// ---------------------------------------------------------------------------
// Flow Type Constants
// ---------------------------------------------------------------------------

object OID4FlowTypes {
    const val OID4VCI = "oid4vci"
    const val OID4VP = "oid4vp"
}

// ---------------------------------------------------------------------------
// OID4VCI Step Constants
// ---------------------------------------------------------------------------

object VCIStep {
    const val PARSING_OFFER = "parsing_offer"
    const val RESOLVING_METADATA = "resolving_metadata"
    const val METADATA_FETCHED = "metadata_fetched"
    const val EVALUATING_TRUST = "evaluating_trust"
    const val TRUST_EVALUATED = "trust_evaluated"
    const val AWAITING_OFFER_ACCEPTANCE = "awaiting_offer_acceptance"
    const val AWAITING_TX_CODE = "awaiting_tx_code"
    const val AUTHORIZATION_PENDING = "authorization_pending"
    const val GENERATING_PROOF = "generating_proof"
    const val REQUESTING_CREDENTIAL = "requesting_credential"
    const val CREDENTIAL_RECEIVED = "credential_received"
}

// ---------------------------------------------------------------------------
// OID4VP Step Constants
// ---------------------------------------------------------------------------

object VPStep {
    const val PARSING_REQUEST = "parsing_request"
    const val REQUEST_PARSED = "request_parsed"
    const val MATCHING_CREDENTIALS = "matching_credentials"
    const val AWAITING_CONSENT = "awaiting_consent"
    const val GENERATING_PRESENTATION = "generating_presentation"
}

// ---------------------------------------------------------------------------
// Action Constants
// ---------------------------------------------------------------------------

object OID4Action {
    const val ACCEPT_OFFER = "accept_offer"
    const val PROVIDE_TX_CODE = "provide_tx_code"
    const val AUTHORIZE = "authorize"
    const val SELECT_CREDENTIALS = "select_credentials"
    const val CANCEL = "cancel"

    /**
     * Report the outcome of the wallet's own DCQL matching
     * (go-wallet-backend#336, `ActionCredentialsMatched`). An empty match set
     * ends the presentation at once with `NO_MATCHING_CREDENTIAL` instead of
     * leaving it to the engine's five-minute user-interaction timeout; a
     * non-empty one is informational.
     */
    const val CREDENTIALS_MATCHED = "credentials_matched"
}

// ---------------------------------------------------------------------------
// Credential Format Constants
// ---------------------------------------------------------------------------

object CredentialFormat {
    const val VC_SD_JWT = "vc+sd-jwt"
    const val DC_SD_JWT = "dc+sd-jwt"
    const val MSO_MDOC = "mso_mdoc"
    const val JWT_VC_JSON = "jwt_vc_json"
}

// ---------------------------------------------------------------------------
// Grant Type Constants
// ---------------------------------------------------------------------------

object GrantType {
    const val AUTHORIZATION_CODE = "authorization_code"
    const val PRE_AUTHORIZED_CODE = "pre-authorized_code"
}

// ---------------------------------------------------------------------------
// Proof Type Constants
// ---------------------------------------------------------------------------

object ProofType {
    const val JWT = "jwt"
    const val ATTESTATION = "attestation"
    const val CWT = "cwt"
}

// ---------------------------------------------------------------------------
// OID4VCI §10 Credential Lifecycle Events
// ---------------------------------------------------------------------------

object CredentialEvent {
    const val ACCEPTED = "credential_accepted"
    const val FAILURE = "credential_failure"
}

// ---------------------------------------------------------------------------
// Typed Data Structures
// ---------------------------------------------------------------------------

@Serializable
data class CredentialConfigurationSupported(
    val format: String,
    val scope: String? = null,
    val vct: String? = null,
    val doctype: String? = null,
    @SerialName("proof_types_supported") val proofTypesSupported: JsonObject? = null,
    val display: List<CredentialDisplay>? = null,
)

@Serializable
data class CredentialDisplay(
    val name: String,
    val locale: String? = null,
    val description: String? = null,
    @SerialName("logo_uri") val logoUri: String? = null,
    @SerialName("logo_alt_text") val logoAltText: String? = null,
    @SerialName("background_color") val backgroundColor: String? = null,
    @SerialName("text_color") val textColor: String? = null,
)

@Serializable
data class CredentialResult(
    val format: String,
    val credential: String,
    val vct: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("notification_id") val notificationId: String? = null,
)

@Serializable
data class VPTokenResult(
    @SerialName("vp_token") val vpToken: String? = null,
    @SerialName("presentation_submission") val presentationSubmission: JsonElement? = null,
    @SerialName("response_code") val responseCode: String? = null,
)

/**
 * One OID4VP `transaction_data` entry as an orchestrator relays it (OpenID4x
 * profile Section 3.2.5; go-wmp `openid4x.TransactionData`). The same shape
 * is used by the legacy engine WebSocket's `sign_request.params`.
 *
 * **[raw] is the only trustworthy member.** It is the base64url string the
 * verifier sent, and the only input to `transaction_data_hashes`
 * (OpenID4VP 1.0 Appendix B). [type], [payload] and [credentialIds] are the
 * orchestrator's decoded hint: a wallet decodes [raw] itself and must refuse
 * when the two disagree, never display or bind the hint.
 *
 * @property raw The entry exactly as the verifier sent it. `null` from an
 *   orchestrator that predates it; a wallet cannot bind to such an entry.
 * @property payload The entry's `payload` object (EC TS12 4.2), hint only.
 * @property params Pre-TS12 type-specific members (deprecated upstream).
 * @property hashAlgorithm Non-standard legacy member (deprecated upstream).
 * @property transactionDataHashesAlg The verifier's list of acceptable hash
 *   algorithms. An array in OpenID4VP; a bare string from older peers is
 *   accepted and read as a one-element list.
 */
@Serializable
data class TransactionData(
    val type: String,
    val params: JsonObject? = null,
    @SerialName("credential_ids") val credentialIds: List<String>? = null,
    @SerialName("hash_alg") val hashAlgorithm: String? = null,
    val raw: String? = null,
    val payload: JsonElement? = null,
    @SerialName("transaction_data_hashes_alg")
    @Serializable(with = StringOrStringListSerializer::class)
    val transactionDataHashesAlg: List<String>? = null,
)

@Serializable
data class SignSubFlowParams(
    val action: String,
    // Non-null for the generate_proof / sign_presentation callers that always
    // have them, but a DPoP-only `sign_client_auth` (credential, deferred,
    // notification request) carries no audience and no c_nonce, and a peer
    // may omit the members rather than send "". Default to empty so decoding
    // does not fail the whole sub-flow with INVALID_PARAMS.
    val nonce: String = "",
    val audience: String = "",
    @SerialName("proof_type") val proofType: String? = null,
    @SerialName("proof_types_supported") val proofTypesSupported: JsonObject? = null,
    @SerialName("parent_flow_id") val parentFlowId: String? = null,
    val count: Int? = null,
    @SerialName("transaction_data") val transactionData: List<TransactionData>? = null,
    /**
     * The OID4VP `response_mode` of the request being answered; required in
     * the key binding JWT of an SCA presentation (EC TS12 3.6). Present for
     * a request that carries `transaction_data`.
     */
    @SerialName("response_mode") val responseMode: String? = null,
    /** The credentials the orchestrator already selected for a `sign_presentation`, with their DCQL query ids. */
    @SerialName("credentials_to_include") val credentialsToInclude: List<CredentialRef>? = null,
    /** The verifier's own session id for this presentation. */
    @SerialName("verifier_session_id") val verifierSessionId: String? = null,
    /** PoP/proof `iss` (the flow's OAuth client_id) for `request_attestation` and `sign_client_auth`. */
    val issuer: String? = null,
    /**
     * `sign_client_auth` parameters (go-wallet-backend#317), same names and
     * meaning as the legacy transport's `SignRequestParams`: [htm]/[htu] ask
     * for a DPoP proof (with [dpopNonce] and [ath] claims), [keyId] names the
     * key to sign with on a renewal. `audience` doubles as the attestation
     * PoP aud when the request also needs client attestation.
     */
    val htm: String? = null,
    val htu: String? = null,
    @SerialName("dpop_nonce") val dpopNonce: String? = null,
    val ath: String? = null,
    @SerialName("key_id") val keyId: String? = null,
)

// ---------------------------------------------------------------------------
// Client Attestation (WIA)
// ---------------------------------------------------------------------------

/**
 * Provider for OAuth client attestation (WIA + PoP).
 * Implementations obtain attestation credentials from the wallet provider
 * infrastructure.
 */
interface ClientAttestationProvider {
    /**
     * Obtain a client attestation for the given audience.
     * @param audience The token endpoint URL of the issuer.
     * @return The client attestation pair (WIA JWT + PoP JWT).
     */
    suspend fun getAttestation(audience: String): ClientAttestation
}

@Serializable
data class ClientAttestation(
    /** Wallet Instance Attestation JWT. */
    @SerialName("client_assertion") val clientAssertion: String,
    /** Proof of Possession JWT. */
    @SerialName("client_assertion_pop") val clientAssertionPop: String,
)

// ---------------------------------------------------------------------------
// OpenID4x Profile Implementation
// ---------------------------------------------------------------------------

/**
 * Configuration for the OpenID4x profile.
 *
 * @param onProgress Called for each flow progress notification.
 * @param onSignRequest Called when the engine requests a key proof or VP signature.
 * @param onMatchRequest Called when the engine requests credential matching.
 * @param onTrustEvaluation Called when the engine requests trust evaluation.
 * @param onComplete Called when a flow completes successfully.
 * @param onError Called when a flow fails.
 */
data class OpenID4xConfig(
    val onProgress: (suspend (String, String, JsonObject?) -> Unit)? = null,
    val onSignRequest: (suspend (String, SignSubFlowParams) -> SignSubFlowResult)? = null,
    val onMatchRequest: (suspend (String, JsonObject?) -> MatchResult)? = null,
    val onTrustEvaluation: (suspend (String, JsonObject?) -> TrustResult)? = null,
    val onComplete: (suspend (String, JsonObject?) -> Unit)? = null,
    val onError: (suspend (String, String?, String?) -> Unit)? = null,
    val attestationProvider: ClientAttestationProvider? = null,
)

/** Result of a sign sub-flow request. */
data class SignSubFlowResult(
    val proofs: List<ProofObject>? = null,
    val vpToken: String? = null,
    /**
     * Extra members for the OID4VCI credential request the backend is about
     * to send on this wallet's behalf.
     *
     * Same field, same meaning and same reserved-name rule as the legacy
     * protocol's `SignResponseMessage.credential_request_extras`. The two
     * transports carry it identically on the wire so a backend can accept
     * either without a second code path, and so a flow behaves the same
     * whichever transport it runs over.
     */
    val credentialRequestExtras: JsonObject? = null,
    /**
     * `request_attestation` / `sign_client_auth` results, carried on the
     * wire under the same names as the legacy transport's
     * `SignResponseMessage` (`client_attestation`, `client_attestation_pop`,
     * `dpop_key_id`, `dpop_proof`) so a backend accepts either transport
     * without a second code path.
     */
    val clientAttestation: String? = null,
    val clientAttestationPoP: String? = null,
    val dpopKeyId: String? = null,
    val dpopProof: String? = null,
)

@Serializable
data class ProofObject(
    @SerialName("proof_type") val proofType: String = ProofType.JWT,
    val jwt: String? = null,
    val attestation: String? = null,
)

/** Result of a credential matching request. */
data class MatchResult(
    val matches: List<CredentialMatch>,
    /**
     * Why [matches] is empty - the wallet's own account, which the engine
     * relays in the `NO_MATCHING_CREDENTIAL` error it reports back. Null
     * whenever something matched.
     */
    val noMatchReason: String? = null,
)

@Serializable
data class CredentialMatch(
    @SerialName("credential_id") val credentialId: String,
    @SerialName("credential_query_id") val credentialQueryId: String? = null,
    @SerialName("disclosed_claims") val disclosedClaims: List<String>? = null,
)

/** Result of trust evaluation. */
data class TrustResult(
    val trusted: Boolean,
    val framework: String? = null,
    val reason: String? = null,
)

// Sub-flow step names used by the engine
private const val STEP_SIGN_REQUEST = "sign_request"
private const val STEP_MATCH_REQUEST = "match_request"
private const val STEP_TRUST_EVALUATION = "trust_evaluation_required"

/**
 * OpenID4x WMP profile for OID4VCI and OID4VP flows.
 *
 * Handles server-initiated flows: the backend engine starts flows and
 * the SDK responds to progress events, sign requests, match requests,
 * and trust evaluations.
 */
class OpenID4xProfile(
    private val config: OpenID4xConfig = OpenID4xConfig(),
) : WmpProfile, WmpFlowHandler {

    private var peer: WmpPeerContext? = null

    // ---- WmpProfile ----

    override val name: String = "openid4x"
    override val capabilities: List<String> = listOf("oid4vci", "oid4vp")

    override fun init(ctx: WmpPeerContext) {
        peer = ctx
    }

    // ---- WmpFlowHandler ----

    override val flowTypes: List<String> = listOf(OID4FlowTypes.OID4VCI, OID4FlowTypes.OID4VP)

    override suspend fun startFlow(params: FlowStartParams): FlowStartResult {
        return FlowStartResult(flowId = params.flowId, flowType = params.flowType)
    }

    override suspend fun handleProgress(params: FlowProgressParams) {
        val flowId = params.flowId
        val step = params.step
        val payload = params.payload

        Timber.d("OpenID4x progress: flow=$flowId step=$step")

        when {
            // Sign request sub-flow (generate_proof or sign_presentation)
            step == STEP_SIGN_REQUEST || step == VCIStep.GENERATING_PROOF -> {
                handleSignRequest(flowId, payload)
            }
            // Match request (credential selection for VP)
            step == STEP_MATCH_REQUEST || step == VPStep.MATCHING_CREDENTIALS -> {
                handleMatchRequest(flowId, payload)
            }
            // Trust evaluation
            step == STEP_TRUST_EVALUATION || step == VCIStep.EVALUATING_TRUST -> {
                handleTrustEvaluation(flowId, payload)
            }
            // General progress
            else -> {
                config.onProgress?.invoke(flowId, step, payload)
            }
        }
    }

    override suspend fun handleAction(params: FlowActionParams): FlowActionResult {
        return FlowActionResult(flowId = params.flowId, accepted = true)
    }

    override suspend fun handleComplete(params: FlowCompleteParams) {
        config.onComplete?.invoke(params.flowId, params.result)
    }

    override suspend fun handleError(params: FlowErrorParams) {
        config.onError?.invoke(params.flowId, params.code, params.message)
    }

    override suspend fun handleCancel(params: FlowCancelParams) {
        Timber.d("OpenID4x flow cancelled: ${params.flowId} reason=${params.reason}")
    }

    // ---- Sub-flow handlers ----

    private suspend fun handleSignRequest(flowId: String, payload: JsonObject?) {
        val handler = config.onSignRequest ?: return
        val ctx = peer ?: return

        val signParams = payload?.let {
            try {
                ctx.codec.json.decodeFromJsonElement(SignSubFlowParams.serializer(), it)
            } catch (e: Exception) {
                Timber.e(e, "Failed to decode sign request params")
                null
            }
        } ?: return

        try {
            val result = handler.invoke(flowId, signParams)
            sendSignResponse(flowId, result)
        } catch (e: TransactionDataError) {
            // A refused transaction_data request names its reason (the
            // verifier-facing OpenID4VP error) instead of the generic code.
            Timber.w("Sign request refused: transaction_data (${e.reason.code})")
            sendFlowError(flowId, e.verifierError, e.reason.code)
        } catch (e: Exception) {
            Timber.e(e, "Sign request handler failed")
            sendFlowError(flowId, "SIGN_ERROR", e.message)
        }
    }

    private suspend fun handleMatchRequest(flowId: String, payload: JsonObject?) {
        val handler = config.onMatchRequest ?: return

        try {
            val result = handler.invoke(flowId, payload)
            sendMatchResponse(flowId, result)
            if (result.matches.isEmpty()) {
                // The engine's OID4VP flow delegates matching to the client
                // and then waits for consent/decline - it never reads a
                // match_response, so on its own the answer above leaves the
                // presentation stalled until the user-interaction timeout.
                // credentials_matched is the action it does act on.
                sendCredentialsMatched(flowId, result)
            }
        } catch (e: Exception) {
            Timber.e(e, "Match request handler failed")
            sendFlowError(flowId, "MATCH_ERROR", e.message)
        }
    }

    private suspend fun handleTrustEvaluation(flowId: String, payload: JsonObject?) {
        val handler = config.onTrustEvaluation ?: return

        try {
            val result = handler.invoke(flowId, payload)
            sendTrustResult(flowId, result)
        } catch (e: Exception) {
            Timber.e(e, "Trust evaluation handler failed")
            sendTrustResult(flowId, TrustResult(trusted = false, reason = e.message))
        }
    }

    // ---- Response helpers ----

    private suspend fun sendSignResponse(flowId: String, result: SignSubFlowResult) {
        val ctx = peer ?: return
        val params = buildJsonObject {
            put("wmp", ctx.codec.json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
            put("flow_id", JsonPrimitive(flowId))
            put("action", JsonPrimitive("sign_response"))
            result.proofs?.let { proofs ->
                put("proofs", ctx.codec.json.encodeToJsonElement(
                    ListSerializer(ProofObject.serializer()),
                    proofs,
                ))
            }
            result.vpToken?.let {
                put("vp_token", JsonPrimitive(it))
            }
            result.credentialRequestExtras?.let {
                put("credential_request_extras", it)
            }
            result.clientAttestation?.let { put("client_attestation", JsonPrimitive(it)) }
            result.clientAttestationPoP?.let { put("client_attestation_pop", JsonPrimitive(it)) }
            result.dpopKeyId?.let { put("dpop_key_id", JsonPrimitive(it)) }
            result.dpopProof?.let { put("dpop_proof", JsonPrimitive(it)) }
        }
        ctx.notify(WmpMethods.FLOW_ACTION, params)
    }

    private suspend fun sendMatchResponse(flowId: String, result: MatchResult) {
        val ctx = peer ?: return
        val params = buildJsonObject {
            put("wmp", ctx.codec.json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
            put("flow_id", JsonPrimitive(flowId))
            put("action", JsonPrimitive("match_response"))
            put("matches", ctx.codec.json.encodeToJsonElement(
                ListSerializer(CredentialMatch.serializer()),
                result.matches,
            ))
            // Carried on the wire under the same name the legacy transport's
            // MatchResponseMessage uses. It was dropped here, so a wallet
            // that knew why it had nothing to offer could not say so.
            result.noMatchReason?.let { put("no_match_reason", JsonPrimitive(it)) }
        }
        ctx.notify(WmpMethods.FLOW_ACTION, params)
    }

    private suspend fun sendCredentialsMatched(flowId: String, result: MatchResult) {
        val ctx = peer ?: return
        val params = buildJsonObject {
            put("wmp", ctx.codec.json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
            put("flow_id", JsonPrimitive(flowId))
            put("action", JsonPrimitive(OID4Action.CREDENTIALS_MATCHED))
            put("matches", ctx.codec.json.encodeToJsonElement(
                ListSerializer(CredentialMatch.serializer()),
                result.matches,
            ))
            result.noMatchReason?.let { put("no_match_reason", JsonPrimitive(it)) }
        }
        ctx.notify(WmpMethods.FLOW_ACTION, params)
    }

    private suspend fun sendTrustResult(flowId: String, result: TrustResult) {
        val ctx = peer ?: return
        val params = buildJsonObject {
            put("wmp", ctx.codec.json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
            put("flow_id", JsonPrimitive(flowId))
            put("action", JsonPrimitive("trust_result"))
            put("trusted", JsonPrimitive(result.trusted))
            result.framework?.let { put("framework", JsonPrimitive(it)) }
            result.reason?.let { put("reason", JsonPrimitive(it)) }
        }
        ctx.notify(WmpMethods.FLOW_ACTION, params)
    }

    private suspend fun sendFlowError(flowId: String, code: String, message: String?) {
        val ctx = peer ?: return
        val params = buildJsonObject {
            put("wmp", ctx.codec.json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
            put("flow_id", JsonPrimitive(flowId))
            put("code", JsonPrimitive(code))
            message?.let { put("message", JsonPrimitive(it)) }
        }
        ctx.notify(WmpMethods.FLOW_ERROR, params)
    }
}
