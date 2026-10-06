// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.transport.engine

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import org.siros.sdk.credentials.interop.AuthorizationDetail
import org.siros.sdk.transport.wmp.openid4x.TransactionData

/** Message types used in the wallet backend engine WebSocket protocol. */
object MessageTypes {
    // Client → Server
    const val HANDSHAKE = "handshake"
    const val FLOW_START = "flow_start"
    const val FLOW_ACTION = "flow_action"
    const val SIGN_RESPONSE = "sign_response"
    const val MATCH_RESPONSE = "match_response"
    const val CREDENTIAL_NOTIFICATION = "credential_notification"

    // Server → Client
    const val HANDSHAKE_COMPLETE = "handshake_complete"
    const val FLOW_PROGRESS = "flow_progress"
    const val FLOW_COMPLETE = "flow_complete"
    const val FLOW_ERROR = "flow_error"
    const val SIGN_REQUEST = "sign_request"
    const val MATCH_REQUEST = "match_request"
    const val PUSH = "push"
    const val ERROR = "error"
    const val NOTIFICATION_ACK = "notification_ack"
}

/** Base envelope — every engine message carries at least a type. */
@Serializable
data class EngineMessage(
    val type: String,
    @SerialName("flow_id") val flowId: String? = null,
    @SerialName("message_id") val messageId: String? = null,
    val timestamp: String? = null,
)

// ── Client → Server ─────────────────────────────────────────────────

@Serializable
data class HandshakeMessage(
    val type: String = MessageTypes.HANDSHAKE,
    @SerialName("app_token") val appToken: String,
)

@Serializable
data class FlowStartMessage(
    val type: String = MessageTypes.FLOW_START,
    val protocol: String,
    val offer: String? = null,
    @SerialName("credential_offer_uri") val credentialOfferUri: String? = null,
    @SerialName("request_uri") val requestUri: String? = null,
    @SerialName("request_uri_ref") val requestUriRef: String? = null,
    val vct: String? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    @SerialName("auth_code") val authCode: String? = null,
    @SerialName("code_verifier") val codeVerifier: String? = null,
    /**
     * OAuth Client Attestation (draft-ietf-oauth-attestation-based-client-auth-04
     * §3.1): a Wallet Instance Attestation JWT (`typ: oauth-client-attestation+jwt`)
     * obtained from this wallet's own backend (`/wallet-provider/wia/generate`).
     * Forwarded by go-wallet-backend as the `OAuth-Client-Attestation` HTTP
     * header on PAR/token requests to the credential issuer - see
     * `internal/engine/client_attestation.go`'s `TransportSuppliedAttestation`.
     *
     * DEPRECATED as an up-front field: when absent, the backend requests the
     * attestation itself via a `request_attestation` sign request after
     * resolving the issuer's authorization server, which is the only place the
     * PoP audience is reliably known - reply via
     * [SignResponseMessage.clientAttestation]. Kept on the wire for clients
     * that have already resolved the offer/AS themselves.
     */
    @SerialName("client_attestation") val clientAttestation: String? = null,
    /**
     * The matching PoP JWT (`typ: oauth-client-attestation-pop+jwt`), freshly
     * signed per flow with `aud` = the credential issuer's own authorization
     * server, proving possession of the instance key the WIA above is bound
     * to (`cnf.jwk`/`cnf.jkt`). Forwarded as `OAuth-Client-Attestation-PoP`.
     */
    @SerialName("client_attestation_pop") val clientAttestationPoP: String? = null,
    /**
     * Renewal fields (credential re-issuance/renewal plan, Phase 1 Slice 2 -
     * see go-wallet-backend's `internal/engine/oid4vci.go` `Execute`). When
     * [refreshToken] is set, this is a renewal request rather than a fresh
     * issuance: [offer]/[credentialOfferUri] are unused, and [credentialIssuer]/
     * [selectedCredentialConfigurationId] are required instead (the client
     * already knows both from the credential being renewed).
     */
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("credential_issuer") val credentialIssuer: String? = null,
    @SerialName("selected_credential_configuration_id") val selectedCredentialConfigurationId: String? = null,
    /**
     * When set, asks the server to request a `generate_proof` signature
     * using this existing kid instead of a fresh key - same-wallet-unit
     * continuity evidence for a renewal (see
     * [SignRequestParams.reissuanceKid] equivalent server-side). Optional
     * even on a renewal request.
     */
    @SerialName("reissuance_kid") val reissuanceKid: String? = null,
    /**
     * On a renewal request, the private DPoP JWK previously captured from
     * [FlowCompleteMessage.dpopJwk] for this same refresh_token. The issuer
     * binds refresh_token to the exact DPoP key used at initial issuance
     * (RFC 9449/ARF 3.0 §6.6.6.2.2), so the backend must reuse this key
     * rather than generate a fresh one - see go-wallet-backend's
     * FlowStartMessage.DPoPJWK doc comment. Never persisted by the SDK
     * itself beyond whatever the caller does with it (privatedata, Phase 2).
     */
    @SerialName("dpop_jwk") val dpopJwk: String? = null,
    /**
     * Renewal only: the `dpop_key_id` this wallet returned at
     * [FlowCompleteMessage.dpopKeyId] for the flow that issued [refreshToken] -
     * the client-held key the token is bound to. The engine passes it back as
     * [SignRequestParams.keyId] on every `sign_client_auth` of the renewal so
     * this wallet signs with that same key. Takes precedence over [dpopJwk].
     */
    @SerialName("dpop_key_id") val dpopKeyId: String? = null,
    /**
     * Optional protocol features this client implements (go-wallet-backend
     * `FlowStartMessage.Features`). `"transaction_data.v1"`
     * ([FEATURE_TRANSACTION_DATA_V1]) declares that the client validates,
     * shows and binds OID4VP `transaction_data` (EC TS12); the backend
     * refuses a request carrying `transaction_data` for a client that did not
     * declare it. `null` (the default) declares nothing.
     */
    val features: List<String>? = null,
    val timestamp: String? = null,
    // Appended rather than placed with the other OID4VCI fields above: this
    // is a data class, so a property's position is part of the binary API
    // (componentN, copy, the constructor descriptor). Inserting it mid-list
    // re-typed component11 for existing consumers. New fields go at the end.
    /**
     * OID4VCI `authorization_details` (1.0 §5.1.1) for the Authorization
     * Request. DIIP requires a Wallet to be able to ask for a credential
     * configuration this way as well as by `scope`.
     *
     * The engine builds the Authorization Request, so the wallet cannot add
     * the parameter itself - it states the intent here and the engine forwards
     * it. Null omits the field entirely, which the engine reads as "do not ask
     * this way", leaving the `scope` path unchanged. Wire name and shape match
     * go-wallet-backend's `FlowStartMessage.AuthorizationDetails` and
     * wallet-frontend's `flow_start` exactly.
     */
    @SerialName("authorization_details")
    val authorizationDetails: List<AuthorizationDetail>? = null,
) {
    companion object {
        /** The [features] entry declaring OID4VP `transaction_data` support. */
        const val FEATURE_TRANSACTION_DATA_V1 = "transaction_data.v1"
    }
}

@Serializable
data class FlowActionMessage(
    val type: String = MessageTypes.FLOW_ACTION,
    @SerialName("flow_id") val flowId: String,
    val action: String,
    val payload: JsonObject? = null,
    val timestamp: String? = null,
)

@Serializable
data class SignResponseMessage(
    val type: String = MessageTypes.SIGN_RESPONSE,
    @SerialName("flow_id") val flowId: String,
    @SerialName("message_id") val messageId: String? = null,
    @SerialName("proof_jwt") val proofJwt: String? = null,
    @SerialName("vp_token") val vpToken: String? = null,
    val proofs: List<ProofObject>? = null,
    /**
     * Extra members for the OID4VCI credential request the backend is about
     * to send on this wallet's behalf.
     *
     * The wallet, not the backend, holds the state some credential formats
     * need at issuance: blind BBS requires a commitment the holder computed
     * locally, and the issuer will not sign without it. The backend builds
     * the credential request, so that value has to travel here.
     *
     * Deliberately a generic bag rather than named BBS fields. It mirrors
     * `ZkIssuancePreparation.credentialRequestFields`, so a future proof
     * system needing its own request members costs a registry entry rather
     * than another protocol change - the same argument as
     * privatedata-spec's `S.extensions`.
     *
     * The backend MUST refuse members that collide with ones it sets itself
     * (`credential_configuration_id`, `proofs`,
     * `credential_response_encryption`). A wallet cannot be allowed to
     * redirect or reshape the request through this field.
     *
     * Absent on every flow that does not need it, which is all of them
     * today except blind BBS issuance.
     */
    @SerialName("credential_request_extras") val credentialRequestExtras: JsonObject? = null,
    /**
     * Response to a `request_attestation` sign request (go-wallet-backend
     * `SignActionRequestAttestation`): the Wallet Instance Attestation JWT
     * (`oauth-client-attestation+jwt`) and the per-flow PoP
     * (`oauth-client-attestation-pop+jwt`) signed with the instance key over
     * the `audience`/`issuer` the engine supplied in [SignRequestParams].
     * Both null means "no attestation available - proceed without".
     */
    @SerialName("client_attestation") val clientAttestation: String? = null,
    @SerialName("client_attestation_pop") val clientAttestationPoP: String? = null,
    /**
     * Response to a `sign_client_auth` sign request (go-wallet-backend#317):
     * [dpopKeyId] is this wallet's identifier for the key that is both its WIA
     * `cnf` key and its DPoP key, and is set whenever the action is
     * understood, even when no proof was asked for (its absence tells the
     * engine to fall back to an engine-held DPoP key). [dpopProof] is the
     * RFC 9449 DPoP proof when `htm`/`htu` were given; the attestation fields
     * above carry the WIA and a freshly signed PoP when `audience` was given.
     */
    @SerialName("dpop_key_id") val dpopKeyId: String? = null,
    @SerialName("dpop_proof") val dpopProof: String? = null,
    val timestamp: String? = null,
)

@Serializable
data class ProofObject(
    @SerialName("proof_type") val proofType: String,
    val jwt: String? = null,
    val attestation: String? = null,
)

@Serializable
data class MatchResponseMessage(
    val type: String = MessageTypes.MATCH_RESPONSE,
    @SerialName("flow_id") val flowId: String,
    val matches: List<CredentialMatch>,
    @SerialName("no_match_reason") val noMatchReason: String? = null,
    val error: String? = null,
    val timestamp: String? = null,
)

@Serializable
data class CredentialMatch(
    @SerialName("credential_query_id") val credentialQueryId: String? = null,
    @SerialName("credential_id") val credentialId: String,
    val format: String,
    val vct: String? = null,
    @SerialName("available_claims") val availableClaims: List<String>? = null,
)

// ── Server → Client ─────────────────────────────────────────────────

@Serializable
data class HandshakeCompleteMessage(
    val type: String = MessageTypes.HANDSHAKE_COMPLETE,
    @SerialName("session_id") val sessionId: String,
    val capabilities: List<String>? = null,
    val timestamp: String? = null,
    /**
     * Server-controlled tunables the client should adopt - see
     * [SessionConfig]'s own doc comment. Nullable/defaulted so this parses
     * cleanly against an older server that predates this field entirely,
     * not just an older server that sends it empty.
     */
    val config: SessionConfig? = null,
)

/**
 * Server-controlled tunables delivered via [HandshakeCompleteMessage] right
 * after authentication succeeds. Deliberately the seed of a general
 * post-auth config/capability handshake rather than a one-off field:
 * anywhere the client would otherwise have to hardcode a value that only
 * works if it happens to match what the server independently assumes, that
 * value belongs here instead - [pingIntervalMs] is just the first case (see
 * its own doc comment for why it specifically had to stop being
 * independently guessed by each side). Add new fields as nullable/defaulted
 * so an older client ignores fields it doesn't understand yet, and a client
 * talking to an older server that never sends a given field falls back to
 * its own hardcoded default.
 */
@Serializable
data class SessionConfig(
    /**
     * How often THIS client should send its own WebSocket ping frames, in
     * milliseconds - mirrors the server's own keepalive cadence
     * (go-wallet-backend's `config.ServerConfig.EngineWSPingInterval`) so
     * neither side has to independently guess a value low enough to satisfy
     * whatever intermediary (Fly.io's edge proxy, in production - confirmed
     * empirically to close an idle connection after ~5-6s, nowhere near the
     * 30s this used to be hardcoded to on both sides) would otherwise
     * consider the connection idle and close it. Null/0 (the server hasn't
     * said, or this is being decoded somewhere that never received a real
     * handshake_complete) means: use [WalletEngineSession]'s own hardcoded
     * default rather than treat it as "no ping at all".
     */
    @SerialName("ping_interval_ms") val pingIntervalMs: Long? = null,
)

@Serializable
data class FlowProgressMessage(
    val type: String = MessageTypes.FLOW_PROGRESS,
    @SerialName("flow_id") val flowId: String,
    val step: String,
    val payload: JsonElement? = null,
    val timestamp: String? = null,
)

@Serializable
data class FlowCompleteMessage(
    val type: String = MessageTypes.FLOW_COMPLETE,
    @SerialName("flow_id") val flowId: String,
    val credentials: List<CredentialResult>? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    @SerialName("type_metadata") val typeMetadata: JsonElement? = null,
    @SerialName("credential_issuer") val credentialIssuer: String? = null,
    @SerialName("selected_credential_configuration_id") val selectedCredentialConfigurationId: String? = null,
    /**
     * OAuth refresh_token the issuer returned alongside this batch, if any
     * (credential re-issuance/renewal plan, Phase 1). The SDK does not
     * persist this durably yet (that's Phase 2 - `privatedata` storage);
     * for now the caller is responsible for holding onto it if a renewal
     * is wanted later.
     */
    @SerialName("refresh_token") val refreshToken: String? = null,
    /**
     * Present only alongside [refreshToken]: the private JWK of the
     * ephemeral DPoP key this flow used for its token exchange. Must be
     * presented back as [FlowStartMessage.dpopJwk] on a renewal request -
     * see that field's doc comment for why. The backend does not persist
     * this itself; the caller is responsible for storing it durably
     * alongside [refreshToken] (e.g. via privatedata).
     */
    @SerialName("dpop_jwk") val dpopJwk: String? = null,
    /**
     * Identifier of the client-held key this flow used for DPoP via
     * `sign_client_auth` (go-wallet-backend#317), present only alongside
     * [refreshToken] and only when this wallet signed the DPoP proofs itself
     * (in which case [dpopJwk] is absent: the engine never had the key).
     * Persist with the refresh token and present back as
     * [FlowStartMessage.dpopKeyId] on renewal.
     */
    @SerialName("dpop_key_id") val dpopKeyId: String? = null,
    val timestamp: String? = null,
)

@Serializable
data class CredentialResult(
    val format: String,
    val credential: String,
    val vct: String? = null,
    @SerialName("type_metadata") val typeMetadata: JsonElement? = null,
    @SerialName("notification_id") val notificationId: String? = null,
)

@Serializable
data class FlowErrorMessage(
    val type: String = MessageTypes.FLOW_ERROR,
    @SerialName("flow_id") val flowId: String? = null,
    val step: String? = null,
    val error: FlowError,
    val timestamp: String? = null,
)

@Serializable
data class FlowError(
    val code: String,
    val message: String,
    val details: JsonObject? = null,
)

@Serializable
data class SignRequestMessage(
    val type: String = MessageTypes.SIGN_REQUEST,
    @SerialName("flow_id") val flowId: String,
    @SerialName("message_id") val messageId: String? = null,
    val action: String,
    val params: SignRequestParams,
    val timestamp: String? = null,
)

@Serializable
data class SignRequestParams(
    val audience: String? = null,
    val nonce: String? = null,
    val issuer: String? = null,
    @SerialName("proof_type") val proofType: String? = null,
    @SerialName("proof_types_supported") val proofTypesSupported: JsonObject? = null,
    val count: Int? = null,
    @SerialName("credentials_to_include") val credentialsToInclude: List<CredentialRef>? = null,
    @SerialName("response_uri") val responseUri: String? = null,
    @SerialName("verifier_jwk_thumbprint") val verifierJwkThumbprint: String? = null,
    // The verifier's own session id for this presentation (from the
    // request_uri's "sessionId" query param, forwarded by go-wallet-backend)
    // - a real ZK/PPID pseudonym's verifier_context binds to THIS specific
    // session, not the verifier's static identity (confirmed 2026-08-17,
    // direct report from zk-cred-longfellow's V8/PPID author). Null for
    // non-ZK presentations or verifiers whose request_uri never carried one.
    @SerialName("verifier_session_id") val verifierSessionId: String? = null,
    /**
     * `sign_client_auth` parameters (go-wallet-backend#317). [htm] and [htu],
     * when set, ask for an RFC 9449 DPoP proof over that HTTP method and URL,
     * with [dpopNonce] as the server-provided `nonce` claim and [ath] as the
     * base64url(SHA-256(access_token)) claim for resource requests (absent at
     * the token endpoint). [keyId], when set (a renewal), names the key this
     * wallet reported as `dpop_key_id` at the original issuance and must sign
     * with again. [audience]/[issuer] double as the attestation PoP aud/iss
     * when the same request also needs client attestation.
     */
    val htm: String? = null,
    val htu: String? = null,
    @SerialName("dpop_nonce") val dpopNonce: String? = null,
    val ath: String? = null,
    @SerialName("key_id") val keyId: String? = null,
    /**
     * The OID4VP `transaction_data` entries of the request being answered by a
     * `sign_presentation`, one per element of the verifier's array in the
     * verifier's order (same shape as the WMP sign sub-flow). Only sent to a
     * client that declared [FlowStartMessage.FEATURE_TRANSACTION_DATA_V1].
     * Each entry's `raw` is the verifier's original base64url string; the rest
     * is an untrusted decoded hint.
     */
    @SerialName("transaction_data") val transactionData: List<TransactionData>? = null,
    /** The OID4VP `response_mode` of the request; required in an SCA key binding JWT (EC TS12 3.6). */
    @SerialName("response_mode") val responseMode: String? = null,
)

@Serializable
data class CredentialRef(
    @SerialName("credential_query_id") val credentialQueryId: String? = null,
    @SerialName("credential_id") val credentialId: String,
    @SerialName("disclosed_claims") val disclosedClaims: List<String>? = null,
)

@Serializable
data class MatchRequestMessage(
    val type: String = MessageTypes.MATCH_REQUEST,
    @SerialName("flow_id") val flowId: String,
    @SerialName("dcql_query") val dcqlQuery: JsonElement? = null,
    val timestamp: String? = null,
)

@Serializable
data class PushMessage(
    val type: String = MessageTypes.PUSH,
    @SerialName("push_type") val pushType: String,
    val credentials: List<CredentialResult>? = null,
    val timestamp: String? = null,
)

@Serializable
data class ErrorMessage(
    val type: String = MessageTypes.ERROR,
    val code: String,
    @SerialName("message") val details: String,
    val timestamp: String? = null,
)

/**
 * Outgoing OID4VCI §10 credential lifecycle notification. The client supplies
 * the notification_id obtained at issuance; the backend supplies the issuer
 * endpoint and access token from ephemeral flow state.
 */
@Serializable
data class CredentialNotificationMessage(
    val type: String = MessageTypes.CREDENTIAL_NOTIFICATION,
    @SerialName("flow_id") val flowId: String,
    @SerialName("notification_id") val notificationId: String,
    val event: String,
    @SerialName("event_description") val eventDescription: String? = null,
    val timestamp: String? = null,
)

/** Incoming acknowledgement for a credential_notification. */
@Serializable
data class NotificationAckMessage(
    val type: String = MessageTypes.NOTIFICATION_ACK,
    @SerialName("flow_id") val flowId: String? = null,
    @SerialName("notification_id") val notificationId: String? = null,
    val status: String,
    val error: String? = null,
    val timestamp: String? = null,
)

/** OID4VCI §10 credential lifecycle event identifiers reportable to the backend. */
object CredentialNotificationEvent {
    const val ACCEPTED = "credential_accepted"
    const val FAILURE = "credential_failure"
}
