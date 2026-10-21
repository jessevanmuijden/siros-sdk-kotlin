package org.siros.sdk.transport

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/**
 * Wire shapes shared by the legacy engine WebSocket and the WMP sign sub-flow for the engine-blind encryption
 * contract: the wallet, not the engine, holds the response-encryption key of an issuance and builds the encrypted
 * `direct_post.jwt` response of a presentation, so the engine relays ciphertext only.
 */

/**
 * `credential_response_encryption` on a `generate_proof` sign request: the pair the engine negotiated against the
 * issuer's metadata. The wallet answers with a fresh public key for it (`credential_response_encryption_jwk`), or
 * declines by leaving that out; a decline fails the issuance when [required] is true.
 */
@Serializable
data class CredentialResponseEncryptionRequest(
    val alg: String,
    val enc: String,
    val required: Boolean = false,
)

/**
 * `response_encryption` on a `direct_post.jwt` `sign_presentation` request: the verifier's public key with its
 * `kid`, and the `alg`/`enc` the engine resolved (client_metadata, else the request object's x5c key; GCM by default),
 * so the wallet re-derives none of it.
 */
@Serializable
data class ResponseEncryptionRequest(
    val jwk: JsonObject,
    val alg: String,
    val enc: String,
) {
    // The verifier's key is public, but nothing here needs to appear in a log.
    override fun toString() = "ResponseEncryptionRequest($alg/$enc)"
}

/**
 * `verified_request` of a `sign_presentation` request (go-wallet-backend#471): the OpenID4VP request as the ENGINE
 * validated it. It carries no trust verdict. For an encrypted (`direct_post.jwt`) response the wallet takes the JARM
 * `aud` from [clientId], never from the sign request's `audience`; the engine alone POSTs, and only to [responseUri].
 * Members the wallet does not understand are ignored.
 */
@Serializable
data class VerifiedRequest(
    @SerialName("client_id") val clientId: String? = null,
    @SerialName("client_id_scheme") val clientIdScheme: String? = null,
    @SerialName("response_mode") val responseMode: String? = null,
    @SerialName("response_uri") val responseUri: String? = null,
    /** True only when [signatureVerification] is `verified`; a client that does not know the field reads it as not signed. */
    val signed: Boolean = false,
    /** `verified`, `deferred` or `none`; `deferred` is never treated as verified. */
    @SerialName("signature_verification") val signatureVerification: String? = null,
    @SerialName("client_metadata") val clientMetadata: JsonElement? = null,
)

/** The member names of the encrypted-issuance answer, shared so the two transports cannot drift. */
object BlindEncryptionWire {
    /** Sign action: the engine hands the wallet one issuer JWE to open. */
    const val ACTION_DECRYPT_CREDENTIAL_RESPONSE = "decrypt_credential_response"
}
