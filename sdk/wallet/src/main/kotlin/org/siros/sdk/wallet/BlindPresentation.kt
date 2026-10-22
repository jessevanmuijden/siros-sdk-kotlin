// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.transport.ResponseEncryptionRequest

/**
 * The wallet's side of an engine-blind `direct_post.jwt` presentation: the `vp_token` it signed is shaped and
 * encrypted to the verifier here, and the engine only POSTs the resulting JWE. Nothing here logs.
 */
internal object BlindPresentation {
    /**
     * The `vp_token` of the authorization response. When any presented credential answers a DCQL query (carries a
     * `credential_query_id`) it is the OpenID4VP 1.0 section 8.1 object `{queryId: [token, ...]}`, tokens grouped by
     * query id in presentation order, an entry without a query id left out exactly as the engine did; otherwise it is
     * the tokens as one string (newline-joined when there are several), as the engine passed it through.
     *
     * @param parts one `(credentialQueryId, token)` per presented credential, in presentation order.
     */
    fun vpToken(parts: List<Pair<String?, String>>): JsonElement {
        // The same test as the grouping below: an empty query id is no query id.
        if (parts.none { !it.first.isNullOrEmpty() }) return JsonPrimitive(parts.joinToString("\n") { it.second })
        val byQuery = LinkedHashMap<String, MutableList<String>>()
        for ((queryId, token) in parts) {
            if (queryId.isNullOrEmpty()) continue
            byQuery.getOrPut(queryId) { mutableListOf() }.add(token)
        }
        return JsonObject(byQuery.mapValues { (_, tokens) -> JsonArray(tokens.map { JsonPrimitive(it) }) })
    }

    /** The compact JWE to answer `sign_presentation` with (`response_jwe`). */
    fun responseJwe(
        request: ResponseEncryptionRequest,
        audience: String,
        state: String?,
        parts: List<Pair<String?, String>>,
    ): String = responseJwe(request, audience, state, vpToken(parts))

    /**
     * The same for a `vp_token` the caller already shaped (the `zkp_req` redirect route builds
     * `{queryId: [base64url CBOR]}` itself).
     */
    fun responseJwe(
        request: ResponseEncryptionRequest,
        audience: String,
        state: String?,
        vpToken: JsonElement,
    ): String = AuthorizationResponseEncryption.encrypt(
        vpToken = vpToken,
        audience = audience,
        state = state,
        verifierJwk = request.jwk,
        alg = request.alg,
        enc = request.enc,
    )
}
