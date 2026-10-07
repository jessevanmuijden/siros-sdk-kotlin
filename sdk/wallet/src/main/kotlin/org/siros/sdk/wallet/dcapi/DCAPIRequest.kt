// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class DCAPIRequestException(message: String) : Exception(message)

/**
 * Key material a signed/multisigned DC API JAR request conveyed in its JWS
 * header, for trust evaluation - the same shape (x5c or jwk) already used by
 * [org.siros.sdk.wallet.SirosWallet]'s engine-relayed trust evaluation.
 */
data class DCAPIRequestKeyMaterial(
    val x5c: List<String>? = null,
    val jwk: JsonObject? = null,
)

/**
 * A parsed W3C Digital Credentials API OpenID4VP request (OpenID4VP 1.0
 * Appendix A). [clientId] is null for the unsigned protocol variant (the
 * verified browser origin stands in for it - see
 * [org.siros.sdk.wallet.SirosWallet.handleDCAPIRequest]).
 */
data class DCAPIRequest(
    val clientId: String?,
    val responseMode: String,
    val nonce: String,
    val dcqlQuery: JsonObject?,
    val clientMetadata: JsonObject?,
    /** Present only for the signed/multisigned protocol variant. */
    val keyMaterial: DCAPIRequestKeyMaterial? = null,
    /**
     * The protocol identifier from the incoming request's `requests[0].protocol`
     * (e.g. "openid4vp-v1-signed") - the platform's own reference wallet
     * (https://github.com/digitalcredentialsdev/CMWallet) echoes this back
     * verbatim in the final response envelope (`{"protocol": ..., "data":
     * ...}`), so it must be threaded through from the request.
     */
    val protocol: String,
    /**
     * OAuth2/OIDC `state` (OpenID4VP 1.0 §5.1) - the verifier's only means of
     * correlating this response back to the right authorization session,
     * since the response arrives via a wholly separate channel (the DC API
     * callback) with no other correlator. The wallet MUST echo this back
     * unchanged in its response body; omitting it left the verifier with no
     * way to find which session's ephemeral key/DCQL query to use.
     */
    val state: String?,
    /**
     * Whether the request object has a `transaction_data` member (OpenID4VP
     * 1.0 5.1), whatever its value. The SDK must never answer such a request
     * as if it were absent, so presence alone is what is recorded here; any
     * value, including `null` or an empty array, counts.
     */
    val hasTransactionData: Boolean = false,
    /** The value of the `transaction_data` member when present (not validated here); `null` when absent. */
    val transactionData: kotlinx.serialization.json.JsonElement? = null,
)

/**
 * Parses the raw request data string handed to the wallet by the OS/browser
 * for a `navigator.credentials.get({digital: {requests: [{protocol, data}]}})`
 * call - either a raw OpenID4VP authorization request JSON object (the
 * `openid4vp-v1-unsigned` protocol variant) or `{"request": "<JWT>"}` (the
 * `openid4vp-v1-signed`/`-multisigned` JAR variant).
 *
 * For the signed variant, the JWS signature IS verified here against the key
 * material embedded in the JWT's own header (x5c or jwk) - an unverified
 * "signed" request would otherwise provide false assurance of authenticity.
 * Whether that key is itself trustworthy (i.e. actually belongs to a
 * legitimate relying party) is a separate, later step - the existing AuthZEN
 * trust-evaluation call, unchanged from the redirect-flow presentation path.
 */
object DCAPIRequestParser {
    private val json = Json { ignoreUnknownKeys = true }

    fun parse(rawRequestJson: String): DCAPIRequest {
        val outer = try {
            json.parseToJsonElement(rawRequestJson).jsonObject
        } catch (e: Exception) {
            throw DCAPIRequestException("DC API request is not valid JSON: ${e.message}")
        }

        // [GetDigitalCredentialOption.requestJson] is the FULL request handed
        // to navigator.credentials.get({digital: {requests: [{protocol,
        // data}]}}) - {"requests": [{"protocol": ..., "data": {...}}, ...]} -
        // not a single request's `data` object on its own. The platform
        // picker only surfaces an entry after matching it against one of our
        // registered protocols, so the first (and in practice only, since
        // the caller picks one best protocol before invoking the API) entry
        // is the one that was selected; its `data` is what the rest of this
        // parser (signed vs. unsigned) actually operates on.
        val requestEntries = (outer["requests"] as? JsonArray)
            ?: throw DCAPIRequestException("DC API request missing 'requests' array")
        val requestEntry = requestEntries.firstOrNull()?.jsonObject
            ?: throw DCAPIRequestException("DC API request's 'requests' array is empty")
        val data = requestEntry["data"]?.jsonObject
            ?: throw DCAPIRequestException("DC API request's first entry is missing 'data'")

        val requestJwt = data["request"]?.jsonPrimitive?.contentOrNull
        // The platform's own reference wallet echoes this protocol identifier
        // back verbatim in the final response envelope - see
        // SirosWallet.handleDCAPIRequest's doc comment on why this can't just
        // be inferred/hardcoded there. Falls back to the OpenID4VP protocol
        // implied by this request's own shape if the entry omits it (should
        // not happen per the DC API spec, but the response envelope still
        // needs *some* value).
        val protocol = requestEntry["protocol"]?.jsonPrimitive?.contentOrNull
            ?: if (requestJwt != null) "openid4vp-v1-signed" else "openid4vp-v1-unsigned"
        return if (requestJwt != null) parseSigned(requestJwt, protocol) else parseUnsigned(data, protocol)
    }

    private fun parseUnsigned(obj: JsonObject, protocol: String): DCAPIRequest {
        return DCAPIRequest(
            clientId = obj["client_id"]?.jsonPrimitive?.contentOrNull,
            responseMode = obj["response_mode"]?.jsonPrimitive?.contentOrNull ?: "dc_api",
            nonce = obj["nonce"]?.jsonPrimitive?.contentOrNull
                ?: throw DCAPIRequestException("DC API request missing required 'nonce'"),
            dcqlQuery = obj["dcql_query"]?.jsonObject,
            clientMetadata = obj["client_metadata"]?.jsonObject,
            keyMaterial = null,
            protocol = protocol,
            state = obj["state"]?.jsonPrimitive?.contentOrNull,
            hasTransactionData = obj.containsKey("transaction_data"),
            transactionData = obj["transaction_data"],
        )
    }

    private fun parseSigned(jwt: String, protocol: String): DCAPIRequest {
        val signedJwt = try {
            SignedJWT.parse(jwt)
        } catch (e: Exception) {
            throw DCAPIRequestException("DC API signed request is not a valid JWS: ${e.message}")
        }

        val header = signedJwt.header
        val x5cChain = header.x509CertChain?.takeIf { it.isNotEmpty() }
        val headerJwk = header.jwk

        val verifier: JWSVerifier = when {
            x5cChain != null -> {
                val cert = X509CertUtils.parse(x5cChain.first().decode())
                    ?: throw DCAPIRequestException("Failed to parse DC API request's x5c leaf certificate")
                buildVerifier(cert.publicKey)
            }
            headerJwk != null -> buildVerifier(headerJwk)
            else -> throw DCAPIRequestException(
                "DC API signed request header has neither x5c nor jwk - cannot verify signature"
            )
        }

        if (!signedJwt.verify(verifier)) {
            throw DCAPIRequestException("DC API signed request JWS signature verification failed")
        }

        val payload = json.parseToJsonElement(signedJwt.payload.toString()).jsonObject
        val keyMaterialJwkJson = headerJwk?.let {
            json.parseToJsonElement(it.toJSONString()).jsonObject
        }

        return DCAPIRequest(
            clientId = payload["client_id"]?.jsonPrimitive?.contentOrNull,
            responseMode = payload["response_mode"]?.jsonPrimitive?.contentOrNull ?: "dc_api.jwt",
            nonce = payload["nonce"]?.jsonPrimitive?.contentOrNull
                ?: throw DCAPIRequestException("DC API signed request payload missing required 'nonce'"),
            dcqlQuery = payload["dcql_query"]?.jsonObject,
            clientMetadata = payload["client_metadata"]?.jsonObject,
            keyMaterial = DCAPIRequestKeyMaterial(
                x5c = x5cChain?.map { it.toString() },
                jwk = keyMaterialJwkJson,
            ),
            protocol = protocol,
            state = payload["state"]?.jsonPrimitive?.contentOrNull,
            hasTransactionData = payload.containsKey("transaction_data"),
            transactionData = payload["transaction_data"],
        )
    }

    private fun buildVerifier(publicKey: java.security.PublicKey): JWSVerifier = when (publicKey) {
        is java.security.interfaces.ECPublicKey -> ECDSAVerifier(publicKey)
        is java.security.interfaces.RSAPublicKey -> RSASSAVerifier(publicKey)
        else -> throw DCAPIRequestException("Unsupported DC API request signing key type: ${publicKey.algorithm}")
    }

    private fun buildVerifier(jwk: JWK): JWSVerifier = when (jwk) {
        is ECKey -> ECDSAVerifier(jwk)
        is RSAKey -> RSASSAVerifier(jwk)
        else -> throw DCAPIRequestException("Unsupported DC API request signing JWK type: ${jwk.keyType}")
    }
}
