// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import java.util.concurrent.ConcurrentHashMap
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import org.siros.sdk.transport.CredentialResponseEncryptionRequest
import org.siros.sdk.transport.DeliveredResponseMetadata
import org.siros.sdk.transport.ResponseCredentialMetadata

/**
 * The wallet could not do what the engine asked for an encrypted issuance. The message names no content.
 * [notificationId] is the `notification_id` of a response the wallet DID decrypt but rejected, so the issuer can still be told
 * (`credential_failure`); null when nothing could be read.
 */
internal class BlindIssuanceException(message: String, val notificationId: String? = null) : Exception(message)

/**
 * The only members of an opened Credential Response the engine may learn, because it must act on them: EXACTLY ONE of
 * [credentialCount] (1..[MAX_CREDENTIAL_COUNT], credentials issued) or [transactionId] (deferred, with the optional [interval]).
 */
internal class BlindIssuanceControl(val credentialCount: Int?, val transactionId: String?, val interval: Int?) {
    companion object {
        /** The engine refuses a larger `credential_count`. */
        const val MAX_CREDENTIAL_COUNT = 256
    }
}

/**
 * The Credential Response(s) of one issuance as the wallet opened them: the credentials, the response-level
 * `credential_metadata` and the `notification_id` never left the wallet, so the engine could not read them.
 * Nothing here prints a value.
 */
internal class OpenedIssuance(
    val credentials: List<String>,
    override val credentialMetadata: ResponseCredentialMetadata?,
    val notificationId: String?,
    /** True when the credentials arrived in a Deferred Credential Response. */
    override val deferredResponse: Boolean,
) : DeliveredResponseMetadata {
    /** Only a response the wallet itself decrypted is an [OpenedIssuance]. */
    override val credentialMetadataEncryptedResponse: Boolean get() = true

    override fun toString() = "OpenedIssuance(redacted)"
}

/**
 * Per-flow key and opened-response state for the engine-blind issuance of OpenID4VCI: the wallet generates the
 * credential-response encryption key, opens the issuer's JWE, and keeps what is in it.
 *
 * A key is generated fresh for EVERY `generate_proof` request (a c_nonce retry sends a new request and so gets a new
 * key; the key of the request that produced the issuer's reply is the latest one) and lives only here, in memory.
 * [drop] and [clear] forget a flow's key and everything opened for it.
 */
internal class BlindIssuance {
    private class FlowState {
        @Volatile var key: CredentialResponseKey? = null
        val opened = mutableListOf<OpenedIssuance>()
    }

    private val flows = ConcurrentHashMap<String, FlowState>()

    /**
     * The `generate_proof` step: returns the public JWK to answer with, or null to decline (the engine offered no
     * encryption). A previous key of the flow is replaced.
     *
     * @throws BlindIssuanceException when the issuer REQUIRES encryption and the wallet cannot provide a key for the
     *   negotiated pair: the issuance fails here, with a message that says why, instead of at the issuer.
     */
    fun offer(flowId: String, request: CredentialResponseEncryptionRequest?): JsonObject? {
        if (request == null) {
            flows[flowId]?.key = null
            return null
        }
        val key = CredentialResponseKey.generate(request.alg, request.enc)
        if (key == null) {
            flows[flowId]?.key = null
            if (request.required) {
                throw BlindIssuanceException("The issuer requires an encrypted credential response (${request.alg}/${request.enc}) and this wallet cannot decrypt it")
            }
            return null
        }
        flows.getOrPut(flowId) { FlowState() }.key = key
        return key.publicJwk
    }

    /**
     * The `decrypt_credential_response` step: opens [jwe] with the flow's key and keeps what it says. Returns what
     * the engine needs to continue (a deferred issuance's `transaction_id`), nothing else.
     *
     * @throws BlindIssuanceException when there is no key for the flow, the JWE does not decrypt, or what it
     *   decrypts to is not a Credential Response.
     */
    fun open(flowId: String, jwe: String, deferred: Boolean): BlindIssuanceControl {
        val state = flows[flowId]
        val key = state?.key ?: throw BlindIssuanceException("No credential response key exists for this flow")
        val plaintext = try {
            key.decrypt(jwe)
        } catch (e: IllegalArgumentException) {
            throw BlindIssuanceException(e.message ?: "The credential response could not be decrypted")
        }
        val body = try {
            Json.parseToJsonElement(plaintext) as? JsonObject
        } catch (e: Exception) {
            null
        } ?: throw BlindIssuanceException("The decrypted credential response is not a JSON object")
        val credentials = buildList {
            // OpenID4VCI 1.0 returns `credentials`; an earlier draft returned one `credential`. Same order as before.
            body["credential"]?.takeIf { it !is kotlinx.serialization.json.JsonNull }?.let { add(credentialString(it)) }
            (body["credentials"] as? JsonArray)?.forEach { add(credentialString(it)) }
        }
        val metadata = body["credential_metadata"]?.takeIf { it !is kotlinx.serialization.json.JsonNull }?.let {
            (it as? JsonObject)?.let { obj -> ResponseCredentialMetadata(obj) } ?: ResponseCredentialMetadata(malformed = true)
        }
        val notificationId = (body["notification_id"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.takeIf { it.isNotEmpty() }
        val transactionId = (body["transaction_id"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.takeIf { it.isNotEmpty() }
        val interval = (body["interval"] as? JsonPrimitive)?.intOrNull
        // Exactly one of credentials issued or deferred: both or neither is not a Credential Response the engine can act on.
        // Nothing is kept for a response that is refused, and its notification_id (if any) lets the issuer be told.
        if (transactionId != null && credentials.isNotEmpty()) {
            throw BlindIssuanceException("The credential response carries both credentials and a transaction_id", notificationId)
        }
        if (transactionId == null && credentials.isEmpty()) {
            throw BlindIssuanceException("The credential response carries neither credentials nor a transaction_id", notificationId)
        }
        if (credentials.size > BlindIssuanceControl.MAX_CREDENTIAL_COUNT) {
            throw BlindIssuanceException("The credential response carries more than ${BlindIssuanceControl.MAX_CREDENTIAL_COUNT} credentials", notificationId)
        }
        synchronized(state.opened) {
            state.opened += OpenedIssuance(credentials, metadata, notificationId, deferred)
        }
        return if (transactionId != null) {
            BlindIssuanceControl(credentialCount = null, transactionId = transactionId, interval = interval)
        } else {
            BlindIssuanceControl(credentialCount = credentials.size, transactionId = null, interval = null)
        }
    }

    /**
     * The issuance at completion: every credential opened for the flow, in order, with the metadata and
     * `notification_id` of the response that carried them. Removes the flow's state: the key is gone after this.
     * Null when nothing was opened for the flow.
     */
    fun take(flowId: String): OpenedIssuance? {
        val state = flows.remove(flowId) ?: return null
        val opened = synchronized(state.opened) { state.opened.toList() }
        if (opened.isEmpty()) return null
        val carriers = opened.filter { it.credentials.isNotEmpty() }
        val last = carriers.lastOrNull() ?: opened.last()
        return OpenedIssuance(
            credentials = carriers.flatMap { it.credentials },
            credentialMetadata = last.credentialMetadata,
            notificationId = last.notificationId,
            deferredResponse = last.deferredResponse,
        )
    }

    /** Forgets one flow's key and everything opened for it. */
    fun drop(flowId: String) {
        flows.remove(flowId)
    }

    /** Forgets every flow's key and everything opened (cancel, logout, a new connection). */
    fun clear() {
        flows.clear()
    }

    /** Whether a key is currently held for [flowId]. */
    fun holdsKey(flowId: String): Boolean = flows[flowId]?.key != null

    private fun credentialString(value: JsonElement): String = when {
        value is JsonPrimitive && value.isString -> value.content
        value is JsonObject && (value["credential"] as? JsonPrimitive)?.isString == true -> (value["credential"] as JsonPrimitive).content
        else -> value.toString()
    }
}
