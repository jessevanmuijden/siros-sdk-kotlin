// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * What the wallet declares to an orchestrator about OpenID4VP
 * `transaction_data` (EC TS12), and the refusal applied to a request that
 * carries it.
 */
internal object TransactionDataSupport {
    /** The `transaction_data` WMP capability name (OpenID4x profile 2.3). */
    const val CAPABILITY = "transaction_data"

    /** Hash algorithms (`transaction_data_hashes_alg` names) this SDK can compute. */
    val HASH_ALGS: List<String> = org.siros.sdk.keystore.TransactionBinding.HASH_ALGS

    /**
     * The `capabilities_offered` object for a WMP session, or `null` when
     * nothing is to be declared. Keyed by capability name.
     */
    fun capabilitiesOffered(effectivelyEnabled: Boolean): JsonObject? {
        if (!effectivelyEnabled) return null
        return buildJsonObject {
            put(
                CAPABILITY,
                buildJsonObject {
                    put("versions", JsonArray(listOf(JsonPrimitive(1))))
                    put("hash_algs", JsonArray(HASH_ALGS.map(::JsonPrimitive)))
                },
            )
        }
    }

    /**
     * The `flow_start.features` list for the legacy engine WebSocket, or
     * `null` when nothing is to be declared.
     */
    fun engineFeatures(effectivelyEnabled: Boolean): List<String>? =
        if (effectivelyEnabled) {
            listOf(org.siros.sdk.transport.engine.FlowStartMessage.FEATURE_TRANSACTION_DATA_V1)
        } else {
            null
        }
}
