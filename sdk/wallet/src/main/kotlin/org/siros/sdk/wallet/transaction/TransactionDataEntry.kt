// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.transport.wmp.openid4x.TransactionData
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.Base64

/**
 * One entry of an OpenID4VP `transaction_data` array as a transport delivers
 * it: [raw], the base64url string exactly as the verifier sent it, and an
 * optional decoded [hint] from an orchestrator (the engine WebSocket and WMP
 * send one; the DC API has none).
 *
 * [raw] is the only trusted member and the only hash input (OpenID4VP 1.0
 * Appendix B). The hint is checked against the wallet's own decoding and
 * otherwise ignored.
 */
internal class TransactionDataEntry(val raw: String, val hint: TransactionDataHint? = null) {
    companion object {
        /**
         * From the wire entry of the engine WebSocket or WMP.
         *
         * @throws TransactionDataError `INVALID_ENTRY` when the orchestrator
         *   did not send `raw` (one that predates it): without the original
         *   string the wallet cannot bind to the transaction.
         */
        fun fromWire(wire: TransactionData): TransactionDataEntry {
            val raw = wire.raw
            if (raw.isNullOrEmpty()) {
                throw TransactionDataError(
                    TransactionDataReason.INVALID_ENTRY,
                    "The orchestrator sent a transaction_data entry without its original encoding (raw)",
                )
            }
            return TransactionDataEntry(
                raw,
                TransactionDataHint(
                    type = wire.type,
                    credentialIds = wire.credentialIds,
                    payload = wire.payload,
                    hashAlgs = wire.transactionDataHashesAlg,
                ),
            )
        }
    }
}

/** The orchestrator's decoded copy of an entry. Untrusted; see [TransactionDataEntry]. */
internal class TransactionDataHint(
    val type: String?,
    val credentialIds: List<String>?,
    val payload: JsonElement?,
    val hashAlgs: List<String>?,
)

/** An entry decoded by this wallet from its own [raw]. */
internal class DecodedTransactionData(
    val raw: String,
    val type: String,
    val credentialIds: List<String>,
    val payload: JsonObject,
    /** The verifier's list of acceptable hash algorithms; `null` when it gave none. */
    val hashAlgs: List<String>?,
)

/** Decodes and structurally checks one entry (contract section 4, steps 1 and 2a). */
internal object TransactionDataDecoder {
    /** Upper bound on an entry's encoded size; a payment confirmation is well under 2 KiB. */
    const val MAX_RAW_CHARS = 64 * 1024

    private const val BAD_ALG_LIST = "bad hash algorithm list"

    private val json = Json

    fun decode(entry: TransactionDataEntry): DecodedTransactionData {
        val raw = entry.raw
        if (raw.isEmpty() || raw.length > MAX_RAW_CHARS) invalid("size of raw is out of bounds")
        if (!raw.all { it.isBase64UrlChar() || it == '=' }) invalid("raw is not base64url")
        val bytes = try {
            Base64.getUrlDecoder().decode(raw)
        } catch (_: IllegalArgumentException) {
            invalid("raw is not base64url")
        }
        val text = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (_: java.nio.charset.CharacterCodingException) {
            invalid("raw is not UTF-8")
        }
        if (JsonDuplicateKeys.has(text)) invalid("the entry repeats a member name")
        val obj = try {
            json.parseToJsonElement(text) as? JsonObject
        } catch (_: Exception) {
            null
        } catch (_: StackOverflowError) {
            null
        } ?: invalid("raw is not a JSON object")

        val type = (obj["type"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        if (type.isNullOrEmpty()) invalid("type is missing or empty")

        val ids = (obj["credential_ids"] as? JsonArray)?.map {
            (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content?.takeIf { s -> s.isNotEmpty() }
                ?: invalid("credential_ids must hold non-empty strings")
        }
        if (ids.isNullOrEmpty()) invalid("credential_ids is missing or empty")

        val payload = obj["payload"] as? JsonObject ?: invalid("payload is missing or not an object")

        val algs = when (val a = obj["transaction_data_hashes_alg"]) {
            null -> null
            is JsonPrimitive -> if (a.isString && a.content.isNotEmpty()) listOf(a.content) else invalid(BAD_ALG_LIST)
            is JsonArray -> a.map {
                (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content?.takeIf { s -> s.isNotEmpty() }
                    ?: invalid(BAD_ALG_LIST)
            }.takeIf { it.isNotEmpty() } ?: invalid(BAD_ALG_LIST)
            else -> invalid(BAD_ALG_LIST)
        }

        val decoded = DecodedTransactionData(raw, type, ids, payload, algs)
        entry.hint?.let { checkHint(it, decoded) }
        return decoded
    }

    /**
     * A hint that disagrees with the entry's own encoding means the
     * orchestrator would have the user shown one transaction while another is
     * bound; refuse rather than pick a side. An absent hint member is not a
     * disagreement.
     */
    private fun checkHint(hint: TransactionDataHint, decoded: DecodedTransactionData) {
        fun mismatch(member: String): Nothing = throw TransactionDataError(
            TransactionDataReason.INCONSISTENT_WITH_ORCHESTRATOR,
            "The orchestrator's decoded '$member' differs from the transaction_data entry itself",
        )
        if (hint.type != null && hint.type != decoded.type) mismatch("type")
        if (hint.credentialIds != null && hint.credentialIds != decoded.credentialIds) mismatch("credential_ids")
        if (hint.payload != null && hint.payload != decoded.payload) mismatch("payload")
        if (hint.hashAlgs != null && hint.hashAlgs != decoded.hashAlgs) mismatch("transaction_data_hashes_alg")
    }

    private fun Char.isBase64UrlChar(): Boolean =
        this in 'A'..'Z' || this in 'a'..'z' || this in '0'..'9' || this == '-' || this == '_'

    private fun invalid(why: String): Nothing =
        throw TransactionDataError(TransactionDataReason.INVALID_ENTRY, "Invalid transaction_data entry: $why")
}
