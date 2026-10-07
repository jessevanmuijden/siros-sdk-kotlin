// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.IOException

/** How an SCA presentation attempt ended (EC TS12 v1.0.1 5.3 covers successful and failed attempts). */
@Serializable
enum class TransactionOutcome {
    /** The user confirmed and a presentation was produced. */
    @SerialName("consented") CONSENTED,

    /** The user declined. */
    @SerialName("declined") DECLINED,

    /** The wallet refused the request; see [TransactionLogEntry.reason]. */
    @SerialName("refused") REFUSED,
}

/**
 * One SCA presentation attempt, as EC TS12 v1.0.1 5.3 requires the wallet to
 * record it. Only the items 5.3 names are kept, never the full payload.
 *
 * @property transactionId `payload.transaction_id`; `null` when the request was
 *   refused before it could be read.
 * @property transactionType the transaction data `type`.
 * @property typeName for the four built-in types, the name 5.3 prescribes
 *   ("Payment Confirmation", "Login, Risk-based Authentication", "Payment
 *   Account Information Access", "E-mandate"); `null` otherwise.
 * @property entities the relevant entity names that are present, keyed
 *   `payee`, `pisp`, `service`, `aisp` (for an e-mandate, the names inside its
 *   `payment_payload`).
 * @property verifier the verifier as the wallet identified it.
 * @property credential display name of the SCA attestation.
 * @property reason for [TransactionOutcome.REFUSED] and [TransactionOutcome.DECLINED]: the
 *   [org.siros.sdk.credentials.TransactionDataReason] code.
 */
@Serializable
data class TransactionLogEntry(
    @SerialName("transaction_id") val transactionId: String?,
    @SerialName("transaction_type") val transactionType: String?,
    @SerialName("type_name") val typeName: String? = null,
    val entities: Map<String, String> = emptyMap(),
    val verifier: String? = null,
    val credential: String? = null,
    @SerialName("timestamp_millis") val timestampMillis: Long,
    val outcome: TransactionOutcome,
    val reason: String? = null,
)

/**
 * Where SCA attempts are recorded (EC TS12 5.3). The host app lists
 * [entries]. The default store keeps them in encrypted app-private storage.
 */
interface TransactionLogStore {
    /**
     * Records [entry]. May throw if the store cannot be written; callers treat
     * that as a logging failure only and never change a decision because of it.
     */
    suspend fun append(entry: TransactionLogEntry)

    /** All entries, newest first. */
    suspend fun entries(): List<TransactionLogEntry>

    /** Removes every entry. */
    suspend fun clear()
}

/**
 * A [TransactionLogStore] over one string slot of durable storage, holding a
 * JSON array. Concurrency-safe; all I/O runs on [Dispatchers.IO].
 *
 * Retention: at most [maxEntries] records and at most [maxRefused] REFUSED
 * ones, evicting REFUSED records first, so a flood of refusals (any web page
 * can fire DC API requests) can never push out the consented and declined
 * attempts TS12 5.3 wants kept. A refusal identical to the newest refusal
 * (same reason, verifier and type) within [refusalDedupMillis] is not written
 * again.
 *
 * Failure handling: a slot that cannot be READ makes [append] and [entries]
 * throw rather than overwrite history from an empty list; a slot holding
 * corrupt JSON is handed to [keepCorrupt] (so it is not destroyed) before a
 * fresh log starts; a failed write ([write] returns `false`) makes [append]
 * throw.
 *
 * @param read the stored text, or `null` if empty; throws if storage is unreadable.
 * @param write stores the text (`null` clears); returns whether it was stored.
 * @param keepCorrupt keeps a copy of text that did not parse.
 */
internal class JsonTransactionLogStore(
    private val read: () -> String?,
    private val write: (String?) -> Boolean,
    private val keepCorrupt: (String) -> Unit = {},
    private val maxEntries: Int = 500,
    private val maxRefused: Int = 100,
    private val refusalDedupMillis: Long = 60_000,
) : TransactionLogStore {
    private val json = Json { ignoreUnknownKeys = true }
    private val serializer = ListSerializer(TransactionLogEntry.serializer())
    private val lock = Any()

    private fun load(): List<TransactionLogEntry> {
        val raw = read() ?: return emptyList()
        return try {
            json.decodeFromString(serializer, raw)
        } catch (_: SerializationException) {
            keepCorrupt(raw)
            emptyList()
        } catch (_: IllegalArgumentException) {
            keepCorrupt(raw)
            emptyList()
        }
    }

    private fun evict(list: List<TransactionLogEntry>): List<TransactionLogEntry> {
        // list is newest first
        var out = list
        var refused = out.count { it.outcome == TransactionOutcome.REFUSED }
        while (refused > maxRefused) {
            out = out.toMutableList().also { it.removeAt(it.indexOfLast { e -> e.outcome == TransactionOutcome.REFUSED }) }
            refused--
        }
        while (out.size > maxEntries) {
            val victim = out.indexOfLast { it.outcome == TransactionOutcome.REFUSED }.takeIf { it >= 0 } ?: out.lastIndex
            out = out.toMutableList().also { it.removeAt(victim) }
        }
        return out
    }

    override suspend fun append(entry: TransactionLogEntry) {
        withContext(Dispatchers.IO) {
            synchronized(lock) {
                val current = load()
                if (entry.outcome == TransactionOutcome.REFUSED) {
                    val last = current.firstOrNull { it.outcome == TransactionOutcome.REFUSED }
                    if (last != null && last.reason == entry.reason && last.verifier == entry.verifier &&
                        last.transactionType == entry.transactionType &&
                        entry.timestampMillis - last.timestampMillis in 0 until refusalDedupMillis
                    ) return@synchronized
                }
                val updated = evict(listOf(entry) + current)
                if (!write(json.encodeToString(serializer, updated))) throw IOException("The transaction log could not be written")
            }
        }
    }

    override suspend fun entries(): List<TransactionLogEntry> = withContext(Dispatchers.IO) { synchronized(lock) { load() } }

    override suspend fun clear() {
        withContext(Dispatchers.IO) {
            synchronized(lock) {
                if (!write(null)) throw IOException("The transaction log could not be cleared")
            }
        }
    }
}
