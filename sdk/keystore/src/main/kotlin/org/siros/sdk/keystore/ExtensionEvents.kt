package org.siros.sdk.keystore

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest

/**
 * `set_extension` events for changes to `S.extensions` (privatedata-spec 3.0, section 6.1.3: a client
 * that keeps no event log of its own MUST still append one, chained by `parentHash` as wallet-frontend
 * chains events, whenever it changes `S.extensions`).
 *
 * The SDK holds `S` as a snapshot, so it derives the events from the difference between the extension
 * entries it loaded (or last wrote) and the ones it holds now.
 */
internal object ExtensionEvents {
    /**
     * The hash of [event] as wallet-frontend computes it (`calculateEventHash`): SHA-256, lowercase hex,
     * of the compact JSON with every object's keys sorted; for `new_keypair` the keypair's
     * `wrappedPrivateKey` is set to null first because it changes with every keystore change.
     */
    fun hash(event: JsonObject): String {
        var e: JsonElement = event
        if ((event["type"] as? JsonPrimitive)?.content == "new_keypair") {
            (event["keypair"] as? JsonObject)?.let { kp ->
                e = JsonObject(event + ("keypair" to JsonObject(kp + ("wrappedPrivateKey" to JsonNull))))
            }
        }
        val bytes = normalize(e).toString().toByteArray(Charsets.UTF_8)
        return MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }

    private fun normalize(e: JsonElement): JsonElement = when (e) {
        is JsonObject -> JsonObject(e.entries.sortedBy { it.key }.associate { it.key to normalize(it.value) })
        is JsonArray -> JsonArray(e.map(::normalize))
        else -> e
    }

    /**
     * The events that turn [before] into [after]: one per changed `(namespace, key)`, in key order, a
     * removal as a tombstone (`value` null). Each is stamped `schemaVersion` 4 and chained from
     * [parentHash] (the hash of the last event, or `lastEventHash` when there is none).
     */
    fun diff(
        before: Map<String, Map<String, String>>,
        after: Map<String, Map<String, String>>,
        parentHash: String,
        usedEventIds: Set<Long>,
        nowSeconds: Long,
        nextEventId: () -> Long,
    ): List<JsonObject> {
        val changes = sortedMapOf<Pair<String, String>, String?>(compareBy({ it.first }, { it.second }))
        for ((ns, entries) in after) for ((k, v) in entries) if (before[ns]?.get(k) != v) changes[ns to k] = v
        for ((ns, entries) in before) for (k in entries.keys) if (after[ns]?.containsKey(k) != true) changes[ns to k] = null
        val out = ArrayList<JsonObject>()
        val taken = HashSet(usedEventIds)
        var parent = parentHash
        for ((nk, value) in changes) {
            var id = nextEventId()
            while (!taken.add(id)) id = nextEventId()
            val event = JsonObject(
                linkedMapOf(
                    "type" to JsonPrimitive("set_extension"),
                    "schemaVersion" to JsonPrimitive(PrivateDataSchema.CURRENT_VERSION),
                    "eventId" to JsonPrimitive(id),
                    "parentHash" to JsonPrimitive(parent),
                    "timestampSeconds" to JsonPrimitive(nowSeconds),
                    "namespace" to JsonPrimitive(nk.first),
                    "key" to JsonPrimitive(nk.second),
                    "value" to (if (value == null) JsonNull else JsonPrimitive(value)),
                ),
            )
            out.add(event)
            parent = hash(event)
        }
        return out
    }
}
