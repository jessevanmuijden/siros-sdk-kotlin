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
    private const val MAX_EVENT_ID = 0xFFFFFFFFL

    /**
     * The hash of [event] as wallet-frontend computes it (`calculateEventHash`): SHA-256, lowercase hex,
     * of `JSON.stringify(normalize(event))`: every object's keys sorted, then serialized the way
     * JavaScript does (integer-like keys first in numeric order, then the others in sorted order;
     * JavaScript string escapes and number formatting). For `new_keypair` the keypair's
     * `wrappedPrivateKey` is set to null first because it changes with every keystore change.
     */
    fun hash(event: JsonObject): String {
        var e: JsonElement = event
        if ((event["type"] as? JsonPrimitive)?.content == "new_keypair") {
            (event["keypair"] as? JsonObject)?.let { kp ->
                e = JsonObject(event + ("keypair" to JsonObject(kp + ("wrappedPrivateKey" to JsonNull))))
            }
        }
        val bytes = StringBuilder().also { stringify(e, it) }.toString().toByteArray(Charsets.UTF_8)
        return MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }

    private val ARRAY_INDEX = Regex("0|[1-9][0-9]{0,8}|[1-3][0-9]{9}")

    private fun isArrayIndex(k: String): Boolean = ARRAY_INDEX.matches(k) && k.toLong() < 4294967295L

    private fun stringify(e: JsonElement, sb: StringBuilder) {
        when (e) {
            is JsonObject -> {
                // normalize() inserts the keys sorted; JS then enumerates array-index keys first, ascending.
                val sorted = e.keys.sorted()
                val ordered = sorted.filter(::isArrayIndex).sortedBy { it.toLong() } + sorted.filterNot(::isArrayIndex)
                sb.append('{')
                ordered.forEachIndexed { i, k ->
                    if (i > 0) sb.append(',')
                    quote(k, sb); sb.append(':'); stringify(e.getValue(k), sb)
                }
                sb.append('}')
            }
            is JsonArray -> {
                sb.append('[')
                e.forEachIndexed { i, v -> if (i > 0) sb.append(','); stringify(v, sb) }
                sb.append(']')
            }
            is JsonNull -> sb.append("null")
            is JsonPrimitive -> if (e.isString) quote(e.content, sb) else sb.append(jsNumberOrLiteral(e.content))
        }
    }

    /** `true`/`false` as they are; a number as JavaScript prints it where that differs from the literal (1.0, 1E2). */
    private fun jsNumberOrLiteral(c: String): String {
        if (c == "true" || c == "false") return c
        val bd = c.toBigDecimalOrNull() ?: return c
        val abs = bd.abs()
        if (bd.signum() == 0) return "0"
        val inPlainRange = abs >= java.math.BigDecimal("1e-6") && abs < java.math.BigDecimal("1e21")
        return if (inPlainRange) bd.stripTrailingZeros().toPlainString() else c
    }

    /** JSON.stringify's string quoting: \b \f \n \r \t, other control characters as lowercase \u00xx, lone surrogates as \udxxx. */
    private fun quote(s: String, sb: StringBuilder) {
        sb.append('"')
        var i = 0
        while (i < s.length) {
            val ch = s[i]
            when {
                ch == '"' -> sb.append("\\\"")
                ch == '\\' -> sb.append("\\\\")
                ch == '\b' -> sb.append("\\b")
                ch == '\u000C' -> sb.append("\\f")
                ch == '\n' -> sb.append("\\n")
                ch == '\r' -> sb.append("\\r")
                ch == '\t' -> sb.append("\\t")
                ch < ' ' -> sb.append("\\u%04x".format(ch.code))
                Character.isHighSurrogate(ch) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> { sb.append(ch).append(s[i + 1]); i++ }
                Character.isSurrogate(ch) -> sb.append("\\u%04x".format(ch.code))
                else -> sb.append(ch)
            }
            i++
        }
        sb.append('"')
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
        existing: List<JsonObject>,
        nowSeconds: Long,
        nextEventId: () -> Long,
    ): List<JsonObject> {
        val changes = sortedMapOf<Pair<String, String>, String?>(compareBy({ it.first }, { it.second }))
        for ((ns, entries) in after) for ((k, v) in entries) if (before[ns]?.get(k) != v) changes[ns to k] = v
        for ((ns, entries) in before) for (k in entries.keys) if (after[ns]?.containsKey(k) != true) changes[ns to k] = null
        val out = ArrayList<JsonObject>()
        val taken = existing.mapNotNull { (it["eventId"] as? JsonPrimitive)?.content?.toLongOrNull() }.toHashSet()
        // Merge is last-write-wins by (timestampSeconds, eventId), so a new event for a key must sort
        // after every event already written for it, even within the same second.
        val best = HashMap<Pair<String, String>, Pair<Long, Long>>()
        for (ev in existing) {
            if ((ev["type"] as? JsonPrimitive)?.content != "set_extension") continue
            val key = (ev["namespace"] as? JsonPrimitive)?.content.orEmpty() to (ev["key"] as? JsonPrimitive)?.content.orEmpty()
            val at = ((ev["timestampSeconds"] as? JsonPrimitive)?.content?.toLongOrNull() ?: 0L) to
                ((ev["eventId"] as? JsonPrimitive)?.content?.toLongOrNull() ?: 0L)
            val cur = best[key]
            if (cur == null || at.first > cur.first || (at.first == cur.first && at.second > cur.second)) best[key] = at
        }
        var parent = parentHash
        for ((nk, value) in changes) {
            var ts = nowSeconds
            var id = nextEventId()
            best[nk]?.let { (bTs, bId) ->
                if (ts < bTs) ts = bTs
                if (ts == bTs && id <= bId) {
                    if (bId < MAX_EVENT_ID) id = bId + 1 else { ts = bTs + 1 }
                }
            }
            while (!taken.add(id)) id = if (id < MAX_EVENT_ID) id + 1 else 1L
            best[nk] = ts to id
            val event = JsonObject(
                linkedMapOf(
                    "type" to JsonPrimitive("set_extension"),
                    "schemaVersion" to JsonPrimitive(PrivateDataSchema.CURRENT_VERSION),
                    "eventId" to JsonPrimitive(id),
                    "parentHash" to JsonPrimitive(parent),
                    "timestampSeconds" to JsonPrimitive(ts),
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
