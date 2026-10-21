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

    /** A canonical array index: "0" or digits without a leading zero, below 2^32 - 1. */
    private fun isArrayIndex(k: String): Boolean =
        k.isNotEmpty() && k.length <= 10 && k.all { it in '0'..'9' } && (k == "0" || k[0] != '0') && k.toLong() < 4294967295L

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

    /** A number as `Number.prototype.toString` prints it (ECMA-262 Number::toString), via the double it denotes. */
    private fun jsNumberOrLiteral(c: String): String {
        if (c == "true" || c == "false") return c
        val d = c.toDoubleOrNull() ?: return c
        if (d.isNaN() || d.isInfinite()) return "null" // JSON.stringify of a non-finite number
        if (d == 0.0) return "0"
        val neg = d < 0
        // The shortest digit string that reads back as the same double (what ECMAScript prints). Not
        // Double.toString: before JDK 19 it is not always the shortest (1e23 gives 9.999999999999999E22).
        val exact = java.math.BigDecimal(Math.abs(d))
        val target = Math.abs(d)
        val bd = (1..17).firstNotNullOf { p ->
            // Both neighbours at this precision, not only the nearest: the shortest string that reads
            // back as the same double may be the farther one; if both do, the nearer wins.
            val down = exact.round(java.math.MathContext(p, java.math.RoundingMode.DOWN))
            val up = exact.round(java.math.MathContext(p, java.math.RoundingMode.UP))
            val ok = listOf(down, up).filter { it.toDouble() == target }
            if (ok.size == 2 && ok[0].compareTo(ok[1]) != 0 && (ok[0] - exact).abs() == (ok[1] - exact).abs()) {
                // Equidistant: ECMAScript takes the candidate whose last digit is even.
                ok.first { it.unscaledValue().mod(java.math.BigInteger.valueOf(2)).signum() == 0 }
            } else {
                ok.minByOrNull { (it - exact).abs() }
            }
        }.stripTrailingZeros()
        val digits = bd.unscaledValue().toString()
        val k = digits.length
        val n = k - bd.scale() // value = 0.digits * 10^n
        val body = when {
            n in k..21 -> digits + "0".repeat(n - k)
            n in 1..21 -> digits.substring(0, n) + "." + digits.substring(n)
            n in -5..0 -> "0." + "0".repeat(-n) + digits
            else -> {
                val e = n - 1
                val mant = if (k == 1) digits else digits[0] + "." + digits.substring(1)
                mant + "e" + (if (e < 0) "-" else "+") + Math.abs(e)
            }
        }
        return if (neg) "-$body" else body
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
        extraTombstones: Set<Pair<String, String>> = emptySet(),
        nextEventId: () -> Long,
    ): List<JsonObject> {
        val changes = sortedMapOf<Pair<String, String>, String?>(compareBy({ it.first }, { it.second }))
        for ((ns, entries) in after) for ((k, v) in entries) if (before[ns]?.get(k) != v) changes[ns to k] = v
        for ((ns, entries) in before) for (k in entries.keys) if (after[ns]?.containsKey(k) != true) changes[ns to k] = null
        for (nk in extraTombstones) if (after[nk.first]?.containsKey(nk.second) != true) changes.putIfAbsent(nk, null)
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
            val (bTs, bId) = best[nk] ?: (Long.MIN_VALUE to 0L)
            while (true) {
                if (ts < bTs) ts = bTs
                if (ts == bTs && id <= bId) {
                    if (bId < MAX_EVENT_ID) id = bId + 1 else { ts = bTs + 1; id = nextEventId() }
                }
                if (id in taken) { if (id < MAX_EVENT_ID) id++ else { ts++; id = 1L }; continue }
                break
            }
            taken.add(id)
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
