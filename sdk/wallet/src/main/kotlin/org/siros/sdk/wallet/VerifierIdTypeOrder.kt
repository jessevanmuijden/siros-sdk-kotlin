// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

/**
 * The wallet's ORDERED list of supported `verifier_id_type`s, and the helpers
 * that validate, persist and edit it (so a settings UI stays a thin view).
 *
 * Which `verifier_id_type` identifies a verifier is agreed in the trust
 * framework, not chosen per request. For a pseudonym the wallet therefore
 * walks this list in order and uses the first type for which an identifier is
 * available (see [VerifierIdRegistry.resolve]); the type a request names is not
 * consulted.
 *
 * The strings are OPAQUE: they are compared for equality with the
 * `verifier_id_type` the policy decision point returns, never aliased or
 * mapped. The names in the wallet's list must therefore match what the PDP
 * returns; go-trust is aligning its type names and value forms to the trust
 * framework (the `x509_san_dns` value is the prefixed Client Identifier `x509_san_dns:<dns name>`, derived by the PDP,
 * so the default below, `semantic` then `x509_san_dns`, is supplied by it). The
 * PDP is the single default source of verifier ids: the wallet derives nothing
 * from the request itself.
 *
 * An EMPTY list is valid and means "no verifier-id type is supported": every
 * request that needs a pseudonym is refused (fail closed).
 */
object VerifierIdTypeOrder {
    /** `semantic` first, then `x509_san_dns`. */
    val DEFAULT: List<String> = listOf("semantic", "x509_san_dns")

    private const val SEPARATOR = ','

    /** Why [types] is not acceptable, or null if it is: entries must be non-blank, trimmed, free of `,` and unique. */
    fun problem(types: List<String>): String? {
        for (t in types) {
            if (t.isBlank()) return "blank verifier_id_type"
            if (t != t.trim()) return "verifier_id_type '$t' has surrounding whitespace"
            if (t.indexOf(SEPARATOR) >= 0) return "verifier_id_type '$t' contains ','"
        }
        types.groupingBy { it }.eachCount().entries.firstOrNull { it.value > 1 }?.let { return "duplicate verifier_id_type '${it.key}'" }
        return null
    }

    fun isValid(types: List<String>): Boolean = problem(types) == null

    /** [types] itself, or [IllegalArgumentException] if [problem] finds one. */
    fun require(types: List<String>): List<String> {
        problem(types)?.let { throw IllegalArgumentException(it) }
        return types
    }

    /** The flat string a host stores: the types joined by `,`; an empty list is the empty string. */
    fun toStored(types: List<String>): String = require(types).joinToString(SEPARATOR.toString())

    /**
     * Reads what [toStored] wrote. The empty string is the deliberate empty list; a missing, blank-entry,
     * untrimmed or duplicated value is null, so the caller falls back to [DEFAULT] rather than silently
     * disabling pseudonyms or guessing.
     */
    fun fromStored(stored: String?): List<String>? {
        if (stored == null) return null
        if (stored.isEmpty()) return emptyList()
        return stored.split(SEPARATOR).takeIf { isValid(it) }
    }

    /** [types] with [raw] (trimmed) appended, or null when it is blank, contains `,` or is already present. */
    fun add(types: List<String>, raw: String): List<String>? =
        (types + raw.trim()).takeIf { isValid(it) }

    /** [types] without the entry at [index]; unchanged for an out-of-range index. */
    fun remove(types: List<String>, index: Int): List<String> =
        if (index in types.indices) types.filterIndexed { i, _ -> i != index } else types

    /** [types] with the entry at [index] moved by [delta] places (negative = earlier); unchanged if either end is out of range. */
    fun move(types: List<String>, index: Int, delta: Int): List<String> {
        val to = index + delta
        if (index !in types.indices || to !in types.indices) return types
        return types.toMutableList().also { val t = it.removeAt(index); it.add(to, t) }
    }
}
