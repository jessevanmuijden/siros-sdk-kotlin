// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * How an issuer delivers, and advertises, the `secret_seed` of a `nym_auth` credential: a member of the
 * `credential_metadata` object of OpenID4VCI 1.1 (openid/OpenID4VCI#721), defined by privatedata-spec section 5A.
 *
 * - In a Credential Response (and Deferred Credential Response) the member [MEMBER] maps a namespace to a seed:
 *   `{"org.siros.secret_seed": {"<namespace>": "<32 lowercase hex characters>"}}`. See [parseDelivery].
 * - In issuer metadata the same member may appear only as the advertisement `{"namespaces": ["<namespace>", ...]}`:
 *   names, never values. See [classifyAdvertisement].
 * - The member is stripped from the response object before it goes anywhere near display metadata
 *   ([stripped], [mergeDisplay]): the seed goes only to the secret store.
 *
 * Pure and stateless; nothing here logs or returns a seed other than the parsed map [parseDelivery] gives its caller.
 */
object SecretSeedDelivery {
    /** The `credential_metadata` member name. One constant: the spec defines it. */
    const val MEMBER = "org.siros.secret_seed"

    /** The namespace the `nym_auth` credential type designates (the one whose seed opens `ssc`). */
    const val DEFAULT_NAMESPACE = "org.siros.nym_auth"

    /** The reserved key of the advertisement form: never a namespace of a delivery. */
    const val ADVERTISEMENT_KEY = "namespaces"

    private const val MAX_NAMESPACES = 8
    private const val MAX_NAMESPACE_BYTES = 64
    private val HEX_32 = Regex("[0-9a-f]{32}")

    /** The outcome of reading the member of an issuer metadata entry. */
    sealed interface Advertisement {
        /** The metadata has no such member: the configuration does not deliver a seed. */
        object None : Advertisement

        /** A well-formed advertisement: the configuration delivers a seed, so response encryption is required. */
        class Valid(val namespaces: List<String>) : Advertisement

        /** Anything else, including a seed value in public metadata: the configuration is treated as not offered. */
        object Malformed : Advertisement
    }

    private fun namespaceOk(ns: String) = ns.isNotEmpty() && ns.toByteArray(Charsets.UTF_8).size <= MAX_NAMESPACE_BYTES

    /**
     * The namespace-to-hex map of a delivered [value], or null when it is malformed: not an object, no or more
     * than 8 members, a namespace that is empty, over 64 UTF-8 bytes or the reserved [ADVERTISEMENT_KEY], or a seed
     * that is not exactly 32 lowercase hexadecimal characters. Members keep their order.
     */
    fun parseDelivery(value: JsonElement?): Map<String, String>? {
        val obj = value as? JsonObject ?: return null
        if (obj.isEmpty() || obj.size > MAX_NAMESPACES) return null
        val out = LinkedHashMap<String, String>()
        for ((ns, v) in obj) {
            if (!namespaceOk(ns) || ns == ADVERTISEMENT_KEY) return null
            val hex = (v as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
            if (!HEX_32.matches(hex)) return null
            out[ns] = hex
        }
        return out
    }

    /** Reads the [MEMBER] value of an issuer metadata entry's `credential_metadata` ([member], null when absent). */
    fun classifyAdvertisement(member: JsonElement?): Advertisement {
        if (member == null) return Advertisement.None
        val obj = member as? JsonObject ?: return Advertisement.Malformed
        // Only the namespaces list: a seed value (or any other member) in public metadata is malformed.
        if (obj.keys != setOf(ADVERTISEMENT_KEY)) return Advertisement.Malformed
        val list = obj[ADVERTISEMENT_KEY] as? JsonArray ?: return Advertisement.Malformed
        if (list.isEmpty() || list.size > MAX_NAMESPACES) return Advertisement.Malformed
        val names = list.map { e -> (e as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf(::namespaceOk) ?: return Advertisement.Malformed }
        if (names.toSet().size != names.size || names.any { it == ADVERTISEMENT_KEY } || names.any { HEX_32.matches(it) }) return Advertisement.Malformed
        return Advertisement.Valid(names)
    }

    /**
     * [response] without any secret-bearing member of any supported shape (this legacy [MEMBER], Auxiliary Data v0.1's
     * `auxiliary_data`, ...): the only form of a response `credential_metadata` that display code may see.
     */
    fun stripped(response: JsonObject): JsonObject = AuxiliaryDataShapes.all.fold(response) { acc, shape -> shape.stripFromMetadata(acc) }

    /**
     * Display metadata: the issuer's `credential_metadata` ([issuer], null for none) overwritten member by member by the
     * [stripped] response object. The seed is never an input of the merge, so it cannot be in the result; the issuer's
     * public advertisement stays.
     */
    fun mergeDisplay(issuer: JsonObject?, response: JsonObject): JsonObject =
        JsonObject((issuer?.toMap().orEmpty()) + stripped(response))
}
