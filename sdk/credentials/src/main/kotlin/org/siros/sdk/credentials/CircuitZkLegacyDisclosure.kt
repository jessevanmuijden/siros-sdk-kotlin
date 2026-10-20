// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

/**
 * PROPOSAL, not part of the `circuit_zk` rulebook: a `circuit_zk` function that discloses named claims of an
 * mdoc through one of the existing (legacy) proof systems, Longfellow (`longfellow-libzk-v1`) and Vega
 * (`vega-mc-p256-v1`), which prove disclosure of claims rather than the rulebook's `age_check` and
 * `pseudonym`. The naming is for the rulebook owners to settle; the id is this one constant.
 *
 * ```
 * function item: { "id": "zk-claim-disclosure-v1", "return": <handle>, "params": {
 *     "claims":      [ + tstr ],        // element identifiers of the credential's namespace to disclose
 *     "systems":     [ + { "id": tstr, "system": tstr, ? "params": { * tstr => tstr } } ],
 *                                        // the verifier's zk_system_type list: `id` is a catalog circuit id,
 *                                        // `system` the proof system id, `params` e.g. num_attributes
 *     ? "pseudonym": bool,              // default false: also return the proof system's legacy pseudonym
 *     ? "verifier_context": tstr        // the legacy pseudonym's context, when `pseudonym` is true
 * } }
 * ```
 *
 * Result for the handle (the existing `ResultValue` CDDL, no new variant):
 * - `pseudonym` absent or false: `true`. The claim values are in the proof.
 * - `pseudonym` true: the 32-byte legacy pseudonym (`SHA-256(pseudonym_seed || verifier_context)` for
 *   Longfellow). It is NOT the rulebook pseudonym. A system that cannot return one (Vega) makes the request
 *   refused.
 *
 * `CircuitZkPresentation.proof` is the ZK `DeviceResponse` CBOR the legacy path already produces
 * (`{version, status, zkDocuments: [...]}`, with the proof system's proof bytes and the disclosed claims, see
 * `MdocDeviceResponseBuilder.buildZkDeviceResponse`), and `circuit_id` is the catalog circuit proved with.
 */
object CircuitZkLegacyDisclosure {
    /** The function id. One constant, so renaming it is a one-line change. */
    const val FUNCTION_ID = "zk-claim-disclosure-v1"

    /** What a request of this function asks for. */
    class Request(
        val claims: List<String>,
        val systems: List<ZkSystemSpec>,
        val pseudonym: Boolean,
        val verifierContext: String?,
    )

    /** The parsed [function], or null when it is not a well-formed request of this function. */
    fun parse(function: CircuitZkFunction): Request? {
        if (function.id != FUNCTION_ID) return null
        val p = function.params
        if (p.keys.any { it !in KNOWN_PARAMS }) return null
        val claims = (p["claims"] as? JsonArray)?.map { text(it) ?: return null } ?: return null
        if (claims.isEmpty() || claims.toSet().size != claims.size) return null
        val systems = (p["systems"] as? JsonArray)?.map { spec(it) ?: return null } ?: return null
        if (systems.isEmpty()) return null
        val pseudonym = when (val v = p["pseudonym"]) {
            null -> false
            is JsonPrimitive -> if (v.isString) return null else v.booleanOrNull ?: return null
            else -> return null
        }
        val context = p["verifier_context"]?.let { text(it) ?: return null }
        if (context != null && !pseudonym) return null
        return Request(claims, systems, pseudonym, context)
    }

    private val KNOWN_PARAMS = setOf("claims", "systems", "pseudonym", "verifier_context")

    private fun text(e: kotlinx.serialization.json.JsonElement): String? =
        (e as? JsonPrimitive)?.takeIf { it.isString }?.content

    private fun spec(e: kotlinx.serialization.json.JsonElement): ZkSystemSpec? {
        val o = e as? JsonObject ?: return null
        val id = text(o["id"] ?: return null) ?: return null
        val system = text(o["system"] ?: return null) ?: return null
        val params = when (val pp = o["params"]) {
            null -> emptyMap()
            is JsonObject -> pp.mapValues { (_, v) -> text(v) ?: (v as? JsonPrimitive)?.content ?: return null }
            else -> return null
        }
        return ZkSystemSpec(id, system, params)
    }

    /** The function rules for [CircuitZkRuleSet]: at most one item, and a well-formed one. */
    val RULES: CircuitZkFunctionRules = CircuitZkFunctionRules(
        maxItems = 1,
        countRuleId = "claim-disclosure-count",
        rules = listOf(CircuitZkFunctionRule("claim-disclosure-malformed") { f, _ -> parse(f) != null }),
    )
}
