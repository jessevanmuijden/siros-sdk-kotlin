// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

/**
 * What the rules may consult besides the plan itself: the circuits (for the wallet-only `function-not-declared` rule) and
 * the plan's `meta.source_format`, which the pseudonym's `prf` rule depends on. There is deliberately no
 * `verifier_id_type` registry: the member is gone from the request (an undeclared parameter if sent).
 */
class CircuitZkRuleEnv(val circuits: CircuitZkCircuitSource?, val sourceFormat: String? = null)

/** A rule over the whole plan: [holds] false makes the request unsatisfiable, reported as [id]. */
class CircuitZkPlanRule(val id: String, val holds: (CircuitZkPlan, CircuitZkRuleEnv) -> Boolean)

/** A rule over one function item of the plan. */
class CircuitZkFunctionRule(val id: String, val holds: (CircuitZkFunction, CircuitZkRuleEnv) -> Boolean)

/**
 * The rules of one function id: at most [maxItems] items per request (null =
 * unlimited, rule id [countRuleId]) and the [rules] each item must satisfy.
 */
class CircuitZkFunctionRules(
    val maxItems: Int?,
    val countRuleId: String,
    val rules: List<CircuitZkFunctionRule>,
)

/**
 * A named, data-driven rule set. A function id that is a key of [functions]
 * is a known function; any other function id is unsatisfiable. New functions
 * and credential types add entries; the validator does not change. The rule ids of the rulebook rules are the stable
 * codes of the matcher's `zkp_req_unsat` vectors.
 */
class CircuitZkRuleSet(
    val planRules: List<CircuitZkPlanRule>,
    val functions: Map<String, CircuitZkFunctionRules>,
) {
    /** This rule set plus the function [id] with [rules]. */
    fun withFunction(id: String, rules: CircuitZkFunctionRules): CircuitZkRuleSet = CircuitZkRuleSet(planRules, functions + (id to rules))

    companion object {
        const val PSEUDONYM = "pseudonym"
        const val AGE_CHECK = "age_check"

        /** The `meta.source_format`s of the rulebook: `mso_mdoc` (stored here) and `bbs_cd` (held). */
        private val SOURCE_FORMATS = setOf("mso_mdoc", "bbs_cd")
        private const val PRF_SHA256 = "sha-256"
        private const val PRF_HASHDH = "hashdh-bls12381g1"
        private const val SSC_CONFIG = "known-offender-matching-ssc"

        /** How a pseudonym config uses `verifier_input` and `verifier_context` (rulebook v0.4). */
        class PseudonymConfig(val id: String, val usesVerifierInput: Boolean, val requiresVerifierContext: Boolean)

        /** The four rulebook configurations. */
        val RULEBOOK_PSEUDONYM_CONFIGS: List<PseudonymConfig> = listOf(
            PseudonymConfig("known-offender-matching-ssc", usesVerifierInput = true, requiresVerifierContext = false),
            PseudonymConfig("known-offender-matching-psc", usesVerifierInput = true, requiresVerifierContext = false),
            PseudonymConfig("account-recovery-ssc", usesVerifierInput = true, requiresVerifierContext = true),
            PseudonymConfig("user-managed-pseudonym-xsite-ssc", usesVerifierInput = false, requiresVerifierContext = false),
        )

        private const val MAX_CONTEXT_BYTES = 64

        /** The rules of rulebook v0.4. [pseudonymConfigs] is the set of configurations this wallet supports. */
        fun rulebookV04(
            pseudonymConfigs: List<PseudonymConfig> = RULEBOOK_PSEUDONYM_CONFIGS,
            /** The predicate functions this wallet declares: each one's per-function rules come from its declaration. */
            predicates: PredicateFunctions = PredicateFunctions.DEFAULT,
        ): CircuitZkRuleSet {
            val byId = pseudonymConfigs.associateBy { it.id }
            return CircuitZkRuleSet(
                planRules = listOf(
                    CircuitZkPlanRule("source_format_unsupported") { plan, _ -> meta(plan)?.get("source_format")?.let { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content } in SOURCE_FORMATS },
                    CircuitZkPlanRule("meta_type_value_invalid") { plan, _ ->
                        val meta = meta(plan)
                        val format = (meta?.get("source_format") as? JsonPrimitive)?.takeIf { it.isString }?.content
                        // Exactly the type value of the source format, and never `vct_values`.
                        meta != null && !meta.containsKey("vct_values") && when (format) {
                            "mso_mdoc" -> meta.containsKey("doctype_value") && !meta.containsKey("schema_id_value")
                            "bbs_cd" -> meta.containsKey("schema_id_value") && !meta.containsKey("doctype_value")
                            else -> true
                        }
                    },
                    CircuitZkPlanRule("holder_binding_waived") { plan, _ ->
                        val v = plan.raw["require_cryptographic_holder_binding"]
                        v == null || (v is JsonPrimitive && !v.isString && v.booleanOrNull == true)
                    },
                    CircuitZkPlanRule("function-not-declared") { plan, env -> functionsDeclared(plan, env) },
                ),
                functions = mapOf(
                    PSEUDONYM to CircuitZkFunctionRules(
                        maxItems = 1,
                        countRuleId = "pseudonym_repeated",
                        rules = listOf(
                            CircuitZkFunctionRule("pseudonym_config_missing") { f, _ -> f.params.containsKey("config") },
                            CircuitZkFunctionRule("pseudonym_config_unknown") { f, _ -> str(f.params, "config")?.let { it in byId } == true },
                            CircuitZkFunctionRule("pseudonym_ver_missing") { f, _ -> f.params.containsKey("ver") },
                            CircuitZkFunctionRule("pseudonym_ver_unsupported") { f, _ ->
                                val ver = f.params["ver"] as? JsonPrimitive
                                ver != null && !ver.isString && ver.content == "1"
                            },
                            CircuitZkFunctionRule("pseudonym_prf_missing") { f, _ -> f.params.containsKey("prf") },
                            CircuitZkFunctionRule("pseudonym_prf_unsupported") { f, env ->
                                val prf = str(f.params, "prf")
                                when (env.sourceFormat ?: "mso_mdoc") {
                                    "mso_mdoc" -> prf == PRF_SHA256
                                    "bbs_cd" -> prf == PRF_HASHDH && str(f.params, "config") == SSC_CONFIG
                                    else -> false
                                }
                            },
                            CircuitZkFunctionRule("verifier_context_invalid") { f, _ ->
                                val cfg = byId[str(f.params, "config")] ?: return@CircuitZkFunctionRule true
                                if (cfg.requiresVerifierContext != f.params.containsKey("verifier_context")) return@CircuitZkFunctionRule false
                                if (!f.params.containsKey("verifier_context")) return@CircuitZkFunctionRule true
                                val bytes = str(f.params, "verifier_context")?.toByteArray(Charsets.UTF_8)?.size
                                bytes != null && bytes in 1..MAX_CONTEXT_BYTES
                            },
                        ),
                    ),
                ) + predicates.ids.associateWith { predicates[it]!!.validatorRules() },
            )
        }

        private fun meta(plan: CircuitZkPlan): JsonObject? = plan.raw["meta"] as? JsonObject

        private fun str(params: JsonObject, key: String): String? =
            (params[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

        /**
         * When some circuit fits the plan's doctype and circuit list, at least
         * one of them must support every function: it declares none (no
         * function filtering) or declares all of them. This is a satisfiability rule shared with the other SDKs'
         * vectors; whether a circuit declaring none is ever offered is decided by [CircuitZkMatching] (it is not). A circuit constrained
         * by the matcher ([CircuitZkCircuit.constrainedByMatcher]) is not
         * subject to this legacy check.
         */
        private fun functionsDeclared(plan: CircuitZkPlan, env: CircuitZkRuleEnv): Boolean {
            val source = env.circuits ?: return true
            val doctype = ((plan.raw["meta"] as? JsonObject)?.get("doctype_value") as? JsonPrimitive)?.content
            val relevant = source.circuits().filter { c ->
                (doctype == null || doctype in c.docTypes) &&
                    (plan.circuitFilter == null || plan.circuitFilter.admits(c))
            }
            if (relevant.isEmpty()) return true
            // A matcher-constrained circuit's legacy `functions` are not read (as in CircuitZkMatching.fits).
        return relevant.any { c -> c.constrainedByMatcher || c.functions == null || plan.functions.all { it.id in c.functions } }
        }
    }
}

/**
 * The wallet-side satisfiability rules for a planned `circuit_zk` request:
 * the rulebook's data-independent MUST rules, as a [CircuitZkRuleSet].
 * Whether a predicate holds for the holder's `birth_date` is data-dependent
 * and is checked when proving, not here.
 *
 * A `verifier_id_type` member is an undeclared parameter and ignored here.
 *
 * Every failure is [CircuitZkVerdict.AccessDenied]. Its `ruleId` is for local
 * logs and tests; it must never reach the verifier.
 */
class RulebookCircuitZkValidator(
    private val rules: CircuitZkRuleSet = CircuitZkRuleSet.rulebookV04(),
    circuits: CircuitZkCircuitSource? = null,
) : CircuitZkRequestValidator {
    private val env = CircuitZkRuleEnv(circuits)

    override fun validate(plan: CircuitZkPlan): CircuitZkVerdict {
        val planEnv = CircuitZkRuleEnv(env.circuits, plan.sourceFormat)
        for (rule in rules.planRules) {
            if (!rule.holds(plan, planEnv)) return CircuitZkVerdict.AccessDenied(rule.id)
        }
        for (function in plan.functions) {
            if (function.id !in rules.functions) return CircuitZkVerdict.AccessDenied("function_unknown")
        }
        for ((id, entry) in rules.functions) {
            val items = plan.functions.filter { it.id == id }
            val max = entry.maxItems
            if (max != null && items.size > max) return CircuitZkVerdict.AccessDenied(entry.countRuleId)
            for (item in items) {
                for (rule in entry.rules) {
                    if (!rule.holds(item, planEnv)) return CircuitZkVerdict.AccessDenied(rule.id)
                }
            }
        }
        return CircuitZkVerdict.Ok
    }
}


/**
 * The validator rules of one declared predicate function, derived from its declaration so the same data drives
 * consent, the local pre-check, the cross-query rule and the validator. Rule ids are `<function id>_<rule>`
 * (`age_check`: `age_check_repeated`, `age_check_no_bound`, `age_check_bad_date`, `age_check_inverted`,
 * `age_check_span_too_short`: for the rulebook's function, the matcher's own codes). Like the rulebook's, they do not reject a param they do not
 * know (the prover does); each is data-independent.
 */
fun PredicateFunction.validatorRules(): CircuitZkFunctionRules {
    val slug = id
    val rules = mutableListOf<CircuitZkFunctionRule>()
    rules += CircuitZkFunctionRule("${slug}_no_bound") { f, _ -> comparisons.keys.any { f.params.containsKey(it) } }
    rules += CircuitZkFunctionRule(if (valueType == ValueType.DATE) "${slug}_bad_date" else "${slug}_bad_operand") { f, _ ->
        comparisons.all { (param, op) -> operandWellFormed(f.params[param], op) }
    }
    if (claim == ClaimSource.FromParam) {
        rules += CircuitZkFunctionRule("${slug}_bad_claim") { f, _ -> f.params["claim"]?.let { claimParam(it) } != null }
    }
    val ge = comparisons.entries.firstOrNull { it.value == ComparisonOp.GE }?.key
    val le = comparisons.entries.firstOrNull { it.value == ComparisonOp.LE }?.key
    if (ge != null && le != null) {
        rules += CircuitZkFunctionRule("${slug}_inverted") { f, _ ->
            val lo = operandOf(f.params[ge], ComparisonOp.GE)
            val hi = operandOf(f.params[le], ComparisonOp.LE)
            lo == null || hi == null || PredicateFunctions.compareOperands(valueType, hi, lo) >= 0
        }
        if (minSpan != null) {
            rules += CircuitZkFunctionRule("${slug}_span_too_short") { f, _ ->
                val lo = operandOf(f.params[ge], ComparisonOp.GE)
                val hi = operandOf(f.params[le], ComparisonOp.LE)
                lo == null || hi == null || PredicateFunctions.spanAtLeast(valueType, lo, hi, minSpan)
            }
        }
    }
    return CircuitZkFunctionRules(maxItems = 1, countRuleId = "${slug}_repeated", rules = rules)
}

private fun PredicateFunction.operandOf(e: kotlinx.serialization.json.JsonElement?, op: ComparisonOp): String? =
    if (e == null || op == ComparisonOp.IN) null else operand(e)

private fun PredicateFunction.operandWellFormed(e: kotlinx.serialization.json.JsonElement?, op: ComparisonOp): Boolean = when {
    e == null -> true
    op == ComparisonOp.IN -> (e as? kotlinx.serialization.json.JsonArray)?.let { a -> a.isNotEmpty() && a.all { operand(it) != null } } == true
    else -> operand(e) != null
}
