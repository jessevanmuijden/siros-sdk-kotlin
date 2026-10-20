// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** One declaration drives the validator's per-function rules (as it drives consent, the pre-check and the merge rule). */
class PredicateValidatorRulesTest {
    private val numberRange = PredicateFunction(
        id = "number_range", claim = ClaimSource.FromParam, valueType = ValueType.NUMBER,
        comparisons = linkedMapOf("ge" to ComparisonOp.GE, "le" to ComparisonOp.LE), minSpan = 10,
    )
    private val country = PredicateFunction(
        id = "string_match", claim = ClaimSource.FromParam, valueType = ValueType.STRING,
        comparisons = linkedMapOf("eq" to ComparisonOp.EQ, "in" to ComparisonOp.IN),
    )
    private val declared = PredicateFunctions(listOf(PredicateFunctions.AGE_CHECK, numberRange, country))
    private val validator = RulebookCircuitZkValidator(CircuitZkRuleSet.rulebookV04(predicates = declared))

    private fun verdict(id: String, params: String): String {
        val plan = CircuitZkPlan(listOf(CircuitZkFunction(id, "p", Json.parseToJsonElement(params).jsonObject)), raw = Json.parseToJsonElement("""{"meta":{"source_format":"mso_mdoc","doctype_value":"d"}}""").jsonObject)
        return when (val v = validator.validate(plan)) {
            CircuitZkVerdict.Ok -> "ok"
            is CircuitZkVerdict.AccessDenied -> v.ruleId ?: "denied"
        }
    }

    @Test
    fun `a declared predicate is satisfiable by its own rules, and an undeclared one is not`() {
        assertEquals("ok", verdict("number_range", """{"claim":"score","ge":10,"le":20}"""))
        assertEquals("ok", verdict("number_range", """{"claim":["a","b"],"ge":10}"""))
        assertEquals("ok", verdict("string_match", """{"claim":"country","in":["SE","FI"]}"""))
        assertEquals("function_unknown", verdict("mystery", """{"claim":"x","ge":1}"""))
        // Without the declaration the validator does not know the function.
        val bare = RulebookCircuitZkValidator()
        val plan = CircuitZkPlan(listOf(CircuitZkFunction("number_range", "p", Json.parseToJsonElement("""{"claim":"s","ge":1}""").jsonObject)), raw = Json.parseToJsonElement("""{"meta":{"source_format":"mso_mdoc","doctype_value":"d"}}""").jsonObject)
        assertEquals("function_unknown", (bare.validate(plan) as CircuitZkVerdict.AccessDenied).ruleId)
    }

    @Test
    fun `each rule of a declared function is derived from the declaration`() {
        assertEquals("number_range_no_bound", verdict("number_range", """{"claim":"score"}"""))
        assertEquals("number_range_bad_operand", verdict("number_range", """{"claim":"score","ge":"10"}"""))
        assertEquals("number_range_bad_claim", verdict("number_range", """{"ge":10}"""))
        assertEquals("number_range_bad_claim", verdict("number_range", """{"claim":[],"ge":10}"""))
        assertEquals("number_range_inverted", verdict("number_range", """{"claim":"s","ge":30,"le":20}"""))
        // The declared minimum span (10) is a number: le - ge.
        assertEquals("number_range_span_too_short", verdict("number_range", """{"claim":"s","ge":10,"le":19}"""))
        assertEquals("ok", verdict("number_range", """{"claim":"s","ge":10,"le":20}"""))
        assertEquals("string_match_bad_operand", verdict("string_match", """{"claim":"c","in":[]}"""))
        assertEquals("string_match_bad_operand", verdict("string_match", """{"claim":"c","eq":1}"""))
    }

    @Test
    fun `the age rules are the declaration's, with the rulebook's rule ids`() {
        assertEquals("age_check_no_bound", verdict("age_check", "{}"))
        assertEquals("age_check_bad_date", verdict("age_check", """{"ge":"2000-1-1"}"""))
        assertEquals("age_check_inverted", verdict("age_check", """{"ge":"2001-01-01","le":"2000-01-01"}"""))
        assertEquals("age_check_span_too_short", verdict("age_check", """{"ge":"2001-01-01","le":"2001-12-30"}"""))
        assertEquals("ok", verdict("age_check", """{"ge":"2001-01-01","le":"2001-12-31"}"""))
        // The declared id set is what the rule set knows: one declaration, one set of rules.
        assertTrue(CircuitZkRuleSet.rulebookV04(predicates = declared).functions.keys.containsAll(declared.ids))
    }
}
