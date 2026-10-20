package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [RulebookCircuitZkValidator] beyond the matcher's `zkp_req_unsat` vectors (which `ZkpReqVectorsTest` runs for the rulebook
 * rules): the rule set as data, the wallet-only circuit check, and the `ver`/`prf` pseudonym parameters.
 */
class RulebookCircuitZkValidatorTest {
    private fun obj(s: String): JsonObject = Json.parseToJsonElement(s).jsonObject
    private fun rawOf(source: String = "mso_mdoc") = obj("""{"meta":{"source_format":"$source","doctype_value":"d.1"}}""")
    private fun plan(fns: List<CircuitZkFunction>, raw: JsonObject = rawOf()) = CircuitZkPlan(fns, raw = raw)
    private fun pseudonym(params: String) = CircuitZkFunction(CircuitZkRuleSet.PSEUDONYM, "n", obj(params))
    private fun ruleOf(v: CircuitZkVerdict) = (v as CircuitZkVerdict.AccessDenied).ruleId

    @Test
    fun `a verifier_id_type is an undeclared parameter and does not make the request unsatisfiable`() {
        val rules = RulebookCircuitZkValidator()
        for (extra in listOf(""","verifier_id_type":"semantic"""", ""","verifier_id_type":1""", ""","verifier_id_type":null""")) {
            val fn = pseudonym("""{"config":"known-offender-matching-ssc","ver":1,"prf":"sha-256"$extra}""")
            assertTrue(extra, rules.validate(plan(listOf(fn))) === CircuitZkVerdict.Ok)
        }
    }

    @Test
    fun `the pseudonym needs ver 1 and a prf the source format defines`() {
        val rules = RulebookCircuitZkValidator()
        fun verdict(params: String, source: String = "mso_mdoc") = rules.validate(plan(listOf(pseudonym(params)), rawOf(source)))
        assertTrue(verdict("""{"config":"known-offender-matching-ssc","ver":1,"prf":"sha-256"}""") === CircuitZkVerdict.Ok)
        assertEquals("pseudonym_ver_missing", ruleOf(verdict("""{"config":"known-offender-matching-ssc","prf":"sha-256"}""")))
        assertEquals("pseudonym_ver_unsupported", ruleOf(verdict("""{"config":"known-offender-matching-ssc","ver":"1","prf":"sha-256"}""")))
        assertEquals("pseudonym_prf_missing", ruleOf(verdict("""{"config":"known-offender-matching-ssc","ver":1}""")))
        assertEquals("pseudonym_prf_unsupported", ruleOf(verdict("""{"config":"known-offender-matching-ssc","ver":1,"prf":"hashdh-bls12381g1"}""")))
    }

    @Test
    fun `the rule set is data - a new function and a new config need no validator change`() {
        val base = CircuitZkRuleSet.rulebookV04()
        val extended = CircuitZkRuleSet(
            planRules = base.planRules,
            functions = base.functions + ("my_fn" to CircuitZkFunctionRules(1, "my-fn-count", listOf(
                CircuitZkFunctionRule("my-fn-needs-x") { f, _ -> f.params.containsKey("x") },
            ))),
        )
        val v = RulebookCircuitZkValidator(extended)
        assertTrue(v.validate(plan(listOf(CircuitZkFunction("my_fn", "h", obj("""{"x":1}"""))))) === CircuitZkVerdict.Ok)
        assertEquals("my-fn-needs-x", ruleOf(v.validate(plan(listOf(CircuitZkFunction("my_fn", "h"))))))
        assertEquals("function_unknown", ruleOf(RulebookCircuitZkValidator().validate(plan(listOf(CircuitZkFunction("my_fn", "h"))))))

        val onlyXsite = CircuitZkRuleSet.rulebookV04(CircuitZkRuleSet.RULEBOOK_PSEUDONYM_CONFIGS.filter { it.id.startsWith("user-managed") })
        val fn = pseudonym("""{"config":"known-offender-matching-ssc","ver":1,"prf":"sha-256"}""")
        assertEquals("pseudonym_config_unknown", ruleOf(RulebookCircuitZkValidator(onlyXsite).validate(plan(listOf(fn)))))
    }

    @Test
    fun `the default configs are the NymPseudonym table`() {
        assertEquals(NymPseudonym.configs.keys, CircuitZkRuleSet.RULEBOOK_PSEUDONYM_CONFIGS.map { it.id }.toSet())
    }

    @Test
    fun `a plan without meta source_format is unsatisfiable`() {
        val fn = pseudonym("""{"config":"known-offender-matching-ssc","ver":1,"prf":"sha-256"}""")
        assertEquals("source_format_unsupported", ruleOf(RulebookCircuitZkValidator().validate(CircuitZkPlan(listOf(fn), raw = JsonObject(emptyMap())))))
    }

    @Test
    fun `a matcher-constrained circuit is not subject to the legacy functions check, an unconstrained one is`() {
        val rules = CircuitZkRuleSet(
            planRules = CircuitZkRuleSet.rulebookV04().planRules,
            functions = mapOf("my_fn" to CircuitZkFunctionRules(1, "my-fn-count", emptyList())),
        )
        val p = plan(listOf(CircuitZkFunction("my_fn", "h")))
        fun verdict(c: CircuitZkCircuit) = RulebookCircuitZkValidator(rules, circuits = CircuitZkCircuitSource { listOf(c) }).validate(p)
        val stale = setOf("other_fn")
        assertTrue(verdict(CircuitZkCircuit("s", "c", setOf("d.1"), functions = stale, capabilities = "{}")) === CircuitZkVerdict.Ok)
        assertTrue(verdict(CircuitZkCircuit("s", "c", setOf("d.1"), functions = stale, credentialType = "t")) === CircuitZkVerdict.Ok)
        assertEquals("function-not-declared", ruleOf(verdict(CircuitZkCircuit("s", "c", setOf("d.1"), functions = stale))))
        assertTrue(verdict(CircuitZkCircuit("s", "c", setOf("d.1"), functions = setOf("my_fn"))) === CircuitZkVerdict.Ok)
    }
}
