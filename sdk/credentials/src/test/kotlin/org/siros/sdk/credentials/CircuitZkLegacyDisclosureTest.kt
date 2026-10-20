// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The proposed claim-disclosure function's params, and its place in the validator. */
class CircuitZkLegacyDisclosureTest {
    private fun fn(params: String, id: String = CircuitZkLegacyDisclosure.FUNCTION_ID) =
        CircuitZkFunction(id, "h", Json.parseToJsonElement(params).jsonObject)

    private val systems = """[{"id":"longfellow-libzk-v1_8_2_4307_2945","system":"longfellow-libzk-v1","params":{"num_attributes":"2"}}]"""

    @Test
    fun `a well-formed request parses with its claims, specs and defaults`() {
        val r = CircuitZkLegacyDisclosure.parse(fn("""{"claims":["family_name","given_name"],"systems":$systems}"""))!!
        assertEquals(listOf("family_name", "given_name"), r.claims)
        assertEquals(listOf(ZkSystemSpec("longfellow-libzk-v1_8_2_4307_2945", "longfellow-libzk-v1", mapOf("num_attributes" to "2"))), r.systems)
        assertFalse(r.pseudonym)
        assertNull(r.verifierContext)
        val p = CircuitZkLegacyDisclosure.parse(fn("""{"claims":["a"],"systems":$systems,"pseudonym":true,"verifier_context":"ctx"}"""))!!
        assertTrue(p.pseudonym)
        assertEquals("ctx", p.verifierContext)
    }

    @Test
    fun `anything else is not a request of this function`() {
        val bad = listOf(
            """{"systems":$systems}""",
            """{"claims":[],"systems":$systems}""",
            """{"claims":["a","a"],"systems":$systems}""",
            """{"claims":[1],"systems":$systems}""",
            """{"claims":["a"]}""",
            """{"claims":["a"],"systems":[]}""",
            """{"claims":["a"],"systems":[{"id":"x"}]}""",
            """{"claims":["a"],"systems":$systems,"pseudonym":"true"}""",
            """{"claims":["a"],"systems":$systems,"verifier_context":"ctx"}""",
            """{"claims":["a"],"systems":$systems,"extra":1}""",
        )
        for (b in bad) assertNull(b, CircuitZkLegacyDisclosure.parse(fn(b)))
        assertNull(CircuitZkLegacyDisclosure.parse(fn("""{"claims":["a"],"systems":$systems}""", id = "age_check")))
    }

    private val rawMeta = Json.parseToJsonElement("""{"meta":{"source_format":"mso_mdoc","doctype_value":"d"}}""").jsonObject

    private fun ruleOf(v: CircuitZkVerdict) = (v as CircuitZkVerdict.AccessDenied).ruleId

    @Test
    fun `the rulebook validator refuses the function until the rule set adds it`() {
        val plan = CircuitZkPlan(listOf(fn("""{"claims":["a"],"systems":$systems}""")), raw = rawMeta)
        assertEquals("function_unknown", ruleOf(RulebookCircuitZkValidator().validate(plan)))
        val withIt = RulebookCircuitZkValidator(CircuitZkRuleSet.rulebookV04().withFunction(CircuitZkLegacyDisclosure.FUNCTION_ID, CircuitZkLegacyDisclosure.RULES))
        assertEquals(CircuitZkVerdict.Ok, withIt.validate(plan))
        assertEquals("claim-disclosure-malformed", ruleOf(withIt.validate(CircuitZkPlan(listOf(fn("""{"claims":[],"systems":$systems}""")), raw = rawMeta))))
        assertEquals("claim-disclosure-count", ruleOf(withIt.validate(CircuitZkPlan(listOf(plan.functions[0], plan.functions[0].copy(handle = "h2")), raw = rawMeta))))
        assertNotNull(CircuitZkLegacyDisclosure.FUNCTION_ID)
    }
}
