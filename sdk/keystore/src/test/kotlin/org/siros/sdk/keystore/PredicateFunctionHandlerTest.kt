// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.ClaimSource
import org.siros.sdk.credentials.ComparisonOp
import org.siros.sdk.credentials.PredicateFunction
import org.siros.sdk.credentials.PredicateFunctions
import org.siros.sdk.credentials.ValueType
import org.siros.sdk.credentials.mdoc.DocumentMdoc
import org.siros.sdk.credentials.mdoc.MdocCbor

/** The generic handler of a declared predicate: `holds` is the shared pre-check over the credential's own claims. */
class PredicateFunctionHandlerTest {
    private val docType = "org.example.nym.1"

    private fun mdoc(extraNamespace: Boolean = false, birth: String = "2000-06-15", score: CBORObject = CBORObject.FromObject(15L)): DocumentMdoc {
        fun c(o: Any) = CBORObject.FromObject(o)
        fun item(id: Long, name: String, v: CBORObject): CBORObject {
            val m = CBORObject.NewMap()
            m[c("digestID")] = c(id); m[c("random")] = c(ByteArray(16)); m[c("elementIdentifier")] = c(name); m[c("elementValue")] = v
            return CBORObject.FromObjectAndTag(m.EncodeToBytes(), 24)
        }
        val items = CBORObject.NewArray()
        items.Add(item(0, "birth_date", CBORObject.FromObjectAndTag(birth, 1004)))
        items.Add(item(1, "score", score))
        val ns = CBORObject.NewMap(); ns[c(docType)] = items
        if (extraNamespace) ns[c("org.example.other")] = CBORObject.NewArray().also { it.Add(item(2, "birth_date", CBORObject.FromObjectAndTag("1980-01-01", 1004))) }
        val mso = CBORObject.NewMap(); mso[c("docType")] = c(docType)
        val auth = CBORObject.NewArray()
        auth.Add(c(ByteArray(0))); auth.Add(CBORObject.NewMap())
        auth.Add(c(CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes())); auth.Add(c(ByteArray(64)))
        val signed = CBORObject.NewMap(); signed[c("nameSpaces")] = ns; signed[c("issuerAuth")] = auth
        return MdocCbor.parseStoredCredential(signed.EncodeToBytes())
    }

    private fun fn(id: String, json: String) = CircuitZkFunction(id, "p", Json.parseToJsonElement(json).jsonObject)

    private val numberRange = PredicateFunction(
        id = "number_range", claim = ClaimSource.FromParam, valueType = ValueType.NUMBER,
        comparisons = linkedMapOf("ge" to ComparisonOp.GE, "le" to ComparisonOp.LE), minSpan = 10,
    )

    @Test
    fun `the registry keeps only hook-style functions, the predicates come from their declarations`() {
        assertTrue(HOOK_CIRCUIT_ZK_HANDLERS.map { it.functionId }.toSet().none { it in PredicateFunctions.DEFAULT.ids })
        assertNotNull(DEFAULT_CIRCUIT_ZK_HANDLERS.singleOrNull { it.functionId == "age_check" })
        assertTrue(PredicateFunctionHandler.handlersFor(PredicateFunctions(listOf(PredicateFunctions.AGE_CHECK, numberRange))).any { it.functionId == "number_range" })
    }

    @Test
    fun `age_check holds for the birth date in range, and is judged like any other declared predicate`() {
        val h = PredicateFunctionHandler(PredicateFunctions.AGE_CHECK)
        assertTrue(h.holds(fn("age_check", """{"ge":"1999-01-01","le":"2005-01-01"}"""), mdoc()))
        assertFalse(h.holds(fn("age_check", """{"le":"1990-01-01"}"""), mdoc()))
        assertFalse(h.holds(fn("age_check", """{}"""), mdoc()))
    }

    @Test
    fun `a declared predicate on another claim holds for the claim's own value`() {
        val h = PredicateFunctionHandler(numberRange)
        assertTrue(h.holds(fn("number_range", """{"claim":"score","ge":10,"le":20}"""), mdoc(score = CBORObject.FromObject(15L))))
        assertFalse(h.holds(fn("number_range", """{"claim":"score","ge":10,"le":20}"""), mdoc(score = CBORObject.FromObject(25L))))
        // An absent claim cannot satisfy it.
        assertFalse(h.holds(fn("number_range", """{"claim":"nope","ge":10,"le":20}"""), mdoc()))
    }

    @Test
    fun `a function whose circuit binds the doctype namespace refuses a credential with an extra namespace`() {
        val age = PredicateFunctionHandler(PredicateFunctions.AGE_CHECK)
        val f = fn("age_check", """{"ge":"1999-01-01","le":"2005-01-01"}""")
        assertTrue(age.admitsCredential(f, mdoc()))
        assertFalse(age.admitsCredential(f, mdoc(extraNamespace = true)))
        // A declaration that does not bind the layout admits it.
        assertTrue(PredicateFunctionHandler(numberRange).admitsCredential(fn("number_range", """{"claim":"score","ge":1}"""), mdoc(extraNamespace = true)))
    }

    @Test
    fun `a float is compared at its exact value, like the equivalent exact decimal encoding`() {
        val h = PredicateFunctionHandler(numberRange.let { PredicateFunction(it.id, it.claim, it.valueType, it.comparisons) })
        // float64 0.1 is exactly 0.1000000000000000055511151231257827...: above the decimal 0.1, below ...0003 + 1e-18.
        val float = mdoc(score = CBORObject.FromObject(0.1))
        val decimal = mdoc(score = CBORObject.FromObject(com.upokecenter.numbers.EDecimal.FromString("0.1")))
        fun f(json: String) = fn("number_range", json)
        // ge 0.100000000000000003 is satisfied by the float (its exact value is larger), as by no rounding to 0.1.
        assertTrue(h.holds(f("""{"claim":"score","ge":0.100000000000000003}"""), float))
        assertFalse(h.holds(f("""{"claim":"score","ge":0.100000000000000003}"""), decimal))
        // le 0.1 is NOT satisfied by the float (exactly above 0.1), but is by the decimal 0.1.
        assertFalse(h.holds(f("""{"claim":"score","le":0.1}"""), float))
        assertTrue(h.holds(f("""{"claim":"score","le":0.1}"""), decimal))
    }
}
