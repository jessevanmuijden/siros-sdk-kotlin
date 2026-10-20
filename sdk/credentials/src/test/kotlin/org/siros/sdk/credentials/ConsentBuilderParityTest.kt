package org.siros.sdk.credentials

import java.time.LocalDate
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Builder rules that the shared vectors cannot express: caller-stated requestSigned, exact span refusals, age wording in code. */
class ConsentBuilderParityTest {
    private val today = LocalDate.parse("2026-10-19")
    private val trust = ConsentRequests.Trust("RP", null, null)
    private val cred = CredentialRef("Nym", "Issuer")

    private fun request(signed: Boolean, queries: List<ConsentRequests.Query>) = ConsentRequests.build(
        queries = queries, trust = trust, verifiedClientIdDisplayName = null, attestedOrigin = "https://rp.example",
        verifierIdType = null, requestSigned = signed, today = today, locale = "en",
    )

    private val ageQuery = ConsentRequests.Query(
        CircuitZkPlan(listOf(CircuitZkFunction("age_check", "a", buildJsonObject { put("le", JsonPrimitive("2008-10-19")) }))), cred, null,
    )

    @Test
    fun requestSignedIsWhatTheCallerSays_notAssumed() {
        assertEquals(true, request(true, listOf(ageQuery))!!.requestSigned)
        assertEquals(false, request(false, listOf(ageQuery))!!.requestSigned)
    }

    @Test
    fun anEmptyQueryListIsRefused() {
        assertNull(request(true, emptyList()))
        assertNotNull(request(true, listOf(ageQuery)))
    }

    private fun ageWithEq() = PredicateFunction(
        id = "age_with_eq", claim = ClaimSource.Fixed(listOf("birth_date")), valueType = ValueType.DATE,
        comparisons = linkedMapOf("ge" to ComparisonOp.GE, "le" to ComparisonOp.LE, "eq" to ComparisonOp.EQ), ageSpecialisation = true,
    )

    private fun item(registry: PredicateFunctions, vararg params: Pair<String, String>) =
        registry.item(CircuitZkFunction("age_with_eq", "a", buildJsonObject { params.forEach { (k, v) -> put(k, JsonPrimitive(v)) } }), emptyList(), today)

    @Test
    fun anAgeFunctionThatAlsoDeclaresEq_isAnAgeOnlyWhenEveryConditionIsASingleGeOrLeBound() {
        val registry = PredicateFunctions(listOf(ageWithEq()))
        assertTrue(item(registry, "le" to "2008-10-19")!!.age is AgeForm.AtLeast)
        assertTrue(item(registry, "ge" to "1990-01-01", "le" to "2008-10-19")!!.age is AgeForm.Between)
        assertNull(item(registry, "le" to "2008-10-19", "eq" to "2000-01-01")!!.age)
        assertNull(item(registry, "eq" to "2000-01-01")!!.age)
    }

    @Test
    fun aNumericSpanIsExact_wideBeyond64Bits_and_aBoundThatCannotBeAlignedIsRefused() {
        assertTrue(PredicateFunctions.spanAtLeast(ValueType.NUMBER, "0", "18446744073709551616", Long.MAX_VALUE))
        assertFalse(PredicateFunctions.spanAtLeast(ValueType.NUMBER, "1e-100", "10", 10))
        // 1e999999999 - 1 would need a billion digits: refused, not computed.
        assertFalse(PredicateFunctions.spanAtLeast(ValueType.NUMBER, "1", "1e999999999", 10))
        assertTrue(PredicateFunctions.spanAtLeast(ValueType.NUMBER, "0", "1e100", 10))
    }
}
