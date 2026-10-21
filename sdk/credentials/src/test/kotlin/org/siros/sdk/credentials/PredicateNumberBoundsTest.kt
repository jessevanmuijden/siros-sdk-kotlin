package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORObject
import org.junit.Assert.assertEquals
import org.junit.Test

/** A claim number is read as exact decimal text, but never expanded without bound (a CBOR decimal fraction can name 1E+100000000). */
class PredicateNumberBoundsTest {
    private fun decimalFraction(exponent: Long, mantissa: Long): CBORObject =
        CBORObject.FromObjectAndTag(CBORObject.NewArray().Add(exponent).Add(mantissa), 4)

    @Test
    fun `a reasonable decimal fraction is read exactly`() {
        assertEquals(ClaimValue(ValueType.NUMBER, "1.5"), PredicateFunctions.read(decimalFraction(-1, 15), ValueType.NUMBER))
        assertEquals(ClaimValue(ValueType.NUMBER, "100"), PredicateFunctions.read(decimalFraction(2, 1), ValueType.NUMBER))
        assertEquals(ClaimValue(ValueType.NUMBER, "1" + "0".repeat(1000)), PredicateFunctions.read(decimalFraction(1000, 1), ValueType.NUMBER))
    }

    @Test
    fun `an absurd exponent is refused before any expansion, in both directions`() {
        val started = System.nanoTime()
        for (e in listOf(100_000_000L, -100_000_000L, 1001L, -1001L, 2_000_000_000L)) {
            val v = PredicateFunctions.read(decimalFraction(e, 1), ValueType.NUMBER)
            // A mismatching type: no comparison holds, the request is refused downstream (fail closed).
            assertEquals("exponent $e", ValueType.STRING, v.type)
        }
        org.junit.Assert.assertTrue("took ${(System.nanoTime() - started) / 1_000_000} ms", System.nanoTime() - started < 2_000_000_000L)
    }

    @Test
    fun `a bignum with an absurd mantissa is refused`() {
        val huge = CBORObject.FromObjectAndTag(ByteArray(2000) { 0x7f }, 2)   // ~16000 bits
        assertEquals(ValueType.STRING, PredicateFunctions.read(huge, ValueType.NUMBER).type)
        val ok = CBORObject.FromObjectAndTag(ByteArray(100) { 0x7f }, 2)
        assertEquals(ValueType.NUMBER, PredicateFunctions.read(ok, ValueType.NUMBER).type)
    }

    private fun bigfloat(exponent: Long, mantissa: Long): CBORObject =
        CBORObject.FromObjectAndTag(CBORObject.NewArray().Add(exponent).Add(mantissa), 5)

    @Test
    fun `a bigfloat with an absurd binary exponent is refused before it is converted to a decimal`() {
        val started = System.nanoTime()
        // Exact conversion of [-100000000, 1] needs 5^100000000: it must never be attempted.
        for (e in listOf(-100_000_000L, 100_000_000L, 4097L, -4097L)) {
            assertEquals("exponent $e", ValueType.STRING, PredicateFunctions.read(bigfloat(e, 1), ValueType.NUMBER).type)
        }
        org.junit.Assert.assertTrue("took ${(System.nanoTime() - started) / 1_000_000} ms", System.nanoTime() - started < 2_000_000_000L)
        assertEquals(ValueType.NUMBER, PredicateFunctions.read(bigfloat(-2, 1), ValueType.NUMBER).type)
        assertEquals(ClaimValue(ValueType.NUMBER, "0.25"), PredicateFunctions.read(bigfloat(-2, 1), ValueType.NUMBER))
    }

    @Test
    fun `a nested decimal in the exponent or the mantissa is refused without being converted`() {
        val inner = decimalFraction(100_000_000L, 1)
        val started = System.nanoTime()
        // 4([4([100000000, 1]), 1]) and 4([1, 4([100000000, 1])]) and the same under a bigfloat.
        for (tag in listOf(4, 5)) {
            val nestedExponent = CBORObject.FromObjectAndTag(CBORObject.NewArray().Add(inner).Add(1L), tag)
            val nestedMantissa = CBORObject.FromObjectAndTag(CBORObject.NewArray().Add(1L).Add(inner), tag)
            for (v in listOf(nestedExponent, nestedMantissa)) assertEquals("tag $tag", ValueType.STRING, PredicateFunctions.read(v, ValueType.NUMBER).type)
        }
        org.junit.Assert.assertTrue("took ${(System.nanoTime() - started) / 1_000_000} ms", System.nanoTime() - started < 2_000_000_000L)
    }
}
