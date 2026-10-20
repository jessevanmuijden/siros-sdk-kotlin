// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.nymdemo

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NymAuthDemoRunnerTest {
    private val runner = NymAuthDemoRunner(ByteArray(32) { it.toByte() })
    private val base = NymAuthDemoRunner.Params(
        birthDate = "1990-05-17",
        ge = "1900-01-01",
        le = "2008-10-14",
        verifierId = "verifier.example.org",
    )

    @Test
    fun `a satisfiable request is presented and the pseudonym matches an independent recompute`() = runTest {
        val outcome = runner.run(base)
        val presented = outcome as NymAuthDemoRunner.Outcome.Presented
        assertTrue(presented.pseudonymMatches)
        assertEquals("true", presented.ageResult)
        assertEquals(setOf("nym", "age"), presented.decodedHandles.toSet())
    }

    @Test
    fun `the pseudonym differs per verifier id`() = runTest {
        val a = runner.run(base) as NymAuthDemoRunner.Outcome.Presented
        val b = runner.run(base.copy(verifierId = "other.example.org")) as NymAuthDemoRunner.Outcome.Presented
        assertTrue(a.pseudonymHex != b.pseudonymHex)
    }

    @Test
    fun `the pseudonym is stable across presentations`() = runTest {
        val a = runner.run(base) as NymAuthDemoRunner.Outcome.Presented
        val b = runner.run(base) as NymAuthDemoRunner.Outcome.Presented
        assertEquals(a.pseudonymHex, b.pseudonymHex)
    }

    @Test
    fun `a foreign psc is refused`() = runTest {
        assertEquals(NymAuthDemoRunner.Outcome.Refused, runner.run(base.copy(foreignPsc = true)))
    }

    @Test
    fun `a false age predicate is refused`() = runTest {
        assertEquals(NymAuthDemoRunner.Outcome.Refused, runner.run(base.copy(birthDate = "2015-01-01")))
    }

    @Test
    fun `an unsatisfiable age span is refused`() = runTest {
        assertEquals(NymAuthDemoRunner.Outcome.Refused, runner.run(base.copy(ge = "2000-01-01", le = "2000-06-01")))
    }

    // -------- the issuer-delivered secret_seed (ssc) scenario --------

    private val seedA = ByteArray(16) { it.toByte() }
    private val sscRunner = NymAuthDemoRunner(ByteArray(32) { it.toByte() }, newSecretSeed = { seedA.copyOf() })
    private val ssc = base.copy(scenario = NymAuthDemoRunner.Scenario.KNOWN_OFFENDER_SSC)

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test
    fun `the ssc scenario presents with the delivered seed and the pseudonym equals a recompute from it`() = runTest {
        val presented = sscRunner.run(ssc) as NymAuthDemoRunner.Outcome.Presented
        assertTrue(presented.pseudonymMatches)
        assertEquals(
            hex(org.siros.sdk.credentials.NymPseudonym.derive("known-offender-matching-ssc", seedA, verifierId = base.verifierId)),
            presented.pseudonymHex,
        )
    }

    @Test
    fun `a wrong delivered seed is refused`() = runTest {
        assertEquals(NymAuthDemoRunner.Outcome.Refused, sscRunner.run(ssc.copy(wrongSeed = true)))
    }

    @Test
    fun `the seed and its hex appear nowhere in what the demo returns`() = runTest {
        val presented = sscRunner.run(ssc) as NymAuthDemoRunner.Outcome.Presented
        val shown = listOf(presented.token, presented.pseudonymHex, presented.recomputedHex, presented.proofAscii, presented.decodedHandles.toString())
        for (line in shown) assertTrue(line, !line.contains(hex(seedA)))
    }

    @Test
    fun `the demo issuer commits to a random 16-byte seed with ssc = SHA256 of it`() {
        val a = NymAuthDemoIssuer.newSecretSeed()
        val b = NymAuthDemoIssuer.newSecretSeed()
        assertEquals(16, a.size)
        assertTrue(!a.contentEquals(b))
        assertEquals(
            hex(java.security.MessageDigest.getInstance("SHA-256").digest(a)),
            hex(NymAuthDemoIssuer.commitmentTo(a)),
        )
        assertTrue(runCatching { NymAuthDemoIssuer.commitmentTo(ByteArray(15)) }.isFailure)
    }

    @Test
    fun `the psc scenario still refuses a foreign psc and is unaffected by the seed`() = runTest {
        assertEquals(NymAuthDemoRunner.Outcome.Refused, sscRunner.run(base.copy(foreignPsc = true)))
        assertTrue(sscRunner.run(base) is NymAuthDemoRunner.Outcome.Presented)
    }
}
