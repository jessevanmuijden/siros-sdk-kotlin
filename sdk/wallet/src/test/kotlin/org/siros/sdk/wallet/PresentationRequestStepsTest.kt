// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.StoredCredential

/** How many consent steps a request needs: a request that discloses no claims is one step, anything else is unchanged. */
class PresentationRequestStepsTest {
    private val cred = StoredCredential(id = 1L, format = "mso_mdoc", raw = "r", batchId = 1L, instanceId = 0)

    private fun result(queryId: String, format: String?, claims: List<List<String>>) =
        CredentialMatcher.MatchResult(queryId = queryId, format = format, candidates = listOf(cred), requestedClaims = claims)

    private fun request(vararg results: CredentialMatcher.MatchResult) =
        PresentationRequest(verifierName = "v", matchResults = results.toList(), candidates = listOf(cred))

    @Test
    fun aZkpReqRequestDisclosesNothingAndIsOneStep() {
        val r = request(result("q", "zkp_req", emptyList()))
        assertTrue(r.disclosesNoClaims)
        assertEquals(1, r.consentStepCount)
        // Several zkp_req queries (a pseudonym and an age proof) are still one step.
        val two = request(result("q1", "zkp_req", emptyList()), result("q2", "zkp_req", emptyList()))
        assertTrue(two.disclosesNoClaims)
        assertEquals(1, two.consentStepCount)
    }

    @Test
    fun anyRequestThatCanDiscloseDataKeepsAllItsSteps() {
        // A claim-listing query: preview + one selection per query + summary.
        val withClaims = request(result("q", "mso_mdoc", listOf(listOf("org.iso.18013.5.1", "family_name"))))
        assertFalse(withClaims.disclosesNoClaims)
        assertEquals(3, withClaims.consentStepCount)
        // A query without claims in another format may ask for the whole credential: NOT skipped.
        val wholeCredential = request(result("q", "dc+sd-jwt", emptyList()))
        assertFalse(wholeCredential.disclosesNoClaims)
        assertEquals(3, wholeCredential.consentStepCount)
        // A zkp_req query next to a disclosing one is not skipped either.
        val mixed = request(result("a", "zkp_req", emptyList()), result("b", "mso_mdoc", listOf(listOf("ns", "x"))))
        assertFalse(mixed.disclosesNoClaims)
        assertEquals(4, mixed.consentStepCount)
        // An empty request is not "discloses nothing".
        assertFalse(request().disclosesNoClaims)
        assertEquals(2, request().consentStepCount)
    }
}
