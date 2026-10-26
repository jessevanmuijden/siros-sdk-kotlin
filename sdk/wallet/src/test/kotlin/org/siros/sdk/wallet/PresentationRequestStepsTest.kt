// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlinx.serialization.json.JsonObject
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.StoredCredential

/** How many consent steps a request needs: a request that discloses no claims is one step, anything else is unchanged. */
class PresentationRequestStepsTest {
    private val cred = StoredCredential(id = 1L, format = "mso_mdoc", raw = "r", batchId = 1L, instanceId = 0)

    private fun fn(id: String, params: JsonObject = JsonObject(emptyMap())) = CircuitZkFunction(id = id, handle = "h-$id", params = params)

    private fun plan(vararg ids: String) = CircuitZkPlan(functions = ids.map { fn(it) })

    private fun result(queryId: String, format: String?, claims: List<List<String>>, plan: CircuitZkPlan? = null) =
        CredentialMatcher.MatchResult(queryId = queryId, format = format, candidates = listOf(cred), requestedClaims = claims, circuitZkPlan = plan)

    /** What the matcher builds for a circuit_zk query: format zkp_req, requestedClaims always empty, the work is in the plan. */
    private fun zk(queryId: String, plan: CircuitZkPlan?) = result(queryId, "zkp_req", emptyList(), plan)

    private fun request(vararg results: CredentialMatcher.MatchResult) =
        PresentationRequest(verifierName = "v", matchResults = results.toList(), candidates = listOf(cred))

    @Test
    fun aZkpReqRequestDisclosesNothingAndIsOneStep() {
        val r = request(zk("q", plan("pseudonym")))
        assertTrue(r.disclosesNoClaims)
        assertEquals(1, r.consentStepCount)
        // Several zkp_req queries (a pseudonym and an age proof) are still one step.
        val two = request(zk("q1", plan("pseudonym")), zk("q2", plan("age_check")))
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
        val mixed = request(zk("a", plan("pseudonym")), result("b", "mso_mdoc", listOf(listOf("ns", "x"))))
        assertFalse(mixed.disclosesNoClaims)
        assertEquals(4, mixed.consentStepCount)
        // An empty request is not "discloses nothing".
        assertFalse(request().disclosesNoClaims)
        assertEquals(2, request().consentStepCount)
    }

    @Test
    fun aPlanThatDisclosesClaimsKeepsEveryStepWhateverRequestedClaimsSays() {
        // requestedClaims is empty for every circuit_zk query; the legacy claim disclosure (and so mso_mdoc_zk-style age-over-18 and
        // any ZK mdoc with claims) lives in the plan's functions.
        val legacyClaims = CircuitZkPlan(functions = listOf(fn("zk-claim-disclosure-v1")))
        for ((label, req) in listOf(
            "legacy claim disclosure" to request(zk("q", legacyClaims)),
            "legacy disclosure beside a pseudonym" to request(zk("q", plan("pseudonym", "zk-claim-disclosure-v1"))),
            "an unknown function" to request(zk("q", plan("some-future-function"))),
            "an empty plan" to request(zk("q", CircuitZkPlan(functions = emptyList()))),
            "no plan at all" to request(zk("q", null)),
            "one disclosing query among proofs" to request(zk("a", plan("pseudonym")), zk("b", legacyClaims)),
        )) {
            assertFalse(label, req.disclosesNoClaims)
            assertEquals(label, req.consentMatchResults.size + 2, req.consentStepCount)
        }
    }

    private fun unmatched(queryId: String) =
        CredentialMatcher.MatchResult(queryId = queryId, format = "mso_mdoc", candidates = emptyList(), requestedClaims = listOf(listOf("ns", "given_name")))

    @Test
    fun aQueryTheWalletCouldNotMatchGetsNoStepAndNoCard() {
        // gdc: one dcql_query with five alternatives (mdl, photoid, pid_1_5, pid_1_8, pid_mdoc) asking for the same claims;
        // the wallet holds only pid_1_8. The stepper must not iterate the four others.
        val matched = result("pid_1_8", "mso_mdoc", listOf(listOf("ns", "given_name")))
        val r = request(unmatched("mdl"), unmatched("photoid"), unmatched("pid_1_5"), matched, unmatched("pid_mdoc"))
        assertEquals(listOf("pid_1_8"), r.consentMatchResults.map { it.queryId })
        // preview + one claim step + summary
        assertEquals(3, r.consentStepCount)
        // five listed alternatives remain visible to the matcher's consumers
        assertEquals(5, r.matchResults.size)
    }

    @Test
    fun noMatchAtAllIsPreviewAndSummaryOnly_andUnmatchedZkpQueriesDoNotBlockTheSkip() {
        assertEquals(2, request(unmatched("a"), unmatched("b")).consentStepCount)
        // a zkp_req alternative that matched, beside alternatives that did not: still a request that discloses nothing
        val z = zk("pid_1_8", plan("pseudonym"))
        val r = request(unmatched("mdl"), z, unmatched("photoid"))
        assertTrue(r.disclosesNoClaims)
        assertEquals(1, r.consentStepCount)
    }
}
