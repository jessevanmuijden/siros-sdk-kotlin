// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.transport.engine.CredentialRef

/**
 * Defence in depth against a buggy or compromised engine: `credentials_to_include` must never be trusted as the engine
 * round-trips it, only as a reference to be checked against what this wallet itself reported consenting to.
 */
class ConsentGuardTest {
    private fun record(vararg entries: Triple<String?, String, Set<String>?>) =
        ConsentRecord(entries.map { (q, c, claims) -> ConsentedSelection(q, c, claims) })

    private fun ref(queryId: String?, credentialId: String, claims: List<String>? = null) =
        CredentialRef(credentialQueryId = queryId, credentialId = credentialId, disclosedClaims = claims)

    @Test
    fun aRefAskingForExactlyTheConsentedClaimsIsAccepted_andTheReturnedClaimsAreTheRecordsOwn() {
        val r = record(Triple("q1", "1", setOf("given_name", "family_name")))
        val result = ConsentGuard.verify(r, listOf(ref("q1", "1", listOf("given_name"))))
        assertEquals(setOf("given_name", "family_name"), result["q1" to "1"])
    }

    @Test
    fun aRefAskingForMoreThanConsentedIsRefused() {
        val r = record(Triple("q1", "1", setOf("age_over_18")))
        // The engine tries to disclose every claim although the user only consented to one.
        try {
            ConsentGuard.verify(r, listOf(ref("q1", "1", listOf("age_over_18", "given_name", "family_name", "birth_date"))))
            fail("accepted a batch that over-discloses")
        } catch (e: ConsentMismatchException) {
            assertTrue(e.reason is ConsentMismatchReason.ExtraClaims)
            assertEquals(3, (e.reason as ConsentMismatchReason.ExtraClaims).count)
            // The message never names a claim.
            assertTrue(e.message!!.none { it.isUpperCase() } || !e.message!!.contains("given_name"))
        }
    }

    @Test
    fun anUnknownQueryOrCredentialIsRefused() {
        val r = record(Triple("q1", "1", setOf("given_name")))
        try {
            ConsentGuard.verify(r, listOf(ref("q1", "2", listOf("given_name"))))
            fail("accepted a credential the user was never asked about")
        } catch (e: ConsentMismatchException) {
            assertTrue(e.reason is ConsentMismatchReason.UnknownSelection)
        }
        try {
            ConsentGuard.verify(r, listOf(ref("q2", "1", listOf("given_name"))))
            fail("accepted a query the user was never asked about")
        } catch (e: ConsentMismatchException) {
            assertTrue(e.reason is ConsentMismatchReason.UnknownSelection)
        }
    }

    @Test
    fun aMalformedEntryWithNoCredentialIdIsRefused() {
        val r = record(Triple("q1", "1", setOf("given_name")))
        try {
            ConsentGuard.verify(r, listOf(ref("q1", "")))
            fail("accepted an entry with no credential id")
        } catch (e: ConsentMismatchException) {
            assertTrue(e.reason is ConsentMismatchReason.MalformedEntry)
        }
    }

    @Test
    fun noRecordAtAllForTheFlowIsRefused() {
        try {
            ConsentGuard.verify(null, listOf(ref("q1", "1", listOf("given_name"))))
            fail("accepted a sign request for a flow with no recorded consent")
        } catch (e: ConsentMismatchException) {
            assertEquals(ConsentMismatchReason.NoRecord, e.reason)
        }
    }

    @Test
    fun reorderedRefsAreAccepted_orderIsNotSignificant() {
        val r = record(Triple("q1", "1", setOf("a")), Triple("q2", "2", setOf("b")))
        val result = ConsentGuard.verify(r, listOf(ref("q2", "2", listOf("b")), ref("q1", "1", listOf("a"))))
        assertEquals(setOf("a"), result["q1" to "1"])
        assertEquals(setOf("b"), result["q2" to "2"])
    }

    @Test
    fun aNullOrEmptyDisclosedClaimsIsNotTriviallyAccepted_asTheCorrespondingConsentedSetInstead() {
        // The caller must use the RETURNED (consented) claims downstream, never the ref's own disclosedClaims - a null/empty
        // value there is not a safe "nothing more" input, since some signing paths read it as "disclose everything". A null
        // ref.disclosedClaims against a NON-empty consented set still passes verify() (null asks for nothing beyond what was
        // consented), but the claims to actually use come from the record, not from the (absent) ref value.
        val r = record(Triple("q1", "1", setOf("given_name")))
        val result = ConsentGuard.verify(r, listOf(ref("q1", "1", null)))
        assertEquals(setOf("given_name"), result["q1" to "1"])
    }

    @Test
    fun zkpReqEntriesConsentedWithNoClaimsRefuseAnyDisclosedClaim() {
        // circuit_zk queries are recorded with an empty claim set (handleCredentialSelection); the engine asking to disclose
        // even one named claim for such a query is refused, not silently dropped.
        val r = record(Triple("q1", "1", emptySet()))
        assertEquals(emptySet<String>(), ConsentGuard.verify(r, listOf(ref("q1", "1", emptyList())))["q1" to "1"])
        try {
            ConsentGuard.verify(r, listOf(ref("q1", "1", listOf("pairwise_pseudonym"))))
            fail("accepted a disclosed claim for a zkp_req-consented query")
        } catch (e: ConsentMismatchException) {
            assertTrue(e.reason is ConsentMismatchReason.ExtraClaims)
        }
    }

    @Test
    fun aWholeCredentialConsentIsRecordedAsNull_distinctFromAnExplicitEmptyClaimSet() {
        // A DCQL query with no `claims` array (or a non-DCQL match) means "the whole credential was consented", recorded as
        // null - NOT an empty set. The engine may then ask for any specific claims (it already showed the user everything),
        // and the claims to actually disclose downstream must stay null (never defaulted to empty - see mdoc's semantics
        // below, where an empty disclosed-claims list means "disclose nothing").
        val r = record(Triple("q1", "1", null))
        val result = ConsentGuard.verify(r, listOf(ref("q1", "1", listOf("given_name", "family_name"))))
        assertEquals(null, result["q1" to "1"])
    }

    @Test
    fun aWholeCredentialConsentAcceptsNoDisclosedClaimsToo() {
        val r = record(Triple("q1", "1", null))
        val result = ConsentGuard.verify(r, listOf(ref("q1", "1", null)))
        assertTrue(result.containsKey("q1" to "1"))
        assertEquals(null, result["q1" to "1"])
    }

    @Test
    fun aMismatchInOneEntryRefusesTheWholeBatch_notJustThatEntry() {
        val r = record(Triple("q1", "1", setOf("given_name")), Triple("q2", "2", setOf("family_name")))
        try {
            ConsentGuard.verify(r, listOf(ref("q1", "1", listOf("given_name")), ref("q2", "2", listOf("family_name", "ssn"))))
            fail("accepted a batch with one over-disclosing entry")
        } catch (e: ConsentMismatchException) {
            assertTrue(e.reason is ConsentMismatchReason.ExtraClaims)
        }
    }
}
