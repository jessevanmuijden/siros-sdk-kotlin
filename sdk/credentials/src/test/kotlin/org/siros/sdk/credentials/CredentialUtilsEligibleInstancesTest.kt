// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import org.junit.Assert.assertEquals
import org.junit.Test

class CredentialUtilsEligibleInstancesTest {

    private fun credential(
        id: Long,
        batchId: Long = 1L,
        instanceId: Int = 0,
        format: String = "vc+sd-jwt",
        kid: String? = null,
    ) = StoredCredential(
        id = id,
        format = format,
        raw = "raw-$id",
        batchId = batchId,
        instanceId = instanceId,
        kid = kid,
    )

    private fun presentation(vararg credentialIds: Long) = PresentationRecord(
        id = credentialIds.sum() + 1000L,
        flowId = "flow",
        credentialIds = credentialIds.toList(),
        timestamp = 0L,
    )

    @Test
    fun neverConsume_returnsEveryInstanceRegardlessOfHistory() {
        val instances = listOf(credential(id = 1L, instanceId = 0), credential(id = 2L, instanceId = 1))
        val history = listOf(presentation(1L), presentation(2L))

        val result = CredentialUtils.eligibleInstances(instances, CredentialConsumptionPolicy.NEVER_CONSUME, history, setOf("irrelevant-kid"))

        assertEquals(instances, result)
    }

    @Test
    fun consumeAll_excludesInstancesAlreadyPresented() {
        val used = credential(id = 1L, instanceId = 0)
        val unused = credential(id = 2L, instanceId = 1)
        val history = listOf(presentation(1L))

        val result = CredentialUtils.eligibleInstances(listOf(used, unused), CredentialConsumptionPolicy.CONSUME_ALL, history, setOf("irrelevant-kid"))

        assertEquals(listOf(unused), result)
    }

    @Test
    fun consumeAll_withNoHistory_everyInstanceIsEligible() {
        val instances = listOf(credential(id = 1L, instanceId = 0), credential(id = 2L, instanceId = 1))

        val result = CredentialUtils.eligibleInstances(instances, CredentialConsumptionPolicy.CONSUME_ALL, emptyList(), setOf("irrelevant-kid"))

        assertEquals(instances, result)
    }

    @Test
    fun consumeAll_allInstancesUsed_returnsEmptyList() {
        val a = credential(id = 1L, instanceId = 0)
        val b = credential(id = 2L, instanceId = 1)
        val history = listOf(presentation(1L), presentation(2L))

        val result = CredentialUtils.eligibleInstances(listOf(a, b), CredentialConsumptionPolicy.CONSUME_ALL, history, setOf("irrelevant-kid"))

        assertEquals(emptyList<StoredCredential>(), result)
    }

    @Test
    fun consumeNonZkp_behavesIdenticallyToConsumeAll_sinceNoZkpFormatExistsYet() {
        // Every format this SDK supports today discloses via salted-hash
        // digests, not a real ZKP proof - see CredentialUtils.isZkpFormat's
        // doc comment. This test pins that current equivalence so a future
        // change introducing a real ZKP format is forced to reconsider it.
        val used = credential(id = 1L, instanceId = 0, format = "mso_mdoc")
        val unused = credential(id = 2L, instanceId = 1, format = "mso_mdoc")
        val history = listOf(presentation(1L))

        val result = CredentialUtils.eligibleInstances(listOf(used, unused), CredentialConsumptionPolicy.CONSUME_NON_ZKP, history, setOf("irrelevant-kid"))

        assertEquals(listOf(unused), result)
    }

    @Test
    fun sigCountOfTwoOrMore_stillCountsAsUsed_notJustExactlyOne() {
        val overused = credential(id = 1L, instanceId = 0)
        val history = listOf(presentation(1L), presentation(1L), presentation(1L))

        val result = CredentialUtils.eligibleInstances(listOf(overused), CredentialConsumptionPolicy.CONSUME_ALL, history, setOf("irrelevant-kid"))

        assertEquals(emptyList<StoredCredential>(), result)
    }

    // ── Key-availability checks ────────────────────────────────────────
    // A real, recurring bug (found via live proximity-presentation testing):
    // a credential whose signing key was silently lost (e.g. a sync that
    // never folded a software key into the persisted container) kept
    // reporting "available" under NEVER_CONSUME forever, since the old
    // 3-arg eligibleInstances was entirely blind to key existence.

    @Test
    fun neverConsume_stillExcludesInstanceWhoseKeyIsMissing() {
        val hasKey = credential(id = 1L, instanceId = 0, kid = "kid-1")
        val missingKey = credential(id = 2L, instanceId = 1, kid = "kid-2")

        val result = CredentialUtils.eligibleInstances(
            listOf(hasKey, missingKey),
            CredentialConsumptionPolicy.NEVER_CONSUME,
            emptyList(),
            availableKeyIds = setOf("kid-1"),
        )

        assertEquals(listOf(hasKey), result)
    }

    @Test
    fun instanceWithNullKid_eligibleWhenSignerHoldsAnyKeyAtAll() {
        // A null kid can't be matched against a specific availableKeyIds
        // entry, but as long as the signer holds *some* key, the low-level
        // "no specific kid" call shape (see WscdKeystoreAdapter's
        // selectSigningKey doc comment) can still succeed.
        val noKidBinding = credential(id = 1L, instanceId = 0, kid = null)

        val result = CredentialUtils.eligibleInstances(
            listOf(noKidBinding),
            CredentialConsumptionPolicy.NEVER_CONSUME,
            emptyList(),
            availableKeyIds = setOf("some-other-kid"),
        )

        assertEquals(listOf(noKidBinding), result)
    }

    @Test
    fun instanceWithNullKid_excludedWhenSignerHoldsNoKeysAtAll() {
        // Real StoredCredentials always get a kid at storage time (see
        // SirosWallet's activeAttestedKeyIds wiring) - a null kid reaching
        // here is a sign its binding was silently lost (e.g. a concurrent-
        // flow race, task #403), not a legitimate legacy call shape. With
        // zero keys in the signer, a null-kid credential is certain to fail
        // to sign exactly like a known-but-missing kid would, so it must be
        // excluded the same way.
        val noKidBinding = credential(id = 1L, instanceId = 0, kid = null)

        val result = CredentialUtils.eligibleInstances(
            listOf(noKidBinding),
            CredentialConsumptionPolicy.NEVER_CONSUME,
            emptyList(),
            availableKeyIds = emptySet(),
        )

        assertEquals(emptyList<StoredCredential>(), result)
    }

    @Test
    fun consumeAll_excludesInstanceThatIsBothUnusedAndKeyless() {
        // Consumption-eligible (never presented) but its key is gone -
        // both conditions are independently enforced.
        val keyless = credential(id = 1L, instanceId = 0, kid = "kid-1")

        val result = CredentialUtils.eligibleInstances(
            listOf(keyless),
            CredentialConsumptionPolicy.CONSUME_ALL,
            emptyList(),
            availableKeyIds = emptySet(),
        )

        assertEquals(emptyList<StoredCredential>(), result)
    }

    @Test
    fun consumeNonZkp_withResolverReturningTrue_keepsUsedInstanceEligible() {
        // A real ZK presentation (per the caller's own resolver - see
        // eligibleInstances' isZkPresentation doc comment) is never
        // consumed under CONSUME_NON_ZKP, even if it was already presented.
        val used = credential(id = 1L, instanceId = 0, format = "mso_mdoc")
        val history = listOf(presentation(1L))

        val result = CredentialUtils.eligibleInstances(
            listOf(used),
            CredentialConsumptionPolicy.CONSUME_NON_ZKP,
            history,
            setOf("irrelevant-kid"),
            isZkPresentation = { true },
        )

        assertEquals(listOf(used), result)
    }

    @Test
    fun consumeNonZkp_withResolverReturningFalse_excludesUsedInstance() {
        // A raw disclosure (per the caller's resolver) is consumed under
        // CONSUME_NON_ZKP just like under CONSUME_ALL.
        val used = credential(id = 1L, instanceId = 0, format = "mso_mdoc")
        val unused = credential(id = 2L, instanceId = 1, format = "mso_mdoc")
        val history = listOf(presentation(1L))

        val result = CredentialUtils.eligibleInstances(
            listOf(used, unused),
            CredentialConsumptionPolicy.CONSUME_NON_ZKP,
            history,
            setOf("irrelevant-kid"),
            isZkPresentation = { false },
        )

        assertEquals(listOf(unused), result)
    }

    @Test
    fun consumeNonZkp_withResolver_isEvaluatedPerInstance() {
        // The resolver is evaluated per-instance, not once for the whole
        // batch - a zk instance and a raw instance already presented in the
        // same batch must be judged independently of each other.
        val zkUsed = credential(id = 1L, instanceId = 0, format = "mso_mdoc")
        val rawUsed = credential(id = 2L, instanceId = 1, format = "mso_mdoc")
        val history = listOf(presentation(1L), presentation(2L))

        val result = CredentialUtils.eligibleInstances(
            listOf(zkUsed, rawUsed),
            CredentialConsumptionPolicy.CONSUME_NON_ZKP,
            history,
            setOf("irrelevant-kid"),
            isZkPresentation = { it.id == zkUsed.id },
        )

        assertEquals(listOf(zkUsed), result)
    }

    private fun matchResult(format: String?, vararg candidates: StoredCredential) = CredentialMatcher.MatchResult(
        queryId = "q", format = format, candidates = candidates.toList(), requestedClaims = emptyList(),
    )

    @Test
    fun perQuery_aZkpReqQueryDoesNotConsumeItsMdocCandidatesUnderConsumeNonZkp() {
        val mdoc = credential(id = 1L, format = "mso_mdoc")
        val history = listOf(presentation(1L))
        // The stored format is a raw mdoc: by it alone the second presentation would look like a consuming one.
        assertEquals(emptyList<StoredCredential>(), CredentialUtils.eligibleInstances(listOf(mdoc), CredentialConsumptionPolicy.CONSUME_NON_ZKP, history, setOf("k")))
        // The query is a zkp_req: it is answered with a proof, so the credential is still eligible.
        assertEquals(
            listOf(mdoc),
            CredentialUtils.eligibleInstances(matchResult("zkp_req", mdoc), CredentialConsumptionPolicy.CONSUME_NON_ZKP, history, setOf("k")),
        )
        // A raw mdoc query still consumes, and CONSUME_ALL consumes everything.
        assertEquals(emptyList<StoredCredential>(), CredentialUtils.eligibleInstances(matchResult("mso_mdoc", mdoc), CredentialConsumptionPolicy.CONSUME_NON_ZKP, history, setOf("k")))
        assertEquals(emptyList<StoredCredential>(), CredentialUtils.eligibleInstances(matchResult("zkp_req", mdoc), CredentialConsumptionPolicy.CONSUME_ALL, history, setOf("k")))
    }
}
