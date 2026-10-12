// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pure cache-logic tests - no native `zk_cred_vega` calls, so these run as
 * plain JVM unit tests rather than needing the Android instrumented
 * environment [VegaZkVectorTest] does. `credentialBytes`/state values below
 * are arbitrary opaque bytes; nothing here cares what they actually encode.
 */
class VegaProofCacheTest {

    private val credentialA = byteArrayOf(1, 2, 3)
    private val credentialB = byteArrayOf(4, 5, 6)
    private val stateV1 = byteArrayOf(0x10)
    private val stateV2 = byteArrayOf(0x20)

    @Test
    fun `nothing cached returns null`() = runTest {
        val cache = VegaProofCache()
        assertNull(cache.priorStateFor(credentialA, listOf("age_over_18")))
    }

    @Test
    fun `a recorded state is returned for the exact same credential and claims`() = runTest {
        val cache = VegaProofCache()
        cache.record(credentialA, listOf("age_over_18"), stateV1, usedCachedState = false)
        assertArrayEquals(stateV1, cache.priorStateFor(credentialA, listOf("age_over_18")))
    }

    @Test
    fun `claim order does not matter - only the set does`() = runTest {
        // The circuit's slots are fixed per credential (VegaProofSystem.buildWitness's
        // own doc comment) - the order requestedClaims happened to be built
        // in is never meaningful, only which claims are in it.
        val cache = VegaProofCache()
        cache.record(credentialA, listOf("age_over_18", "nationality"), stateV1, usedCachedState = false)
        assertArrayEquals(stateV1, cache.priorStateFor(credentialA, listOf("nationality", "age_over_18")))
    }

    @Test
    fun `a different disclosed-claims set for the SAME credential is a cache miss`() = runTest {
        // The critical correctness property: confirmed empirically (see
        // VegaProofCache's own doc comment) that reusing a prep-chain across
        // a DIFFERENT disclosure combination fails outright at the native
        // layer. A stale hit here would not just be a wasted cache - it
        // would hand back a state that crashes the next prove() call.
        val cache = VegaProofCache()
        cache.record(credentialA, listOf("age_over_18"), stateV1, usedCachedState = false)
        assertNull(cache.priorStateFor(credentialA, listOf("age_over_18", "nationality")))
        assertNull(cache.priorStateFor(credentialA, listOf("nationality")))
    }

    @Test
    fun `the same disclosed-claims set for a DIFFERENT credential is a cache miss`() = runTest {
        val cache = VegaProofCache()
        cache.record(credentialA, listOf("age_over_18"), stateV1, usedCachedState = false)
        assertNull(cache.priorStateFor(credentialB, listOf("age_over_18")))
    }

    @Test
    fun `recording again for the same key overwrites the previous state`() = runTest {
        val cache = VegaProofCache()
        cache.record(credentialA, listOf("age_over_18"), stateV1, usedCachedState = false)
        cache.record(credentialA, listOf("age_over_18"), stateV2, usedCachedState = true)
        assertArrayEquals(stateV2, cache.priorStateFor(credentialA, listOf("age_over_18")))
    }

    @Test
    fun `a null nextState is never recorded`() = runTest {
        val cache = VegaProofCache()
        cache.record(credentialA, listOf("age_over_18"), null, usedCachedState = false)
        assertNull(cache.priorStateFor(credentialA, listOf("age_over_18")))
    }

    @Test
    fun `an entry stops being returned once it hits its reuse limit`() = runTest {
        // maxReusesPerEntry=2 means one prep chain may serve at most 2
        // presentations total (the original fresh prep_prove plus one
        // reuse) before a 3rd lookup is refused, forcing a fresh prep_prove.
        val cache = VegaProofCache(maxReusesPerEntry = 2)
        val claims = listOf("age_over_18")

        // Presentation #1: a fresh prep_prove ran (usedCachedState=false),
        // recorded with reuseCount=1. Still under the limit, so presentation
        // #2 can reuse it.
        cache.record(credentialA, claims, stateV1, usedCachedState = false)
        assertArrayEquals(stateV1, cache.priorStateFor(credentialA, claims))

        // Presentation #2 consumed that cached state and is recorded
        // (usedCachedState=true), bumping reuseCount to 2 - exactly at the
        // limit now, so a 3rd lookup must fail.
        cache.record(credentialA, claims, stateV2, usedCachedState = true)
        assertNull(cache.priorStateFor(credentialA, claims))
    }

    @Test
    fun `a fresh prep_prove after hitting the limit restarts the reuse count`() = runTest {
        val cache = VegaProofCache(maxReusesPerEntry = 2)
        val claims = listOf("age_over_18")

        cache.record(credentialA, claims, stateV1, usedCachedState = false) // presentation #1, reuseCount=1
        cache.record(credentialA, claims, stateV1, usedCachedState = true) // presentation #2, reuseCount=2, at the limit
        assertNull(cache.priorStateFor(credentialA, claims)) // presentation #3 is refused

        // A host that re-ran prep_prove fresh (e.g. VegaProofSystem.prewarm,
        // or generateProof itself after the above miss) records
        // usedCachedState=false again, starting a brand new chain.
        cache.record(credentialA, claims, stateV2, usedCachedState = false)
        assertArrayEquals(stateV2, cache.priorStateFor(credentialA, claims))
    }

    @Test
    fun `clear drops every entry`() = runTest {
        val cache = VegaProofCache()
        cache.record(credentialA, listOf("age_over_18"), stateV1, usedCachedState = false)
        cache.clear()
        assertNull(cache.priorStateFor(credentialA, listOf("age_over_18")))
    }
}
