// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PresentationLinkLedgerTest {
    private var now = 1_000L
    private fun ledger(capacity: Int = 16) = PresentationLinkLedger(ttlMillis = 60_000, capacity = capacity, clock = { now })

    @Test
    fun `the same link is admitted once inside the window and again after it`() {
        val l = ledger()
        assertTrue(l.admit("openid4vp://?client_id=x&nonce=1"))
        assertFalse("redelivered", l.admit("openid4vp://?client_id=x&nonce=1"))
        assertTrue("a different link is a different request", l.admit("openid4vp://?client_id=x&nonce=2"))
        now += 60_001
        assertTrue("after the window", l.admit("openid4vp://?client_id=x&nonce=1"))
    }

    @Test
    fun `a released link and a cleared ledger admit a retry at once`() {
        val l = ledger()
        l.admit("a")
        l.release("a")
        assertTrue(l.admit("a"))
        l.admit("b")
        l.releaseAll()
        assertTrue(l.admit("a"))
        assertTrue(l.admit("b"))
    }

    @Test
    fun `it keeps at most its capacity`() {
        val l = ledger(capacity = 2)
        l.admit("1"); l.admit("2"); l.admit("3")
        assertTrue("the oldest was forgotten", l.admit("1"))
        assertFalse(l.admit("3"))
    }

    @Test
    fun `a completed link is kept for a full window from its completion`() {
        val l = ledger()
        l.admit("a")
        now += 50_000
        l.markCompleted("a")
        now += 50_000 // 100 s after the start, 50 s after the answer
        assertFalse("still inside the window of the answer", l.admit("a"))
        now += 10_001
        assertTrue(l.admit("a"))
    }
}
