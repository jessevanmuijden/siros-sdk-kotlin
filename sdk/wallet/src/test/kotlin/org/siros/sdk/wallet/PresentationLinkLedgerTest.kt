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
        l.markCompleted("openid4vp://?client_id=x&nonce=1")
        now += 60_001
        assertTrue("an answered link, after its window", l.admit("openid4vp://?client_id=x&nonce=1"))
        now += 10 * 60_000 + 1
        assertTrue("an unanswered one is forgotten after ten minutes", l.admit("openid4vp://?client_id=x&nonce=2"))
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

    @Test
    fun `a flow ending releases only its own link`() {
        val l = ledger()
        l.admit("A", 1); l.admit("B", 1)
        l.associate("flow-a", 1) // the first flow the engine reports on connection 1 is the oldest start's
        l.associate("flow-b", 1)
        l.releaseFlow("flow-a")
        assertTrue("A is retryable", l.admit("A", 1))
        assertFalse("B is untouched: its flow is still going", l.admit("B", 1))
    }

    @Test
    fun `an answered link survives a cancelled flow, a session end and a connection loss, an unanswered one does not`() {
        val l = ledger()
        l.admit("answered", 1); l.associate("f1", 1); l.completeFlow("f1")
        l.admit("pending", 1)
        l.releaseUnassociated() // a cancelled start
        assertTrue(l.admit("pending", 1))
        l.releaseInFlight() // the session ended
        assertFalse("answered stays", l.admit("answered", 1))
        assertTrue(l.admit("pending", 1))
        l.releaseUpTo(1) // the connection was lost
        assertFalse(l.admit("answered", 1))
        assertTrue(l.admit("pending", 1))
    }

    @Test
    fun `connections that are gone release what was started on them, and a start on the new one is untouched`() {
        val l = ledger()
        l.admit("old", 1)
        l.admit("new", 2)
        l.releaseOlderThan(2)
        assertTrue("sent on the replaced connection: never answered", l.admit("old", 2))
        assertFalse("started on the current connection", l.admit("new", 2))
    }

    @Test
    fun `a start whose connection was replaced while it connected is re-admitted by rebind`() {
        val l = ledger()
        l.admit("B", 1)
        l.releaseOlderThan(2) // the forced reconnect of ensureEngineConnected
        l.rebind("B", 2)
        assertFalse("the duplicate is still ignored", l.admit("B", 2))
        l.releaseUpTo(2)
        assertTrue(l.admit("B", 2))
    }

    @Test
    fun `an answer is recorded for its full window even when the start was pruned or evicted`() {
        val l = ledger(capacity = 2)
        l.admit("A", 1)
        l.admit("B", 1); l.admit("C", 1) // A is evicted at capacity
        l.markCompleted("A")
        assertFalse("A's redelivery is a spent request", l.admit("A", 1))
    }

    @Test
    fun `a slow presentation is still on record when it completes, past the answered window`() {
        val l = ledger()
        l.admit("A", 1); l.associate("fa", 1)
        now += 3 * 60_000 // three minutes in flight
        l.admit("B", 1) // prunes: A is still in flight, not expired
        l.completeFlow("fa")
        assertFalse("A was answered: its redelivery is ignored", l.admit("A", 1))
    }
}
