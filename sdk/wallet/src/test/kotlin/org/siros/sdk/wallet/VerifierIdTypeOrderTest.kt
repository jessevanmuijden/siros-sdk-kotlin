// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VerifierIdTypeOrderTest {
    @Test
    fun theDefaultIsSemanticThenX509SanDns() {
        assertEquals(listOf("semantic", "x509_san_dns"), VerifierIdTypeOrder.DEFAULT)
        assertEquals(VerifierIdTypeOrder.DEFAULT, WalletConfig(backendUrl = "https://b.example").circuitZkVerifierIdTypes)
        assertTrue(WalletConfig(backendUrl = "https://b.example").circuitZkVerifierIdSources.isEmpty())
    }

    @Test
    fun blankUntrimmedCommaAndDuplicateEntriesAreRejected_emptyListIsValid() {
        assertTrue(VerifierIdTypeOrder.isValid(emptyList()))
        assertTrue(VerifierIdTypeOrder.isValid(listOf("a", "b")))
        for (bad in listOf(listOf(""), listOf("  "), listOf("a", ""), listOf(" a"), listOf("a "), listOf("a,b"), listOf("a", "b", "a"))) {
            assertFalse(bad.toString(), VerifierIdTypeOrder.isValid(bad))
            assertNotNull(VerifierIdTypeOrder.problem(bad))
            assertThrows(IllegalArgumentException::class.java) { VerifierIdTypeOrder.require(bad) }
        }
    }

    @Test
    fun addTrimsAndRefusesBlankAndDuplicates() {
        assertEquals(listOf("a", "b"), VerifierIdTypeOrder.add(listOf("a"), "  b "))
        assertNull(VerifierIdTypeOrder.add(listOf("a"), "   "))
        assertNull(VerifierIdTypeOrder.add(listOf("a"), "a"))
        assertNull(VerifierIdTypeOrder.add(listOf("a"), " a "))
        assertNull(VerifierIdTypeOrder.add(listOf("a"), "x,y"))
    }

    @Test
    fun removeAndMoveEditInPlaceAndIgnoreOutOfRange() {
        val l = listOf("a", "b", "c")
        assertEquals(listOf("a", "c"), VerifierIdTypeOrder.remove(l, 1))
        assertEquals(l, VerifierIdTypeOrder.remove(l, 3))
        assertEquals(l, VerifierIdTypeOrder.remove(l, -1))
        assertEquals(listOf("b", "a", "c"), VerifierIdTypeOrder.move(l, 1, -1))
        assertEquals(listOf("a", "c", "b"), VerifierIdTypeOrder.move(l, 1, 1))
        assertEquals(l, VerifierIdTypeOrder.move(l, 0, -1))
        assertEquals(l, VerifierIdTypeOrder.move(l, 2, 1))
        assertEquals(l, VerifierIdTypeOrder.move(l, 5, -1))
    }

    @Test
    fun storedFormRoundTripsInOrder_emptyIsTheEmptyList() {
        for (l in listOf(emptyList(), listOf("a"), listOf("b", "a", "c"))) {
            assertEquals(l, VerifierIdTypeOrder.fromStored(VerifierIdTypeOrder.toStored(l)))
        }
        assertNull(VerifierIdTypeOrder.fromStored(null))
        assertNull(VerifierIdTypeOrder.fromStored("a,a"))
    }
}
