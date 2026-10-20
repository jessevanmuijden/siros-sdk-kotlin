// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import org.junit.Assert.assertEquals
import org.junit.Test

/** An absent or unreadable picker selection fails closed; it is never the empty "present anything" list. */
class DCAPISelectionTest {
    private val none = DCAPISelection.NO_SUCH_CREDENTIAL

    @Test
    fun `a selected set wins and a foreign id becomes an id no credential has`() {
        assertEquals(listOf(4L, 9L), DCAPISelection.resolve({ listOf("4", "9") }, { "1" }))
        assertEquals(listOf(none), DCAPISelection.resolve({ listOf("4", "debug") }, { null }))
        assertEquals(listOf(none), DCAPISelection.resolve({ listOf("debug", "4") }, { "4" }))
    }

    @Test
    fun `a single selected entry is used when there is no set`() {
        assertEquals(listOf(7L), DCAPISelection.resolve({ null }, { "7" }))
        assertEquals(listOf(7L), DCAPISelection.resolve({ emptyList() }, { "7" }))
        assertEquals(listOf(none), DCAPISelection.resolve({ null }, { "diagnostics" }))
    }

    @Test
    fun `an absent selection is refused, not treated as no selection`() {
        assertEquals(listOf(none), DCAPISelection.resolve({ null }, { null }))
        assertEquals(listOf(none), DCAPISelection.resolve({ emptyList() }, { null }))
    }

    @Test
    fun `an unreadable selection is refused, not treated as no selection`() {
        assertEquals(listOf(none), DCAPISelection.resolve({ throw IllegalStateException("x") }, { "7" }))
        assertEquals(listOf(none), DCAPISelection.resolve({ null }, { throw IllegalStateException("x") }))
    }
}
