package org.siros.sdk.credentials

import org.junit.Assert.assertEquals
import org.junit.Test

/** Property order of a data class is binary API: `proofSystem` is appended last, `docTypes` stays the fifth component. */
class ZkCircuitDescriptorBinaryShapeTest {
    @Test
    fun `docTypes is still component5 and proofSystem is the last component`() {
        val d = ZkCircuitDescriptor(id = "i", docTypes = listOf("dt"), proofSystem = "ps")
        assertEquals(listOf("dt"), d.component5())
        val n = d.javaClass.methods.count { Regex("component\\d+").matches(it.name) }
        assertEquals("ps", d.javaClass.getMethod("component$n").invoke(d))
    }
}
