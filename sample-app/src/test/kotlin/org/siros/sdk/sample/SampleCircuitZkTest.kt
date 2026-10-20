package org.siros.sdk.sample

import org.junit.Assert.assertEquals
import org.junit.Test
import org.siros.sdk.credentials.NonDisclosurePolicy

class SampleCircuitZkTest {
    @Test
    fun theDemoCircuitServesOnlyTheNymAuthDocType() {
        assertEquals(setOf(NonDisclosurePolicy.NYM_AUTH_DOCTYPE), SampleCircuitZk.circuits.circuits().flatMap { it.docTypes }.toSet())
    }
}
