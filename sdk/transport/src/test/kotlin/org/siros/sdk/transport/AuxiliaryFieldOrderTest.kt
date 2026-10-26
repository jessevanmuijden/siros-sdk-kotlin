package org.siros.sdk.transport

import org.junit.Assert.assertEquals
import org.junit.Test

/** A data class's property order is part of its binary API: the auxiliary-data field was appended, never inserted. */
class AuxiliaryFieldOrderTest {
    @Test
    fun theAuxiliaryDataFieldIsTheLastElementOfBothSignParamsClasses() {
        val engine = org.siros.sdk.transport.engine.SignRequestParams.serializer().descriptor
        val wmp = org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams.serializer().descriptor
        assertEquals("auxiliary_data_to_issuer", engine.getElementName(engine.elementsCount - 1))
        assertEquals("auxiliary_data_to_issuer", wmp.getElementName(wmp.elementsCount - 1))
    }
}
