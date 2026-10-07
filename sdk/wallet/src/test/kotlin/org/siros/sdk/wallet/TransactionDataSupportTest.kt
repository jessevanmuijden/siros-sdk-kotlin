package org.siros.sdk.wallet

import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TransactionDataSupportTest {

    @Test
    fun `nothing is declared unless effectively enabled`() {
        assertNull(TransactionDataSupport.capabilitiesOffered(false))
        assertNull(TransactionDataSupport.engineFeatures(false))
    }

    @Test
    fun `WMP capability is the profile 2_3 shape`() {
        val offered = TransactionDataSupport.capabilitiesOffered(true)!!

        assertEquals(setOf("transaction_data"), offered.keys)
        val cap = offered["transaction_data"]!!.jsonObject
        assertEquals(listOf(1), cap["versions"]!!.jsonArray.map { it.jsonPrimitive.content.toInt() })
        assertEquals(
            listOf("sha-256", "sha-384", "sha-512"),
            cap["hash_algs"]!!.jsonArray.map { it.jsonPrimitive.content },
        )
    }

    @Test
    fun `engine feature is transaction_data_v1`() {
        assertEquals(listOf("transaction_data.v1"), TransactionDataSupport.engineFeatures(true))
    }
}
