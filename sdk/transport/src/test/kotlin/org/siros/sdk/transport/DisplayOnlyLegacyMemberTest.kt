package org.siros.sdk.transport

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The engine's relay of the response-level metadata drops every member but display data, and says only THAT a superseded one was there. */
class DisplayOnlyLegacyMemberTest {
    private fun decode(text: String) = Json.decodeFromString(DisplayOnlyCredentialMetadataSerializer, text)

    @Test
    fun everySupersededMemberNameLeavesAValueFreeMarker_andNoMember() {
        for (name in listOf("org.siros.secret_seed", "org.siros.holder_commitments", "org.siros.psc", "holder_commitments", "secret_members")) {
            for (value in listOf("""{"k":"00112233"}""", "\"x\"", "null", "[]")) {
                val md = decode("""{"display":[],"$name":$value}""")
                assertTrue("$name=$value", md.legacyMemberPresent)
                assertEquals(setOf("display"), md.members.keys)
                assertFalse(md.toString().contains("0011"))
            }
        }
    }

    @Test
    fun displayDataAloneLeavesNoMarker() {
        val md = decode("""{"display":[{"name":"x"}],"claims":[],"other":1}""")
        assertFalse(md.legacyMemberPresent)
        assertEquals(setOf("display", "claims"), md.members.keys)
    }
}
