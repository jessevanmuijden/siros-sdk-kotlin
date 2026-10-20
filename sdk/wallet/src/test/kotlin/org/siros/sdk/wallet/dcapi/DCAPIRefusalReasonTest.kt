// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DCAPIRefusalReasonTest {

    private val locales = listOf("values", "values-sv", "values-fi", "values-el", "values-pt")

    private fun strings(dir: String): Map<String, String> {
        val file = File("src/main/res/$dir/strings.xml")
        assertTrue("missing ${file.path}", file.exists())
        val nodes = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file).getElementsByTagName("string")
        return (0 until nodes.length).associate { nodes.item(it).attributes.getNamedItem("name").nodeValue to nodes.item(it).textContent }
    }

    @Test
    fun everyReasonHasItsOwnMessageResource() {
        val ids = DCAPIRefusalReason.values().map { it.userMessageRes }
        assertEquals(ids.size, ids.toSet().size)
    }

    @Test
    fun everyLocaleHasEveryRefusalStringAndItIsPlainLanguage() {
        val english = strings("values").filterKeys { it.startsWith("siros_dcapi_refused_") }
        // one per reason, plus the title and the button
        assertEquals(DCAPIRefusalReason.values().size + 2, english.size)
        for (dir in locales) {
            val localised = strings(dir).filterKeys { it.startsWith("siros_dcapi_refused_") }
            assertEquals("$dir is missing a refusal string", english.keys, localised.keys)
            for ((name, text) in localised) {
                assertFalse("$dir/$name is empty", text.isBlank())
                // The user text is fixed: nothing in it can carry request content, an id, or a pseudonym.
                assertFalse("$dir/$name has a placeholder", Regex("%|\\{|\\}").containsMatchIn(text))
            }
        }
    }

    @Test
    fun theDefaultReasonOfAParserRefusalIsRequestNotVerified() {
        assertEquals(DCAPIRefusalReason.REQUEST_NOT_VERIFIED, DCAPIRequestRefused("p").reason)
        // The message never depends on the reason: nothing but the protocol reaches a log.
        assertEquals(
            DCAPIRequestRefused("p", DCAPIRefusalReason.NOT_TRUSTED).message,
            DCAPIRequestRefused("p", DCAPIRefusalReason.PROOF_FAILED).message,
        )
    }
}
