// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SvgTemplateRendererTest {

    @Test
    fun `substitutes a matched token`() {
        val template = "<text>{{givenName}} {{familyName}}</text>"
        val claims = listOf(
            DisplayClaim(key = "credentialSubject.givenName", label = "Given Name", value = "Alice", svgId = "givenName"),
            DisplayClaim(key = "credentialSubject.familyName", label = "Family Name", value = "Wonderland", svgId = "familyName"),
        )
        val result = SvgTemplateRenderer.substitute(template, claims)
        assertEquals("<text>Alice Wonderland</text>", result)
    }

    @Test
    fun `blanks an unmatched token instead of showing it literally`() {
        val template = "<text>{{title}}</text><text>{{givenName}}</text>"
        val claims = listOf(
            DisplayClaim(key = "credentialSubject.givenName", label = "Given Name", value = "Alice", svgId = "givenName"),
        )
        val result = SvgTemplateRenderer.substitute(template, claims)
        assertEquals("<text></text><text>Alice</text>", result)
        assertFalse("{{" in result)
    }

    @Test
    fun `claims without an svgId are ignored`() {
        val template = "<text>{{givenName}}</text>"
        val claims = listOf(
            DisplayClaim(key = "some.other.claim", label = "Other", value = "ignored", svgId = null),
        )
        val result = SvgTemplateRenderer.substitute(template, claims)
        assertEquals("<text></text>", result)
    }

    @Test
    fun `escapes XML special characters in substituted values`() {
        val template = "<text>{{name}}</text>"
        val claims = listOf(
            DisplayClaim(key = "name", label = "Name", value = "A & B <C> \"D\" 'E'", svgId = "name"),
        )
        val result = SvgTemplateRenderer.substitute(template, claims)
        assertEquals("<text>A &amp; B &lt;C&gt; &quot;D&quot; &apos;E&apos;</text>", result)
    }

    @Test
    fun `is a no-op on templates with no tokens`() {
        val template = "<svg><rect width=\"100\" height=\"100\"/></svg>"
        val result = SvgTemplateRenderer.substitute(template, emptyList())
        assertEquals(template, result)
    }

    @Test
    fun `escapeXml handles all five special characters`() {
        assertEquals("&amp;&lt;&gt;&quot;&apos;", SvgTemplateRenderer.escapeXml("&<>\"'"))
    }

    @Test
    fun `substitutes a data URI image claim unescaped`() {
        val template = """<image href="{{portrait}}"/>"""
        val dataUri = "data:image/jpeg;base64,/9j/4AAQ"
        val claims = listOf(
            DisplayClaim(key = "org.iso.23220.1.portrait", label = "Portrait", value = dataUri, svgId = "portrait"),
        )
        val result = SvgTemplateRenderer.substitute(template, claims)
        assertEquals("""<image href="$dataUri"/>""", result)
    }

    @Test
    fun `renders a dash for an svg-bound claim that could not be decoded as an image`() {
        // Mirrors CredentialUtils.formatCborValue's fallback for a byte
        // string that isn't a recognized JPEG/PNG (e.g. JPEG 2000, or a
        // filtered/undisclosed portrait) - showing the raw byte count where
        // an image was expected would be more confusing than an explicit
        // "not shown" marker.
        val template = """<image href="{{portrait}}"/>"""
        val claims = listOf(
            DisplayClaim(key = "org.iso.23220.1.portrait", label = "Portrait", value = "<38000 bytes>", svgId = "portrait"),
        )
        val result = SvgTemplateRenderer.substitute(template, claims)
        assertEquals("""<image href="-"/>""", result)
    }

    @Test
    fun `real dc4eu diploma template substitutes correctly`() {
        // Reproduces the actual live template fetched from
        // sirosid-leifj-vc-apigw's diploma VCTM during manual verification.
        val template = """
            <text>Title</text>
            <text>{{title}}</text>
            <text>Name</text>
            <text>{{givenName}} {{familyName}}</text>
            <text>Institution</text>
            <text>{{awardingInstitution}} {{country}}</text>
            <text>Awarding Date</text>
            <text>{{awardingDate}}</text>
        """.trimIndent()
        val claims = listOf(
            DisplayClaim(key = "a", label = "Title", value = "HBO Master Architectuur", svgId = "title"),
            DisplayClaim(key = "b", label = "Given Name", value = "Alice", svgId = "givenName"),
            DisplayClaim(key = "c", label = "Family Name", value = "Wonderland", svgId = "familyName"),
            DisplayClaim(key = "d", label = "Institution", value = "ArtEZ", svgId = "awardingInstitution"),
            DisplayClaim(key = "e", label = "Country", value = "Netherlands", svgId = "country"),
            DisplayClaim(key = "f", label = "Awarding Date", value = "2004-03-31", svgId = "awardingDate"),
        )
        val result = SvgTemplateRenderer.substitute(template, claims)
        assertTrue(result.contains("HBO Master Architectuur"))
        assertTrue(result.contains("Alice Wonderland"))
        assertTrue(result.contains("ArtEZ Netherlands"))
        assertTrue(result.contains("2004-03-31"))
        assertFalse("{{" in result)
    }
}
