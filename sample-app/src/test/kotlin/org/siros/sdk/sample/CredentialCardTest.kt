// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.ui.graphics.Color
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `coilLogoModel` works around Coil's default components not decoding a
 * `data:` URI *string* on their own (they only handle raw byte arrays, via
 * the built-in `ByteArrayMapper` -> `ByteBufferFetcher`) - issuer-published
 * logos are frequently embedded this way (e.g.
 * geneva2026.mdoc.online's `credential_metadata.display[].logo.uri`), which
 * silently failed to render before this fix.
 */
class CredentialCardTest {

    /**
     * The card used to decide its three text slots separately, so a
     * credential with no metadata read "dc+sd-jwt" as its name and
     * "DC+SD-JWT" again underneath it.
     */
    @Test
    fun `card labels never say the same thing twice`() {
        val everyShape = listOf(
            cardLabels("Company Certificate", "dc+sd-jwt", "urn:eudi:eucc:1"),
            cardLabels(null, "dc+sd-jwt", "uri:eu.ebw.oid.1"),
            cardLabels("dc+sd-jwt", "dc+sd-jwt", "uri:eu.ebw.oid.1"),
            cardLabels("uri:eu.ebw.oid.1", "dc+sd-jwt", "uri:eu.ebw.oid.1"),
            cardLabels(null, "dc+sd-jwt", null),
            cardLabels("  ", "mso_mdoc", null),
        )
        everyShape.forEach { labels ->
            val shown = listOfNotNull(labels.title, labels.typeBadge)
            assertEquals("$labels repeats itself", shown.size, shown.distinct().size)
        }
    }

    @Test
    fun `card labels prefer a real name, then the type, then the format`() {
        assertEquals(
            CardLabels("Company Certificate", "urn:eudi:eucc:1"),
            cardLabels("Company Certificate", "dc+sd-jwt", "urn:eudi:eucc:1"),
        )
        // No name: the type is the most identifying thing left, and the badge
        // beneath drops out rather than repeating it.
        assertEquals(
            CardLabels("uri:eu.ebw.oid.1", null),
            cardLabels(null, "dc+sd-jwt", "uri:eu.ebw.oid.1"),
        )
        // Nothing at all: the format, said once, because something must name
        // the card.
        assertEquals(CardLabels("dc+sd-jwt", null), cardLabels(null, "dc+sd-jwt", null))
    }

    @Test
    fun `issuer label falls back to the host of the issuer URL`() {
        assertEquals("SIROS ID (dev)", issuerLabel("SIROS ID (dev)", "https://issuer.example"))
        assertEquals("issuer.example", issuerLabel(null, "https://issuer.example/path"))
        assertEquals("issuer.example", issuerLabel("  ", "https://issuer.example"))
        assertEquals("not a url", issuerLabel(null, "not a url"))
        assertNull(issuerLabel(null, null))
        assertNull(issuerLabel(null, "  "))
    }

    private val realTypes = listOf(
        "uri:eu.ebw.oid.1", "urn:eudi:eucc:1", "uri:eu.eudi.eu-poa.1",
        "eu.we-build.iban-ov.1", "urn:eudi:pid:arf-1.8:1", "eu.europa.ec.eudi.pid.1",
    )

    /** The colour is part of what a credential looks like to its holder. */
    @Test
    fun `type tint is the same every time for the same type`() {
        realTypes.forEach { type ->
            assertEquals(typeTintColor(type, dark = false), typeTintColor(type, dark = false))
            assertEquals(typeTintColor(type, dark = true), typeTintColor(type, dark = true))
        }
    }

    /**
     * The point of the change: the four EU Business Wallet types declare no
     * colour of their own and used to draw as four copies of one card.
     *
     * This is not a claim that no two types ever collide - with a fixed
     * number of slots and no coordination between types, two can share one.
     * It is a claim about the types this wallet actually carries.
     */
    @Test
    fun `type tint separates the types that rely on it`() {
        val noColourOfTheirOwn = listOf(
            "uri:eu.ebw.oid.1", "urn:eudi:eucc:1", "uri:eu.eudi.eu-poa.1", "eu.we-build.iban-ov.1",
        )
        listOf(false, true).forEach { dark ->
            val tints = noColourOfTheirOwn.map { typeTintColor(it, dark) }
            assertEquals("dark=$dark", noColourOfTheirOwn.size, tints.distinct().size)
        }
    }

    /**
     * Two different tints must also LOOK different. An earlier version took
     * the hue straight from the hash and put two types 2 degrees apart, which
     * passes an equality check and fails a person.
     */
    @Test
    fun `two type tints are never a near miss`() {
        listOf(false, true).forEach { dark ->
            val tints = realTypes.mapNotNull { typeTintColor(it, dark) }
            for (i in tints.indices) {
                for (j in i + 1 until tints.size) {
                    if (tints[i] == tints[j]) continue
                    val distance = kotlin.math.abs(tints[i].red - tints[j].red) +
                        kotlin.math.abs(tints[i].green - tints[j].green) +
                        kotlin.math.abs(tints[i].blue - tints[j].blue)
                    assertTrue(
                        "tints differ but only by $distance (dark=$dark)",
                        distance >= 0.06f,
                    )
                }
            }
        }
    }

    @Test
    fun `type tint has no colour to offer without an identifier`() {
        assertNull(typeTintColor(null, dark = false))
        assertNull(typeTintColor("", dark = false))
        assertNull(typeTintColor("   ", dark = false))
    }

    /**
     * Every generated tint sits in one lightness band per theme, so the
     * existing contrast logic resolves against it exactly as it does against
     * an issuer-declared colour. No hash can produce an unreadable card.
     */
    @Test
    fun `every type tint carries readable text`() {
        listOf(false, true).forEach { dark ->
            // Every slot, not just the types we happen to carry today: the
            // next credential type is someone else's identifier.
            (0 until 400).forEach { i ->
                val type = "urn:probe:$i"
                val bg = typeTintColor(type, dark)!!
                val fg = contrastingTextColor(bg)
                assertTrue(
                    "$type (dark=$dark) must carry readable text",
                    contrastRatio(fg, bg) >= MIN_READABLE_CONTRAST_RATIO,
                )
            }
        }
    }

    /**
     * The floor holds for any colour at all, including one an issuer
     * declares: black and white are equally readable at luminance 0.179, and
     * that worst case is still 4.6:1.
     */
    @Test
    fun `text is readable on any background`() {
        val steps = 12
        for (r in 0..steps) for (g in 0..steps) for (b in 0..steps) {
            val bg = Color(r.toFloat() / steps, g.toFloat() / steps, b.toFloat() / steps)
            assertTrue(
                "unreadable on $bg",
                contrastRatio(contrastingTextColor(bg), bg) >= MIN_READABLE_CONTRAST_RATIO,
            )
        }
    }

    @Test
    fun `the two themes tint differently`() {
        realTypes.forEach { type ->
            assertTrue(typeTintColor(type, dark = false) != typeTintColor(type, dark = true))
        }
    }

    @Test
    fun `hsl conversion hits the primaries`() {
        assertEquals(Color(1f, 0f, 0f), hslColor(0f, 1f, 0.5f))
        assertEquals(Color(0f, 1f, 0f), hslColor(120f, 1f, 0.5f))
        assertEquals(Color(0f, 0f, 1f), hslColor(240f, 1f, 0.5f))
        assertEquals(Color(0f, 0f, 0f), hslColor(0f, 1f, 0f))
        assertEquals(Color(1f, 1f, 1f), hslColor(0f, 1f, 1f))
        // Hue wraps rather than clamping.
        assertEquals(hslColor(10f, 0.5f, 0.5f), hslColor(370f, 0.5f, 0.5f))
    }

    /**
     * The badge names the type. Cutting at the last dot - what this used to
     * do - is right for a hostname and wrong for every reverse-DNS or URN
     * identifier actually in use.
     */
    @Test
    fun `type badge keeps a non-URL identifier whole`() {
        assertEquals("uri:eu.ebw.oid.1", credentialTypeBadge("uri:eu.ebw.oid.1"))
        assertEquals("eu.we-build.iban-ov.1", credentialTypeBadge("eu.we-build.iban-ov.1"))
        assertEquals("urn:eudi:pid:arf-1.8:1", credentialTypeBadge("urn:eudi:pid:arf-1.8:1"))
        assertEquals("urn:eudi:eucc:1", credentialTypeBadge("urn:eudi:eucc:1"))
        assertEquals("eu.europa.ec.eudi.pid.1", credentialTypeBadge("eu.europa.ec.eudi.pid.1"))
    }

    @Test
    fun `type badge shortens a URL identifier to the part that names the type`() {
        assertEquals("student-id", credentialTypeBadge("https://example.com/credentials/student-id"))
        assertEquals("mdl", credentialTypeBadge("https://registry.siros.org/sunet/mdl.vctm.json"))
    }

    @Test
    fun `type badge never returns an empty or misleading label`() {
        // A bare origin has no path naming a type; shortening it would leave
        // "example", which names nothing.
        assertEquals("https://example.com/", credentialTypeBadge("https://example.com/"))
        assertEquals("https://example.com", credentialTypeBadge("https://example.com"))
        assertEquals(".json", credentialTypeBadge("https://example.com/.json"))
        assertEquals("", credentialTypeBadge(""))
    }

    @Test
    fun `decodes a base64 data URI into raw bytes`() {
        val payload = "hello logo bytes".toByteArray(Charsets.UTF_8)
        val encoded = java.util.Base64.getEncoder().encodeToString(payload)
        val uri = "data:image/png;base64,$encoded"

        val model = coilLogoModel(uri)

        assertArrayEquals(payload, model as ByteArray)
    }

    @Test
    fun `leaves an http url unchanged`() {
        val uri = "https://issuer.example.com/logo.png"
        assertEquals(uri, coilLogoModel(uri))
    }

    @Test
    fun `leaves a non-base64 data URI unchanged`() {
        // e.g. a URL-encoded (not base64) data URI - not what we're built to unwrap.
        val uri = "data:image/svg+xml,%3Csvg%2F%3E"
        assertEquals(uri, coilLogoModel(uri))
    }

    @Test
    fun `falls back to the original string when the payload is not valid base64`() {
        val uri = "data:image/png;base64,not-valid-base64!!!"
        assertEquals(uri, coilLogoModel(uri))
    }

    // ── contrastRatio / MIN_READABLE_CONTRAST_RATIO ────────────────────
    //
    // A real credential card's issuer-declared text/background color pair
    // rendered nearly unreadable (confirmed via live testing) - the fix
    // (see CredentialCard.kt) only honors a declared textColor if it clears
    // this ratio, falling back to a computed high-contrast color otherwise.

    @Test
    fun `contrastRatio is maximal for black on white`() {
        assertEquals(21f, contrastRatio(Color.Black, Color.White), 0.01f)
    }

    @Test
    fun `contrastRatio is minimal for identical colors`() {
        assertEquals(1f, contrastRatio(Color(0xFF1B4587), Color(0xFF1B4587)), 0.01f)
    }

    @Test
    fun `contrastRatio is symmetric regardless of argument order`() {
        val a = Color(0xFF1B4587)
        val b = Color(0xFFF3F4F6)
        assertEquals(contrastRatio(a, b), contrastRatio(b, a), 0.001f)
    }

    @Test
    fun `a poor issuer-declared pairing falls below the minimum readable ratio`() {
        // Two similarly-dark, similarly-saturated blues - exactly the kind
        // of "technically different but practically illegible" pairing an
        // issuer's own branding can produce.
        val background = Color(0xFF1B4587)
        val declaredText = Color(0xFF3D66A7)
        assertTrue(
            "a near-identical-luminance pairing must be rejected as unreadable",
            contrastRatio(declaredText, background) < MIN_READABLE_CONTRAST_RATIO,
        )
    }

    @Test
    fun `a strong pairing clears the minimum readable ratio`() {
        val background = Color(0xFF1B4587)
        assertTrue(contrastRatio(Color.White, background) >= MIN_READABLE_CONTRAST_RATIO)
    }

    // ── correctSvgTextContrast ──────────────────────────────────────────
    //
    // Confirmed necessary via live testing: a real issuer's SVG credential
    // template (wwwallet.org's demo PID) baked in unreadable text-color
    // contrast against its own background, and SvgTemplateRenderer.substitute
    // only replaces {{claimId}} text tokens - it never touches SVG styling.

    @Test
    fun `overrides a text fill that fails the contrast check`() {
        val background = Color(0xFF1B4587) // dark navy
        val svg = """<svg><text fill="#3D66A7" x="0" y="0">Alice</text></svg>"""

        val corrected = correctSvgTextContrast(svg, background)

        assertTrue("a low-contrast fill must not survive unchanged", "fill=\"#3D66A7\"" !in corrected)
        assertTrue("Alice" in corrected)
    }

    @Test
    fun `leaves an already-adequate-contrast fill untouched`() {
        val background = Color(0xFF1B4587) // dark navy
        val svg = """<svg><text fill="#FFFFFF" x="0" y="0">Alice</text></svg>"""

        val corrected = correctSvgTextContrast(svg, background)

        assertEquals("a fill that already contrasts well must not be rewritten", svg, corrected)
    }

    @Test
    fun `corrects fill on both text and tspan elements`() {
        val background = Color(0xFF1B4587)
        val svg = """<svg><text fill="#3D66A7"><tspan fill="#3D66A7">Alice</tspan></text></svg>"""

        val corrected = correctSvgTextContrast(svg, background)

        assertEquals(0, Regex("""fill="#3D66A7"""").findAll(corrected).count())
    }

    @Test
    fun `leaves an element with no fill attribute unchanged`() {
        val background = Color(0xFF1B4587)
        val svg = """<svg><text x="0" y="0">Alice</text></svg>"""

        assertEquals(svg, correctSvgTextContrast(svg, background))
    }

    @Test
    fun `leaves a non-hex fill (inherited or named color) unchanged`() {
        val background = Color(0xFF1B4587)
        val svg = """<svg><text fill="currentColor" x="0" y="0">Alice</text></svg>"""

        // Not resolvable without a full DOM/style walk - documented
        // limitation, not a bug: must be left exactly as the issuer wrote it.
        assertEquals(svg, correctSvgTextContrast(svg, background))
    }

    @Test
    fun `does not touch fill on non-text elements like rect or path`() {
        val background = Color(0xFF1B4587)
        val svg = """<svg><rect fill="#3D66A7" width="10" height="10"/><text fill="#FFFFFF">Alice</text></svg>"""

        // A shape's fill is decorative, not text-legibility-critical -
        // only <text>/<tspan> elements are in scope for correction.
        assertTrue("fill=\"#3D66A7\"" in correctSvgTextContrast(svg, background))
    }

    // ── ensureSvgViewBox ─────────────────────────────────────────────────
    //
    // Confirmed necessary via live testing: a real issuer's SVG credential
    // template (wwwallet.org's demo PID) has its root <svg width="829"
    // height="504" version="1.1"> declare NO viewBox at all - without one,
    // percentage dimensions on children only resolve consistently if every
    // renderer picks the same reference size, which isn't guaranteed. The
    // symptom was the whole graphic rendering visibly shifted/distorted.

    @Test
    fun `injects a viewBox and preserveAspectRatio=none derived from width and height when both are plain numbers`() {
        val svg = """<svg xmlns="http://www.w3.org/2000/svg" width="829"
	height="504" version="1.1">
	<image width="100%" xlink:href="data:image/png;base64,AAA=" />
</svg>"""

        val result = ensureSvgViewBox(svg)

        assertTrue("viewBox=\"0 0 829 504\"" in result)
        // Confirmed necessary via rendering the same template through a
        // browser <object> embed at a deliberately mismatched aspect ratio:
        // a viewBox with no preserveAspectRatio activates the SVG default
        // (xMidYMid meet), which letterboxes - the gap is baked into the
        // decoded bitmap and survives Compose's own FillBounds stretch
        // untouched, showing as the Card's flat background color filling
        // part of the card.
        assertTrue("preserveAspectRatio=\"none\"" in result)
    }

    @Test
    fun `leaves an svg that already has a viewBox unchanged`() {
        val svg = """<svg width="829" height="504" viewBox="0 0 829 504"><image width="100%" /></svg>"""

        assertEquals(svg, ensureSvgViewBox(svg))
    }

    @Test
    fun `does not override an already-declared preserveAspectRatio`() {
        val svg = """<svg width="829" height="504" preserveAspectRatio="xMidYMid slice"><image width="100%" /></svg>"""

        val result = ensureSvgViewBox(svg)

        assertTrue("viewBox=\"0 0 829 504\"" in result)
        assertTrue("preserveAspectRatio=\"xMidYMid slice\"" in result)
        assertTrue("preserveAspectRatio=\"none\"" !in result)
    }

    @Test
    fun `leaves an svg with a percentage width or height unchanged`() {
        val svg = """<svg width="100%" height="504"><image width="100%" /></svg>"""

        assertEquals(svg, ensureSvgViewBox(svg))
    }

    @Test
    fun `leaves an svg missing width or height unchanged`() {
        val svg = """<svg height="504"><image width="100%" /></svg>"""

        assertEquals(svg, ensureSvgViewBox(svg))
    }

    // ── ensureSvgImageHeight ────────────────────────────────────────────
    //
    // Confirmed necessary via live testing: a real issuer's SVG credential
    // template (wwwallet.org's demo PID) has its full-bleed background
    // <image> declare width="100%" with NO height attribute at all - per
    // SVG 1.1 (which this template declares via version="1.1"), that
    // defaults height to 0 (invisible) unless the renderer implements the
    // newer SVG2/CSS auto-sizing fallback, which this app's Android SVG
    // decoder apparently doesn't. The graphic never appeared; only this
    // card's own flat backgroundColor showed through.

    @Test
    fun `injects height on a self-closing percentage-width image with no height`() {
        // Mirrors the real template's actual self-closing background image tag.
        val svg = """<svg><image x="0" y="0" width="100%" xlink:href="data:image/png;base64,AAA=" /></svg>"""

        val result = ensureSvgImageHeight(svg)

        assertTrue("height=\"100%\"" in result)
        assertTrue("width=\"100%\"" in result)
        // Must still be a valid self-closing tag, not a mangled one with a stray "/".
        assertTrue(result.contains("""height="100%" />"""))
    }

    @Test
    fun `injects height on a non-self-closing percentage-width image with no height`() {
        val svg = """<svg><image width="100%" xlink:href="data:image/png;base64,AAA="></image></svg>"""

        val result = ensureSvgImageHeight(svg)

        assertTrue("height=\"100%\"" in result)
        assertTrue(result.contains("""height="100%">"""))
    }

    @Test
    fun `leaves an image with an already-declared height unchanged`() {
        val svg = """<svg><image width="100%" height="50%" xlink:href="data:image/png;base64,AAA=" /></svg>"""

        assertEquals(svg, ensureSvgImageHeight(svg))
    }

    @Test
    fun `leaves an absolute-unit-width image with no height unchanged`() {
        // Mirrors the same real template's separate placeholder-photo image
        // (width="220", an absolute unit) - correctly sizing this would need
        // the embedded image's own intrinsic pixel dimensions, not attempted.
        val svg = """<svg><image x="45" y="100" width="220" href="{{picture}}" preserveAspectRatio="xMidYMid meet" /></svg>"""

        assertEquals(svg, ensureSvgImageHeight(svg))
    }

    @Test
    fun `leaves an image with no width attribute at all unchanged`() {
        val svg = """<svg><image xlink:href="data:image/png;base64,AAA=" /></svg>"""

        assertEquals(svg, ensureSvgImageHeight(svg))
    }

    @Test
    fun `corrects only the background image, leaving the placeholder photo image untouched`() {
        // The real template has exactly this shape: one full-bleed
        // percentage-width background image needing correction, and one
        // absolute-width placeholder photo image that must be left alone.
        val svg = """<svg>
            |<image x="0" y="0" width="100%" xlink:href="data:image/png;base64,AAA=" />
            |<image x="45" y="100" width="220" href="{{picture}}" preserveAspectRatio="xMidYMid meet" />
            |</svg>
        """.trimMargin()

        val result = ensureSvgImageHeight(svg)

        // height is always appended at the very end of the tag (after
        // whatever attributes, like the long xlink:href, originally
        // followed width), not spliced in right next to width.
        assertTrue("""width="100%" xlink:href="data:image/png;base64,AAA=" height="100%" />""" in result)
        assertTrue("""width="220" href="{{picture}}"""" in result)
        assertEquals("only the background image's tag should have gained a height", 1, Regex("""height="100%"""").findAll(result).count())
    }

    // ── extractFullBleedBackgroundImage ────────────────────────────────
    //
    // Confirmed necessary via live testing: a real PID credential's SVG
    // template's exact final bytes render perfectly outside the app
    // (inkscape) and its embedded PNG is pixel-uniform with no dark region,
    // yet coil-svg/AndroidSVG still rendered a ~30%-down dark band on
    // device - while a sibling template with no embedded <image> at all
    // (a diploma credential, same pipeline otherwise) rendered correctly.
    // That isolates AndroidSVG's handling of a large embedded base64
    // <image> as the bug, so it's pulled out and decoded via Coil's normal
    // bitmap path instead.

    private val TINY_PNG_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="

    @Test
    fun `extracts a full-bleed background image and strips it from the svg`() {
        val svg = """<svg viewBox="0 0 829 504">
            |<image x="0" y="0" width="100%" height="100%" xlink:href="data:image/png;base64,$TINY_PNG_BASE64" />
            |<text fill="#000000">Hello</text>
            |</svg>
        """.trimMargin()

        val (stripped, bytes) = extractFullBleedBackgroundImage(svg)

        assertTrue("background bytes should be decoded", bytes != null && bytes.isNotEmpty())
        assertTrue("stripped svg must not contain the extracted <image>", "<image" !in stripped)
        assertTrue("stripped svg must keep unrelated content", "<text" in stripped)
    }

    @Test
    fun `leaves a smaller absolute-positioned placeholder image in place`() {
        val svg = """<svg><image x="45" y="100" width="220" height="150" href="{{picture}}" /></svg>"""

        val (stripped, bytes) = extractFullBleedBackgroundImage(svg)

        assertEquals(svg, stripped)
        assertEquals(null, bytes)
    }

    @Test
    fun `leaves an svg with no image element unchanged`() {
        val svg = """<svg><rect width="100%" height="100%" fill="#fff" /></svg>"""

        val (stripped, bytes) = extractFullBleedBackgroundImage(svg)

        assertEquals(svg, stripped)
        assertEquals(null, bytes)
    }

    // ── decodeSvgDataUri ──────────────────────────────────────────────
    //
    // Confirmed necessary via live testing: re-issuing a credential caused
    // svgTemplates[].uri to arrive as a data:image/svg+xml;base64,... URI
    // instead of an https:// one (same underlying template, different
    // delivery) - fetchAndSubstituteSvg's OkHttp fetch throws
    // IllegalArgumentException for a non-http(s) scheme, so this must be
    // decoded directly instead of fetched.

    @Test
    fun `decodes a base64 data URI SVG template`() {
        val svg = """<svg xmlns="http://www.w3.org/2000/svg"><text>Alice</text></svg>"""
        val encoded = java.util.Base64.getEncoder().encodeToString(svg.toByteArray(Charsets.UTF_8))
        val uri = "data:image/svg+xml;base64,$encoded"

        assertEquals(svg, decodeSvgDataUri(uri))
    }

    @Test
    fun `decodes a URL-encoded (non-base64) data URI SVG template`() {
        val uri = "data:image/svg+xml,%3Csvg%3E%3Ctext%3EAlice%3C%2Ftext%3E%3C%2Fsvg%3E"

        assertEquals("<svg><text>Alice</text></svg>", decodeSvgDataUri(uri))
    }

    @Test
    fun `returns null for invalid base64 payload in a data URI`() {
        val uri = "data:image/svg+xml;base64,not-valid-base64!!!"

        assertEquals(null, decodeSvgDataUri(uri))
    }

    @Test
    fun `returns null for a data URI with no comma separator`() {
        assertEquals(null, decodeSvgDataUri("data:image/svg+xml;base64"))
    }

    // ── fetchAndNormalizeLogoModel ──────────────────────────────────────
    //
    // The Add Credentials offer list and the stored-credential detail
    // screen both previously used the plain (synchronous) coilLogoModel,
    // which never runs a fetched remote SVG through ensureSvgImageHeight -
    // exactly the gap that made a real issuer's EHIC card (demo-issuer.
    // wwwallet.org, missing <image> height) render fully blank there while
    // an already-stored credential's own card (which does go through
    // ensureSvgImageHeight via fetchAndSubstituteSvg) rendered fine.

    @Test
    fun `normalizes a missing-height image in a data URI SVG logo`() = kotlinx.coroutines.runBlocking {
        // x="10" (not "0"), unlike extractFullBleedBackgroundImage's own full-
        // bleed fixture below - keeps this test isolated to ensureSvgImageHeight
        // and out of the full-bleed-background extraction path.
        val svg = """<svg><image x="10" y="0" width="100%" xlink:href="data:image/png;base64,AAA=" /></svg>"""
        val encoded = java.util.Base64.getEncoder().encodeToString(svg.toByteArray(Charsets.UTF_8))
        val uri = "data:image/svg+xml;base64,$encoded"

        val result = fetchAndNormalizeLogoModel(uri)

        assertTrue(result.model is ByteArray)
        val resultSvg = String(result.model as ByteArray, Charsets.UTF_8)
        assertTrue("""height="100%"""" in resultSvg)
    }

    @Test
    fun `leaves a non-SVG data URI logo exactly as coilLogoModel would`() = kotlinx.coroutines.runBlocking {
        val uri = "data:image/png;base64,AAA="

        // Both sides decode to a ByteArray - assertArrayEquals compares
        // contents, unlike assertEquals which would compare references.
        assertArrayEquals(coilLogoModel(uri) as ByteArray, fetchAndNormalizeLogoModel(uri).model as ByteArray)
    }

    @Test
    fun `fetches and normalizes a missing-height image in a remote SVG logo`() = kotlinx.coroutines.runBlocking {
        // x="10" (not "0") - see the data-URI variant's test above for why.
        val svg = """<svg><image x="10" y="0" width="100%" xlink:href="data:image/png;base64,AAA=" /></svg>"""
        val server = okhttp3.mockwebserver.MockWebServer()
        server.enqueue(
            okhttp3.mockwebserver.MockResponse()
                .setBody(svg)
                .addHeader("Content-Type", "image/svg+xml"),
        )
        server.start()
        try {
            val result = fetchAndNormalizeLogoModel(server.url("/ehic.svg").toString())

            assertTrue(result.model is ByteArray)
            val resultSvg = String(result.model as ByteArray, Charsets.UTF_8)
            assertTrue("""height="100%"""" in resultSvg)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `leaves a remote non-SVG logo URL untouched`() = kotlinx.coroutines.runBlocking {
        val server = okhttp3.mockwebserver.MockWebServer()
        server.enqueue(
            okhttp3.mockwebserver.MockResponse()
                .setBody("not an svg")
                .addHeader("Content-Type", "image/png"),
        )
        server.start()
        try {
            val uri = server.url("/logo.png").toString()

            assertEquals(uri, fetchAndNormalizeLogoModel(uri).model)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `falls back to the URI when the remote fetch fails`() = kotlinx.coroutines.runBlocking {
        val server = okhttp3.mockwebserver.MockWebServer()
        server.enqueue(okhttp3.mockwebserver.MockResponse().setResponseCode(500))
        server.start()
        try {
            val uri = server.url("/broken.svg").toString()

            assertEquals(uri, fetchAndNormalizeLogoModel(uri).model)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `extracts a full-bleed embedded raster background from a logo SVG`() = kotlinx.coroutines.runBlocking {
        // Same shape as extractFullBleedBackgroundImage's own test fixture -
        // confirms the Add Credentials/detail-screen logo path now gets the
        // same background extraction the full-size card pipeline already
        // had, fixing the ~30%-down dark-band mis-render for offers whose
        // logo happens to be a full-card template with an embedded raster.
        val pngBytes = byteArrayOf(1, 2, 3, 4)
        val encodedPng = java.util.Base64.getEncoder().encodeToString(pngBytes)
        val svg = """<svg width="829" height="504"><image x="0" y="0" width="100%" height="100%" """ +
            """xlink:href="data:image/png;base64,$encodedPng" /><text>Name</text></svg>"""
        val encoded = java.util.Base64.getEncoder().encodeToString(svg.toByteArray(Charsets.UTF_8))
        val uri = "data:image/svg+xml;base64,$encoded"

        val result = fetchAndNormalizeLogoModel(uri)

        assertArrayEquals(pngBytes, result.backgroundImageBytes)
        val resultSvg = String(result.model as ByteArray, Charsets.UTF_8)
        assertTrue("<image" !in resultSvg)
        assertTrue("<text>Name</text>" in resultSvg)
    }
}
