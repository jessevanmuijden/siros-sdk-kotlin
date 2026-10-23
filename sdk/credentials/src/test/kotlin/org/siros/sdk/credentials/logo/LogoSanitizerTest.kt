// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.logo

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import java.io.ByteArrayOutputStream
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class LogoSanitizerTest {

    private fun encode(format: Bitmap.CompressFormat, w: Int = 16, h: Int = 16): ByteArray {
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        bmp.eraseColor(Color.RED)
        return ByteArrayOutputStream().also { bmp.compress(format, 90, it) }.toByteArray()
    }

    private fun dataUri(type: String, bytes: ByteArray) =
        "data:$type;base64," + Base64.getEncoder().encodeToString(bytes)

    private fun rejected(uri: String?): LogoRejection =
        (LogoSanitizer.sanitize(uri) as LogoResult.Rejected).reason

    private fun image(uri: String): DisplayLogo.Image =
        ((LogoSanitizer.sanitize(uri) as LogoResult.Accepted).logo as DisplayLogo.Image)

    private fun pngOf(img: DisplayLogo.Image) = BitmapFactory.decodeByteArray(img.png, 0, img.png.size)

    @Test
    fun `valid png data uri yields a decodable png`() {
        val img = image(dataUri("image/png", encode(Bitmap.CompressFormat.PNG)))
        assertEquals(16, img.width)
        assertEquals(Color.RED, pngOf(img).getPixel(3, 3))
    }

    @Test
    fun `valid jpeg data uri is re-encoded as png`() {
        val img = image(dataUri("image/jpeg", encode(Bitmap.CompressFormat.JPEG)))
        assertEquals("image/png", BitmapFactory.Options().also {
            it.inJustDecodeBounds = true
            BitmapFactory.decodeByteArray(img.png, 0, img.png.size, it)
        }.outMimeType)
    }

    @Test
    fun `valid webp data uri renders`() {
        @Suppress("DEPRECATION")
        image(dataUri("image/webp", encode(Bitmap.CompressFormat.WEBP)))
    }

    @Test
    fun `https is accepted and http is rejected`() {
        val ok = LogoSanitizer.sanitize("https://example.org/logo.png") as LogoResult.Accepted
        assertEquals(DisplayLogo.Remote("https://example.org/logo.png"), ok.logo)
        assertEquals(LogoRejection.UnsupportedScheme, rejected("http://example.org/logo.png"))
        assertEquals(LogoRejection.UnsupportedScheme, rejected("file:///etc/passwd"))
        assertEquals(LogoRejection.UnsupportedScheme, rejected("javascript:alert(1)"))
        assertEquals(LogoRejection.UnsupportedScheme, rejected(null))
        assertEquals(LogoRejection.InvalidUrl, rejected("https://user:pw@example.org/l.png"))
        assertEquals(LogoRejection.InvalidUrl, rejected("https://"))
    }

    @Test
    fun `oversized payload is rejected`() {
        val big = ByteArray(LogoSanitizer.MAX_DECODED_BYTES + 1)
        assertEquals(LogoRejection.TooLarge, rejected(dataUri("image/png", big)))
    }

    @Test
    fun `malformed base64 is rejected`() {
        assertEquals(LogoRejection.MalformedBase64, rejected("data:image/png;base64,@@@not base64@@@"))
        assertEquals(LogoRejection.MalformedBase64, rejected("data:image/png;base64,"))
    }

    @Test
    fun `non base64 and malformed data uris are rejected`() {
        assertEquals(LogoRejection.MalformedDataUri, rejected("data:image/png,%89PNG"))
        assertEquals(LogoRejection.MalformedDataUri, rejected("data:image/png;base64"))
        assertEquals(LogoRejection.MalformedDataUri, rejected("data:;base64,AAAA"))
        assertEquals(LogoRejection.MalformedDataUri, rejected("data:image/png;foo=bar;base64,AAAA"))
    }

    @Test
    fun `media type outside the allowlist is rejected`() {
        val png = encode(Bitmap.CompressFormat.PNG)
        assertEquals(LogoRejection.UnsupportedMediaType, rejected(dataUri("text/html", png)))
        assertEquals(LogoRejection.UnsupportedMediaType, rejected(dataUri("application/javascript", png)))
        assertEquals(LogoRejection.UnsupportedMediaType, rejected(dataUri("image/bmp", png)))
    }

    @Test
    fun `declared type that disagrees with the bytes is rejected`() {
        assertEquals(
            LogoRejection.MediaTypeMismatch,
            rejected(dataUri("image/jpeg", encode(Bitmap.CompressFormat.PNG))),
        )
    }

    @Test
    fun `truncated image is rejected`() {
        val png = encode(Bitmap.CompressFormat.PNG, 64, 64)
        assertEquals(LogoRejection.UndecodableImage, rejected(dataUri("image/png", png.copyOf(20))))
        assertEquals(LogoRejection.UndecodableImage, rejected(dataUri("image/png", "not an image".toByteArray())))
    }

    @Test
    fun `image over the dimension cap is rejected`() {
        val wide = encode(Bitmap.CompressFormat.PNG, LogoSanitizer.MAX_EDGE_PIXELS + 1, 1)
        assertEquals(LogoRejection.DimensionsTooLarge, rejected(dataUri("image/png", wide)))
    }

    @Test
    fun `polyglot payload after the image is dropped by re-encoding`() {
        val marker = "<script>alert('pwned')</script>EVILMARKER"
        val polyglot = encode(Bitmap.CompressFormat.PNG) + marker.toByteArray()
        // Sanity: the input really carries the payload.
        assertTrue(String(polyglot, Charsets.ISO_8859_1).contains("EVILMARKER"))
        val img = image(dataUri("image/png", polyglot))
        assertFalse(String(img.png, Charsets.ISO_8859_1).contains("EVILMARKER"))
        assertFalse(String(img.png, Charsets.ISO_8859_1).contains("script"))
        assertFalse(img.png.size == polyglot.size)
    }

    @Test
    fun `png text chunk metadata is dropped`() {
        val png = encode(Bitmap.CompressFormat.PNG)
        // Insert a tEXt chunk (bad CRC is fine for the decoder to skip or we only need the marker present in input).
        val text = "Comment\u0000META-PAYLOAD".toByteArray()
        val chunk = java.nio.ByteBuffer.allocate(12 + text.size).putInt(text.size)
            .put("tEXt".toByteArray()).put(text)
            .putInt(java.util.zip.CRC32().also { it.update("tEXt".toByteArray()); it.update(text) }.value.toInt()).array()
        val withMeta = png.copyOfRange(0, 33) + chunk + png.copyOfRange(33, png.size)
        val img = image(dataUri("image/png", withMeta))
        assertFalse(String(img.png, Charsets.ISO_8859_1).contains("META-PAYLOAD"))
    }

    private fun svg(body: String, attrs: String = "") =
        """<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="64" height="64" viewBox="0 0 64 64" $attrs>$body</svg>"""

    private fun svgUri(s: String) = dataUri("image/svg+xml", s.toByteArray())

    @Test
    fun `clean svg is rasterized to png`() {
        val img = image(svgUri(svg("""<rect width="64" height="64" fill="#f00"/>""")))
        assertTrue(img.width > 0 && img.height > 0)
        assertEquals("image/png", BitmapFactory.Options().also {
            it.inJustDecodeBounds = true
            BitmapFactory.decodeByteArray(img.png, 0, img.png.size, it)
        }.outMimeType)
    }

    @Test
    fun `svg with script is rejected and nothing of it is returned`() {
        assertEquals(
            LogoRejection.ActiveContent,
            rejected(svgUri(svg("""<script>alert(1)</script><rect width="64" height="64"/>"""))),
        )
    }

    @Test
    fun `svg active content variants are all rejected`() {
        val bad = listOf(
            svg("""<foreignObject><body xmlns="http://www.w3.org/1999/xhtml"/></foreignObject>"""),
            svg("""<rect width="1" height="1" onload="alert(1)"/>"""),
            svg("""<rect width="1" height="1" onclick="alert(1)"/>""", ""),
            svg("""<use xlink:href="https://evil.example/x.svg#a"/>"""),
            svg("""<use href="#a"/>"""),
            svg("""<image href="https://evil.example/track.png" width="8" height="8"/>"""),
            svg("""<image xlink:href="http://evil.example/track.png" width="8" height="8"/>"""),
            svg("""<a href="javascript:alert(1)"><rect width="1" height="1"/></a>"""),
            svg("""<rect width="1" height="1"><animate attributeName="href" to="javascript:alert(1)"/></rect>"""),
            svg("""<style>@import url(https://evil.example/x.css);</style>"""),
            svg("""<rect width="1" height="1" style="fill:url(https://evil.example/p)"/>"""),
            "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>" + svg("<text>&x;</text>"),
        )
        for (s in bad) {
            assertEquals(s, LogoRejection.ActiveContent, rejected(svgUri(s)))
        }
    }

    @Test
    fun `malformed svg is rejected`() {
        assertEquals(LogoRejection.InvalidSvg, rejected(svgUri("<svg><rect></svg>")))
        assertEquals(LogoRejection.InvalidSvg, rejected(svgUri("<html><body/></html>")))
    }

    @Test
    fun `svg with embedded raster data image and local gradient reference is allowed`() {
        val png = Base64.getEncoder().encodeToString(encode(Bitmap.CompressFormat.PNG))
        val s = svg(
            """<defs><linearGradient id="g"><stop offset="0" stop-color="#f00"/></linearGradient></defs>""" +
                """<rect width="64" height="64" fill="url(#g)"/>""" +
                """<image width="8" height="8" xlink:href="data:image/png;base64,$png"/>""",
        )
        image(svgUri(s))
    }

    @Test
    fun `output never aliases the input`() {
        val input = encode(Bitmap.CompressFormat.PNG)
        val img = image(dataUri("image/png", input))
        assertFalse(java.util.Arrays.equals(input, img.png) && img.png === input)
        assertArrayEquals(input, input)
    }
}
