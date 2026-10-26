// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.logo

import android.util.Xml
import java.io.ByteArrayInputStream
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserException

/**
 * Refuses (never repairs) an SVG that contains anything but static shapes,
 * text and gradients. `<image>` is refused outright, embedded `data:` rasters
 * included: AndroidSVG would decode them before any size check could run. Uses the platform pull
 * parser, so malformed XML is itself a refusal. This is a gate in front of
 * the rasterizer, not a sanitizer: nothing is rewritten.
 */
internal object SvgActiveContentGuard {
    private val FORBIDDEN_ELEMENTS = setOf(
        "script", "foreignobject", "use", "iframe", "object", "embed", "a",
        "image", "audio", "video", "animate", "set", "animatetransform", "animatemotion",
        "animatecolor", "handler", "listener", "feimage", "cursor", "font-face-uri",
        // Reference-expansion constructs: a clipPath/mask/pattern/filter applied to
        // many elements made AndroidSVG run for over a minute (measured), so they
        // are refused rather than budgeted. Same for symbol/marker/textPath/tref.
        "clippath", "mask", "pattern", "filter", "marker", "symbol", "textpath", "tref",
        "fegaussianblur", "feoffset", "feblend", "fecolormatrix", "fecomposite", "feflood", "femerge",
        "feturbulence", "fedisplacementmap", "fediffuselighting", "fespecularlighting", "fetile",
        "femorphology", "feconvolvematrix", "fecomponenttransfer",
    )

    /** Attributes that apply a refused reference-expansion construct. */
    private val FORBIDDEN_ATTRIBUTES = setOf("clip-path", "mask", "filter")

    /** Bounds on document shape, so parse and render cost stays small. */
    const val MAX_ELEMENTS = 500
    const val MAX_DEPTH = 24
    const val MAX_GRADIENTS = 32
    const val MAX_STOPS = 64
    const val MAX_STYLE_CHARS = 32 * 1024

    /** A `url(...)` that points anywhere but a same-document `#fragment`. */
    private val EXTERNAL_URL = Regex("url\\(\\s*+(?!['\"]?\\s*+#)", RegexOption.IGNORE_CASE)
    private val CSS_IMPORT = Regex("@(import|font-face|namespace)", RegexOption.IGNORE_CASE)

    /** Returns null when the SVG may be rasterized, otherwise the reason it must not be. */
    fun check(bytes: ByteArray): LogoRejection? {
        val parser = Xml.newPullParser()
        try {
            parser.setFeature(XmlPullParser.FEATURE_PROCESS_DOCDECL, false)
            parser.setInput(ByteArrayInputStream(bytes), null)
            var sawSvgRoot = false
            var elements = 0
            var depth = 0
            var gradients = 0
            var stops = 0
            var style: StringBuilder? = null
            // One document-wide CSS budget: <style> text and style attribute values together.
            var cssChars = 0
            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                when (event) {
                    XmlPullParser.DOCDECL, XmlPullParser.ENTITY_REF -> return LogoRejection.ActiveContent
                    // Comments and CDATA inside <style> can split a token (`u/**/rl(`, `@im<![CDATA[port`).
                    XmlPullParser.COMMENT, XmlPullParser.CDSECT -> if (style != null) return LogoRejection.ActiveContent
                    XmlPullParser.START_TAG -> {
                        if (style != null) return LogoRejection.ActiveContent
                        val name = localName(parser.name)
                        if (++elements > MAX_ELEMENTS || ++depth > MAX_DEPTH) return LogoRejection.ActiveContent
                        if (sawSvgRoot && name == "svg") return LogoRejection.ActiveContent
                        if (name == "lineargradient" || name == "radialgradient") gradients++
                        if (name == "stop") stops++
                        if (gradients > MAX_GRADIENTS || stops > MAX_STOPS) return LogoRejection.ActiveContent
                        if (!sawSvgRoot) {
                            if (name != "svg") return LogoRejection.InvalidSvg
                            sawSvgRoot = true
                        }
                        if (name in FORBIDDEN_ELEMENTS) return LogoRejection.ActiveContent
                        if (name == "style") style = StringBuilder()
                        for (i in 0 until parser.attributeCount) {
                            if (localName(parser.getAttributeName(i)) == "style") cssChars += parser.getAttributeValue(i).length
                        }
                        if (cssChars > MAX_STYLE_CHARS || !attributesAreSafe(parser)) return LogoRejection.ActiveContent
                    }
                    XmlPullParser.END_TAG -> {
                        // The element's complete text is validated once, never token by token.
                        style?.let { if (cssIsUnsafe(it.toString())) return LogoRejection.ActiveContent }
                        style = null
                        depth--
                    }
                    XmlPullParser.TEXT -> style?.let {
                        val text = parser.text
                        it.append(text)
                        cssChars += text.length
                        if (cssChars > MAX_STYLE_CHARS) return LogoRejection.ActiveContent
                    }
                }
                event = parser.nextToken()
            }
            return if (sawSvgRoot) null else LogoRejection.InvalidSvg
        } catch (e: XmlPullParserException) {
            return LogoRejection.InvalidSvg
        } catch (e: java.io.IOException) {
            return LogoRejection.InvalidSvg
        }
    }

    private fun attributesAreSafe(parser: XmlPullParser): Boolean {
        for (i in 0 until parser.attributeCount) {
            val attr = localName(parser.getAttributeName(i))
            val value = parser.getAttributeValue(i)
            if (attr.startsWith("on") || attr in FORBIDDEN_ATTRIBUTES) return false
            if (value.contains("javascript:", ignoreCase = true)) return false
            if (cssIsUnsafe(value)) return false
            if (attr == "href" || attr == "src") {
                if (!value.trim().startsWith("#")) return false
            }
        }
        return true
    }

    /** CSS comments and backslash escapes can disguise `url(` / `@import`; neither is accepted. */
    private fun cssIsUnsafe(css: String): Boolean =
        css.contains("/*") || css.contains('\\') ||
            EXTERNAL_URL.containsMatchIn(css) || CSS_IMPORT.containsMatchIn(css)

    private fun localName(qualified: String): String = qualified.substringAfter(':').lowercase()
}
