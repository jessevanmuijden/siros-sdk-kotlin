// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.logo

import android.util.Xml
import java.io.ByteArrayInputStream
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserException

/**
 * Refuses (never repairs) an SVG that contains anything but static shapes,
 * text, gradients and embedded raster `data:` images. Uses the platform pull
 * parser, so malformed XML is itself a refusal. This is a gate in front of
 * the rasterizer, not a sanitizer: nothing is rewritten.
 */
internal object SvgActiveContentGuard {
    private val FORBIDDEN_ELEMENTS = setOf(
        "script", "foreignobject", "use", "iframe", "object", "embed", "a",
        "audio", "video", "animate", "set", "animatetransform", "animatemotion",
        "animatecolor", "handler", "listener", "feimage", "cursor", "font-face-uri",
    )

    /** A `url(...)` that points anywhere but a same-document `#fragment`. */
    private val EXTERNAL_URL = Regex("url\\(\\s*['\"]?\\s*(?!#)", RegexOption.IGNORE_CASE)
    private val CSS_IMPORT = Regex("@import", RegexOption.IGNORE_CASE)
    private val EMBEDDED_RASTER = Regex("^data:image/(png|jpeg|webp|gif);base64,", RegexOption.IGNORE_CASE)

    /** Returns null when the SVG may be rasterized, otherwise the reason it must not be. */
    fun check(bytes: ByteArray): LogoRejection? {
        val parser = Xml.newPullParser()
        try {
            parser.setFeature(XmlPullParser.FEATURE_PROCESS_DOCDECL, false)
            parser.setInput(ByteArrayInputStream(bytes), null)
            var inStyle = false
            var sawSvgRoot = false
            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                when (event) {
                    XmlPullParser.DOCDECL, XmlPullParser.ENTITY_REF -> return LogoRejection.ActiveContent
                    XmlPullParser.START_TAG -> {
                        val name = localName(parser.name)
                        if (!sawSvgRoot) {
                            if (name != "svg") return LogoRejection.InvalidSvg
                            sawSvgRoot = true
                        }
                        if (name in FORBIDDEN_ELEMENTS) return LogoRejection.ActiveContent
                        inStyle = name == "style"
                        if (!attributesAreSafe(parser, name)) return LogoRejection.ActiveContent
                    }
                    XmlPullParser.END_TAG -> inStyle = false
                    XmlPullParser.TEXT, XmlPullParser.CDSECT -> if (inStyle && cssIsUnsafe(parser.text)) {
                        return LogoRejection.ActiveContent
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

    private fun attributesAreSafe(parser: XmlPullParser, element: String): Boolean {
        for (i in 0 until parser.attributeCount) {
            val attr = localName(parser.getAttributeName(i))
            val value = parser.getAttributeValue(i)
            if (attr.startsWith("on")) return false
            if (value.contains("javascript:", ignoreCase = true)) return false
            if (cssIsUnsafe(value)) return false
            if (attr == "href" || attr == "src") {
                val ok = if (element == "image") EMBEDDED_RASTER.containsMatchIn(value.trim()) else value.trim().startsWith("#")
                if (!ok) return false
            }
        }
        return true
    }

    private fun cssIsUnsafe(css: String): Boolean = EXTERNAL_URL.containsMatchIn(css) || CSS_IMPORT.containsMatchIn(css)

    private fun localName(qualified: String): String = qualified.substringAfter(':').lowercase()
}
