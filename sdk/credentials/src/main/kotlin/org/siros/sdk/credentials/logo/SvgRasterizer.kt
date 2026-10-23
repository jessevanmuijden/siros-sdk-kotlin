// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.logo

import android.graphics.Bitmap
import android.graphics.Canvas
import com.caverock.androidsvg.SVG
import java.io.ByteArrayOutputStream

/**
 * Renders an SVG that already passed [SvgActiveContentGuard] to PNG with
 * AndroidSVG. AndroidSVG has no script engine and no network access (no
 * external file resolver is registered), and the output is pixels, so no
 * vector content survives.
 */
internal object SvgRasterizer {
    fun rasterize(svgBytes: ByteArray): ByteArray? {
        val svg = try {
            SVG.getFromString(String(svgBytes, Charsets.UTF_8))
        } catch (e: Exception) {
            return null
        }
        var w = svg.documentWidth
        var h = svg.documentHeight
        if (w <= 0f || h <= 0f) {
            val box = svg.documentViewBox
            if (box == null || box.width() <= 0f || box.height() <= 0f) return null
            w = box.width()
            h = box.height()
        }
        val scale = LogoSanitizer.SVG_RENDER_EDGE_PIXELS / maxOf(w, h)
        val pw = (w * scale).toInt().coerceIn(1, LogoSanitizer.SVG_RENDER_EDGE_PIXELS)
        val ph = (h * scale).toInt().coerceIn(1, LogoSanitizer.SVG_RENDER_EDGE_PIXELS)
        svg.documentWidth = pw.toFloat()
        svg.documentHeight = ph.toFloat()
        val bitmap = Bitmap.createBitmap(pw, ph, Bitmap.Config.ARGB_8888)
        try {
            svg.renderToCanvas(Canvas(bitmap))
            val out = ByteArrayOutputStream()
            if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)) return null
            return out.toByteArray()
        } finally {
            bitmap.recycle()
        }
    }
}
