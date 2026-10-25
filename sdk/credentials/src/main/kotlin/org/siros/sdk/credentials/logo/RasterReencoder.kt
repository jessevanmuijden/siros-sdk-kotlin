// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.logo

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import java.io.ByteArrayOutputStream

/**
 * Decodes a raster image with the platform decoder and re-encodes the pixels
 * as PNG, so metadata chunks, EXIF, trailing bytes and anything polyglot in
 * the original never reach the caller.
 */
internal object RasterReencoder {
    /** [declaredMediaType] null means unknown: accept whichever allowed raster type the decoder finds. */
    fun reencode(bytes: ByteArray, declaredMediaType: String?): LogoResult {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
            return LogoResult.Rejected(LogoRejection.UndecodableImage)
        }
        val sniffed = bounds.outMimeType?.lowercase()
        if (sniffed == null || sniffed !in LogoSanitizer.ALLOWED_MEDIA_TYPES ||
            (declaredMediaType != null && sniffed != declaredMediaType)
        ) {
            return LogoResult.Rejected(LogoRejection.MediaTypeMismatch)
        }
        if (bounds.outWidth > LogoSanitizer.MAX_EDGE_PIXELS || bounds.outHeight > LogoSanitizer.MAX_EDGE_PIXELS) {
            return LogoResult.Rejected(LogoRejection.DimensionsTooLarge)
        }
        val opts = BitmapFactory.Options().apply { inPreferredConfig = Bitmap.Config.ARGB_8888 }
        val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)
            ?: return LogoResult.Rejected(LogoRejection.UndecodableImage)
        try {
            val out = ByteArrayOutputStream()
            if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)) {
                return LogoResult.Rejected(LogoRejection.UndecodableImage)
            }
            return LogoResult.Accepted(DisplayLogo.Image(out.toByteArray(), bitmap.width, bitmap.height))
        } finally {
            bitmap.recycle()
        }
    }
}
