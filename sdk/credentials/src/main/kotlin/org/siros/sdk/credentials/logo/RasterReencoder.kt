// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.logo

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import androidx.exifinterface.media.ExifInterface
import java.io.ByteArrayInputStream
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
        val decoded = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)
            ?: return LogoResult.Rejected(LogoRejection.UndecodableImage)
        // BitmapFactory ignores EXIF orientation and the re-encode drops it: bake it in first.
        val bitmap = applyOrientation(decoded, exifOrientation(bytes))
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

    private fun exifOrientation(bytes: ByteArray): Int = try {
        ExifInterface(ByteArrayInputStream(bytes))
            .getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)
    } catch (e: Exception) {
        ExifInterface.ORIENTATION_NORMAL
    }

    /** Output is at most as large as the (already capped) source; 90/270 just swap its edges. */
    private fun applyOrientation(src: Bitmap, orientation: Int): Bitmap {
        val m = Matrix()
        when (orientation) {
            ExifInterface.ORIENTATION_FLIP_HORIZONTAL -> m.postScale(-1f, 1f)
            ExifInterface.ORIENTATION_ROTATE_180 -> m.postRotate(180f)
            ExifInterface.ORIENTATION_FLIP_VERTICAL -> m.postScale(1f, -1f)
            ExifInterface.ORIENTATION_TRANSPOSE -> { m.postRotate(90f); m.postScale(-1f, 1f) }
            ExifInterface.ORIENTATION_ROTATE_90 -> m.postRotate(90f)
            ExifInterface.ORIENTATION_TRANSVERSE -> { m.postRotate(270f); m.postScale(-1f, 1f) }
            ExifInterface.ORIENTATION_ROTATE_270 -> m.postRotate(270f)
            else -> return src
        }
        val out = Bitmap.createBitmap(src, 0, 0, src.width, src.height, m, true)
        if (out !== src) src.recycle()
        return out
    }
}
