// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.logo

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import timber.log.Timber

/**
 * Why a logo URI was refused. Every refusal is final: the caller shows its
 * placeholder (the issuer initial) and never falls back to the raw URI.
 */
enum class LogoRejection {
    /** Blank, or not a URI this API handles (`http:`, `file:`, `javascript:`, relative, ...). */
    UnsupportedScheme,

    /** `https:` URL without a host, or with embedded credentials. */
    InvalidUrl,

    /** `data:` URI that is not `data:<type>;base64,<payload>` (RFC 2397, base64 only). */
    MalformedDataUri,

    /** Media type is not in [LogoSanitizer.ALLOWED_MEDIA_TYPES]. */
    UnsupportedMediaType,

    /** The base64 payload is not valid base64. */
    MalformedBase64,

    /** Decoded payload exceeds [LogoSanitizer.MAX_DECODED_BYTES]. */
    TooLarge,

    /** The platform decoder could not decode the image (truncated, corrupt, not an image). */
    UndecodableImage,

    /** The bytes decode as a different format than the declared media type. */
    MediaTypeMismatch,

    /** Image is wider or taller than [LogoSanitizer.MAX_EDGE_PIXELS]. */
    DimensionsTooLarge,

    /** SVG contains script, foreignObject, event handlers, external references, DOCTYPE or similar. */
    ActiveContent,

    /** SVG is not well-formed or the SVG renderer refused it. */
    InvalidSvg,
}

/** What a caller may render. Nothing else ever comes out of [LogoSanitizer]. */
sealed interface DisplayLogo {
    /** A well-formed `https:` URL; the app's own image loader fetches it. */
    data class Remote(val url: String) : DisplayLogo

    /**
     * A clean PNG produced by this SDK: decoded by the platform decoder and
     * re-encoded, so no metadata, trailing bytes, script or vector content
     * from the original survives.
     */
    class Image(val png: ByteArray, val width: Int, val height: Int) : DisplayLogo
}

sealed interface LogoResult {
    data class Accepted(val logo: DisplayLogo) : LogoResult
    data class Rejected(val reason: LogoRejection) : LogoResult
}

/**
 * Turns an untrusted display-logo URI (credential metadata `display[].logo.uri`,
 * issuer logo) into something safe to render, or a typed refusal. Fails closed.
 *
 * - `https:` is accepted as a [DisplayLogo.Remote] (URL parsed by OkHttp). `http:`
 *   and every other scheme are rejected.
 * - `data:` is parsed strictly (RFC 2397, `;base64` only), the media type must be
 *   in [ALLOWED_MEDIA_TYPES], and the decoded payload is capped at
 *   [MAX_DECODED_BYTES].
 * - Raster (png, jpeg, webp, gif) is decoded with `BitmapFactory`, checked
 *   against [MAX_EDGE_PIXELS] and the declared type, and re-encoded as PNG.
 * - SVG is the vector for embedded script, so it is never passed on as XML. A
 *   pull-parser pass refuses documents containing script, foreignObject, `use`,
 *   animation, event-handler attributes, external references, DOCTYPE or
 *   entities; what remains is rasterized by AndroidSVG (which has no script
 *   engine) to a PNG that then goes through the same raster path.
 */
object LogoSanitizer {
    /** Decoded payload cap: 256 KiB. */
    const val MAX_DECODED_BYTES = 256 * 1024

    /** Longest accepted edge of a decoded raster, in pixels. */
    const val MAX_EDGE_PIXELS = 2048

    /** Longest edge an SVG is rasterized to, in pixels. */
    const val SVG_RENDER_EDGE_PIXELS = 512

    val ALLOWED_MEDIA_TYPES: Set<String> = setOf(
        "image/png",
        "image/jpeg",
        "image/webp",
        "image/gif",
        "image/svg+xml",
    )

    fun sanitize(uri: String?): LogoResult = try {
        sanitizeUnchecked(uri)
    } catch (e: Exception) {
        // Any surprise from a platform decoder is a refusal, never a pass-through.
        Timber.w(e, "Logo sanitizer failed closed")
        LogoResult.Rejected(LogoRejection.UndecodableImage)
    } catch (e: OutOfMemoryError) {
        LogoResult.Rejected(LogoRejection.DimensionsTooLarge)
    }

    private fun sanitizeUnchecked(uri: String?): LogoResult {
        val trimmed = uri?.trim().orEmpty()
        return when {
            trimmed.startsWith("data:", ignoreCase = true) -> sanitizeData(trimmed)
            trimmed.startsWith("https://", ignoreCase = true) -> sanitizeHttps(trimmed)
            else -> reject(LogoRejection.UnsupportedScheme)
        }
    }

    private fun sanitizeHttps(uri: String): LogoResult {
        val url = uri.toHttpUrlOrNull() ?: return reject(LogoRejection.InvalidUrl)
        if (!url.isHttps || url.host.isEmpty() || url.username.isNotEmpty() || url.password.isNotEmpty()) {
            return reject(LogoRejection.InvalidUrl)
        }
        return LogoResult.Accepted(DisplayLogo.Remote(url.toString()))
    }

    private fun sanitizeData(uri: String): LogoResult {
        val parsed = when (val p = DataUri.parse(uri)) {
            is DataUri.Parsed -> p
            is DataUri.Failure -> return reject(p.reason)
        }
        if (parsed.mediaType !in ALLOWED_MEDIA_TYPES) return reject(LogoRejection.UnsupportedMediaType)
        val bytes = when (val d = DataUri.decodeBase64(parsed.base64, MAX_DECODED_BYTES)) {
            is DataUri.Decoded -> d.bytes
            is DataUri.Failure -> return reject(d.reason)
        }
        return if (parsed.mediaType == "image/svg+xml") {
            sanitizeSvg(bytes)
        } else {
            RasterReencoder.reencode(bytes, parsed.mediaType)
        }
    }

    private fun sanitizeSvg(bytes: ByteArray): LogoResult {
        SvgActiveContentGuard.check(bytes)?.let { return reject(it) }
        val png = SvgRasterizer.rasterize(bytes) ?: return reject(LogoRejection.InvalidSvg)
        // The rasterized PNG is re-validated and re-encoded like any other raster.
        return RasterReencoder.reencode(png, "image/png")
    }

    private fun reject(reason: LogoRejection): LogoResult {
        Timber.d("Logo rejected: %s", reason)
        return LogoResult.Rejected(reason)
    }
}
