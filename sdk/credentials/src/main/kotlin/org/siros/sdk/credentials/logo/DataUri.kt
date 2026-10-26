// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.logo

import java.util.Base64

/**
 * Strict RFC 2397 `data:` URI parsing, base64 form only: `data:<type/subtype>[;charset=...];base64,<payload>`.
 * Percent-encoded (non-base64) payloads, unknown parameters and a missing media type are refused.
 */
internal object DataUri {
    sealed interface ParseResult
    sealed interface DecodeResult
    class Parsed(val mediaType: String, val base64: String) : ParseResult
    class Decoded(val bytes: ByteArray) : DecodeResult
    class Failure(val reason: LogoRejection) : ParseResult, DecodeResult

    fun parse(uri: String): ParseResult {
        // `data:` was already checked by the caller.
        val comma = uri.indexOf(',')
        if (comma < 0) return Failure(LogoRejection.MalformedDataUri)
        val header = uri.substring("data:".length, comma)
        val parts = header.split(';')
        val mediaType = parts[0].lowercase()
        if (!MEDIA_TYPE.matches(mediaType)) return Failure(LogoRejection.MalformedDataUri)
        if (parts.size < 2 || parts.last().lowercase() != "base64") return Failure(LogoRejection.MalformedDataUri)
        val params = parts.subList(1, parts.size - 1)
        if (params.any { !it.lowercase().matches(CHARSET_PARAM) }) return Failure(LogoRejection.MalformedDataUri)
        return Parsed(mediaType, uri.substring(comma + 1))
    }

    /** Decodes with the JDK's strict decoder; refuses oversize before allocating. */
    fun decodeBase64(payload: String, maxBytes: Int): DecodeResult {
        if (payload.isEmpty()) return Failure(LogoRejection.MalformedBase64)
        // 4 chars encode 3 bytes; reject on length alone so a huge URI never gets decoded.
        if (payload.length / 4L * 3 > maxBytes + 3) return Failure(LogoRejection.TooLarge)
        val bytes = try {
            Base64.getDecoder().decode(payload)
        } catch (e: IllegalArgumentException) {
            return Failure(LogoRejection.MalformedBase64)
        }
        if (bytes.isEmpty()) return Failure(LogoRejection.MalformedBase64)
        if (bytes.size > maxBytes) return Failure(LogoRejection.TooLarge)
        return Decoded(bytes)
    }

    private val MEDIA_TYPE = Regex("[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*")
    private val CHARSET_PARAM = Regex("charset=(utf-8|us-ascii)")
}
