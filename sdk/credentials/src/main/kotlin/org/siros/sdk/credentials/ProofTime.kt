// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeParseException

/** Why a `proof_time` was refused; the codes are those of the matcher's `proof_time` vectors. */
enum class ProofTimeError(val code: String) {
    OUT_OF_RANGE("proof_time_out_of_range"),
    FORM("proof_time_form"),
    NOT_AN_INSTANT("proof_time_not_an_instant"),
    IN_FUTURE("proof_time_in_future"),
    TOO_OLD("proof_time_too_old"),
}

/** Raised by [ProofTime.render] and [ProofTime.parse]. */
class ProofTimeException(val error: ProofTimeError) : IllegalArgumentException(error.code)

/**
 * The `proof_time` of a `ZkpPresentation` (rulebook v0.4): the prover-supplied circuit input, in the EXACT 20-byte form
 * `YYYY-MM-DDThh:mm:ssZ` (second precision, no fraction, upper-case `T` and `Z`, no offset, a real UTC instant),
 * byte-identical between prover and verifier. This is the one place the form is produced and read; the device clock is
 * the time source only when the request carries no better one (it carries none today).
 */
object ProofTime {
    /** 1970-01-01T00:00:00Z .. 9999-12-31T23:59:59Z. */
    private const val MAX_SECS = 253402300799L

    /** The recommended tolerance of a verifier: seconds into the future, and seconds of age. */
    const val RECOMMENDED_SKEW_SECS = 60L
    const val RECOMMENDED_MAX_AGE_SECS = 600L

    private val FORM = Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

    /** [epochSecs] as the 20-byte form. @throws ProofTimeException [ProofTimeError.OUT_OF_RANGE] outside year 0000..9999. */
    fun render(epochSecs: Long): String {
        if (epochSecs < 0 || epochSecs > MAX_SECS) throw ProofTimeException(ProofTimeError.OUT_OF_RANGE)
        return LocalDateTime.ofEpochSecond(epochSecs, 0, ZoneOffset.UTC).let {
            "%04d-%02d-%02dT%02d:%02d:%02dZ".format(java.util.Locale.ROOT, it.year, it.monthValue, it.dayOfMonth, it.hour, it.minute, it.second)
        }
    }

    /** [instant] truncated to the second, as the 20-byte form. */
    fun render(instant: Instant): String = render(instant.epochSecond)

    /** Epoch seconds of a 20-byte [text]. @throws ProofTimeException [ProofTimeError.FORM] or [ProofTimeError.NOT_AN_INSTANT]. */
    fun parse(text: String): Long {
        if (!FORM.matches(text)) throw ProofTimeException(ProofTimeError.FORM)
        return try {
            LocalDateTime.parse(text.dropLast(1)).toEpochSecond(ZoneOffset.UTC)
        } catch (e: DateTimeParseException) {
            throw ProofTimeException(ProofTimeError.NOT_AN_INSTANT)
        }
    }

    /** Whether [text] is a valid 20-byte `proof_time`. */
    fun isValid(text: String): Boolean = try { parse(text); true } catch (e: ProofTimeException) { false }

    /**
     * The verifier's tolerance check: `now - maxAge <= proof_time <= now + skew`, both inclusive; the form is checked first.
     * A verifier-side helper (the wallet is the prover); kept to run the shared vectors.
     */
    fun checkTolerance(proofTime: String, nowSecs: Long, skewSecs: Long, maxAgeSecs: Long): ProofTimeError? {
        val t = try { parse(proofTime) } catch (e: ProofTimeException) { return e.error }
        if (t > nowSecs + skewSecs) return ProofTimeError.IN_FUTURE
        if (t < nowSecs - maxAgeSecs) return ProofTimeError.TOO_OLD
        return null
    }
}
