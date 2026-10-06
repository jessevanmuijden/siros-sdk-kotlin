// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.interop

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull
import timber.log.Timber
import java.time.Instant
import java.time.format.DateTimeParseException

/**
 * Why a credential cannot currently be used, or [VALID] when it can.
 *
 * These are the outcomes of DIIP's Validity and Revocation Algorithm: the
 * `validFrom` / `validUntil` window, and the issuer's Token Status List.
 *
 * This is deliberately one enum rather than a set of booleans. A wallet shows
 * one reason a credential is unusable, and an `isExpired` flag alongside an
 * `isRevoked` flag invites UI that shows the wrong one, or both.
 */
enum class CredentialStatus {
    /** Inside its validity window and not revoked or suspended. */
    VALID,

    /** `validFrom` / `nbf` lies in the future. */
    NOT_YET_VALID,

    /** `validUntil` / `exp` has passed. */
    EXPIRED,

    /** The issuer's Token Status List marks this credential invalid. */
    REVOKED,

    /**
     * This wallet cannot say. Either the credential's own validity data would
     * not parse, or the issuer's Status List published a value this wallet
     * does not recognise.
     *
     * Deliberately not [VALID]: an unreachable status list leaves a
     * credential usable - that is what keeps a wallet working offline - but
     * data that is present and not understood is a different thing, and
     * calling it valid would be a claim this wallet cannot support.
     */
    UNKNOWN,

    /** The issuer's Token Status List marks this credential suspended - temporary, unlike [REVOKED]. */
    SUSPENDED,
    ;

    /** Whether the credential can be presented. */
    val isUsable: Boolean get() = this == VALID
}

/**
 * The window a credential is valid in.
 *
 * `validFrom` / `validUntil` are the W3C VCDM 2.0 properties; `nbf` / `exp`
 * are their JWT-native equivalents. An absent bound means "no bound" - the
 * VCDM reads a missing `validUntil` as valid indefinitely, not as expired.
 */
data class ValidityWindow(
    val validFrom: Instant? = null,
    val validUntil: Instant? = null,
    /** When the credential was signed (`iat`), for display only. */
    val signed: Instant? = null,
)

/** Reads and checks credential validity windows. */
object CredentialValidity {

    /**
     * Derive the validity window from a credential's claims.
     *
     * The VCDM 2.0 dateTime properties win over the numeric JWT claims when
     * both are present: a VCDM credential's own `validFrom` / `validUntil`
     * are authoritative, and `exp` on such a credential is the enveloping
     * JWT's lifetime, which may be shorter.
     */
    fun extract(claims: JsonObject): ValidityWindow = ValidityWindow(
        validFrom = parseDateTime(claims["validFrom"]) ?: parseEpochSeconds(claims["nbf"]),
        validUntil = parseDateTime(claims["validUntil"]) ?: parseEpochSeconds(claims["exp"]),
        signed = parseEpochSeconds(claims["iat"]),
    )

    /**
     * Check a window against the current time.
     *
     * @param clockToleranceSeconds leeway, matching the tolerance used for
     *        signature verification - a credential is not shown as expired
     *        because of a few seconds of clock skew.
     * @return [CredentialStatus.EXPIRED] or [CredentialStatus.NOT_YET_VALID],
     *         or [CredentialStatus.VALID] when inside the window.
     */
    fun check(
        window: ValidityWindow,
        clockToleranceSeconds: Long = 0,
        nowMillis: Long = System.currentTimeMillis(),
    ): CredentialStatus {
        val toleranceMillis = clockToleranceSeconds * 1000
        window.validUntil?.let {
            if (it.toEpochMilli() + toleranceMillis < nowMillis) return CredentialStatus.EXPIRED
        }
        window.validFrom?.let {
            if (it.toEpochMilli() - toleranceMillis > nowMillis) return CredentialStatus.NOT_YET_VALID
        }
        return CredentialStatus.VALID
    }

    private fun parseDateTime(element: kotlinx.serialization.json.JsonElement?): Instant? {
        val text = (element as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() } ?: return null
        return try {
            Instant.parse(text)
        } catch (e: DateTimeParseException) {
            // An XMLSchema dateTime with an offset rather than 'Z'.
            runCatching { java.time.OffsetDateTime.parse(text).toInstant() }.getOrElse {
                Timber.d(e, "Ignoring unparseable validity timestamp")
                null
            }
        }
    }

    private fun parseEpochSeconds(element: kotlinx.serialization.json.JsonElement?): Instant? =
        (element as? JsonPrimitive)?.longOrNull?.let(Instant::ofEpochSecond)
}

/**
 * Runs DIIP's Validity and Revocation Algorithm over a credential.
 *
 * Construct one per wallet session and share it: it holds the Token Status
 * List cache, so a list covering many credentials is fetched once.
 *
 * @param statusListClient looks up revocation. Null disables the revocation
 *        half - the validity window is still checked, which is what an
 *        offline-only wallet can do.
 * @param clockToleranceSeconds leeway applied to both halves.
 */
class CredentialStatusEvaluator(
    private val statusListClient: TokenStatusListClient? = null,
    private val clockToleranceSeconds: Long = 0,
    private val nowMillis: () -> Long = { System.currentTimeMillis() },
) {
    /**
     * Evaluate a credential from its claims.
     *
     * The validity window is checked first and short-circuits: an expired
     * credential is expired whether or not its status list is reachable, and
     * saying so needs no network.
     *
     * A status list that cannot be reached is a warning, not a revocation -
     * refusing to show a credential because the issuer's status endpoint is
     * down would make the wallet unusable offline. That is a deliberate
     * choice, and it matches wallet-frontend.
     */
    /**
     * @param credentialIssuer the issuer this credential was stored under, used
     *   when the claims themselves name none. An mdoc's normalised claims
     *   carry no `iss`, and without this the Status List Token's issuer
     *   binding would be skipped for every mdoc - letting a token served from
     *   the credential's own status URI claim to be from any issuer at all.
     */
    suspend fun evaluate(claims: JsonObject, credentialIssuer: String? = null): CredentialStatus {
        val windowStatus = CredentialValidity.check(
            CredentialValidity.extract(claims),
            clockToleranceSeconds,
            nowMillis(),
        )
        if (windowStatus != CredentialStatus.VALID) return windowStatus

        val client = statusListClient ?: return CredentialStatus.VALID
        val reference = TokenStatusList.extractReference(claims) ?: return CredentialStatus.VALID

        // The credential's own `iss` wins - it is signed - and the stored
        // issuer identifier stands in only when there is none.
        val expectedIssuer = issuerOf(claims) ?: credentialIssuer
        return when (val resolution = client.resolve(reference, expectedIssuer, clockToleranceSeconds)) {
            is TokenStatusList.Resolution.Unavailable -> {
                Timber.w("Could not determine revocation status: ${resolution.reason}")
                CredentialStatus.VALID
            }
            is TokenStatusList.Resolution.Found -> when (resolution.status) {
                TokenStatusList.Status.VALID -> CredentialStatus.VALID
                TokenStatusList.Status.INVALID -> CredentialStatus.REVOKED
                TokenStatusList.Status.SUSPENDED -> CredentialStatus.SUSPENDED
                // The issuer published something this wallet does not know.
                // Reading that as "valid" would be fail-open: the draft
                // reserves further values, and an application-specific one
                // means whatever the issuer's ecosystem says, not "fine".
                else -> {
                    Timber.w("Status list published an unrecognised status ${resolution.status}")
                    CredentialStatus.UNKNOWN
                }
            }
        }
    }

    /**
     * The issuer identifier of a credential.
     *
     * SD-JWT VC and JWT VC JSON use the JOSE `iss` claim. A W3C VCDM 2.0
     * credential secured with SD-JWT (VC-JOSE-COSE §3.2.1) instead carries
     * the VCDM `issuer` property, which is either an identifier string or an
     * object with an `id`.
     */
    private fun issuerOf(claims: JsonObject): String? {
        (claims["iss"] as? JsonPrimitive)?.contentOrNull?.let { return it }
        // Anything else - an array, say - is not an issuer identifier in any
        // shape this reads. `jsonPrimitive` would throw on it, and since the
        // caller evaluates every held credential in one pass, one malformed
        // credential would suppress the status of all of them.
        return when (val issuer = claims["issuer"]) {
            is JsonObject -> (issuer["id"] as? JsonPrimitive)?.contentOrNull
            is JsonPrimitive -> issuer.contentOrNull
            else -> null
        }
    }
}
