package org.siros.sdk.credentials.interop

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class CredentialStatusTest {

    private val now = Instant.parse("2026-06-01T12:00:00Z").toEpochMilli()

    private fun claims(json: String) = Json.parseToJsonElement(json) as JsonObject

    // ── the validity window ─────────────────────────────────────────

    @Test
    fun `VCDM properties are preferred over the JWT claims`() {
        // A VCDM credential's own validFrom/validUntil are authoritative; the
        // enveloping JWT's exp may be shorter and is not the credential's.
        val window = CredentialValidity.extract(
            claims(
                """{"validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z",
                    "nbf":1,"exp":2}""",
            ),
        )
        assertEquals(Instant.parse("2026-01-01T00:00:00Z"), window.validFrom)
        assertEquals(Instant.parse("2027-01-01T00:00:00Z"), window.validUntil)
    }

    @Test
    fun `nbf and exp stand in when the VCDM properties are absent`() {
        val window = CredentialValidity.extract("""{"nbf":1700000000,"exp":1800000000,"iat":1700000000}""".let(::claims))
        assertEquals(Instant.ofEpochSecond(1700000000), window.validFrom)
        assertEquals(Instant.ofEpochSecond(1800000000), window.validUntil)
        assertEquals(Instant.ofEpochSecond(1700000000), window.signed)
    }

    @Test
    fun `a timestamp with an offset rather than Z still parses`() {
        val window = CredentialValidity.extract(claims("""{"validUntil":"2027-01-01T00:00:00+02:00"}"""))
        assertEquals(Instant.parse("2026-12-31T22:00:00Z"), window.validUntil)
    }

    @Test
    fun `an unparseable timestamp is ignored rather than failing the credential`() {
        val window = CredentialValidity.extract(claims("""{"validUntil":"whenever"}"""))
        assertNull(window.validUntil)
    }

    @Test
    fun `no bounds means valid indefinitely`() {
        assertEquals(
            CredentialStatus.VALID,
            CredentialValidity.check(CredentialValidity.extract(claims("{}")), nowMillis = now),
        )
    }

    @Test
    fun `a credential past validUntil is expired`() {
        val window = CredentialValidity.extract(claims("""{"validUntil":"2026-05-01T00:00:00Z"}"""))
        assertEquals(CredentialStatus.EXPIRED, CredentialValidity.check(window, nowMillis = now))
    }

    @Test
    fun `a credential before validFrom is not yet valid`() {
        val window = CredentialValidity.extract(claims("""{"validFrom":"2026-07-01T00:00:00Z"}"""))
        assertEquals(CredentialStatus.NOT_YET_VALID, CredentialValidity.check(window, nowMillis = now))
    }

    @Test
    fun `clock tolerance covers skew at both edges of the window`() {
        val justExpired = CredentialValidity.extract(claims("""{"validUntil":"2026-06-01T11:59:30Z"}"""))
        assertEquals(CredentialStatus.EXPIRED, CredentialValidity.check(justExpired, 0, now))
        assertEquals(CredentialStatus.VALID, CredentialValidity.check(justExpired, 60, now))

        val justStarted = CredentialValidity.extract(claims("""{"validFrom":"2026-06-01T12:00:30Z"}"""))
        assertEquals(CredentialStatus.NOT_YET_VALID, CredentialValidity.check(justStarted, 0, now))
        assertEquals(CredentialStatus.VALID, CredentialValidity.check(justStarted, 60, now))
    }

    @Test
    fun `expiry is reported ahead of not-yet-valid when a window is inverted`() {
        // A malformed window should still name one reason, deterministically.
        val window = ValidityWindow(
            validFrom = Instant.parse("2027-01-01T00:00:00Z"),
            validUntil = Instant.parse("2026-01-01T00:00:00Z"),
        )
        assertEquals(CredentialStatus.EXPIRED, CredentialValidity.check(window, nowMillis = now))
    }

    // ── the whole algorithm ─────────────────────────────────────────

    @Test
    fun `the validity window short-circuits the status list`() = runBlocking {
        // An expired credential is expired whether or not the issuer's status
        // endpoint answers, and saying so needs no network.
        val evaluator = CredentialStatusEvaluator(
            statusListClient = TokenStatusListClient(
                httpGet = { _, _ -> throw AssertionError("the status list must not be fetched") },
            ),
            nowMillis = { now },
        )
        val status = evaluator.evaluate(
            claims("""{"validUntil":"2026-01-01T00:00:00Z","status":{"status_list":{"idx":1,"uri":"https://x.example"}}}"""),
        )
        assertEquals(CredentialStatus.EXPIRED, status)
    }

    @Test
    fun `a credential with no status reference is valid`() = runBlocking {
        val evaluator = CredentialStatusEvaluator(nowMillis = { now })
        assertEquals(CredentialStatus.VALID, evaluator.evaluate(claims("""{"iss":"https://issuer.example"}""")))
    }

    @Test
    fun `an unreachable status list leaves the credential usable`() = runBlocking {
        // Hiding a credential because the issuer's status endpoint is down
        // would make the wallet unusable offline. This is deliberate.
        val evaluator = CredentialStatusEvaluator(
            statusListClient = TokenStatusListClient(httpGet = { _, _ -> null }),
            nowMillis = { now },
        )
        val status = evaluator.evaluate(
            claims("""{"iss":"https://issuer.example","status":{"status_list":{"idx":1,"uri":"https://x.example"}}}"""),
        )
        assertEquals(CredentialStatus.VALID, status)
    }

    @Test
    fun `a status list that is not a typed Status List Token is not trusted`() = runBlocking {
        val evaluator = CredentialStatusEvaluator(
            statusListClient = TokenStatusListClient(httpGet = { _, _ -> "not-a-jws" }),
            nowMillis = { now },
        )
        assertEquals(
            CredentialStatus.VALID,
            evaluator.evaluate(
                claims("""{"iss":"https://issuer.example","status":{"status_list":{"idx":1,"uri":"https://x.example"}}}"""),
            ),
        )
    }

    @Test
    fun `only VALID is usable`() {
        assertTrue(CredentialStatus.VALID.isUsable)
        assertFalse(CredentialStatus.EXPIRED.isUsable)
        assertFalse(CredentialStatus.NOT_YET_VALID.isUsable)
        assertFalse(CredentialStatus.REVOKED.isUsable)
        assertFalse(CredentialStatus.SUSPENDED.isUsable)
    }
    // ── fail-open guards ────────────────────────────────────────────

    @Test
    fun `a status value the wallet does not recognise is not valid`() = runBlocking {
        // The draft reserves further values, and an application-specific one
        // means whatever the issuer's ecosystem says - not "fine". Reading an
        // unrecognised value as VALID would be fail-open on data the issuer
        // deliberately published.
        val key = com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate()
        // One 8-bit entry holding 0x07, an unregistered status.
        val list = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(deflate(byteArrayOf(0x07)))
        val token = com.nimbusds.jwt.SignedJWT(
            com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                .type(com.nimbusds.jose.JOSEObjectType("statuslist+jwt")).build(),
            com.nimbusds.jwt.JWTClaimsSet.Builder()
                .issuer("https://issuer.example")
                .claim("status_list", mapOf("bits" to 8, "lst" to list))
                .build(),
        ).also { it.sign(com.nimbusds.jose.crypto.ECDSASigner(key)) }.serialize()

        val evaluator = CredentialStatusEvaluator(
            statusListClient = TokenStatusListClient(
                httpGet = { _, _ -> token },
                resolveIssuerKey = { _, _ -> key.toPublicJWK() },
            ),
            nowMillis = { now },
        )
        val status = evaluator.evaluate(
            claims("""{"iss":"https://issuer.example","status":{"status_list":{"idx":0,"uri":"https://x.example"}}}"""),
        )
        assertEquals(CredentialStatus.UNKNOWN, status)
    }

    @Test
    fun `a credential that names no issuer falls back to the one it was stored under`() = runBlocking {
        // An mdoc's normalised claims carry no `iss`. Without the stored
        // identifier the Status List Token's issuer binding is skipped, and a
        // token served from the credential's own status URI could claim to be
        // from any issuer at all.
        val key = com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate()
        val token = statusToken(key, issuer = "https://issuer.example", entry = 0x01)
        val client = TokenStatusListClient(
            httpGet = { _, _ -> token },
            resolveIssuerKey = { _, _ -> key.toPublicJWK() },
        )
        val evaluator = CredentialStatusEvaluator(statusListClient = client, nowMillis = { now })
        val mdocClaims =
            claims("""{"status":{"status_list":{"idx":0,"uri":"https://x.example"}}}""")

        // With the stored issuer supplied, the token's `iss` matches and the
        // revocation it publishes is applied.
        assertEquals(
            CredentialStatus.REVOKED,
            evaluator.evaluate(mdocClaims, credentialIssuer = "https://issuer.example"),
        )

        // And a token from somebody else is refused for the same credential -
        // the binding this fallback exists to restore.
        assertEquals(
            CredentialStatus.VALID,
            evaluator.evaluate(mdocClaims, credentialIssuer = "https://other.example"),
        )
    }

    @Test
    fun `a signed iss wins over the stored issuer identifier`() = runBlocking {
        val key = com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate()
        val token = statusToken(key, issuer = "https://signed.example", entry = 0x01)
        val evaluator = CredentialStatusEvaluator(
            statusListClient = TokenStatusListClient(
                httpGet = { _, _ -> token },
                resolveIssuerKey = { _, _ -> key.toPublicJWK() },
            ),
            nowMillis = { now },
        )
        val signedClaims = claims(
            """{"iss":"https://signed.example","status":{"status_list":{"idx":0,"uri":"https://x.example"}}}""",
        )
        assertEquals(
            CredentialStatus.REVOKED,
            evaluator.evaluate(signedClaims, credentialIssuer = "https://stored.example"),
        )
    }

    /** A signed Status List Token whose single 8-bit entry holds [entry]. */
    private fun statusToken(key: com.nimbusds.jose.jwk.ECKey, issuer: String, entry: Byte): String {
        val list = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(deflate(byteArrayOf(entry)))
        return com.nimbusds.jwt.SignedJWT(
            com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                .type(com.nimbusds.jose.JOSEObjectType("statuslist+jwt")).build(),
            com.nimbusds.jwt.JWTClaimsSet.Builder()
                .issuer(issuer)
                .claim("status_list", mapOf("bits" to 8, "lst" to list))
                .build(),
        ).also { it.sign(com.nimbusds.jose.crypto.ECDSASigner(key)) }.serialize()
    }

    private fun deflate(data: ByteArray): ByteArray {
        val deflater = java.util.zip.Deflater()
        deflater.setInput(data)
        deflater.finish()
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(256)
        while (!deflater.finished()) out.write(buffer, 0, deflater.deflate(buffer))
        deflater.end()
        return out.toByteArray()
    }
}
