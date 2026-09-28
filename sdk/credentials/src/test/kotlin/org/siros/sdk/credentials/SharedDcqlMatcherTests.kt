// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The SDK's half of the shared DCQL engine.
 *
 * The engine itself is a native library called from [SharedDcqlMatcher.evaluate],
 * which is not exercised here (no native binary is loaded in a plain JVM unit
 * test). What is tested is the translation layer feeding it -
 * [SharedDcqlMatcher.buildFfiClaims] (which claims the engine is told about)
 * and [SharedDcqlMatcher.splitClaimKey] (mdoc path splitting) - since a
 * mistake there silently removes a credential from what a user is offered,
 * exactly as it did for a real user report this file's `buildFfiClaims`
 * tests reproduce (siros-sdk-kotlin, nested `registered_address.full_address`
 * DCQL claim). Mirrors the Swift SDK's `SharedDcqlMatcherTests`, whose
 * `matchingClaims` was already built this way - Kotlin's `extractClaims` +
 * `splitClaimKey` combination was the one with the bug.
 */
class SharedDcqlMatcherTests {

    /** ISO namespaces keep their dots; only the element identifier splits off. */
    @Test
    fun `mdoc claim keys split on the last dot`() {
        assertEquals(
            listOf("org.iso.18013.5.1", "family_name"),
            SharedDcqlMatcher.splitClaimKey("mso_mdoc", "org.iso.18013.5.1.family_name"),
        )
    }

    /** An mdoc key with no dot is an element with no namespace, not an error. */
    @Test
    fun `an mdoc key without a dot stays whole`() {
        assertEquals(listOf("family_name"), SharedDcqlMatcher.splitClaimKey("mso_mdoc", "family_name"))
    }

    /** Format comparison is case-insensitive. */
    @Test
    fun `format match is case-insensitive`() {
        assertEquals(
            listOf("org.iso.18013.5.1", "age_over_18"),
            SharedDcqlMatcher.splitClaimKey("MSO_MDOC", "org.iso.18013.5.1.age_over_18"),
        )
    }

    private fun sdJwtCredential(raw: String, metadata: CredentialMetadata? = null) =
        StoredCredential(id = 1L, batchId = 1L, instanceId = 0, format = "dc+sd-jwt", raw = raw, metadata = metadata)

    private fun b64url(s: String): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray())

    /**
     * The regression this exists for: a real verifier's DCQL query asked for
     * `["registered_address", "full_address"]` against a real `eucc`
     * credential that genuinely has it, and the wallet reported "you do not
     * have any credentials that match this request".
     *
     * Nested claims must get real DCQL paths, not one dotted string -
     * `["registered_address", "full_address"]` is what a claims path
     * pointer looks like (OpenID4VP 1.0 §7); `["registered_address.full_address"]`
     * matches nothing.
     */
    @Test
    fun `nested claims become real paths not dotted keys`() {
        val payload = b64url(
            """{
                "iss": "https://issuer.example.com",
                "vct": "urn:eudi:eucc:1",
                "registered_address": {"full_address": "1 Example Street, Anytown"},
                "_sd_alg": "sha-256"
            }""",
        )
        val credential = sdJwtCredential("${b64url("{\"alg\":\"ES256\"}")}.$payload.sig")

        val claims = SharedDcqlMatcher.buildFfiClaims(credential)
        val paths = claims.map { it.path }

        assertTrue("got $paths", paths.any { it == listOf("registered_address", "full_address") })
        assertTrue("an object is addressable too", paths.any { it == listOf("registered_address") })
        assertFalse(paths.any { it == listOf("registered_address.full_address") })
        val leaf = claims.first { it.path == listOf("registered_address", "full_address") }
        assertEquals("1 Example Street, Anytown", leaf.value)
    }

    /**
     * The same nested claim, but with VCTM declaring it - the second,
     * independent way the same bug used to bite: even when covered by VCTM,
     * `extractClaims` collapses a nested path into one dotted display key
     * (`claim.path.joinToString(".")`), and the old `splitClaimKey`-based
     * pipeline could not tell that dot apart from a literal one.
     */
    @Test
    fun `a VCTM-declared nested claim also becomes a real path`() {
        val payload = b64url(
            """{
                "iss": "https://issuer.example.com",
                "vct": "urn:eudi:eucc:1",
                "registered_address": {"full_address": "1 Example Street, Anytown"},
                "_sd_alg": "sha-256"
            }""",
        )
        val credential = sdJwtCredential(
            "${b64url("{\"alg\":\"ES256\"}")}.$payload.sig",
            metadata = CredentialMetadata(
                claims = listOf(
                    ClaimMeta(path = listOf("registered_address", "full_address"), label = "Address"),
                ),
            ),
        )

        val claims = SharedDcqlMatcher.buildFfiClaims(credential)
        assertTrue(claims.any { it.path == listOf("registered_address", "full_address") })
    }

    /** A claim disclosed inside a nested object's own `_sd` array is resolved too. */
    @Test
    fun `disclosures nested inside disclosures are resolved`() {
        val salt = "eluV5Og3gSNII8EYnsxA_A"
        val disclosureJson = """["$salt","locality","Stockholm"]"""
        val disclosure = b64url(disclosureJson)
        val digest = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(disclosure.toByteArray()))
        val payload = b64url(
            """{
                "vct": "x",
                "address": {"_sd": ["$digest"]},
                "_sd_alg": "sha-256"
            }""",
        )
        val credential = sdJwtCredential("${b64url("{\"alg\":\"ES256\"}")}.$payload.sig~$disclosure~")

        val claims = SharedDcqlMatcher.buildFfiClaims(credential)
        val locality = claims.find { it.path == listOf("address", "locality") }
        assertEquals("Stockholm", locality?.value)
    }

    /** SD-JWT bookkeeping is not a claim - no verifier requests `_sd_alg`. */
    @Test
    fun `structural keys are not offered as claims`() {
        val payload = b64url("""{"vct": "x", "_sd_alg": "sha-256", "iss": "https://issuer.example"}""")
        val credential = sdJwtCredential("${b64url("{\"alg\":\"ES256\"}")}.$payload.sig")

        val paths = SharedDcqlMatcher.buildFfiClaims(credential).map { it.path }
        assertFalse(paths.any { it == listOf("_sd_alg") })
        assertFalse(paths.any { it == listOf("vct") })
    }
}
