package org.siros.sdk.wallet

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Most Issuers are identified by an HTTPS URL rather than a DID. Resolving
 * their signing key only through the DID resolver meant a Status List Token
 * from such an issuer could never be verified, so every revocation check
 * degraded to "unavailable" - which this SDK deliberately treats as usable, so
 * revocation silently never applied.
 *
 * [selectIssuerKey] is the part that decides which published key a token's
 * `kid` means.
 */
class IssuerSigningKeyResolutionTest {

    private fun generated(kid: String?): ECKey =
        ECKeyGenerator(Curve.P_256).let { gen -> if (kid != null) gen.keyID(kid) else gen }.generate()

    private fun published(kid: String?): JWK = generated(kid).toPublicJWK()

    @Test
    fun `a kid names the key it selects`() {
        val wanted = published("b")
        val chosen = selectIssuerKey(listOf(published("a"), wanted), "b")
        assertEquals("b", chosen!!.keyID)
        assertEquals(wanted.toJSONObject()["x"], chosen.toJSONObject()["x"])
    }

    @Test
    fun `a sole key is used when no kid is named`() {
        assertEquals("P-256", selectIssuerKey(listOf(published(null)), null)!!.toJSONObject()["crv"])
    }

    @Test
    fun `several keys with no kid is ambiguous and refused`() {
        // Guessing would mean accepting a signature from whichever key
        // happened to be first in the set.
        assertNull(selectIssuerKey(listOf(published("a"), published("b")), null))
    }

    @Test
    fun `a kid that matches nothing is refused`() {
        assertNull(selectIssuerKey(listOf(published("a")), "missing"))
    }

    @Test
    fun `a key carrying private material is not a verification key`() {
        // A misconfigured JWKS that publishes a private key must not have it
        // treated as something to verify signatures with.
        assertNull(selectIssuerKey(listOf(generated("a")), "a"))
        assertNull(selectIssuerKey(listOf(generated(null)), null))
    }

    @Test
    fun `an empty key set yields nothing`() {
        assertNull(selectIssuerKey(emptyList(), null))
        assertNull(selectIssuerKey(emptyList(), "a"))
    }

    @Test
    fun `a plaintext URL is never fetched`() {
        // Over plaintext anyone on the path can answer "is this credential
        // still valid" and "which key says so" in the issuer's place.
        assertTrue(isPublicFetchAllowed("https://issuer.example/statuslists/1"))
        assertTrue(isPublicFetchAllowed("HTTPS://issuer.example/statuslists/1"))
        assertFalse(isPublicFetchAllowed("http://issuer.example/statuslists/1"))
        assertFalse(isPublicFetchAllowed("HTTP://issuer.example/statuslists/1"))
        assertFalse(isPublicFetchAllowed("ftp://issuer.example/statuslists/1"))
        assertFalse(isPublicFetchAllowed("file:///etc/passwd"))
        assertFalse(isPublicFetchAllowed("not a url at all"))
        assertFalse(isPublicFetchAllowed(""))
    }

    @Test
    fun `a URL carrying userinfo is never fetched`() {
        // The classic way to make a host look like one it is not. Userinfo
        // means nothing for an issuer's metadata or a status list.
        assertFalse(isPublicFetchAllowed("https://issuer.example@evil.example/list"))
        assertFalse(isPublicFetchAllowed("https://user:pass@evil.example/list"))
        assertFalse(isPublicFetchAllowed("https:///no-host"))
        assertTrue(isPublicFetchAllowed("https://issuer.example/list"))
    }
}
