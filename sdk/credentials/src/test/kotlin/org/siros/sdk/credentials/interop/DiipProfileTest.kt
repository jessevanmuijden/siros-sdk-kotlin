package org.siros.sdk.credentials.interop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DiipProfileTest {

    @Test
    fun `the default profile is the newest this SDK implements`() {
        assertEquals(DiipProfile.V6, DiipProfile.LATEST)
    }

    @Test
    fun `a version is parsed however it is spelled in configuration`() {
        assertEquals(DiipProfile.V5, DiipProfile.fromVersion("v5"))
        assertEquals(DiipProfile.V5, DiipProfile.fromVersion("V5"))
        assertEquals(DiipProfile.V5, DiipProfile.fromVersion("5"))
        assertEquals(DiipProfile.V5, DiipProfile.fromVersion("  v5 "))
    }

    @Test
    fun `an unrecognised version is reported rather than guessed at`() {
        assertNull(DiipProfile.fromVersion("v99"))
        assertNull(DiipProfile.fromVersion(""))
        assertNull(DiipProfile.fromVersion(null))
    }

    @Test
    fun `every version identifies Holders by did jwk`() {
        for (profile in DiipProfile.entries) {
            assertEquals(profile.version, DidMethod.JWK, profile.holderDidMethod)
        }
    }

    @Test
    fun `v6 adds did webvh to the methods a wallet resolves`() {
        assertEquals(setOf(DidMethod.JWK, DidMethod.WEB), DiipProfile.V5.resolvableDidMethods)
        assertTrue(DidMethod.WEBVH in DiipProfile.V6.resolvableDidMethods)
        // Additive: nothing v5 required is dropped.
        assertTrue(DiipProfile.V5.resolvableDidMethods.all { it in DiipProfile.V6.resolvableDidMethods })
    }

    @Test
    fun `SD-JWT VC renamed the issuer metadata path between v4 and v5`() {
        assertEquals("/.well-known/jwt-vc-issuer", DiipProfile.V4.sdJwtVcIssuerMetadataPath)
        assertEquals("/.well-known/vc-issuer", DiipProfile.V5.sdJwtVcIssuerMetadataPath)
        assertEquals("/.well-known/vc-issuer", DiipProfile.V6.sdJwtVcIssuerMetadataPath)
    }

    @Test
    fun `OID4VP went from a bare scheme to Client Identifier Prefixes at v5`() {
        assertEquals(ClientIdStyle.BARE_SCHEME, DiipProfile.V4.clientIdStyle)
        assertEquals(ClientIdStyle.PREFIXED, DiipProfile.V5.clientIdStyle)
        assertEquals(ClientIdStyle.PREFIXED, DiipProfile.V6.clientIdStyle)
    }

    @Test
    fun `the DC API and Wallet federation are v6 Future Directions, not v5 requirements`() {
        assertFalse(DiipProfile.V5.requiresDigitalCredentialsApi)
        assertTrue(DiipProfile.V6.requiresDigitalCredentialsApi)
        assertFalse(DiipProfile.V5.requiresWalletFederation)
        assertTrue(DiipProfile.V6.requiresWalletFederation)
    }

    @Test
    fun `the Token Status List draft moves with the profile`() {
        assertEquals(10, DiipProfile.V4.tokenStatusListDraft)
        assertEquals(15, DiipProfile.V5.tokenStatusListDraft)
    }
}
