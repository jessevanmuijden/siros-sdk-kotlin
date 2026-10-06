package org.siros.sdk.credentials.interop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class InteropProfileTest {

    @Test
    fun `adding DIIP does not change what a wallet sends by default`() {
        // Every SIROS ID issuer already accepts the HAIP-shaped proof; making
        // DIIP the default would have been a wire change nobody asked for.
        assertEquals(InteropProfile.HAIP, InteropProfile.DEFAULT)
    }

    @Test
    fun `each profile names the holder key its own way`() {
        assertEquals(HolderBinding.EMBEDDED_JWK, InteropProfile.HAIP.holderBinding)
        assertEquals(HolderBinding.DID_JWK, InteropProfile.DIIP.holderBinding)
    }

    @Test
    fun `a profile is parsed from configuration, and nothing is guessed`() {
        assertEquals(InteropProfile.HAIP, InteropProfile.fromId("haip"))
        assertEquals(InteropProfile.DIIP, InteropProfile.fromId(" DIIP "))
        assertNull(InteropProfile.fromId("something-else"))
        assertNull(InteropProfile.fromId(null))
    }

    // ── negotiation ─────────────────────────────────────────────────
    //
    // The point of these: a wallet holding credentials from a HAIP ecosystem
    // and a DIIP ecosystem has to shape each proof to its issuer, and nobody
    // can reasonably be asked which profile an issuer they just scanned
    // belongs to. The issuer already says so in its own metadata.

    @Test
    fun `a HAIP issuer asks for the key itself`() {
        assertEquals(HolderBinding.EMBEDDED_JWK, HolderBinding.negotiate(listOf("jwk")))
    }

    @Test
    fun `a DIIP issuer asks for a did jwk`() {
        assertEquals(HolderBinding.DID_JWK, HolderBinding.negotiate(listOf("did:jwk")))
        // A bare "did" means any DID method.
        assertEquals(HolderBinding.DID_JWK, HolderBinding.negotiate(listOf("did")))
    }

    @Test
    fun `did jwk wins when an issuer accepts both`() {
        // A wallet that only ever speaks DIIP has no configured profile at
        // all - it sends did:jwk whenever an issuer accepts it, since that
        // is what DIIP requires. Converging on that (rather than preferring
        // the embedded key, which used to make DIIP unreachable against any
        // issuer that also advertises jwk) is converging on the wider DIIP
        // ecosystem's actual behavior, and costs the issuer nothing extra -
        // did:jwk is self-certifying, no network resolution needed.
        assertEquals(HolderBinding.DID_JWK, HolderBinding.negotiate(listOf("did:jwk", "jwk")))
        assertEquals(HolderBinding.DID_JWK, HolderBinding.negotiate(listOf("jwk", "did:jwk")))
    }

    @Test
    fun `case and whitespace in advertised methods do not defeat the match`() {
        assertEquals(HolderBinding.EMBEDDED_JWK, HolderBinding.negotiate(listOf(" JWK ")))
        assertEquals(HolderBinding.DID_JWK, HolderBinding.negotiate(listOf("DID:JWK")))
    }

    @Test
    fun `an issuer that advertises nothing usable leaves the choice to the caller`() {
        // Null means "fall back to the configured profile" - guessing here
        // would fail the issuance just as surely, with less to debug.
        assertNull(HolderBinding.negotiate(null))
        assertNull(HolderBinding.negotiate(emptyList()))
        assertNull(HolderBinding.negotiate(listOf("cose_key")))
        // A DID method whose keys this wallet cannot mint is not a match.
        assertNull(HolderBinding.negotiate(listOf("did:web", "did:ebsi")))
    }

    @Test
    fun `a binding names the OID4VCI method it corresponds to`() {
        assertEquals("jwk", HolderBinding.EMBEDDED_JWK.bindingMethod)
        assertEquals("did:jwk", HolderBinding.DID_JWK.bindingMethod)
    }
    @Test
    fun `a real DIIP issuer's advertised methods negotiate the DID binding`() {
        // Verbatim from https://nl.gov.issuer.dev.eduwallet.nl's
        // .well-known/openid-credential-issuer (PID, dc+sd-jwt), reached
        // through the eduwallet demo launcher. It advertises no `jwk` at all,
        // so a wallet that defaults to HAIP still has to send this issuer the
        // DIIP proof shape - which is the whole point of negotiating rather
        // than configuring.
        assertEquals(
            HolderBinding.DID_JWK,
            HolderBinding.negotiate(listOf("did:jwk", "did:key")),
        )
        // And the substring trap: "jwk" must be matched as a whole value, not
        // found inside "did:jwk".
        assertEquals(HolderBinding.DID_JWK, HolderBinding.negotiate(listOf("did:jwk")))
        assertEquals(HolderBinding.DID_JWK, HolderBinding.negotiate(listOf("jwk", "did:jwk")))
        // A DID method that is not did:jwk names nothing this Holder can use.
        assertNull(HolderBinding.negotiate(listOf("did:key")))
    }
}
