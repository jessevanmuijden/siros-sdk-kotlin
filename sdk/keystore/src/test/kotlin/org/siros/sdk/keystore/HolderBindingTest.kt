package org.siros.sdk.keystore

import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.interop.DidRelationship
import org.siros.sdk.credentials.interop.HolderBinding
import org.siros.sdk.credentials.interop.InteropProfile
import org.siros.sdk.credentials.interop.createDidJwk
import org.siros.sdk.credentials.interop.didJwkKeyId
import org.siros.sdk.credentials.interop.resolveDidJwk
import java.util.Base64

/**
 * The holder-binding half of the keystore, where HAIP and DIIP part company:
 * `did:jwk` key naming, the two `jwt` proof shapes, and looking a key up by
 * whichever identifier a credential happens to name it with.
 */
class HolderBindingTest {

    private val prfOutput = ByteArray(32) { it.toByte() }
    private val hkdfSalt = ByteArray(32) { (it + 0x10).toByte() }
    private val hkdfInfo = "SIROS Wallet PRF".toByteArray(Charsets.UTF_8)

    private suspend fun unlocked(profile: InteropProfile = InteropProfile.DIIP): JweKeystore =
        JweKeystore(profile = profile).also { it.unlock(prfOutput, ByteArray(0), hkdfSalt, hkdfInfo) }

    // ── key naming ──────────────────────────────────────────────────

    @Test
    fun `each profile names keys the way its holder binding needs`() {
        assertEquals(DidKeyVersion.JWK, DidKeyVersion.forProfile(InteropProfile.DIIP))
        assertEquals(DidKeyVersion.P256_PUB, DidKeyVersion.forProfile(InteropProfile.HAIP))
        assertEquals(DidKeyVersion.JWK, DidKeyVersion.fromValue(null))
        assertEquals(DidKeyVersion.P256_PUB, DidKeyVersion.fromValue("p256-pub"))
        assertEquals(DidKeyVersion.JWK_JCS_PUB, DidKeyVersion.fromValue("jwk_jcs-pub"))
    }

    @Test
    fun `a wallet speaks HAIP unless told otherwise`() {
        // Adding DIIP support must not change the proof shape every existing
        // SIROS ID issuer already accepts.
        assertEquals(InteropProfile.HAIP, InteropProfile.DEFAULT)
        assertEquals(HolderBinding.EMBEDDED_JWK, InteropProfile.HAIP.holderBinding)
        assertEquals(HolderBinding.DID_JWK, InteropProfile.DIIP.holderBinding)
    }

    @Test
    fun `a new key is named by its did jwk verification method`() = runTest {
        val keystore = unlocked()
        val kid = keystore.generateKey()
        assertTrue("kid is a DID URL, not a thumbprint: $kid", kid.startsWith("did:jwk:"))
        assertTrue(kid.endsWith("#0"))
        // The DID resolves back to the key it names.
        val document = resolveDidJwk(kid.substringBefore('#')).documentOrNull
        assertNotNull(document)
        assertNotNull(document!!.findPublicKey(kid, DidRelationship.AUTHENTICATION))
    }

    @Test
    fun `a HAIP wallet keeps naming keys by thumbprint`() = runTest {
        val keystore = unlocked(InteropProfile.HAIP)
        val kid = keystore.generateKey()
        assertFalse(kid.startsWith("did:"))
    }

    @Test
    fun `a key pair's DID survives a container round trip`() = runTest {
        val keystore = unlocked()
        val kid = keystore.generateKey()
        val container = keystore.exportEncryptedContainer()

        // A wallet reconfigured for the other profile must not re-identify a
        // key that credentials are already bound to.
        val reloaded = JweKeystore(profile = InteropProfile.HAIP)
        reloaded.unlock(prfOutput, container, hkdfSalt, hkdfInfo)
        assertEquals(listOf(kid), reloaded.listKeys().map { it.keyId })
        assertEquals(kid.substringBefore('#'), reloaded.didForKid(kid))
    }

    // ── the OID4VCI proof ───────────────────────────────────────────

    @Test
    fun `the jwt proof names the holder's DID rather than embedding the key`() = runTest {
        val keystore = unlocked()
        val kid = keystore.generateKey()
        val proof = SignedJWT.parse(keystore.generateProof("https://issuer.example", "n-0S6_WzA2Mj"))

        assertEquals("openid4vci-proof+jwt", proof.header.type.toString())
        assertEquals(kid, proof.header.keyID)
        assertNull("the key is named, not embedded", proof.header.jwk)
        assertEquals(kid.substringBefore('#'), proof.jwtClaimsSet.issuer)
        assertEquals(listOf("https://issuer.example"), proof.jwtClaimsSet.audience)
        assertEquals("n-0S6_WzA2Mj", proof.jwtClaimsSet.getClaim("nonce"))
    }

    @Test
    fun `the proof verifies under the key its DID resolves to`() = runTest {
        // An issuer verifying the proof resolves the DID and checks the
        // signature - this is the seam a mismatch would only show up at.
        val keystore = unlocked()
        val proof = SignedJWT.parse(keystore.generateProof("https://issuer.example", "nonce"))
        val did = proof.jwtClaimsSet.issuer
        val jwk = resolveDidJwk(did).documentOrNull!!
            .findPublicKey(proof.header.keyID, DidRelationship.AUTHENTICATION)!!
        val verifier = com.nimbusds.jose.crypto.ECDSAVerifier(ECKey.parse(jwk.toString()))
        assertTrue(proof.verify(verifier))
    }

    @Test
    fun `a HAIP proof carries the key in the header`() = runTest {
        // A HAIP issuer does not resolve DIDs, so the embedded form is the
        // only one it can verify.
        val keystore = unlocked(InteropProfile.HAIP)
        keystore.generateKey()
        val proof = SignedJWT.parse(keystore.generateProof("https://issuer.example", "nonce"))
        assertNotNull(proof.header.jwk)
        assertNull(proof.jwtClaimsSet.issuer)
    }

    @Test
    fun `one wallet sends each issuer the proof shape it can verify`() = runTest {
        // The whole point of the per-issuance choice: a DIIP-configured wallet
        // must still be able to talk to a HAIP issuer, and the reverse.
        val diipWallet = unlocked(InteropProfile.DIIP)
        val kid = diipWallet.generateKey()

        val toHaipIssuer = SignedJWT.parse(
            diipWallet.generateProof("https://haip.example", "nonce", false, HolderBinding.EMBEDDED_JWK),
        )
        assertNotNull("a HAIP issuer gets the key it can verify", toHaipIssuer.header.jwk)
        assertNull(toHaipIssuer.header.keyID)

        val toDiipIssuer = SignedJWT.parse(
            diipWallet.generateProof("https://diip.example", "nonce", false, HolderBinding.DID_JWK),
        )
        assertEquals(kid, toDiipIssuer.header.keyID)
        assertNull(toDiipIssuer.header.jwk)
    }

    @Test
    fun `a DIIP wallet still emits a HAIP proof when that is what was negotiated`() = runTest {
        // The mirror of the case above: the binding the caller asks for wins
        // over what the keystore's own profile would have chosen, in both
        // directions. A key named by a DID URL still has to be embeddable,
        // since a HAIP issuer resolves no DIDs at all.
        val keystore = unlocked(InteropProfile.DIIP)
        keystore.generateKey()
        val proof = SignedJWT.parse(
            keystore.generateProof(
                "https://issuer.example",
                "nonce",
                freshKey = false,
                holderBinding = HolderBinding.EMBEDDED_JWK,
            ),
        )
        assertNotNull("a HAIP proof carries the key", proof.header.jwk)
        assertNull("and names neither a kid", proof.header.keyID)
        assertNull("nor an iss", proof.jwtClaimsSet.issuer)
    }

    @Test
    fun `one wallet presents a HAIP credential and a DIIP credential correctly`() = runTest {
        // Presentation is where the two profiles have to coexist without any
        // configuration at all: the credential's own `cnf` says how its key is
        // named, so the same wallet answers both without being told which is
        // which.
        val keystore = unlocked(InteropProfile.DIIP)
        val diipKid = keystore.generateKey()
        val haipKid = keystore.generateKey()
        val haipJwk = ECKey.parse(keystore.exportKeypairJwks()[haipKid]!!).toPublicJWK()

        val diipCredential = sdJwt("""{"vct":"urn:example:diip","cnf":{"kid":"$diipKid"}}""")
        val haipCredential = sdJwt("""{"vct":"urn:example:haip","cnf":{"jwk":${haipJwk.toJSONString()}}}""")

        val diipKb = SignedJWT.parse(
            keystore.signVpToken(diipCredential, null, "nonce", "https://verifier.example")
                .substringAfterLast('~'),
        )
        assertEquals(diipKid, diipKb.header.keyID)
        assertNull(diipKb.header.jwk)

        val haipKb = SignedJWT.parse(
            keystore.signVpToken(haipCredential, null, "nonce", "https://verifier.example")
                .substringAfterLast('~'),
        )
        assertNotNull(haipKb.header.jwk)
        assertTrue(
            "the HAIP credential is signed by the key it is bound to, not the DIIP one",
            haipKb.verify(com.nimbusds.jose.crypto.ECDSAVerifier(haipJwk)),
        )
    }

    @Test
    fun `a batch issuance binds each credential to its own key`() = runTest {
        // freshKey is what OID4VCI batch issuance means: without it every copy
        // in the batch shares one holder key, and presenting them is linkable.
        val keystore = unlocked(InteropProfile.DIIP)
        val kids = (1..3).map {
            SignedJWT.parse(
                keystore.generateProof("https://issuer.example", "nonce", freshKey = true),
            ).header.keyID
        }
        assertEquals("each proof names a different key", 3, kids.toSet().size)
        assertEquals(3, keystore.listKeys().size)
    }

    @Test
    fun `without freshKey the wallet reuses the key it has`() = runTest {
        val keystore = unlocked(InteropProfile.DIIP)
        val kid = keystore.generateKey()
        repeat(2) {
            assertEquals(
                kid,
                SignedJWT.parse(keystore.generateProof("https://issuer.example", "nonce")).header.keyID,
            )
        }
        assertEquals(1, keystore.listKeys().size)
    }

    // ── presenting what the wallet already holds ────────────────────

    @Test
    fun `a credential bound by cnf kid is presented with a KB-JWT naming that key`() = runTest {
        val keystore = unlocked()
        val kid = keystore.generateKey()
        val credential = sdJwt("""{"vct":"urn:example:x","cnf":{"kid":"$kid"}}""")

        val vp = keystore.signVpToken(credential, null, "nonce", "https://verifier.example")
        val kb = SignedJWT.parse(vp.substringAfterLast('~'))
        assertEquals("kb+jwt", kb.header.type.toString())
        assertEquals(kid, kb.header.keyID)
        assertNull("a kid-bound credential does not re-embed the key", kb.header.jwk)
    }

    @Test
    fun `a credential bound by cnf jwk keeps the embedded-key KB-JWT`() = runTest {
        // This is the regression that bites an existing wallet: the key pair
        // is named by a DID URL, but the credential can only name it by
        // value, so the lookup has to fall back to the thumbprint.
        val keystore = unlocked()
        val kid = keystore.generateKey()
        val publicJwk = keystore.exportKeypairJwks()[kid]!!.let { ECKey.parse(it).toPublicJWK() }
        val thumbprint = publicJwk.computeThumbprint().toString()
        assertFalse("the stored kid is not the thumbprint", kid == thumbprint)

        val credential = sdJwt("""{"vct":"urn:example:x","cnf":{"jwk":${publicJwk.toJSONString()}}}""")
        val vp = keystore.signVpToken(credential, null, "nonce", "https://verifier.example")
        val kb = SignedJWT.parse(vp.substringAfterLast('~'))
        assertNotNull("a jwk-bound credential keeps the embedded key", kb.header.jwk)
        assertTrue(kb.verify(com.nimbusds.jose.crypto.ECDSAVerifier(publicJwk)))
    }

    @Test
    fun `a key pair is found by thumbprint even when it is named by a DID URL`() = runTest {
        val keystore = unlocked()
        val kid = keystore.generateKey()
        val publicJwk = ECKey.parse(keystore.exportKeypairJwks()[kid]!!).toPublicJWK()
        val thumbprint = publicJwk.computeThumbprint().toString()

        // signPresentation with the thumbprint must reach the same key rather
        // than reporting it unavailable - this is what an mdoc device key or a
        // container written by another client hands us.
        val jwt = SignedJWT.parse(
            keystore.signPresentation("nonce", "https://verifier.example", emptyList(), thumbprint),
        )
        assertTrue(jwt.verify(com.nimbusds.jose.crypto.ECDSAVerifier(publicJwk)))
    }

    @Test
    fun `an unknown kid is still refused`() = runTest {
        // The fallback must not become "sign with whatever key is around".
        val keystore = unlocked()
        keystore.generateKey()
        var threw = false
        try {
            keystore.signPresentation("nonce", "https://verifier.example", emptyList(), "no-such-key")
        } catch (e: Exception) {
            threw = true
        }
        assertTrue("signing with the wrong key is never a safe substitute", threw)
    }

    // ── cnf reading ─────────────────────────────────────────────────

    @Test
    fun `cnf kid is preferred over cnf jwk, and an absent cnf is null`() {
        val jwk = """{"kty":"EC","crv":"P-256","x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0","y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"}"""
        assertEquals(
            "did:jwk:abc#0",
            resolveCnfKid(Json.parseToJsonElement("""{"kid":"did:jwk:abc#0","jwk":$jwk}""") as JsonObject),
        )
        assertEquals(
            ECKey.parse(jwk).computeThumbprint().toString(),
            resolveCnfKid(Json.parseToJsonElement("""{"jwk":$jwk}""") as JsonObject),
        )
        assertNull(resolveCnfKid(null))
    }

    private fun sdJwt(payload: String): String {
        fun b64(s: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray(Charsets.UTF_8))
        return "${b64("""{"alg":"ES256","typ":"dc+sd-jwt"}""")}.${b64(payload)}.sig~"
    }
    // ── negotiation must work on a HAIP-shaped keystore ──────────────

    @Test
    fun `a HAIP keystore can still produce a DIIP proof`() = runTest {
        // The default wallet is HAIP, so its keys are named by thumbprint and
        // carry a did:key. If that decided the proof shape, negotiating DIIP
        // with an issuer could never be satisfied and the whole per-issuer
        // negotiation would be inert for every wallet that ships.
        val keystore = unlocked(profile = InteropProfile.HAIP)
        val kid = keystore.generateKey()
        assertFalse("a HAIP keystore names keys by thumbprint", kid.startsWith("did:jwk:"))

        val proof = SignedJWT.parse(
            keystore.generateProof("https://issuer.example", "n-1", false, HolderBinding.DID_JWK),
        )
        val did = proof.jwtClaimsSet.issuer
        assertNotNull("a DIIP proof names the holder with iss", did)
        assertTrue(did.startsWith("did:jwk:"))
        assertNull("a DIIP proof names the key, it does not embed it", proof.header.jwk)
        assertEquals("$did#0", proof.header.keyID)

        // And it is this key that the DID names.
        val resolved = resolveDidJwk(did).documentOrNull
            ?.findPublicKey(kid = null, relationship = DidRelationship.ANY)
        assertNotNull(resolved)
        assertTrue(proof.verify(com.nimbusds.jose.crypto.ECDSAVerifier(ECKey.parse(resolved.toString()))))
    }

    @Test
    fun `a credential bound to a did jwk finds the thumbprint-named key that signs for it`() = runTest {
        // The issuer binds cnf.kid to the did:jwk from the proof above, but
        // the wallet stored that key under its thumbprint. Without matching
        // the two, the credential could never be presented.
        val keystore = unlocked(profile = InteropProfile.HAIP)
        val storedKid = keystore.generateKey()
        val publicJwk = ECKey.parse(keystore.exportKeypairJwks()[storedKid]!!).toPublicJWK()
        val did = createDidJwk(publicJwk.toJSONString())

        assertTrue(keypairMatchesKid(storedKid, publicJwk, didJwkKeyId(did)))
        assertTrue(keypairMatchesKid(storedKid, publicJwk, did))
        assertEquals(storedKid, thumbprintOfDidJwk(didJwkKeyId(did)))
    }

    @Test
    fun `a did jwk naming some other key is not a match`() = runTest {
        val keystore = unlocked(profile = InteropProfile.HAIP)
        val storedKid = keystore.generateKey()
        val publicJwk = ECKey.parse(keystore.exportKeypairJwks()[storedKid]!!).toPublicJWK()

        val otherKid = keystore.generateKey()
        val otherDid = createDidJwk(
            ECKey.parse(keystore.exportKeypairJwks()[otherKid]!!).toPublicJWK().toJSONString(),
        )

        assertFalse(keypairMatchesKid(storedKid, publicJwk, didJwkKeyId(otherDid)))
        assertNull(thumbprintOfDidJwk("did:web:issuer.example"))
        assertNull(thumbprintOfDidJwk("not-a-did"))
    }
}
