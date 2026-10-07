package org.siros.sdk.keystore

import org.siros.sdk.credentials.KeystoreException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class JweKeystoreTest {

    private val fakePrfOutput = ByteArray(32) { it.toByte() }
    private val hkdfSalt = ByteArray(32) { (it + 0x10).toByte() }
    private val hkdfInfo = "SIROS Wallet PRF".toByteArray(Charsets.UTF_8)

    @Test
    fun unlockWithEmptyContainerCreatesFreshKeystore() = runTest {
        val keystore = JweKeystore()
        assertFalse(keystore.isUnlocked)

        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        assertTrue(keystore.isUnlocked)
        assertEquals(0, keystore.listKeys().size)
    }

    @Test
    fun generateKeyAndListKeys() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)

        val keyId = keystore.generateKey()
        assertNotNull(keyId)

        val keys = keystore.listKeys()
        assertEquals(1, keys.size)
        assertEquals(keyId, keys[0].keyId)
    }

    @Test
    fun exportAndReimportContainer() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)

        // Generate a key and export
        val keyId = keystore.generateKey()
        val exported = keystore.exportEncryptedContainer()
        assertTrue(exported.isNotEmpty())

        // Lock and re-unlock with the same PRF output
        keystore.lock()
        assertFalse(keystore.isUnlocked)

        keystore.unlock(fakePrfOutput, exported, hkdfSalt, hkdfInfo)
        assertTrue(keystore.isUnlocked)
        assertEquals(1, keystore.listKeys().size)
        assertEquals(keyId, keystore.listKeys()[0].keyId)
    }

    @Test
    fun credentialRoundTripPreservesPrivateDataSpecFields() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)

        // Matches EncryptedCredentialStore.save()'s actual shape: the full
        // StoredCredential JSON, including credential_issuer_identifier/
        // credential_configuration_id - privatedata-spec's normative
        // S.credentials[] fields (wallet-frontend's WalletSessionEventNewCredential),
        // needed after a fresh login to re-fetch VCTM display metadata.
        val credentialJson = """{"id":1,"format":"vc+sd-jwt","raw":"header.payload.sig","kid":"key-1","credential_issuer_identifier":"https://issuer.example.com","credential_configuration_id":"diploma"}"""
        keystore.saveCredential(1L, credentialJson)

        val exported = keystore.exportEncryptedContainer()
        keystore.lock()
        keystore.unlock(fakePrfOutput, exported, hkdfSalt, hkdfInfo)

        val restored = keystore.getCredential(1L)
        assertNotNull(restored)
        assertTrue(restored!!.contains("\"credential_issuer_identifier\":\"https://issuer.example.com\""))
        assertTrue(restored.contains("\"credential_configuration_id\":\"diploma\""))
        assertTrue(restored.contains("\"format\":\"vc+sd-jwt\""))
        assertTrue(restored.contains("header.payload.sig"))
    }

    @Test
    fun wscdCredentialsRoundTripThroughExportAndReimport() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)

        // Matches PreviewSignPlugin::export_state()'s JSON shape (opaque to
        // this SDK) - privatedata-spec §6.1 S.wscdCredentials, the
        // native-SDK-only extension letting a FIDO2 (roaming authenticator)
        // key stay addressable from any device sharing this account.
        val fido2State = """{"keys":[{"kid":"fido-0","credential_id":"AQID","key_handle":"BAUG"}],"next_id":1}"""
        keystore.setWscdCredentials("fido2", fido2State)
        assertEquals(fido2State, keystore.exportWscdCredentials()["fido2"])

        val exported = keystore.exportEncryptedContainer()
        keystore.lock()
        assertTrue(keystore.exportWscdCredentials().isEmpty())

        keystore.unlock(fakePrfOutput, exported, hkdfSalt, hkdfInfo)
        assertEquals(fido2State, keystore.exportWscdCredentials()["fido2"])
    }

    @Test
    fun lockClearsKeys() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore.generateKey()
        assertEquals(1, keystore.listKeys().size)

        keystore.lock()
        assertFalse(keystore.isUnlocked)
    }

    @Test
    fun signProducesOutput() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        val keyId = keystore.generateKey()

        val signed = keystore.sign(keyId, "test payload".toByteArray())
        assertTrue(signed.isNotEmpty())
    }

    @Test
    fun generateProofProducesJwt() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore.generateKey()

        val proof = keystore.generateProof("https://issuer.example.com", "test-nonce-123")
        assertTrue(proof.contains("."))  // JWT has dots
        assertEquals(3, proof.split(".").size)  // header.payload.signature
    }

    @Test
    fun generateKeyProofBuildsValidPopJwt() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        val keyId = keystore.generateKey()

        val jwt = keystore.generateKeyProof(
            keyId = keyId,
            typ = "oauth-client-attestation-pop+jwt",
            issuer = "siros-sample://callback",
            audience = "https://wallet-backend.example.com",
            extraClaims = mapOf("nonce" to "challenge-abc"),
        )

        val parsed = com.nimbusds.jwt.SignedJWT.parse(jwt)
        assertEquals("oauth-client-attestation-pop+jwt", parsed.header.type.toString())
        assertEquals(com.nimbusds.jose.JWSAlgorithm.ES256, parsed.header.algorithm)
        assertNotNull(parsed.header.jwk)

        val claims = parsed.jwtClaimsSet
        assertEquals(listOf("https://wallet-backend.example.com"), claims.audience)
        assertEquals("challenge-abc", claims.getClaim("nonce"))
        assertEquals("siros-sample://callback", claims.issuer)
        assertNotNull(claims.expirationTime)
    }

    @Test
    fun generateDPoPProofBuildsRfc9449Proof() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        val keyId = keystore.generateKey()

        val jwt = keystore.generateDPoPProof(
            keyId = keyId,
            htm = "POST",
            htu = "https://as.example.com/token",
            nonce = "server-nonce",
            accessTokenHash = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo",
        )

        val parsed = com.nimbusds.jwt.SignedJWT.parse(jwt)
        assertEquals("dpop+jwt", parsed.header.type.toString())
        assertEquals(com.nimbusds.jose.JWSAlgorithm.ES256, parsed.header.algorithm)
        assertNotNull(parsed.header.jwk)
        assertTrue(parsed.verify(com.nimbusds.jose.crypto.ECDSAVerifier(parsed.header.jwk.toECKey())))

        val claims = parsed.jwtClaimsSet
        assertEquals("POST", claims.getClaim("htm"))
        assertEquals("https://as.example.com/token", claims.getClaim("htu"))
        assertEquals("server-nonce", claims.getClaim("nonce"))
        assertEquals("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo", claims.getClaim("ath"))
        assertNotNull(claims.jwtid)
        assertNotNull(claims.issueTime)
        // DPoP proofs carry no PoP claims.
        assertEquals(null, claims.issuer)
        assertTrue(claims.audience.isEmpty())
        assertEquals(null, claims.expirationTime)
    }

    @Test
    fun generateDPoPProofOmitsNonceAndAthWhenAbsent_andIsFreshPerCall() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        val keyId = keystore.generateKey()

        val a = com.nimbusds.jwt.SignedJWT.parse(keystore.generateDPoPProof(keyId, "POST", "https://as.example.com/token")).jwtClaimsSet
        val b = com.nimbusds.jwt.SignedJWT.parse(keystore.generateDPoPProof(keyId, "POST", "https://as.example.com/token")).jwtClaimsSet
        assertEquals(null, a.getClaim("nonce"))
        assertEquals(null, a.getClaim("ath"))
        assertTrue("each proof must carry a fresh jti", a.jwtid != b.jwtid)
    }

    @Test
    fun generateDPoPProofThrowsForUnknownKeyId() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        try {
            keystore.generateDPoPProof(keyId = "does-not-exist", htm = "POST", htu = "https://x")
            fail("expected KeystoreException")
        } catch (e: KeystoreException) {
            // expected
        }
    }

    @Test
    fun generateKeyProofThrowsForUnknownKeyId() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)

        try {
            keystore.generateKeyProof(keyId = "does-not-exist", typ = "x", issuer = "iss", audience = "aud")
            fail("expected KeystoreException")
        } catch (e: KeystoreException) {
            // expected
        }
    }

    @Test
    fun signPresentationProducesJwt() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore.generateKey()

        val vp = keystore.signPresentation(
            nonce = "nonce-123",
            audience = "https://verifier.example.com",
            credentialIds = listOf(1L),
        )

        assertTrue(vp.contains("."))
        assertEquals(3, vp.split(".").size)
    }

    @Test
    fun lockedKeystoreOperationsThrow() = runTest {
        val keystore = JweKeystore()

        try {
            keystore.generateKey()
            fail("Expected KeystoreException for generateKey on locked keystore")
        } catch (_: KeystoreException) {
        }

        try {
            keystore.generateProof("https://issuer.example.com", "nonce")
            fail("Expected KeystoreException for generateProof on locked keystore")
        } catch (_: KeystoreException) {
        }
    }

    @Test
    fun differentPrfOutputProducesDifferentKeys() = runTest {
        val keystore1 = JweKeystore()
        keystore1.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore1.generateKey()
        val exported = keystore1.exportEncryptedContainer()

        // Trying to unlock with different PRF output should fail (wrong key)
        val differentPrf = ByteArray(32) { (it + 0x80).toByte() }
        val keystore2 = JweKeystore()
        try {
            keystore2.unlock(differentPrf, exported, hkdfSalt, hkdfInfo)
            // If we get here, decryption silently succeeded with wrong key (unlikely)
            // The JWE library should throw
            fail("Should have thrown on wrong key")
        } catch (_: Exception) {
            // Expected: decryption fails with wrong key
        }
    }

    // ── signVpToken tests ───────────────────────────────────────────

    @Test
    fun signVpToken_assembles_sdjwt_with_kbjwt() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore.generateKey()

        // Minimal SD-JWT: issuer JWT + 2 disclosures
        val issuerJwt = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ.c2ln"
        val d1 = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""["salt1","given_name","Alice"]""".toByteArray())
        val d2 = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""["salt2","family_name","Smith"]""".toByteArray())
        val credential = "$issuerJwt~$d1~$d2~"

        val vpToken = keystore.signVpToken(
            credential = credential,
            disclosedClaims = null,
            nonce = "verifier-nonce",
            audience = "https://verifier.example.com",
        )

        // VP token format: IssuerJWT~disclosure1~disclosure2~KB-JWT
        val parts = vpToken.split("~")
        assertEquals(issuerJwt, parts[0])
        assertEquals(d1, parts[1])
        assertEquals(d2, parts[2])

        // Last part is KB-JWT (3-part JWT)
        val kbJwt = parts[3]
        assertEquals(3, kbJwt.split(".").size)

        // Verify KB-JWT header contains typ and jwk
        val headerJson = String(java.util.Base64.getUrlDecoder().decode(kbJwt.split(".")[0]))
        assertTrue("KB-JWT header must contain typ", headerJson.contains("\"typ\":\"kb+jwt\""))
        assertTrue("KB-JWT header must contain jwk", headerJson.contains("\"jwk\""))
        // Must NOT contain private key
        assertFalse("KB-JWT must not contain private key d", headerJson.contains("\"d\""))

        // Verify KB-JWT payload contains sd_hash, nonce, aud
        val payloadJson = String(java.util.Base64.getUrlDecoder().decode(kbJwt.split(".")[1]))
        assertTrue("KB-JWT must contain sd_hash", payloadJson.contains("\"sd_hash\""))
        assertTrue("KB-JWT must contain nonce", payloadJson.contains("\"verifier-nonce\""))
        assertTrue("KB-JWT must contain aud", payloadJson.contains("\"https://verifier.example.com\""))
    }

    @Test
    fun signVpToken_selective_disclosure_filters_claims() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore.generateKey()

        val issuerJwt = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ.c2ln"
        val d1 = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""["salt1","given_name","Alice"]""".toByteArray())
        val d2 = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""["salt2","family_name","Smith"]""".toByteArray())
        val d3 = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""["salt3","birth_date","2000-01-01"]""".toByteArray())
        val credential = "$issuerJwt~$d1~$d2~$d3~"

        // Only disclose given_name
        val vpToken = keystore.signVpToken(
            credential = credential,
            disclosedClaims = listOf("given_name"),
            nonce = "n1",
            audience = "aud",
        )

        val parts = vpToken.split("~")
        // Should have: issuerJwt, disclosure for given_name, KB-JWT
        assertEquals(3, parts.size)
        assertEquals(issuerJwt, parts[0])
        assertEquals(d1, parts[1])  // given_name disclosure
        // KB-JWT
        assertEquals(3, parts[2].split(".").size)
    }

    @Test
    fun signVpToken_sd_hash_is_computed_correctly() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore.generateKey()

        val issuerJwt = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ.c2ln"
        val credential = "$issuerJwt~"

        val vpToken = keystore.signVpToken(
            credential = credential,
            disclosedClaims = null,
            nonce = "n",
            audience = "a",
        )

        val kbJwt = vpToken.split("~").last()
        val payloadJson = String(java.util.Base64.getUrlDecoder().decode(kbJwt.split(".")[1]))

        // Compute expected sd_hash: SHA-256 of the SD-JWT with trailing ~
        val sdJwtPresentation = "$issuerJwt~"
        val expectedHash = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
            java.security.MessageDigest.getInstance("SHA-256")
                .digest(sdJwtPresentation.toByteArray(Charsets.US_ASCII))
        )
        assertTrue("sd_hash must match", payloadJson.contains("\"$expectedHash\""))
    }

    @Test
    fun signVpToken_locked_keystore_throws() = runTest {
        val keystore = JweKeystore()
        try {
            keystore.signVpToken("cred", null, "n", "a")
            fail("Expected KeystoreException")
        } catch (_: KeystoreException) {
        }
    }

    // ── SCA (transaction_data) key binding ──────────────────────────

    private fun kbClaims(vpToken: String): Map<String, Any?> {
        val kb = vpToken.split("~").last()
        return com.nimbusds.jwt.SignedJWT.parse(kb).jwtClaimsSet.claims
    }

    private suspend fun unlockedWithKey(): JweKeystore {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore.generateKey()
        return keystore
    }

    private val scaCredential = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ.c2ln~"

    private fun binding() = TransactionBinding(
        hashes = listOf("aGFzaDE", "aGFzaDI"),
        hashAlg = "sha-256",
        responseMode = "direct_post",
        authenticationFactors = listOf(
            AuthenticationFactor(AuthenticationCategory.KNOWLEDGE, "other"),
            AuthenticationFactor(AuthenticationCategory.POSSESSION, "key_in_local_native_wscd"),
        ),
    )

    @Test
    fun signVpToken_withoutTransaction_hasExactlyTheClaimsItAlwaysHad() = runTest {
        val keystore = unlockedWithKey()

        val claims = kbClaims(keystore.signVpToken(scaCredential, null, "n", "https://v.example"))

        // Snapshot of the non-SCA KB-JWT claim set: the SCA support adds nothing here.
        assertEquals(setOf("aud", "iat", "nonce", "sd_hash"), claims.keys)
    }

    @Test
    fun signVpToken_withTransaction_carriesTheTs12Claims_andVerifies() = runTest {
        val keystore = unlockedWithKey()

        val vp = keystore.signVpToken(scaCredential, null, "n", "https://v.example", null, binding())

        val kb = com.nimbusds.jwt.SignedJWT.parse(vp.split("~").last())
        assertTrue("KB-JWT signature must verify against the jwk in its own header",
            kb.verify(com.nimbusds.jose.crypto.ECDSAVerifier(kb.header.jwk.toECKey())))
        val claims = kb.jwtClaimsSet.claims
        assertEquals(
            setOf("aud", "iat", "nonce", "sd_hash", "transaction_data_hashes", "transaction_data_hashes_alg", "jti", "response_mode", "amr"),
            claims.keys,
        )
        assertEquals(listOf("aGFzaDE", "aGFzaDI"), claims["transaction_data_hashes"])
        assertEquals("sha-256", claims["transaction_data_hashes_alg"])
        assertEquals("direct_post", claims["response_mode"])
        assertEquals(
            listOf(mapOf("knowledge" to "other"), mapOf("possession" to "key_in_local_native_wscd")),
            claims["amr"],
        )
        // sd_hash still covers the presentation exactly as before
        val presentation = vp.substringBeforeLast("~") + "~"
        val expected = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
            java.security.MessageDigest.getInstance("SHA-256").digest(presentation.toByteArray(Charsets.US_ASCII)),
        )
        assertEquals(expected, claims["sd_hash"])
    }

    @Test
    fun signVpToken_withTransaction_hasAFreshJtiEachTime() = runTest {
        val keystore = unlockedWithKey()

        val a = kbClaims(keystore.signVpToken(scaCredential, null, "n", "a", null, binding()))["jti"]
        val b = kbClaims(keystore.signVpToken(scaCredential, null, "n", "a", null, binding()))["jti"]

        assertNotEquals(a, b)
    }
}
