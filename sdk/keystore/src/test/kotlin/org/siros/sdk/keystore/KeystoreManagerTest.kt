package org.siros.sdk.keystore

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.siros.sdk.credentials.KeystoreException
import org.siros.sdk.credentials.interop.HolderBinding
import org.junit.Test

class KeystoreManagerTest {

    // A conformer implementing only the three-argument `generateProof` -
    // exactly what a keystore written before DIIP existed looks like - used
    // by the two tests below to exercise the default
    // `generateProof(...holderBinding:)` implementation itself, not an
    // override (every first-party keystore in this SDK overrides it).
    private fun preDiipKeystore(): KeystoreManager = object : KeystoreManager {
        override val isUnlocked = true
        override suspend fun unlock(prfOutput: ByteArray, encryptedContainer: ByteArray, hkdfSalt: ByteArray, hkdfInfo: ByteArray) {}
        override fun lock() {}
        override suspend fun generateKey(algorithm: String) = "key-1"
        override suspend fun sign(keyId: String, payload: ByteArray, algorithm: String) = ByteArray(0)
        override suspend fun generateProof(audience: String, nonce: String, freshKey: Boolean) = "haip-shaped-proof"
        override suspend fun signPresentation(nonce: String, audience: String, credentialIds: List<Long>, kid: String?) = ""
        override suspend fun signVpToken(credential: String, disclosedClaims: List<String>?, nonce: String, audience: String, kid: String?) = ""
        override suspend fun exportEncryptedContainer() = ByteArray(0)
        override fun listKeys() = emptyList<KeyInfo>()
        override suspend fun saveCredential(id: Long, json: String) {}
        override suspend fun getCredential(id: Long): String? = null
        override suspend fun getAllCredentials() = emptyMap<Long, String>()
        override suspend fun deleteCredential(id: Long) {}
        override suspend fun clearCredentials() {}
        override suspend fun savePresentationRecord(id: Long, json: String) {}
        override suspend fun getAllPresentationRecords() = emptyMap<Long, String>()
        override suspend fun clearPresentationRecords() {}
    }

    @Test
    fun `a pre-DIIP conformer refuses a did-jwk request rather than silently emitting a HAIP proof`() = runTest {
        // The exact bug a DIIP-only Issuer would otherwise hit silently: a
        // third-party KeystoreManager that only ever shipped the HAIP shape
        // must fail the request, not hand back a proof that looks negotiated
        // but isn't.
        try {
            preDiipKeystore().generateProof("https://issuer.example", "nonce", false, HolderBinding.DID_JWK)
            fail("expected a KeystoreException for an unhonourable did:jwk request")
        } catch (e: KeystoreException) {
            // expected
        }
    }

    @Test
    fun `a pre-DIIP conformer still forwards a HAIP-compatible request`() = runTest {
        // null and EMBEDDED_JWK are both requests this conformer can
        // already satisfy by definition - the default must still forward
        // rather than refuse everything.
        assertEquals(
            "haip-shaped-proof",
            preDiipKeystore().generateProof("https://issuer.example", "nonce", false, null),
        )
        assertEquals(
            "haip-shaped-proof",
            preDiipKeystore().generateProof("https://issuer.example", "nonce", false, HolderBinding.EMBEDDED_JWK),
        )
    }

    @Test
    fun generateKeypairsDefaultThrowsUnsupported() = runTest {
        val keystore = object : KeystoreManager {
            override val isUnlocked = true
            override suspend fun unlock(prfOutput: ByteArray, encryptedContainer: ByteArray, hkdfSalt: ByteArray, hkdfInfo: ByteArray) {}
            override fun lock() {}
            override suspend fun generateKey(algorithm: String) = "key-1"
            override suspend fun sign(keyId: String, payload: ByteArray, algorithm: String) = ByteArray(0)
            // The three-argument form is the requirement; the holder-binding
            // overload is defaulted, which is what keeps a keystore written
            // before DIIP compiling. Implementing only that one is exactly
            // what such a keystore looks like.
            override suspend fun generateProof(audience: String, nonce: String, freshKey: Boolean) = ""
            override suspend fun signPresentation(nonce: String, audience: String, credentialIds: List<Long>, kid: String?) = ""
            override suspend fun signVpToken(credential: String, disclosedClaims: List<String>?, nonce: String, audience: String, kid: String?) = ""
            override suspend fun exportEncryptedContainer() = ByteArray(0)
            override fun listKeys() = emptyList<KeyInfo>()
            override suspend fun saveCredential(id: Long, json: String) {}
            override suspend fun getCredential(id: Long): String? = null
            override suspend fun getAllCredentials() = emptyMap<Long, String>()
            override suspend fun deleteCredential(id: Long) {}
            override suspend fun clearCredentials() {}
            override suspend fun savePresentationRecord(id: Long, json: String) {}
            override suspend fun getAllPresentationRecords() = emptyMap<Long, String>()
            override suspend fun clearPresentationRecords() {}
        }

        try {
            keystore.generateKeypairs(1)
            fail("Should throw UnsupportedOperationException")
        } catch (e: UnsupportedOperationException) {
            // expected
        }
    }
}
