package org.siros.sdk.keystore

import com.nimbusds.jwt.JWTClaimsSet
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.KeystoreException
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason

class TransactionBindingTest {
    private val pin = AuthenticationFactor(AuthenticationCategory.KNOWLEDGE, "pin_6_or_more_digits")
    private val key = AuthenticationFactor(AuthenticationCategory.POSSESSION, "key_in_remote_wscd")
    private val face = AuthenticationFactor(AuthenticationCategory.INHERENCE, "face_device")

    private fun binding(factors: List<AuthenticationFactor> = listOf(pin, key)) =
        TransactionBinding(listOf("h1", "h2"), "sha-384", "direct_post.jwt", factors)

    private fun claims(b: TransactionBinding): Map<String, Any?> =
        JWTClaimsSet.Builder().also { b.applyTo(it) }.build().claims

    @Test
    fun `adds exactly the TS12 claims, with a string algorithm and single-key amr objects`() {
        val c = claims(binding())

        assertEquals(listOf("h1", "h2"), c["transaction_data_hashes"])
        assertEquals("sha-384", c["transaction_data_hashes_alg"])
        assertEquals("direct_post.jwt", c["response_mode"])
        assertEquals(
            listOf(mapOf("knowledge" to "pin_6_or_more_digits"), mapOf("possession" to "key_in_remote_wscd")),
            c["amr"],
        )
        assertTrue((c["jti"] as String).isNotEmpty())
        assertEquals(setOf("transaction_data_hashes", "transaction_data_hashes_alg", "response_mode", "amr", "jti"), c.keys)
    }

    @Test
    fun `jti is fresh for every presentation`() {
        val b = binding()
        assertNotEquals(claims(b)["jti"], claims(b)["jti"])
    }

    @Test
    fun `at least two different categories are required`() {
        for (factors in listOf(emptyList(), listOf(pin), listOf(pin, pin), listOf(pin, AuthenticationFactor(AuthenticationCategory.KNOWLEDGE, "pattern")))) {
            val e = assertThrows(TransactionDataError::class.java) { binding(factors) }
            assertEquals(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, e.reason)
        }
        binding(listOf(pin, face))
        binding(listOf(key, face, pin))
    }

    @Test
    fun `a method outside the TS12 vocabulary is rejected`() {
        assertThrows(IllegalArgumentException::class.java) { AuthenticationFactor(AuthenticationCategory.KNOWLEDGE, "key_in_remote_wscd") }
        assertThrows(IllegalArgumentException::class.java) { AuthenticationFactor(AuthenticationCategory.POSSESSION, "pwd") }
        assertThrows(IllegalArgumentException::class.java) { AuthenticationFactor(AuthenticationCategory.INHERENCE, "fpt") }
    }

    @Test
    fun `the vocabulary is exactly TS12 3_6`() {
        assertEquals(7, AuthenticationFactor.METHODS.getValue(AuthenticationCategory.KNOWLEDGE).size)
        assertEquals(
            setOf("key_in_remote_wscd", "key_in_local_external_wscd", "key_in_local_internal_wscd", "key_in_local_native_wscd", "other"),
            AuthenticationFactor.METHODS.getValue(AuthenticationCategory.POSSESSION),
        )
        assertEquals(
            setOf("fingerprint_device", "fingerprint_external", "face_device", "face_external", "other"),
            AuthenticationFactor.METHODS.getValue(AuthenticationCategory.INHERENCE),
        )
    }

    @Test
    fun `hashes, algorithm and response mode are required`() {
        assertThrows(IllegalArgumentException::class.java) { TransactionBinding(emptyList(), "sha-256", "m", listOf(pin, key)) }
        assertThrows(IllegalArgumentException::class.java) { TransactionBinding(listOf(""), "sha-256", "m", listOf(pin, key)) }
        assertThrows(IllegalArgumentException::class.java) { TransactionBinding(listOf("h"), "md5", "m", listOf(pin, key)) }
        assertThrows(IllegalArgumentException::class.java) { TransactionBinding(listOf("h"), "SHA-256", "m", listOf(pin, key)) }
        assertThrows(IllegalArgumentException::class.java) { TransactionBinding(listOf("h"), "sha-256", " ", listOf(pin, key)) }
    }

    @Test
    fun `a keystore that does not override the SCA overload refuses rather than signing without the hashes`() = runTest {
        val keystore = object : KeystoreManager {
            override val isUnlocked = true
            override suspend fun unlock(prfOutput: ByteArray, encryptedContainer: ByteArray, hkdfSalt: ByteArray, hkdfInfo: ByteArray) {}
            override fun lock() {}
            override suspend fun generateKey(algorithm: String) = "k"
            override suspend fun sign(keyId: String, payload: ByteArray, algorithm: String) = ByteArray(0)
            override suspend fun generateProof(audience: String, nonce: String, freshKey: Boolean) = ""
            override suspend fun signPresentation(nonce: String, audience: String, credentialIds: List<Long>, kid: String?) = ""
            override suspend fun signVpToken(credential: String, disclosedClaims: List<String>?, nonce: String, audience: String, kid: String?) = "plain"
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

        val e = runCatching { keystore.signVpToken("c", null, "n", "a", null, binding()) }.exceptionOrNull()

        assertTrue(e.toString(), e is KeystoreException)
    }

    @Test
    fun `the binding copies its lists, so the caller cannot change what is signed afterwards`() {
        val hashes = mutableListOf("h1")
        val factors = mutableListOf(pin, key)
        val b = TransactionBinding(hashes, "sha-256", "m", factors)

        hashes += "h2"
        factors.clear()

        assertEquals(listOf("h1"), b.hashes)
        assertEquals(2, b.authenticationFactors.size)
        assertEquals(listOf("h1"), claims(b)["transaction_data_hashes"])
    }
}
