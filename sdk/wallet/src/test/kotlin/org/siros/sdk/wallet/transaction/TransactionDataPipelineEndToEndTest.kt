package org.siros.sdk.wallet.transaction

import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.keystore.AuthenticationCategory
import org.siros.sdk.keystore.AuthenticationFactor
import org.siros.sdk.keystore.JweKeystore
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.FakeSource
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.credential
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.raw
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.request
import java.security.MessageDigest
import java.util.Base64

/**
 * A request in, a KB-JWT out, checked the way a verifier would: against the
 * bytes of `raw` hashed independently here, not against the code under test.
 * Core pipeline only; the transports are wired in a later change.
 */
class TransactionDataPipelineEndToEndTest {
    private val prf = ByteArray(32) { it.toByte() }
    private val salt = ByteArray(32) { (it + 0x10).toByte() }
    private val info = "SIROS Wallet PRF".toByteArray()

    private val factors = listOf(
        AuthenticationFactor(AuthenticationCategory.KNOWLEDGE, "pin_6_or_more_digits"),
        AuthenticationFactor(AuthenticationCategory.POSSESSION, "key_in_local_native_wscd"),
    )

    private fun independentHash(raw: String, jcaName: String) = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance(jcaName).digest(raw.toByteArray(Charsets.US_ASCII)))

    private fun run(rawEntries: List<String>): Pair<SignedJWT, String> = runBlocking {
        val keystore = JweKeystore()
        keystore.unlock(prf, ByteArray(0), salt, info)
        val cred = credential(kid = keystore.generateKey())
        val req = request(rawEntries.map { TransactionDataEntry(it) }, mapOf("pay" to listOf(cred)), responseMode = "direct_post.jwt")

        val validated = TransactionDataValidator(FakeSource()).validate(req)
        val binding = validated.bindingFor("pay", factors)!!
        val vp = keystore.signVpToken(cred.raw, null, "verifier-nonce", "x509_san_dns:shop.example.com", cred.kid, binding)
        SignedJWT.parse(vp.split("~").last()) to vp
    }

    @Test
    fun `the KB-JWT satisfies the verifier contract`() {
        val e1 = raw(algs = """["sha-512"]""")
        val e2 = raw(payload = """{"transaction_id":"tx-2","payee":{"name":"Åkesson / Son","id":"SE1"},"currency":"SEK","amount":10}""", algs = """["sha-512","sha-256"]""")

        val (kb, _) = run(listOf(e1, e2))

        val claims = kb.jwtClaimsSet.claims
        assertTrue("signature verifies under the header's jwk", kb.verify(ECDSAVerifier(kb.header.jwk.toECKey())))
        assertEquals("kb+jwt", kb.header.type.type)
        assertEquals("sha-512", claims["transaction_data_hashes_alg"])      // a string
        assertEquals(listOf(independentHash(e1, "SHA-512"), independentHash(e2, "SHA-512")), claims["transaction_data_hashes"])
        assertEquals("direct_post.jwt", claims["response_mode"])
        assertTrue((claims["jti"] as String).length >= 32)
        assertEquals("verifier-nonce", claims["nonce"])
        assertEquals(listOf("x509_san_dns:shop.example.com"), kb.jwtClaimsSet.audience)
        val amr = claims["amr"] as List<*>
        assertEquals(2, amr.size)
        assertEquals(2, amr.map { (it as Map<*, *>).keys.single() }.toSet().size)
    }

    @Test
    fun `the hash covers the verifier's bytes, so a non-canonical entry is still bound exactly`() {
        // Pretty-printed JSON: any wallet that re-serialises would hash something else.
        val pretty = TransactionTestFixtures.b64(
            "{\n  \"type\": \"urn:eudi:sca:payment:1\",\n  \"credential_ids\": [\"pay\"],\n" +
                "  \"payload\": {\"transaction_id\": \"tx-1\", \"payee\": {\"name\": \"Shop\", \"id\": \"1\"}, \"currency\": \"EUR\", \"amount\": 5}\n}",
        )

        val (kb, _) = run(listOf(pretty))

        assertEquals(listOf(independentHash(pretty, "SHA-256")), kb.jwtClaimsSet.claims["transaction_data_hashes"])
        assertEquals("sha-256", kb.jwtClaimsSet.claims["transaction_data_hashes_alg"])
    }

    @Test
    fun `two presentations of the same transaction differ in jti`() {
        val e = raw()
        assertNotEquals(run(listOf(e)).first.jwtClaimsSet.claims["jti"], run(listOf(e)).first.jwtClaimsSet.claims["jti"])
    }
}
