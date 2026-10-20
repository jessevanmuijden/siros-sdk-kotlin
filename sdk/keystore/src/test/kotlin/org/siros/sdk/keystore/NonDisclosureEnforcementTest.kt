package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import io.mockk.coEvery
import io.mockk.mockk
import java.util.Base64
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.siros.sdk.credentials.CredentialDisclosureGuard
import org.siros.sdk.credentials.DisclosureRefusedException
import org.siros.sdk.credentials.NonDisclosurePolicy
import org.siros.sdk.credentials.ZkProofSystemRegistry
import timber.log.Timber

/** Presentation building fails closed on a protected claim: every builder, never a silent strip. */
class NonDisclosureEnforcementTest {
    private val nym = NonDisclosurePolicy.NYM_AUTH_DOCTYPE
    private val prf = ByteArray(32) { it.toByte() }
    private val salt = ByteArray(32) { (it + 0x10).toByte() }
    private val info = "SIROS Wallet PRF".toByteArray()

    private val logs = mutableListOf<String>()
    private val tree = object : Timber.Tree() {
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) { logs += message + (t?.toString() ?: "") }
    }

    @Before fun plant() = Timber.plant(tree)

    @After
    fun reset() {
        Timber.uproot(tree)
        CredentialDisclosureGuard.policy = NonDisclosurePolicy.DEFAULT
    }

    private fun item(id: Long, name: String, value: CBORObject): CBORObject {
        val m = CBORObject.NewMap()
        m[CBORObject.FromObject("digestID")] = CBORObject.FromObject(id)
        m[CBORObject.FromObject("random")] = CBORObject.FromObject(ByteArray(16))
        m[CBORObject.FromObject("elementIdentifier")] = CBORObject.FromObject(name)
        m[CBORObject.FromObject("elementValue")] = value
        return CBORObject.FromObjectAndTag(m.EncodeToBytes(), 24)
    }

    private fun mdocBytes(docType: String): ByteArray {
        val items = CBORObject.NewArray()
        items.Add(item(0, "birth_date", CBORObject.FromObjectAndTag("2000-06-15", 1004)))
        items.Add(item(1, "ssc", CBORObject.FromObject(ByteArray(32) { 1 })))
        items.Add(item(2, "psc", CBORObject.FromObject(ByteArray(32) { 2 })))
        items.Add(item(3, "given_name", CBORObject.FromObject("Jane")))
        val ns = CBORObject.NewMap()
        ns[CBORObject.FromObject(docType)] = items
        val mso = CBORObject.NewMap()
        mso[CBORObject.FromObject("docType")] = CBORObject.FromObject(docType)
        val auth = CBORObject.NewArray()
        auth.Add(CBORObject.FromObject(ByteArray(0)))
        auth.Add(CBORObject.NewMap())
        auth.Add(CBORObject.FromObject(CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()))
        auth.Add(CBORObject.FromObject(ByteArray(64)))
        val signed = CBORObject.NewMap()
        signed[CBORObject.FromObject("nameSpaces")] = ns
        signed[CBORObject.FromObject("issuerAuth")] = auth
        return signed.EncodeToBytes()
    }

    /** A compact SD-JWT whose vct has a policy entry for `secret`. */
    private fun sdJwt(vct: String): Pair<String, List<String>> {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val d = listOf(
            enc.encodeToString("""["s1","secret","hidden"]""".toByteArray()),
            enc.encodeToString("""["s2","name","Jane"]""".toByteArray()),
        )
        val payload = enc.encodeToString("""{"vct":"$vct"}""".toByteArray())
        return "${enc.encodeToString("""{"alg":"ES256"}""".toByteArray())}.$payload.c2ln~${d.joinToString("~")}~" to d
    }

    private suspend fun jwe(): JweKeystore = JweKeystore().also {
        it.unlock(prf, ByteArray(0), salt, info)
        it.generateKey()
    }

    private fun adapter(): WscdKeystoreAdapter {
        val signer = mockk<Signer>(relaxed = true)
        coEvery { signer.generateKey(any()) } returns "k1"
        coEvery { signer.sign(any(), any()) } returns ByteArray(64)
        coEvery { signer.listKeys() } returns listOf(SignerKeyInfo("k1", "ES256"))
        coEvery { signer.exportPublicKey(any()) } returns
            com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate().toPublicJWK().toJSONString().toByteArray()
        return WscdKeystoreAdapter(signer)
    }

    private suspend fun WscdKeystoreAdapter.ready() = also { it.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0)) }

    // ---- mdoc: every builder, on both keystores ----

    @Test
    fun `the jwe keystore has no mdoc disclosure path at all`() = runTest {
        // It cannot build an mdoc DeviceResponse, so there is nothing to guard there; the WSCD adapter is the mdoc builder.
        val ks = jwe()
        assertThrows(UnsupportedOperationException::class.java) {
            kotlinx.coroutines.runBlocking { ks.signMdocPresentationForDCAPI(mdocBytes(nym), null, "n", "https://rp.example", null, null) }
        }
    }

    @Test
    fun `wscd adapter refuses the same`() = runTest {
        val a = adapter().ready()
        val bytes = mdocBytes(nym)
        for (claims in listOf(null, listOf("ssc"), listOf("psc"))) {
            assertThrows(DisclosureRefusedException::class.java) {
                kotlinx.coroutines.runBlocking { a.signMdocPresentationForDCAPI(bytes, claims, "n", "https://rp.example", null, null) }
            }
            assertThrows(DisclosureRefusedException::class.java) {
                kotlinx.coroutines.runBlocking { a.signMdocPresentation(bytes, claims, "n", "aud", "https://rp.example/resp", null, null) }
            }
            assertThrows(DisclosureRefusedException::class.java) {
                kotlinx.coroutines.runBlocking { a.signMdocPresentationForProximity(bytes, claims, ByteArray(8), null) }
            }
        }
        assertTrue(a.signMdocPresentationForDCAPI(bytes, listOf("given_name"), "n", "https://rp.example", null, null).isNotEmpty())
    }

    @Test
    fun `a type with no policy entry presents as before, ssc included`() = runTest {
        val bytes = mdocBytes("other.doctype")
        assertTrue(adapter().ready().signMdocPresentationForDCAPI(bytes, listOf("ssc"), "n", "https://rp.example", null, null).isNotEmpty())
        assertTrue(adapter().ready().signMdocPresentationForDCAPI(bytes, null, "n", "https://rp.example", null, null).isNotEmpty())
    }

    @Test
    fun `the policy is data - switching it off allows what the default refuses`() = runTest {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy.NONE
        assertTrue(adapter().ready().signMdocPresentationForDCAPI(mdocBytes(nym), listOf("ssc"), "n", "https://rp.example", null, null).isNotEmpty())
    }

    // ---- SD-JWT ----

    @Test
    fun `both keystores refuse an sd-jwt presentation that would disclose a protected claim`() = runTest {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("secret"))))
        val (raw, _) = sdJwt("my.vct")
        val j = jwe()
        val a = adapter().ready()
        for (claims in listOf(null, emptyList(), listOf("secret"), listOf("secret", "name"))) {
            assertThrows(DisclosureRefusedException::class.java) {
                kotlinx.coroutines.runBlocking { j.signVpToken(raw, claims, "n", "aud") }
            }
            assertThrows(DisclosureRefusedException::class.java) {
                kotlinx.coroutines.runBlocking { a.signVpToken(raw, claims, "n", "aud") }
            }
        }
        // Without the protected disclosure it is presented, and the protected one is not in it.
        val presented = j.signVpToken(raw, listOf("name"), "n", "aud")
        assertFalse(presented.contains(raw.split("~")[1]))
        assertTrue(a.signVpToken(raw, listOf("name"), "n", "aud").isNotEmpty())
        // Another vct is unaffected.
        val (other, _) = sdJwt("another.vct")
        assertTrue(j.signVpToken(other, null, "n", "aud").isNotEmpty())
    }

    /** A compact SD-JWT with the issuer payload verbatim and the given disclosures (none by default). */
    private fun cleartextSdJwt(payloadJson: String, vararg disclosures: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        return "${enc.encodeToString("""{"alg":"ES256"}""".toByteArray())}.${enc.encodeToString(payloadJson.toByteArray())}.c2ln~" +
            disclosures.joinToString("") { "$it~" }
    }

    private val cleartextPolicy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("secret"))))
    private val nameDisclosure = Base64.getUrlEncoder().withoutPadding().encodeToString("""["s2","name","Jane"]""".toByteArray())

    private fun cleartextCredentials() = listOf(
        cleartextSdJwt("""{"vct":"my.vct","secret":"s"}"""),
        cleartextSdJwt("""{"vct":"my.vct","secret":"s"}""", nameDisclosure),
    )

    @Test
    fun `the jwe keystore refuses a protected claim stored in the issuer payload, with or without disclosures`() = runTest {
        CredentialDisclosureGuard.policy = cleartextPolicy
        val j = jwe()
        for (raw in cleartextCredentials()) {
            for (claims in listOf(null, emptyList(), listOf("name"))) {
                assertThrows(DisclosureRefusedException::class.java) { kotlinx.coroutines.runBlocking { j.signVpToken(raw, claims, "n", "aud") } }
            }
        }
        val clean = cleartextSdJwt("""{"vct":"my.vct","other":"o"}""", nameDisclosure)
        assertTrue(j.signVpToken(clean, listOf("name"), "n", "aud").isNotEmpty())
    }

    @Test
    fun `the wscd adapter refuses a protected claim stored in the issuer payload, with or without disclosures`() = runTest {
        CredentialDisclosureGuard.policy = cleartextPolicy
        val a = adapter().ready()
        for (raw in cleartextCredentials()) {
            for (claims in listOf(null, emptyList(), listOf("name"))) {
                assertThrows(DisclosureRefusedException::class.java) { kotlinx.coroutines.runBlocking { a.signVpToken(raw, claims, "n", "aud") } }
            }
        }
        val clean = cleartextSdJwt("""{"vct":"my.vct","other":"o"}""", nameDisclosure)
        assertTrue(a.signVpToken(clean, null, "n", "aud").isNotEmpty())
    }

    // ---- legacy ZK ----

    @Test
    fun `a legacy zk proof over a protected element is refused before any proof system is consulted`() = runTest {
        val presentation = ZkMdocPresentation(ZkProofSystemRegistry(emptyList()))
        assertThrows(DisclosureRefusedException::class.java) {
            kotlinx.coroutines.runBlocking {
                presentation.present(
                    ZkMdocPresentation.Request(mdocBytes(nym), emptyList(), ByteArray(1), listOf("given_name", "ssc")),
                    { _, _ -> ByteArray(64) },
                )
            }
        }
        // A request for an unprotected element gets as far as proof-system resolution.
        assertThrows(ZkMdocPresentation.NoMatchingProofSystem::class.java) {
            kotlinx.coroutines.runBlocking {
                presentation.present(ZkMdocPresentation.Request(mdocBytes(nym), emptyList(), ByteArray(1), listOf("given_name")), { _, _ -> ByteArray(64) })
            }
        }
    }

    @Test
    fun `the public zk response builders refuse a protected element, called directly`() {
        val spec = org.siros.sdk.credentials.ZkSystemSpec(id = "s", system = "longfellow-libzk-v1")
        val result = org.siros.sdk.credentials.ZkProofResult(proofBytes = ByteArray(4), timestamp = "2026-01-01T00:00:00Z")
        val p = ZkMdocPresentation(ZkProofSystemRegistry(emptyList()))
        assertThrows(DisclosureRefusedException::class.java) {
            p.buildDeviceResponse(mdocBytes(nym), nym, spec, listOf("given_name", "ssc"), result)
        }
        assertThrows(DisclosureRefusedException::class.java) {
            MdocDeviceResponseBuilder.buildZkDeviceResponse(
                proofBytes = ByteArray(4), zkSystemId = "s", docType = nym, timestamp = "2026-01-01T00:00:00Z", namespace = nym,
                disclosedClaims = mapOf("psc" to CBORObject.FromObject(ByteArray(32))), issuerAuth = CBORObject.NewArray(),
            )
        }
        // An unprotected element, and a type with no policy entry, still build.
        assertTrue(p.buildDeviceResponse(mdocBytes(nym), nym, spec, listOf("given_name"), result).isNotEmpty())
        assertTrue(
            MdocDeviceResponseBuilder.buildZkDeviceResponse(
                proofBytes = ByteArray(4), zkSystemId = "s", docType = "other.doctype", timestamp = "2026-01-01T00:00:00Z", namespace = "other.doctype",
                disclosedClaims = mapOf("ssc" to CBORObject.FromObject(ByteArray(32))), issuerAuth = CBORObject.NewArray(),
            ).isNotEmpty(),
        )
    }

    @Test
    fun `a private zk witness is not a disclosure, the builder's public paths are`() = runTest {
        val b = MdocDeviceResponseBuilder(mdocBytes(nym))
        val transcript = CBORObject.NewArray().EncodeToBytes()
        assertTrue(b.buildPrivateWitnessResponse(transcript) { ByteArray(64) }.isNotEmpty())
        assertThrows(DisclosureRefusedException::class.java) {
            kotlinx.coroutines.runBlocking { b.buildForProximity(transcript, null) { ByteArray(64) } }
        }
    }

    // ---- logs ----

    @Test
    fun `a refusal logs and says nothing that names the protected claim`() = runTest {
        val ks = adapter().ready()
        val e = runCatching { ks.signMdocPresentationForDCAPI(mdocBytes(nym), listOf("ssc"), "n", "https://rp.example", null, null) }.exceptionOrNull()
        assertTrue(e is DisclosureRefusedException)
        assertFalse(e!!.message!!.contains("ssc"))
        assertEquals(0, logs.count { it.contains("ssc") || it.contains("psc") })
    }
}
