package org.siros.sdk.keystore

import io.mockk.mockk
import java.io.File
import javax.crypto.SecretKey
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.KeystoreException

/**
 * [PrivateSeed] (privatedata-spec 2.7, `private_seed` per issuer, label `v2`) against the spec's own
 * `derived-secrets.json`, vendored verbatim (see `vectors.PROVENANCE.txt`): every vector's seed and psc, every refused
 * input, every must-differ pair; plus the keystore's own contract.
 */
class PrivateSeedTest {
    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    private fun JsonObject.str(key: String) = this[key]!!.jsonPrimitive.content

    /** A fixed root, using the keystore's own HKDF. */
    private class FixedRoot(private val root: ByteArray) : RootSecret {
        override fun deriveSecret(info: ByteArray, length: Int) = EncryptedContainer.hkdfSha256(root, ByteArray(0), info, length)
    }

    private val issuer = "https://issuer-a.example.com"

    private val file: JsonObject by lazy {
        val bytes = javaClass.classLoader!!.getResourceAsStream("privatedata-spec/derived-secrets.json")!!.readBytes()
        val sha = java.security.MessageDigest.getInstance("SHA-256").digest(bytes).toHex()
        assertEquals("derived-secrets.json no longer matches the hash in vectors.PROVENANCE.txt", "fdcdb5f01be080adaed1dc7a9f7c4bc9c9080322a92f764bc6a4b0a961209d2c", sha)
        Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
    }

    private fun list(key: String) = file[key]!!.jsonArray.map { it.jsonObject }

    /** The field of an entry: its text, or `a` repeated `<field>_fill` times. */
    private fun field(v: JsonObject, name: String): String =
        v[name]?.jsonPrimitive?.content ?: "a".repeat(v["${name}_fill"]!!.jsonPrimitive.content.toInt())

    private fun seedOf(v: JsonObject) = PrivateSeed(FixedRoot(hex(v.str("root_hex")))).derive(field(v, "credential_type"), field(v, "issuer"))

    @Test
    fun `the label is the documented one`() {
        assertEquals("org.siros.private_seed/v2", PrivateSeed.LABEL)
        assertEquals(file.str("label"), PrivateSeed.LABEL)
        assertEquals(16, PrivateSeed.SEED_BYTES)
    }

    @Test
    fun `every vector gives its seed and psc`() {
        val vectors = list("vectors")
        assertEquals(11, vectors.size)
        for (v in vectors) {
            val seeds = PrivateSeed(FixedRoot(hex(v.str("root_hex"))))
            val type = field(v, "credential_type")
            val issuer = field(v, "issuer")
            assertEquals(v.str("name"), v.str("seed_hex"), seeds.derive(type, issuer).toHex())
            assertEquals(v.str("name"), v.str("psc_hex"), seeds.psc(type, issuer).toHex())
            assertTrue(v.str("name"), seeds.matchesCommitment(type, issuer, hex(v.str("psc_hex"))))
        }
    }

    @Test
    fun `every refused input derives nothing and its message names no value`() {
        val refused = list("refused")
        assertEquals(4, refused.size)
        for (v in refused) {
            val seeds = PrivateSeed(FixedRoot(hex(v.str("root_hex"))))
            val type = field(v, "credential_type")
            val issuer = field(v, "issuer")
            for (call in listOf<() -> Any>(
                { seeds.derive(type, issuer) },
                { seeds.psc(type, issuer) },
                { seeds.matchesCommitment(type, issuer, ByteArray(32)) },
                { PrivateSeed.info(type, issuer) },
            )) {
                val e = assertThrows(v.str("name"), IllegalArgumentException::class.java) { call() }
                assertFalse(e.message.orEmpty().contains("issuer-a"))
            }
        }
    }

    @Test
    fun `every must-differ pair gives different seeds`() {
        val byName = list("vectors").associateBy { it.str("name") }
        val pairs = file["must_differ"]!!.jsonArray.map { p -> p.jsonArray.map { it.jsonPrimitive.content } }
        assertEquals(5, pairs.size)
        for ((a, b) in pairs) {
            assertNotEquals("$a vs $b", seedOf(byName.getValue(a)).toHex(), seedOf(byName.getValue(b)).toHex())
        }
    }

    @Test
    fun `seed is 16 bytes, stable per type and issuer and distinct across both`() {
        val seeds = PrivateSeed(FixedRoot(ByteArray(32) { it.toByte() }))
        val a = seeds.derive("type-a", issuer)
        assertEquals(16, a.size)
        assertArrayEquals(a, seeds.derive("type-a", issuer))
        assertNotEquals(a.toHex(), seeds.derive("type-b", issuer).toHex())
        assertNotEquals(a.toHex(), seeds.derive("type-a", "https://issuer-b.example.com").toHex())
        assertEquals(32, seeds.psc("type-a", issuer).size)
    }

    @Test
    fun `the issuer is the exact string - a trailing slash is another psc`() {
        val seeds = PrivateSeed(FixedRoot(ByteArray(32) { it.toByte() }))
        assertNotEquals(seeds.psc("t", "https://i.example").toHex(), seeds.psc("t", "https://i.example/").toHex())
        assertNotEquals(seeds.psc("t", "https://i.example").toHex(), seeds.psc("t", "https://I.example").toHex())
        assertNotEquals(seeds.psc("t", "https://i.example").toHex(), seeds.psc("t", "http://i.example").toHex())
        assertTrue(seeds.matchesCommitment("t", "https://i.example/", seeds.psc("t", "https://i.example/")))
        assertFalse(seeds.matchesCommitment("t", "https://i.example", seeds.psc("t", "https://i.example/")))
    }

    @Test
    fun `matchesCommitment fails closed`() {
        val seeds = PrivateSeed(FixedRoot(ByteArray(32) { it.toByte() }))
        val psc = seeds.psc("t", issuer)
        assertTrue(seeds.matchesCommitment("t", issuer, psc))
        assertFalse(seeds.matchesCommitment("other", issuer, psc))
        assertFalse(seeds.matchesCommitment("t", "https://issuer-b.example.com", psc))
        assertFalse(seeds.matchesCommitment("t", issuer, psc.copyOf().also { it[31] = (it[31] + 1).toByte() }))
        assertFalse(seeds.matchesCommitment("t", issuer, psc.copyOf(31)))
        assertFalse(seeds.matchesCommitment("t", issuer, psc + 0))
        assertFalse(seeds.matchesCommitment("t", issuer, ByteArray(0)))
        assertFalse(seeds.matchesCommitment("t", issuer, ByteArray(32)))
    }

    private val prf = ByteArray(32) { it.toByte() }
    private val salt = ByteArray(32) { (it + 0x10).toByte() }
    private val info = "SIROS Wallet PRF".toByteArray()

    @Test
    fun `a locked keystore throws and derives nothing`() = runTest {
        val locked = JweKeystore()
        val seeds = PrivateSeed(locked.rootSecretForTest())
        assertThrows(KeystoreException::class.java) { seeds.psc("t", issuer) }
        assertThrows(KeystoreException::class.java) { seeds.matchesCommitment("t", issuer, ByteArray(32)) }
        assertThrows(KeystoreException::class.java) { seeds.derive("t", issuer) }

        val unlocked = JweKeystore().also { it.unlock(prf, ByteArray(0), salt, info) }
        val unlockedSeeds = PrivateSeed(unlocked.rootSecretForTest())
        unlockedSeeds.psc("t", issuer)
        unlocked.lock()
        assertThrows(KeystoreException::class.java) { unlockedSeeds.psc("t", issuer) }
    }

    @Test
    fun `the seed follows mainKey - stable across reopen, new for a new container`() = runTest {
        val first = JweKeystore().also { it.unlock(prf, ByteArray(0), salt, info) }
        val before = PrivateSeed(first.rootSecretForTest()).psc("t", issuer)
        val reopened = JweKeystore().also { it.unlock(prf, first.exportEncryptedContainer(), salt, info) }
        assertArrayEquals(before, PrivateSeed(reopened.rootSecretForTest()).psc("t", issuer))
        // Same PRF output, new container, new random mainKey: a seed derived from the PRF output would not change.
        val other = JweKeystore().also { it.unlock(prf, ByteArray(0), salt, info) }
        assertNotEquals(before.toHex(), PrivateSeed(other.rootSecretForTest()).psc("t", issuer).toHex())
    }

    @Test
    fun `no public keystore member returns key material`() {
        for (cls in listOf(JweKeystore::class.java, WscdKeystoreAdapter::class.java)) {
            for (m in cls.methods) {
                assertFalse("${cls.simpleName}.${m.name}", SecretKey::class.java.isAssignableFrom(m.returnType))
            }
        }
    }

    @Test
    fun `the WSCD adapter exposes the same purpose-bound source`() {
        val adapter = WscdKeystoreAdapter(mockk(relaxed = true))
        assertTrue(adapter is HolderWitnessSource)
        assertThrows(KeystoreException::class.java) { adapter.privateSeedCommitment("t", issuer) }
    }

    @Test
    fun `no public keystore member derives a secret or exposes the root`() {
        for (cls in listOf(JweKeystore::class.java, WscdKeystoreAdapter::class.java)) {
            assertTrue("${cls.simpleName} implements RootSecret", cls.interfaces.none { it.simpleName == "RootSecret" })
            // An internal member is public in bytecode but carries a `$module` suffix on its name.
            for (m in cls.methods.filter { '$' !in it.name }) {
                assertFalse("${cls.simpleName}.${m.name}", m.name.startsWith("deriveSecret"))
                assertFalse("${cls.simpleName}.${m.name}", m.name.contains("rootSecret", ignoreCase = true))
            }
        }
        // The public source surface has no member that returns a seed or a witness provider.
        for (m in HolderWitnessSource::class.java.methods) {
            assertFalse(m.name, CircuitZkWitnessProvider::class.java.isAssignableFrom(m.returnType))
        }
        assertEquals(setOf("privateSeedCommitment", "circuitZkPresenter"), HolderWitnessSource::class.java.methods.map { it.name }.toSet())
    }

    @Test
    fun `a fixed-root source gives the vector commitment`() {
        val v = list("vectors").first()
        val source = FixedRootHolderWitnessSource(hex(v.str("root_hex")))
        assertEquals(v.str("psc_hex"), source.privateSeedCommitment(v.str("credential_type"), v.str("issuer")).toHex())
        assertThrows(IllegalArgumentException::class.java) { source.privateSeedCommitment(v.str("credential_type"), "") }
    }
}
