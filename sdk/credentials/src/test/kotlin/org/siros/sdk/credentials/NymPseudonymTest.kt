package org.siros.sdk.credentials

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Checks [NymPseudonym] against `spec/nym-pseudonym-vectors.json`, the vector
 * file shared with the Swift SDK. The expected values come from
 * `tools/gen_nym_pseudonym_vectors.py`, independent code; see
 * `spec/nym-pseudonym-vectors.md`.
 */
class NymPseudonymTest {
    private val file: JsonObject by lazy {
        // Gradle runs unit tests with the module directory as the working directory.
        val f = File("../../spec/nym-pseudonym-vectors.json")
        require(f.isFile) { "vector file not found at ${f.absolutePath}" }
        Json.parseToJsonElement(f.readText()).jsonObject
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    private fun JsonObject.str(key: String): String? = this[key]?.jsonPrimitive?.content

    private fun derive(v: JsonObject): ByteArray = NymPseudonym.derive(
        config = v.str("config")!!,
        seed = hex(v.str("seed_hex")!!),
        proverInput = v.str("prover_input_hex")?.let(::hex),
        verifierId = v.str("verifier_id"),
        verifierContext = v.str("verifier_context"),
    )

    @Test
    fun `every shared vector reproduces`() {
        val vectors: JsonArray = file["vectors"]!!.jsonArray
        assertTrue(vectors.size >= 17)
        for (e in vectors) {
            val v = e.jsonObject
            assertEquals(v.str("name"), v.str("expected_hex"), derive(v).toHex())
        }
    }

    @Test
    fun `vectors cover all four configs`() {
        val covered = file["vectors"]!!.jsonArray.map { it.jsonObject.str("config") }.toSet()
        assertEquals(NymPseudonym.configs.keys, covered)
        assertEquals(4, covered.size)
    }

    @Test
    fun `every shared rejection is refused with its error`() {
        val rejections = file["rejections"]!!.jsonArray
        val seen = mutableSetOf<String>()
        for (e in rejections) {
            val v = e.jsonObject
            val expected = v.str("error")!!
            seen += expected
            try {
                derive(v)
                fail("${v.str("name")}: expected $expected")
            } catch (err: NymPseudonymError) {
                assertEquals(v.str("name"), expected, err.reason.name)
            }
        }
        assertEquals(NymPseudonymReason.values().map { it.name }.toSet(), seen)
    }

    @Test
    fun `config table matches the rulebook`() {
        val t = NymPseudonym.configs
        assertEquals(setOf("known-offender-matching-ssc", "known-offender-matching-psc", "account-recovery-ssc", "user-managed-pseudonym-xsite-ssc"), t.keys)
        assertEquals(NymSeedKind.SECRET, t.getValue("known-offender-matching-ssc").seed)
        assertEquals(NymSeedKind.PRIVATE, t.getValue("known-offender-matching-psc").seed)
        assertEquals(NymSeedKind.SECRET, t.getValue("account-recovery-ssc").seed)
        assertEquals(NymSeedKind.SECRET, t.getValue("user-managed-pseudonym-xsite-ssc").seed)
        assertEquals(16, NymSeedKind.SECRET.bytes)
        assertEquals(16, NymSeedKind.PRIVATE.bytes)
    }

    @Test
    fun `describe names the seed kind of every config explicitly`() {
        assertEquals(NymSeedKind.SECRET, NymPseudonym.describe("known-offender-matching-ssc")!!.seedKind)
        assertEquals(NymSeedKind.PRIVATE, NymPseudonym.describe("known-offender-matching-psc")!!.seedKind)
        assertEquals(NymSeedKind.SECRET, NymPseudonym.describe("account-recovery-ssc")!!.seedKind)
        val xsite = NymPseudonym.describe("user-managed-pseudonym-xsite-ssc")!!
        assertEquals(NymSeedKind.SECRET, xsite.seedKind)
        assertTrue(xsite.userValue)
        assertEquals(null, NymPseudonym.describe("made-up"))
    }

    @Test
    fun `output is 32 bytes and the seed is left untouched`() {
        val seed = ByteArray(16) { it.toByte() }
        val copy = seed.copyOf()
        val out = NymPseudonym.derive("known-offender-matching-ssc", seed, verifierId = "x")
        assertEquals(32, out.size)
        assertTrue(seed.contentEquals(copy))
    }

    @Test
    fun `derivation is deterministic and the DST separates configs`() {
        val seed = ByteArray(16)
        val a = NymPseudonym.derive("known-offender-matching-ssc", seed, verifierId = "x")
        assertTrue(a.contentEquals(NymPseudonym.derive("known-offender-matching-ssc", seed, verifierId = "x")))
        assertFalse(a.contentEquals(NymPseudonym.derive("known-offender-matching-psc", seed, verifierId = "x")))
    }

    @Test
    fun `an empty string is supplied, not missing`() {
        NymPseudonym.derive("account-recovery-ssc", ByteArray(16), verifierId = "", verifierContext = "")
    }

    @Test
    fun `error is a SirosException with a machine code and no seed in the message`() {
        val seed = ByteArray(15) { 0x7A }
        try {
            NymPseudonym.derive("known-offender-matching-ssc", seed, verifierId = "x")
            fail()
        } catch (e: NymPseudonymError) {
            assertEquals("nym_pseudonym_wrong_seed_length", e.errorCode)
            assertFalse(e.message!!.contains("7a", ignoreCase = true))
        }
    }
}
