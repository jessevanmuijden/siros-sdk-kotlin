package org.siros.sdk.wallet.transaction

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * The golden hash vectors, `vectors/openid4x/transaction-data-hashes.json` of
 * leifj/wmp (commit 21074e4cd09c87cccbcd62afde7862b4dcb34258), copied to
 * `src/test/resources/ts12/`. Their hashes were computed with Python hashlib,
 * independent of any wallet: base64url(HASH(ASCII bytes of `raw`)), per
 * OpenID4VP 1.0 Appendix B.
 */
class TransactionDataHashingTest {
    private val vectors: List<JsonObject> by lazy {
        val text = javaClass.getResourceAsStream("/ts12/transaction-data-hashes.json")!!.readBytes().toString(Charsets.UTF_8)
        Json.parseToJsonElement(text).jsonObject["vectors"]!!.jsonArray.map { it.jsonObject }
    }

    @Test
    fun `every sha-256, sha-384 and sha-512 vector is reproduced from raw`() {
        assertTrue(vectors.size >= 7)
        for (v in vectors) {
            val raw = v["raw"]!!.jsonPrimitive.content
            for ((alg, expected) in v["hashes"]!!.jsonObject) {
                assertEquals("${v["name"]!!.jsonPrimitive.content} $alg", expected.jsonPrimitive.content, TransactionDataHashing.hash(raw, alg))
            }
        }
    }

    /** Sorted keys, compact, like a Go map re-marshal (which also escapes & < > as \\u00XX). */
    private fun goStyle(e: kotlinx.serialization.json.JsonElement): String = when (e) {
        is JsonObject -> e.entries.sortedBy { it.key }.joinToString(",", "{", "}") { "\"${it.key}\":${goStyle(it.value)}" }
        is kotlinx.serialization.json.JsonArray -> e.joinToString(",", "[", "]") { goStyle(it) }
        else -> e.toString().replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    }

    @Test
    fun `the non-canonical vectors are why raw, not a re-serialisation, is hashed`() {
        val noncanonical = vectors.filter { it["noncanonical"]?.jsonPrimitive?.content == "true" }
        assertTrue(noncanonical.size >= 4)
        fun b64(s: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray())
        for (v in noncanonical) {
            val raw = v["raw"]!!.jsonPrimitive.content
            val tree = Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(raw)))
            val expected = v["hashes"]!!.jsonObject["sha-256"]!!.jsonPrimitive.content
            // What a wallet that decodes and re-encodes would hash.
            val reserialisations = listOf(b64(tree.toString()), b64(goStyle(tree)))
            assertTrue(
                "${v["name"]!!.jsonPrimitive.content}: some re-serialisation must hash differently",
                reserialisations.any { TransactionDataHashing.hash(it, "sha-256") != expected },
            )
        }
    }

    @Test
    fun `raw decodes to the vector's json and the decoder agrees`() {
        for (v in vectors) {
            val raw = v["raw"]!!.jsonPrimitive.content
            assertEquals(v["json"]!!.jsonPrimitive.content, String(Base64.getUrlDecoder().decode(raw)))
            val decoded = TransactionDataDecoder.decode(TransactionDataEntry(raw))
            assertEquals(Json.parseToJsonElement(v["json"]!!.jsonPrimitive.content).jsonObject["type"]!!.jsonPrimitive.content, decoded.type)
        }
    }

    @Test
    fun `hashing is of the string as given, not of its decoded bytes`() {
        val raw = vectors.first()["raw"]!!.jsonPrimitive.content
        val ofDecoded = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(Base64.getUrlDecoder().decode(raw)),
        )
        assertNotEquals(ofDecoded, TransactionDataHashing.hash(raw, "sha-256"))
    }

    @Test
    fun `an unknown algorithm is not computed`() {
        assertThrows(IllegalArgumentException::class.java) { TransactionDataHashing.hash("e30", "md5") }
        assertEquals(listOf("sha-256", "sha-384", "sha-512"), TransactionDataHashing.SUPPORTED)
    }
}
