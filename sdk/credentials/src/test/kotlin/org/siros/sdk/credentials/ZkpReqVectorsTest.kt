package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORObject
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The shared `zkp_req` conformance vectors of siros-dc-matcher (pull request 50 head 69e6be1, rulebook v0.4; vendored
 * verbatim in `spec/zkp-req-vectors`, see its SOURCE.md): the response validator, the unsatisfiable-request rules and
 * `proof_time`; and what the SDK builds against the same validator.
 */
class ZkpReqVectorsTest {
    private val root = File("../../spec/zkp-req-vectors").also { require(it.isDirectory) { "vector dir not found at ${it.absolutePath}" } }
    private fun jsonFiles(dir: String) = File(root, dir).listFiles { f -> f.extension == "json" }!!.sortedBy { it.name }

    private fun plan(query: JsonObject, clientMetadata: JsonObject?): CircuitZkPlan {
        val functions = query["_req"]!!.jsonArray.map {
            val o = it.jsonObject
            CircuitZkFunction(o["fn_id"]!!.jsonPrimitive.content, o["return"]!!.jsonPrimitive.content, (o["params"] as? JsonObject) ?: JsonObject(emptyMap()))
        }
        val offered = clientMetadata?.get("vp_formats_supported")?.jsonObject?.get("zkp_req")?.jsonObject
        fun list(k: String) = offered?.get(k)?.jsonArray?.map { it.jsonPrimitive.content }
        val filter = list("proof_system_values").let { systems -> list("system_id_values").let { ids -> if (systems == null && ids == null) null else CircuitZkCircuitFilter(systems, ids) } }
        return CircuitZkPlan(functions, filter, query)
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test
    fun theVendoredVectorSetIsTheOneConformedTo() {
        // The matcher's scripts/vectors_digest.sh: sha256 of the sorted `sha256sum` manifest of the json files.
        val manifest = listOf("zkp_req", "zkp_req_response", "zkp_req_unsat", "proof_time")
            .flatMap { d -> jsonFiles(d).map { "$d/${it.name}" to hex(MessageDigest.getInstance("SHA-256").digest(File(root, "$d/${it.name}").readBytes())) } }
            .sortedBy { it.first }
        assertEquals(listOf(54, 143, 43, 1), listOf("zkp_req", "zkp_req_response", "zkp_req_unsat", "proof_time").map { jsonFiles(it).size })
        val text = manifest.joinToString("") { "${it.second}  ${it.first}\n" }
        assertEquals("9f482d7a3fb87cb1381d0dfb7a2fc396b6cd3c1eba07c5d76f44e47142b751ac", hex(MessageDigest.getInstance("SHA-256").digest(text.toByteArray())))
    }

    // ── the response validator ────────────────────────────────────────────────────────────────────────

    @Test
    fun everyResponseVectorGivesItsStatedVerdict() {
        val failures = mutableListOf<String>()
        var ok = 0
        var err = 0
        for (f in jsonFiles("zkp_req_response")) {
            val v = Json.parseToJsonElement(f.readText()).jsonObject
            val query = v["query"]!!.jsonObject
            val cm = v["client_metadata"] as? JsonObject
            val token = v["vp_token"]?.toString() ?: v["vp_token_text"]!!.jsonPrimitive.content
            val got = CircuitZkResponseValidator.validate(plan(query, cm), token)
            val expect = v["expect"]!!.jsonObject
            if (f.name.startsWith("ok_") != (expect["valid"] != null)) failures += "${f.name}: name and expect disagree"
            if (expect["valid"] != null) {
                ok++
                if (got != null) failures += "${f.name}: expected ok, got ${got.code}"
            } else {
                err++
                val want = expect["error"]!!.jsonPrimitive.content
                if (got?.code != want) failures += "${f.name}: expected $want, got ${got?.code}"
            }
        }
        assertTrue("ok=$ok err=$err", ok >= 10 && err >= 100)
        assertTrue("\n" + failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun everyResponseRefusalCodeHasAVector() {
        val codes = jsonFiles("zkp_req_response").mapNotNull { Json.parseToJsonElement(it.readText()).jsonObject["expect"]!!.jsonObject["error"]?.jsonPrimitive?.content }.toSet()
        val missing = CircuitZkResponseError.values().map { it.code } - codes
        assertTrue("no vector for $missing", missing.isEmpty())
    }

    // ── unsatisfiable requests: the wallet's rule set is the rulebook's ───────────────────────────────────

    @Test
    fun everyUnsatisfiableRequestVectorGivesItsStatedCode() {
        val failures = mutableListOf<String>()
        for (f in jsonFiles("zkp_req_unsat")) {
            val v = Json.parseToJsonElement(f.readText()).jsonObject
            val verdict = RulebookCircuitZkValidator().validate(plan(v["query"]!!.jsonObject, null))
            val expect = v["expect"]!!.jsonObject
            if (expect["satisfiable"] != null) {
                if (verdict !== CircuitZkVerdict.Ok) failures += "${f.name}: expected satisfiable, got ${(verdict as CircuitZkVerdict.AccessDenied).ruleId}"
            } else {
                val want = expect["error"]!!.jsonPrimitive.content
                val got = (verdict as? CircuitZkVerdict.AccessDenied)?.ruleId
                if (got != want) failures += "${f.name}: expected $want, got $got"
            }
        }
        assertTrue("\n" + failures.joinToString("\n"), failures.isEmpty())
    }

    // ── proof_time ────────────────────────────────────────────────────────────────────────────────────

    private val proofTimeVectors by lazy { Json.parseToJsonElement(File(root, "proof_time/proof_time.json").readText()).jsonObject }

    @Test
    fun proofTimeRendersParsesAndRefusesAsTheVectorsSay() {
        val v = proofTimeVectors
        for (c in v["render"]!!.jsonArray.map { it.jsonObject }) {
            val text = ProofTime.render(c["secs"]!!.jsonPrimitive.long)
            assertEquals(c["text"]!!.jsonPrimitive.content, text)
            assertEquals(20, text.toByteArray(Charsets.US_ASCII).size)
        }
        for (c in v["render_errors"]!!.jsonArray.map { it.jsonObject }) {
            val e = try { ProofTime.render(c["secs"]!!.jsonPrimitive.long); null } catch (e: ProofTimeException) { e.error.code }
            assertEquals(c["error"]!!.jsonPrimitive.content, e)
        }
        for (c in v["parse_ok"]!!.jsonArray.map { it.jsonObject }) assertEquals(c["secs"]!!.jsonPrimitive.long, ProofTime.parse(c["text"]!!.jsonPrimitive.content))
        for (c in v["parse_errors"]!!.jsonArray.map { it.jsonObject }) {
            val e = try { ProofTime.parse(c["text"]!!.jsonPrimitive.content); null } catch (e: ProofTimeException) { e.error.code }
            assertEquals(c["text"]!!.jsonPrimitive.content, c["error"]!!.jsonPrimitive.content, e)
        }
        for (c in v["tolerance"]!!.jsonArray.map { it.jsonObject }) {
            val got = ProofTime.checkTolerance(c["proof_time"]!!.jsonPrimitive.content, c["now_secs"]!!.jsonPrimitive.long, c["skew_secs"]!!.jsonPrimitive.long, c["max_age_secs"]!!.jsonPrimitive.long)
            assertEquals(c["name"]!!.jsonPrimitive.content, c["expect"]!!.jsonPrimitive.content, got?.code ?: "ok")
        }
    }

    // ── what the SDK builds is what the validator accepts ─────────────────────────────────────────────────

    private val query = Json.parseToJsonElement(
        """{"id":"q","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"d"},"_req":[{"fn_id":"pseudonym","return":"p","params":{"config":"known-offender-matching-ssc","ver":1,"prf":"sha-256"}},{"fn_id":"age_check","return":"a","params":{"ge":"2008-10-10","le":"2013-10-09"}}]}""",
    ).jsonObject
    private val offered = Json.parseToJsonElement("""{"vp_formats_supported":{"zkp_req":{"system_id_values":["urn:c"]}}}""").jsonObject

    private fun presentation(
        results: Map<String, ResultValue>? = null,
        keys: List<ByteArray> = listOf(ByteArray(10) { it.toByte() }),
        proofTime: String? = "2026-10-20T12:00:00Z",
    ) = CircuitZkResponsePresentation(
        systemId = "urn:c", proof = ByteArray(40) { (it * 3).toByte() }, issuerKeySet = keys, proofTime = proofTime,
        results = results ?: linkedMapOf("p" to ResultValue.Pseudonym(ByteArray(32) { it.toByte() }), "a" to ResultValue.Predicate),
    )

    private fun vpToken(vararg p: CircuitZkResponsePresentation) = JsonObject(mapOf("q" to JsonArray(p.map { it.toJson() }))).toString()

    @Test
    fun aBuiltPresentationValidatesAndIsTheRulebooksCbor() {
        val p = presentation(keys = listOf(ByteArray(1) { 0xfb.toByte() }, ByteArray(2) { 0xff.toByte() }))
        assertNull(CircuitZkResponseValidator.validate(plan(query, offered), vpToken(p)))
        val cbor = CBORObject.DecodeFromBytes(p.encode())
        assertEquals(setOf("system_id", "proof", "issuer_key_set", "proof_time", "results"), cbor.keys.map { it.AsString() }.toSet())
        assertTrue(cbor["proof_time"].HasMostOuterTag(0))
        assertEquals(2, cbor["issuer_key_set"].size())
        assertEquals(true, cbor["results"]["a"].isTrue)
        // A string, base64url without padding.
        assertTrue(p.toBase64Url().all { it.isLetterOrDigit() || it == '-' || it == '_' })
    }

    @Test
    fun aSecondPresentationNeedsMultiple() {
        val two = vpToken(presentation(), presentation())
        assertEquals(CircuitZkResponseError.PRESENTATIONS_MULTIPLE_NOT_ALLOWED, CircuitZkResponseValidator.validate(plan(query, offered), two))
        assertNull(CircuitZkResponseValidator.validate(plan(JsonObject(query + ("multiple" to JsonPrimitive(true))), offered), two))
    }

    @Test
    fun aResponseToARequestThatOfferedNoSystemIsRefused() {
        assertEquals(CircuitZkResponseError.SYSTEM_ID_NOT_OFFERED, CircuitZkResponseValidator.validate(plan(query, null), vpToken(presentation())))
    }

    @Test
    fun mdocNeedsProofTime_andItIsTheExact20ByteForm() {
        assertEquals(CircuitZkResponseError.PROOF_TIME_MISSING, CircuitZkResponseValidator.validate(plan(query, offered), vpToken(presentation(proofTime = null))))
        try { presentation(proofTime = "2026-10-20T12:00:00.5Z"); fail() } catch (e: IllegalArgumentException) { /* the form is checked at construction */ }
        try { presentation(proofTime = "2026-10-20T12:00:00+00:00"); fail() } catch (e: IllegalArgumentException) { }
    }

    @Test
    fun noItemTypeIsSkipped_anUnknownFunctionOrAMissingHandleRefusesTheResponse() {
        val unknown = JsonObject(query + ("_req" to JsonArray(query["_req"]!!.jsonArray + Json.parseToJsonElement("""{"fn_id":"mystery","return":"m"}"""))))
        val withExtra = presentation(linkedMapOf("p" to ResultValue.Pseudonym(ByteArray(32)), "a" to ResultValue.Predicate, "m" to ResultValue.Predicate))
        assertEquals(CircuitZkResponseError.RESULT_FUNCTION_UNKNOWN, CircuitZkResponseValidator.validate(plan(unknown, offered), vpToken(withExtra)))
        val skipped = presentation(linkedMapOf("p" to ResultValue.Pseudonym(ByteArray(32))))
        assertEquals(CircuitZkResponseError.RESULT_HANDLE_MISSING, CircuitZkResponseValidator.validate(plan(query, offered), vpToken(skipped)))
    }

    @Test(expected = IllegalArgumentException::class)
    fun aPresentationWithoutAnIssuerKeySetCannotBeBuilt() { presentation(keys = emptyList()) }

    @Test(expected = IllegalArgumentException::class)
    fun aNinthIssuerKeyCannotBeBuilt() { presentation(keys = List(9) { ByteArray(4) }) }

    @Test(expected = IllegalArgumentException::class)
    fun anOversizedIssuerKeyCannotBeBuilt() { presentation(keys = listOf(ByteArray(4097))) }
}
