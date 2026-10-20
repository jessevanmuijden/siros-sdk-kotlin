// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.siros_dc_matcher_ffi.ZkpReqPlanException
import uniffi.siros_dc_matcher_ffi.zkpReqPlan

/**
 * [SharedCircuitZkPlanner] against the matcher's own conformance vectors
 * (`spec/zkp-req-vectors/zkp_req/`, copied verbatim; see `spec/zkp-req-vectors/SOURCE.md`),
 * on a device because the planner is reached through the native library.
 *
 * NOT run by `./gradlew test`: needs a device or emulator.
 */
@RunWith(AndroidJUnit4::class)
class SharedCircuitZkPlannerInstrumentedTest {
    private val dir = "zkp-req-vectors/zkp_req"

    private fun vectors(): List<Pair<String, JsonObject>> {
        val assets = InstrumentationRegistry.getInstrumentation().context.assets
        val files = assets.list(dir).orEmpty().filter { it.endsWith(".json") }.sorted()
        return files.map { name ->
            name to Json.parseToJsonElement(assets.open("$dir/$name").bufferedReader().readText()).jsonObject
        }
    }

    /** The vector's query and client metadata as the planner's typed boundary takes them; null where the vector is raw text. */
    private fun JsonObject.query() = this["query"] as? JsonObject
    private fun JsonObject.clientMetadata() = this["client_metadata"] as? JsonObject

    /** The vector as the FFI takes it: raw text where the vector is raw text. */
    private fun JsonObject.queryText(): String =
        (this["query_text"] as? JsonPrimitive)?.content ?: this["query"].toString()
    private fun JsonObject.clientMetadataText(): String? =
        (this["client_metadata_text"] as? JsonPrimitive)?.content ?: this["client_metadata"]?.toString()

    @Test
    fun the_vector_set_is_there() {
        val all = vectors()
        assertTrue("copied vectors not found in the test APK's assets: ${all.size}", all.count { it.first.startsWith("ok_") } >= 10)
        assertTrue(all.count { it.first.startsWith("err_") } >= 30)
    }

    @Test
    fun plans_every_ok_vector_identically_to_the_matcher() {
        for ((name, v) in vectors().filter { it.first.startsWith("ok_") }) {
            val query = v.query() ?: error("$name: an ok vector is an object query")
            val plan = SharedCircuitZkPlanner.planJson(query, v.clientMetadata())
            assertNotNull("$name was not planned", plan)
            val expected = (v["expect"] as JsonObject)["plan"] as JsonObject
            assertEquals("$name: plan", expected, JsonObject(plan!!.filterKeys { it != "raw" }))
            assertEquals("$name: raw is the query, unchanged", query, plan["raw"])
            // And the SDK's own plan reads the same functions.
            val sdk = (SharedCircuitZkPlanner().plan(query, v.clientMetadata()) as CircuitZkPlanResult.Plan).plan
            assertEquals(name, (expected["functions"] as kotlinx.serialization.json.JsonArray).size, sdk.functions.size)
            assertEquals(name, query, sdk.raw)
        }
    }

    /** Every err vector, raw-text ones included, is refused with the planner's own code. */
    @Test
    fun rejects_every_err_vector_with_the_vectors_code() {
        val errors = vectors().filter { it.first.startsWith("err_") }
        for ((name, v) in errors) {
            val code = ((v["expect"] as JsonObject)["error"] as JsonPrimitive).content
            val e = try {
                zkpReqPlan(v.queryText(), v.clientMetadataText())
                null
            } catch (e: ZkpReqPlanException.InvalidRequest) {
                e
            }
            assertNotNull("$name was planned", e)
            assertEquals(name, code, e!!.code)
        }
        // The ones that can reach the typed boundary are refused there too.
        var typed = 0
        for ((name, v) in errors) {
            val query = v.query() ?: continue
            if (v.containsKey("client_metadata_text")) continue
            typed++
            assertNull("$name was planned", SharedCircuitZkPlanner.planJson(query, v.clientMetadata()))
            assertTrue("$name", SharedCircuitZkPlanner().plan(query, v.clientMetadata()) is CircuitZkPlanResult.InvalidRequest)
        }
        assertTrue("only $typed error vectors reached the typed boundary", typed >= 30)
    }

    private fun query(extra: String = "", meta: String = """{"source_format":"mso_mdoc","doctype_value":"d"}""", id: String? = "q") = Json.parseToJsonElement(
        """{${id?.let { "\"id\":\"$it\"," } ?: ""}"format":"zkp_req","meta":$meta,"_req":[{"fn_id":"age_check","return":"h","params":{"ge":"2008-10-10"}}]$extra}""",
    ).jsonObject

    private fun planned(q: JsonObject, clientMetadata: JsonObject? = null) =
        (SharedCircuitZkPlanner().plan(q, clientMetadata) as CircuitZkPlanResult.Plan).plan

    /**
     * What the probe could not do and the planner now does: a request with
     * empty circuit lists, an empty `vct_values`, or no `id` is planned as the
     * matcher plans it.
     */
    @Test
    fun plans_the_requests_the_old_probe_could_not() {
        fun cm(lists: String) = Json.parseToJsonElement("""{"vp_formats_supported":{"zkp_req":$lists}}""").jsonObject
        assertEquals(CircuitZkCircuitFilter(null, emptyList()), planned(query(), cm("""{"system_id_values":[]}""")).circuitFilter)
        assertEquals(CircuitZkCircuitFilter(emptyList(), listOf("c")), planned(query(), cm("""{"proof_system_values":[],"system_id_values":["c"]}""")).circuitFilter)
        assertEquals(1, planned(query(meta = """{"vct_values":[]}""")).functions.size)
        assertEquals(1, planned(query(id = null)).functions.size)
        // The verifier's lists reach the plan (the base64 `input` envelope of the pre-v0.4 draft is gone).
        val plain = cm("""{"proof_system_values":["s1"],"system_id_values":["c1"]}""")
        assertEquals(CircuitZkCircuitFilter(listOf("s1"), listOf("c1")), planned(query(), plain).circuitFilter)
    }

    /** What a request's two circuit lists become in the SDK's plan, end to end. */
    @Test
    fun the_circuit_lists_map_onto_the_sdks_plan() {
        fun planned(vector: String): CircuitZkPlan {
            val v = vectors().first { it.first == vector }.second
            return (SharedCircuitZkPlanner().plan(v.query()!!, v.clientMetadata()) as CircuitZkPlanResult.Plan).plan
        }
        assertEquals(
            CircuitZkCircuitFilter(listOf("longfellow-libzk-v1"), listOf("urn:circuits:longfellow:nym_auth:v1")),
            planned("ok_normative_plain.json").circuitFilter,
        )
        assertNull(planned("ok_client_metadata_without_zkp_req.json").circuitFilter)
    }

    /** The planner is what [CredentialMatcher] uses when the wallet turns circuit_zk on. */
    @Test
    fun matching_uses_the_ffi_planner() {
        val nym = "eu.europa.ec.eudi.nym_auth.1"
        val creds = listOf(
            StoredCredential(id = 1L, format = "mso_mdoc", raw = "", metadata = CredentialMetadata(doctype = nym), batchId = 1L, instanceId = 0),
        )
        val support = CircuitZkSupport(
            planner = SharedCircuitZkPlanner(),
            circuits = CircuitZkCircuitSource {
                listOf(CircuitZkCircuit("longfellow-libzk-v1", "urn:circuits:longfellow:nym_auth:v1", setOf(nym)))
            },
        )
        val v = vectors().first { it.first == "ok_normative_plain.json" }.second
        val dcql = JsonObject(mapOf("credentials" to kotlinx.serialization.json.JsonArray(listOf(v.query()!!))))
        val result = CredentialMatcher.matchDcql(dcql, creds, circuitZk = support, clientMetadata = v.clientMetadata()).queryResults.single()
        assertEquals(listOf(1L), result.candidates.map { it.id })
        assertEquals(listOf("pseudonym", "age_check"), result.circuitZkPlan!!.functions.map { it.id })

        // A verifier naming another circuit is not served, and a structurally invalid request is not planned.
        val other = JsonObject(
            mapOf(
                "vp_formats_supported" to JsonObject(
                    mapOf("zkp_req" to JsonObject(mapOf("system_id_values" to kotlinx.serialization.json.JsonArray(listOf(kotlinx.serialization.json.JsonPrimitive("urn:other")))))),
                ),
            ),
        )
        val unserved = CredentialMatcher.matchDcql(dcql, creds, circuitZk = support, clientMetadata = other).queryResults.single()
        assertTrue(unserved.candidates.isEmpty())
        val invalid = vectors().first { it.first == "err_duplicate_handle.json" }.second
        val bad = JsonObject(mapOf("credentials" to kotlinx.serialization.json.JsonArray(listOf(invalid.query()!!))))
        val refused = CredentialMatcher.matchDcql(bad, creds, circuitZk = support).queryResults.single()
        assertNull(refused.circuitZkPlan)
        assertTrue(refused.candidates.isEmpty())
    }
}
