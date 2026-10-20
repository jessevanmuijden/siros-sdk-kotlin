// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CredentialMetadata
import org.siros.sdk.credentials.StoredCredential
import uniffi.siros_dc_matcher_ffi.matchDcqlWithContext

/**
 * The matcher's circuit capability vectors (`spec/circuit-capabilities-vectors/`,
 * copied verbatim; see its `SOURCE.md`), through [SirosCredentialRegistry].
 *
 * The SDK does not implement the capability rule, the matcher does. What this
 * proves is that a circuit registered with its `capabilities` reaches the
 * matcher unaltered: each case's circuits are registered one at a time, the
 * case's request is matched through the real native library, and the circuits
 * the matcher offers must be exactly the case's `expect` (as a set; ranking is
 * the catalog's). A device test because the matcher is native.
 *
 * A vector speaks of a generic presentation, credential format and type; the
 * matcher's are fixed (`circuit_zk`, stored `mso_mdoc`, `meta.doctype_value`).
 * So the vector's own presentation and format are rewritten to those wherever
 * a circuit or the request repeats them, and a circuit that names something
 * else keeps naming it and must not be offered. Cases the matcher cannot be
 * asked (a malformed request, an empty `req`, which its planner refuses
 * before matching) are checked to offer nothing, whatever the vector expects.
 *
 * NOT run by `./gradlew test`: needs a device or emulator.
 */
@RunWith(AndroidJUnit4::class)
class SirosCredentialRegistryCapabilityVectorsTest {

    private fun vectors(): JsonObject {
        val assets = InstrumentationRegistry.getInstrumentation().context.assets
        return Json.parseToJsonElement(
            assets.open("circuit-capabilities-vectors/match.json").bufferedReader().readText(),
        ).jsonObject
    }

    @Test
    fun the_registry_offers_exactly_the_circuits_the_vectors_expect() {
        val cases = checkNotNull(vectors()["cases"]).jsonArray
        assertTrue("vectors went missing: ${cases.size}", cases.size >= 40)
        val failures = cases.map { it.jsonObject }.mapNotNull { case ->
            // The vectors' `expectError` cases, and `empty-req`, are not requests
            // the matcher is ever asked: its planner refuses an empty `req`
            // (the vectors' README says so), so nothing is offered for them.
            // `expectRejected` cases carry capabilities the matcher must NOT parse (an unknown
            // member such as the old `credential.profile`, an empty `issuance_profile`): no
            // circuit may be served for them. Registration still must not throw.
            val unaskable = case["expectError"]?.jsonPrimitive?.content == "true" ||
                isRejected(case) ||
                case["request"]!!.jsonObject["req"]!!.jsonArray.isEmpty()
            val want = if (unaskable) {
                emptySet()
            } else {
                case["expect"]!!.jsonArray.map { it.jsonPrimitive.content }.toSet()
            }
            val got = offered(case)
            if (got == want) null else "${case["name"]!!.jsonPrimitive.content}: want $want, got $got"
        }
        assertTrue("\n" + failures.joinToString("\n"), failures.isEmpty())
    }

    private fun isRejected(case: JsonObject) = case["expectRejected"]?.jsonPrimitive?.content == "true"

    /**
     * The `expectRejected` cases: their capabilities are registered (the SDK passes them through
     * verbatim and must not throw) and the matcher then serves nothing for them, while the same
     * request with the accepted spelling (`issuance-profile-served`) is served.
     */
    @Test
    fun rejected_capabilities_register_without_error_and_serve_nothing() {
        val cases = vectors()["cases"]!!.jsonArray.map { it.jsonObject }
        val rejected = cases.filter(::isRejected)
        assertTrue("expectRejected cases went missing: ${rejected.size}", rejected.size >= 2)
        for (case in rejected) {
            assertTrue("a rejected case expects nothing", case["expect"]!!.jsonArray.isEmpty())
            assertEquals(case["name"]!!.jsonPrimitive.content, emptySet<String>(), offered(case))
        }
        val served = cases.first { it["name"]!!.jsonPrimitive.content == "issuance-profile-served" }
        assertEquals(setOf("c1"), offered(served))
    }

    /** Guards against a harness that offers nothing, or everything, whatever the case. */
    @Test
    fun the_harness_offers_some_cases_and_refuses_others() {
        val byName = vectors()["cases"]!!.jsonArray.map { it.jsonObject }.associateBy { it["name"]!!.jsonPrimitive.content }
        assertEquals(setOf("c1"), offered(byName.getValue("baseline")))
        assertEquals(setOf("b"), offered(byName.getValue("system-filter")))
        assertEquals(emptySet<String>(), offered(byName.getValue("id-filter-no-hit")))
    }

    private val circuitZkFormat = "zkp_req"
    private val storedFormat = "mso_mdoc"

    /** The ids of the case's circuits the matcher offers for its request. */
    private fun offered(case: JsonObject): Set<String> {
        val request = case["request"]!!.jsonObject
        val presentation = request["presentation"]?.jsonPrimitive?.content.orEmpty()
        val credential = request["credential"]?.jsonObject
        val format = credential?.get("format")?.jsonPrimitive?.content.orEmpty()
        val type = credential?.get("type")?.jsonPrimitive?.content.orEmpty()
        val items = request["req"]!!.jsonArray
        // No presentation, format or type is a malformed request, and an empty
        // `req` is refused by the matcher's planner before it matches.
        if (presentation.isEmpty() || format.isEmpty() || type.isEmpty() || items.isEmpty()) return emptySet()

        val req = JsonArray(
            items.mapIndexed { i, item ->
                val o = item.jsonObject
                JsonObject(
                    buildMap {
                        put("fn_id", o["id"]!!)
                        put("return", JsonPrimitive("r$i"))
                        o["params"]?.let { put("params", it) }
                    },
                )
            },
        )
        val query = JsonObject(
            mapOf(
                "credentials" to JsonArray(
                    listOf(
                        JsonObject(
                            mapOf(
                                "id" to JsonPrimitive("q"),
                                "format" to JsonPrimitive(circuitZkFormat),
                                "meta" to JsonObject(mapOf("source_format" to JsonPrimitive("mso_mdoc"), "doctype_value" to JsonPrimitive(type))),
                                "_req" to req,
                            ),
                        ),
                    ),
                ),
            ),
        ).toString()
        val lists = buildMap {
            request["proofSystems"]?.takeIf { it is JsonArray && it.jsonArray.isNotEmpty() }
                ?.let { put("proof_system_values", it) }
            request["circuitIds"]?.takeIf { it is JsonArray && it.jsonArray.isNotEmpty() }
                ?.let { put("system_id_values", it) }
        }
        val clientMetadata = lists.takeIf { it.isNotEmpty() }?.let {
            JsonObject(mapOf("vp_formats_supported" to JsonObject(mapOf("zkp_req" to JsonObject(it))))).toString()
        }

        val credential1 = StoredCredential(
            id = 1L, format = storedFormat, raw = "",
            metadata = CredentialMetadata(doctype = type), batchId = 1L, instanceId = 0,
        )
        return case["circuits"]!!.jsonArray.map { it.jsonObject }.filter { c ->
            // The wallet's side: a revoked circuit is not registered, and a
            // circuit without capabilities has none to register.
            c["status"]?.jsonPrimitive?.content in setOf("active", "deprecated") && c["capabilities"] != null
        }.filter { c ->
            val circuit = CircuitZkCircuit(
                system = c["system"]!!.jsonPrimitive.content,
                circuitId = c["id"]!!.jsonPrimitive.content,
                docTypes = setOf(type),
                aliases = c["aliases"]?.jsonArray?.map { it.jsonPrimitive.content }?.toSet().orEmpty(),
                capabilities = rewritten(c["capabilities"]!!, presentation, format).toString(),
            )
            val blob = SirosCredentialRegistry.buildBlob(
                listOf(credential1), emptyList(), icons = mapOf(1L to byteArrayOf(1)), circuitZkCircuits = listOf(circuit),
            )
            val direct = matchDcqlWithContext(blob, query, clientMetadata).satisfiable
            // The SDK's own selection asks the matcher the same question through
            // [SharedCircuitZkServing]; without the verifier's lists (which the SDK applies
            // itself) the two must agree, for every case.
            if (clientMetadata == null) {
                val credentialQuery = Json.parseToJsonElement(query).jsonObject["credentials"]!!.jsonArray[0].jsonObject
                assertEquals(
                    "${case["name"]!!.jsonPrimitive.content}/${circuit.circuitId}: SharedCircuitZkServing",
                    direct,
                    org.siros.sdk.credentials.SharedCircuitZkServing.serves(circuit, type, credentialQuery),
                )
            }
            direct
        }.map { it["id"]!!.jsonPrimitive.content }.toSet()
    }

    /** [capabilities] with the vector's presentation and format replaced by the matcher's, where they are the request's. */
    private fun rewritten(capabilities: JsonElement, presentation: String, format: String): JsonElement {
        val o = capabilities as? JsonObject ?: return capabilities
        return JsonObject(
            o.mapValues { (key, value) ->
                when {
                    key == "presentation" && value.isString(presentation) -> JsonPrimitive(circuitZkFormat)
                    key == "credential" && value is JsonObject -> JsonObject(
                        value.mapValues { (k, v) -> if (k == "format" && v.isString(format)) JsonPrimitive(storedFormat) else v },
                    )
                    else -> value
                }
            },
        )
    }

    private fun JsonElement.isString(s: String) = this is JsonPrimitive && this !is JsonNull && isString && content == s
}
