package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Test

/** `circuit_zk` matching in [CredentialMatcher], with a fake planner. */
class CircuitZkMatchingTest {
    private val json = Json { ignoreUnknownKeys = true }
    private val doctype = "test.doctype.1"

    private fun mdoc(id: Long, docType: String?) = StoredCredential(
        id = id, format = "mso_mdoc", raw = "raw-$id",
        metadata = CredentialMetadata(doctype = docType), batchId = id, instanceId = 0,
    )

    // Carries a doctype in its metadata, so only its format keeps it out of an mdoc match.
    private fun sdJwt(id: Long) = StoredCredential(
        id = id, format = "dc+sd-jwt", raw = "raw-$id", metadata = CredentialMetadata(vct = "urn:x", doctype = doctype),
        batchId = id, instanceId = 0,
    )

    /** A real bare IssuerSigned with one claim, so claim registration has something to withhold. */
    private fun mdocRaw(docType: String): String {
        val item = com.upokecenter.cbor.CBORObject.NewMap()
        item[com.upokecenter.cbor.CBORObject.FromObject("digestID")] = com.upokecenter.cbor.CBORObject.FromObject(0L)
        item[com.upokecenter.cbor.CBORObject.FromObject("random")] = com.upokecenter.cbor.CBORObject.FromObject(ByteArray(16))
        item[com.upokecenter.cbor.CBORObject.FromObject("elementIdentifier")] = com.upokecenter.cbor.CBORObject.FromObject("given_name")
        item[com.upokecenter.cbor.CBORObject.FromObject("elementValue")] = com.upokecenter.cbor.CBORObject.FromObject("Jane")
        val items = com.upokecenter.cbor.CBORObject.NewArray()
        items.Add(com.upokecenter.cbor.CBORObject.FromObjectAndTag(item.EncodeToBytes(), 24))
        val nameSpaces = com.upokecenter.cbor.CBORObject.NewMap()
        nameSpaces[com.upokecenter.cbor.CBORObject.FromObject("org.iso.18013.5.1")] = items
        val mso = com.upokecenter.cbor.CBORObject.NewMap()
        mso[com.upokecenter.cbor.CBORObject.FromObject("docType")] = com.upokecenter.cbor.CBORObject.FromObject(docType)
        val taggedMso = com.upokecenter.cbor.CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()
        val issuerAuth = com.upokecenter.cbor.CBORObject.NewArray()
        issuerAuth.Add(com.upokecenter.cbor.CBORObject.FromObject(ByteArray(0)))
        issuerAuth.Add(com.upokecenter.cbor.CBORObject.NewMap())
        issuerAuth.Add(com.upokecenter.cbor.CBORObject.FromObject(taggedMso))
        issuerAuth.Add(com.upokecenter.cbor.CBORObject.FromObject(ByteArray(64)))
        val issuerSigned = com.upokecenter.cbor.CBORObject.NewMap()
        issuerSigned[com.upokecenter.cbor.CBORObject.FromObject("nameSpaces")] = nameSpaces
        issuerSigned[com.upokecenter.cbor.CBORObject.FromObject("issuerAuth")] = issuerAuth
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(issuerSigned.EncodeToBytes())
    }

    private fun query(extraMeta: String = "", format: String = "zkp_req"): JsonObject = json.parseToJsonElement(
        """{"credentials":[{"id":"q","format":"$format","meta":{"source_format":"mso_mdoc","doctype_value":"$doctype"$extraMeta}}]}"""
    ).jsonObject

    private val plan = CircuitZkPlan(functions = listOf(CircuitZkFunction("fn-a", "h1")))

    private class FakePlanner(var result: () -> CircuitZkPlanResult) : CircuitZkPlanner {
        var calls = 0
        var lastMetadata: JsonObject? = null
        override fun plan(credentialQuery: JsonObject, clientMetadata: JsonObject?): CircuitZkPlanResult {
            calls++
            lastMetadata = clientMetadata
            return result()
        }
    }

    private fun circuit(id: String = "c1", system: String = "sys", docTypes: Set<String> = setOf(doctype), functions: Set<String>? = setOf("fn-a"), aliases: Set<String> = emptySet()) =
        CircuitZkCircuit(system, id, docTypes, functions, aliases)

    private fun support(
        planner: CircuitZkPlanner = FakePlanner { CircuitZkPlanResult.Plan(plan) },
        validator: CircuitZkRequestValidator = CircuitZkRequestValidator.PERMISSIVE,
        circuits: List<CircuitZkCircuit> = listOf(circuit()),
    ) = CircuitZkSupport(planner, validator, { circuits })

    private fun match(q: JsonObject, creds: List<StoredCredential>, s: CircuitZkSupport?) =
        CredentialMatcher.matchDcql(q, creds, circuitZk = s).queryResults.single()

    @After
    fun restoreEngine() {
        CredentialMatcher.engine = { q, c, z, d -> SharedDcqlMatcher.evaluate(q, c, z, d) }
    }

    private fun mixed(circuitId: String? = "q"): JsonObject = json.parseToJsonElement(
        """{"credentials":[{${circuitId?.let { "\"id\":\"$it\"," } ?: ""}"format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"$doctype"}},""" +
            """{"id":"p","format":"mso_mdoc","meta":{"doctype_value":"$doctype"},"claims":[{"path":["$doctype","given_name"]}]}]}"""
    ).jsonObject

    @Test
    fun `a circuit_zk query without an id still marks the whole request`() {
        for (support in listOf(null, support())) {
            val out = CredentialMatcher.matchDcql(mixed(circuitId = null), listOf(mdoc(1, doctype)), circuitZk = support)
            // The malformed query is not in the results, but the request still has one.
            assertEquals(listOf("p"), out.queryResults.map { it.queryId })
            assertTrue(out.hasCircuitZkQuery)
            assertEquals(1, out.unparsedQueryCount)
        }
        val ordinary = CredentialMatcher.matchDcql(
            json.parseToJsonElement("""{"credentials":[{"id":"p","format":"mso_mdoc","meta":{"doctype_value":"$doctype"}}]}""").jsonObject,
            listOf(mdoc(1, doctype)),
        )
        assertFalse(ordinary.hasCircuitZkQuery)
        assertEquals(0, ordinary.unparsedQueryCount)
    }

    @Test
    fun `ordinary queries beside a circuit_zk query are still validated by the engine`() {
        var asked: JsonObject? = null
        CredentialMatcher.engine = { q, _, _, _ ->
            asked = q
            // Credential 2 has the claim, credential 1 does not.
            SharedDcqlMatcher.Outcome(satisfiable = true, candidatesByQuery = mapOf("p" to listOf(2L)))
        }
        val creds = listOf(mdoc(1, doctype), mdoc(2, doctype))
        val out = CredentialMatcher.matchDcql(mixed(), creds, circuitZk = support())
        assertEquals(listOf(1L, 2L), out.queryResults.single { it.queryId == "q" }.candidates.map { it.id })
        assertEquals(listOf(2L), out.queryResults.single { it.queryId == "p" }.candidates.map { it.id })
        // The engine is asked about the ordinary query only.
        assertEquals(listOf("p"), asked!!["credentials"]!!.jsonArray.map { it.jsonObject["id"]!!.jsonPrimitive.content })
    }

    @Test
    fun `ordinary queries beside a circuit_zk query are not offered when the engine cannot validate them`() {
        CredentialMatcher.engine = { _, _, _, _ -> null }
        val out = CredentialMatcher.matchDcql(mixed(), listOf(mdoc(1, doctype)), circuitZk = support())
        assertTrue(out.queryResults.single { it.queryId == "p" }.candidates.isEmpty())
        assertEquals(1, out.queryResults.single { it.queryId == "q" }.candidates.size)
    }

    @Test
    fun `a valid plan with a fitting circuit matches the doctype's mdocs and carries the plan`() {
        val r = match(query(), listOf(mdoc(1, doctype), mdoc(2, "other"), sdJwt(3)), support())
        assertEquals(listOf(1L), r.candidates.map { it.id })
        assertEquals(plan, r.circuitZkPlan)
        assertEquals("zkp_req", r.format)
    }

    @Test
    fun `an attestation must be of the requests source_format - a bbs_cd request is not answered with an mdoc`() {
        val bbs = CircuitZkPlan(
            functions = plan.functions,
            raw = json.parseToJsonElement("""{"meta":{"source_format":"bbs_cd","schema_id_value":"s"}}""").jsonObject,
        )
        val r = match(query(), listOf(mdoc(1, doctype)), support(planner = FakePlanner { CircuitZkPlanResult.Plan(bbs) }))
        assertEquals(emptyList<Long>(), r.candidates.map { it.id })
        // The same plan over mso_mdoc matches.
        val mso = CircuitZkPlan(functions = plan.functions, raw = json.parseToJsonElement("""{"meta":{"source_format":"mso_mdoc","doctype_value":"$doctype"}}""").jsonObject)
        assertEquals(listOf(1L), match(query(), listOf(mdoc(1, doctype)), support(planner = FakePlanner { CircuitZkPlanResult.Plan(mso) })).candidates.map { it.id })
    }

    @Test
    fun `flag off - no support - a circuit_zk query matches nothing`() {
        val r = match(query(), listOf(mdoc(1, doctype)), null)
        assertTrue(r.candidates.isEmpty())
        assertNull(r.circuitZkPlan)
    }

    @Test
    fun `flag off - even a credential stored as format circuit_zk is not matched`() {
        val odd = StoredCredential(id = 9, format = "zkp_req", raw = "x", metadata = CredentialMetadata(doctype = doctype), batchId = 9, instanceId = 0)
        assertTrue(match(query(), listOf(odd), null).candidates.isEmpty())
    }

    @Test
    fun `the planner is not even consulted with the flag off`() {
        val planner = FakePlanner { CircuitZkPlanResult.Plan(plan) }
        match(query(), listOf(mdoc(1, doctype)), null)
        assertEquals(0, planner.calls)
    }

    @Test
    fun `an invalid request gives no candidates`() {
        val s = support(planner = FakePlanner { CircuitZkPlanResult.InvalidRequest })
        assertTrue(match(query(), listOf(mdoc(1, doctype)), s).candidates.isEmpty())
    }

    @Test
    fun `a planner failure gives no candidates and never a fallback`() {
        val s = support(planner = FakePlanner { error("boom") })
        val r = match(query(), listOf(mdoc(1, doctype)), s)
        assertTrue(r.candidates.isEmpty())
        assertNull(r.circuitZkPlan)
    }

    @Test
    fun `a validator refusal gives no candidates`() {
        val s = support(validator = { CircuitZkVerdict.AccessDenied("rule-x") })
        val r = match(query(), listOf(mdoc(1, doctype)), s)
        assertTrue(r.candidates.isEmpty())
    }

    @Test
    fun `a validator failure gives no candidates`() {
        val s = support(validator = { error("boom") })
        assertTrue(match(query(), listOf(mdoc(1, doctype)), s).candidates.isEmpty())
    }

    @Test
    fun `a circuit source failure gives no candidates`() {
        val s = CircuitZkSupport(FakePlanner { CircuitZkPlanResult.Plan(plan) }, CircuitZkRequestValidator.PERMISSIVE, { error("boom") })
        assertTrue(match(query(), listOf(mdoc(1, doctype)), s).candidates.isEmpty())
    }

    @Test
    fun `a wallet without a fitting circuit matches nothing`() {
        assertTrue(match(query(), listOf(mdoc(1, doctype)), support(circuits = emptyList())).candidates.isEmpty())
        assertTrue(match(query(), listOf(mdoc(1, doctype)), support(circuits = listOf(circuit(docTypes = setOf("other"))))).candidates.isEmpty())
    }

    @Test
    fun `the verifier's circuit list filters, by id, alias and system`() {
        fun planWith(filter: CircuitZkCircuitFilter) =
            support(planner = FakePlanner { CircuitZkPlanResult.Plan(plan.copy(circuitFilter = filter)) }, circuits = listOf(circuit(aliases = setOf("old-id"))))
        // A null filter: the verifier named no circuits.
        val unfiltered = support(planner = FakePlanner { CircuitZkPlanResult.Plan(plan) }, circuits = listOf(circuit(aliases = setOf("old-id"))))
        val creds = listOf(mdoc(1, doctype))
        assertEquals(1, match(query(), creds, planWith(CircuitZkCircuitFilter(listOf("sys"), listOf("c1")))).candidates.size)
        assertEquals(1, match(query(), creds, planWith(CircuitZkCircuitFilter(null, listOf("c1")))).candidates.size)
        assertEquals(1, match(query(), creds, planWith(CircuitZkCircuitFilter(listOf("sys"), listOf("old-id")))).candidates.size)
        assertEquals(1, match(query(), creds, planWith(CircuitZkCircuitFilter(listOf("sys"), listOf("nope", "c1")))).candidates.size)
        assertTrue(match(query(), creds, planWith(CircuitZkCircuitFilter(listOf("sys"), listOf("nope")))).candidates.isEmpty())
        assertTrue(match(query(), creds, planWith(CircuitZkCircuitFilter(listOf("other-sys"), listOf("c1")))).candidates.isEmpty())
        // A list the verifier did not send is not a constraint; an empty list is one nothing satisfies
        // (the matcher's reading: it is for wallets to conclude that nothing can match).
        assertEquals(1, match(query(), creds, unfiltered).candidates.size)
        assertTrue(match(query(), creds, planWith(CircuitZkCircuitFilter(emptyList(), emptyList()))).candidates.isEmpty())
        // Only a proof-system list, or only an id list: the other list is null.
        assertEquals(1, match(query(), creds, planWith(CircuitZkCircuitFilter(listOf("sys"), null))).candidates.size)
        assertTrue(match(query(), creds, planWith(CircuitZkCircuitFilter(listOf("other-sys"), null))).candidates.isEmpty())
    }

    @Test
    fun `functions filter, and a circuit declaring none fits no plan`() {
        val creds = listOf(mdoc(1, doctype))
        // The loose behaviour (no declared functions = every plan) is gone: such a circuit is offered for nothing.
        assertTrue(match(query(), creds, support(circuits = listOf(circuit(functions = null)))).candidates.isEmpty())
        assertEquals(1, match(query(), creds, support(circuits = listOf(circuit(functions = setOf("fn-a", "fn-b"))))).candidates.size)
        assertTrue(match(query(), creds, support(circuits = listOf(circuit(functions = setOf("fn-b"))))).candidates.isEmpty())
        assertTrue(match(query(), creds, support(circuits = listOf(circuit(functions = emptySet())))).candidates.isEmpty())
    }

    @Test
    fun `any one fitting circuit is enough`() {
        val s = support(circuits = listOf(circuit("c1", docTypes = setOf("other")), circuit("c2")))
        assertEquals(1, match(query(), listOf(mdoc(1, doctype)), s).candidates.size)
    }

    @Test
    fun `the query's own doctype_value must equal the credential's`() {
        val q = json.parseToJsonElement(
            """{"credentials":[{"id":"q","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"other"}}]}"""
        ).jsonObject
        val s = support(circuits = listOf(circuit(docTypes = setOf(doctype, "other"))))
        assertEquals(listOf(2L), match(q, listOf(mdoc(1, doctype), mdoc(2, "other")), s).candidates.map { it.id })
    }

    @Test
    fun `only mso_mdoc credentials match`() {
        assertTrue(match(query(), listOf(sdJwt(1)), support()).candidates.isEmpty())
    }

    @Test
    fun `the client_metadata reaches the planner`() {
        val planner = FakePlanner { CircuitZkPlanResult.Plan(plan) }
        val meta = json.parseToJsonElement("""{"a":1}""").jsonObject
        CredentialMatcher.matchDcql(query(), listOf(mdoc(1, doctype)), circuitZk = support(planner = planner), clientMetadata = meta)
        assertEquals(meta, planner.lastMetadata)
    }

    @Test
    fun `other formats are unaffected by circuit_zk support and by its failures`() {
        val q = json.parseToJsonElement(
            """{"credentials":[{"id":"q","format":"mso_mdoc","meta":{"source_format":"mso_mdoc","doctype_value":"$doctype"}}]}"""
        ).jsonObject
        val broken = support(planner = FakePlanner { error("boom") })
        assertEquals(listOf(1L), match(q, listOf(mdoc(1, doctype)), broken).candidates.map { it.id })
    }

    @Test
    fun `a request mixing circuit_zk with another format keeps the engine's answer for the other format when circuit_zk fails`() {
        CredentialMatcher.engine = { _, _, _, _ -> SharedDcqlMatcher.Outcome(true, mapOf("a" to listOf(1L))) }
        val q = json.parseToJsonElement(
            """{"credentials":[{"id":"a","format":"mso_mdoc","meta":{"source_format":"mso_mdoc","doctype_value":"$doctype"}},{"id":"b","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"$doctype"}}]}"""
        ).jsonObject
        val out = CredentialMatcher.matchDcql(q, listOf(mdoc(1, doctype)), circuitZk = support(planner = FakePlanner { error("x") }))
        assertEquals(listOf(1L), out.queryResults.first { it.queryId == "a" }.candidates.map { it.id })
        assertTrue(out.queryResults.first { it.queryId == "b" }.candidates.isEmpty())
    }

    // ---- routing ----

    @Test
    fun `isCircuitZkFormat is the one predicate and is not the legacy zk format`() {
        assertTrue(CredentialUtils.isCircuitZkFormat("zkp_req"))
        assertTrue(CredentialUtils.isCircuitZkFormat("ZKP_REQ"))
        assertFalse(CredentialUtils.isCircuitZkFormat("circuit_zk"))
        assertFalse(CredentialUtils.isCircuitZkFormat("mso_mdoc_zk"))
        assertFalse(CredentialUtils.isCircuitZkFormat("mso_mdoc"))
        assertFalse(CredentialUtils.isCircuitZkFormat(null))
    }

    @Test
    fun `a circuit_zk result never reads as a legacy mso_mdoc_zk query`() {
        val r = match(query(), listOf(mdoc(1, doctype)), support())
        assertFalse(r.format.equals("mso_mdoc_zk", ignoreCase = true))
        assertFalse(CredentialMatcher.isZkRequest(query()))
        assertNull(r.zkSystemTypes)
    }

    @Test
    fun `the legacy mso_mdoc_zk query still matches plain mso_mdoc, with or without support`() {
        val q = query(format = "mso_mdoc_zk")
        for (s in listOf(null, support())) {
            assertEquals(listOf(1L), match(q, listOf(mdoc(1, doctype)), s).candidates.map { it.id })
        }
        assertTrue(CredentialMatcher.isZkRequest(q))
    }

    // ---- circuit table ----

    private fun descriptor(id: String, published: Boolean = true, deprecatedAt: String? = null, params: String = "{}") =
        ZkCircuitDescriptor(
            id = id, aliases = listOf("$id-alias"), system = "sys", docTypes = listOf(doctype),
            published = published, deprecatedAt = deprecatedAt, params = json.parseToJsonElement(params).jsonObject,
        )

    @Test
    fun `circuits come from the manifest, published and not deprecated, functions optional`() {
        val circuits = CircuitZkCircuitSource.fromManifest(
            ZkManifest(
                circuits = listOf(
                    descriptor("a", params = """{"functions":["fn-a","fn-b"],"other":1}"""),
                    descriptor("b"),
                    descriptor("c", published = false),
                    descriptor("d", deprecatedAt = "2026-01-01"),
                ),
            ),
        )
        assertEquals(listOf("a", "b"), circuits.map { it.circuitId })
        assertEquals(setOf("fn-a", "fn-b"), circuits[0].functions)
        assertNull(circuits[1].functions)
        assertEquals(setOf("a-alias"), circuits[0].aliases)
        assertEquals("sys", circuits[0].system)
    }

    @Test
    fun `a manifest entry no adapter claims is offered for no plan, one an adapter claims only for the functions it declares`() {
        val manifest = ZkManifest(circuits = listOf(descriptor("unclaimed"), descriptor("claimed").copy(systemVersion = "7")))
        val declare: (ZkCircuitDescriptor) -> Set<String>? = { if (it.systemVersion == "7") setOf("fn-a") else null }
        val circuits = CircuitZkCircuitSource.fromManifest(manifest, declare)
        assertNull(circuits[0].functions)
        assertEquals(setOf("fn-a"), circuits[1].functions)
        assertEquals("7", circuits[1].systemVersion)
        val creds = listOf(mdoc(1, doctype))
        // Only the claimed circuit makes the credential a candidate; before the tightening the unclaimed one did too.
        assertTrue(match(query(), creds, support(circuits = listOf(circuits[0]))).candidates.isEmpty())
        assertEquals(1, match(query(), creds, support(circuits = listOf(circuits[1]))).candidates.size)
        assertTrue(match(query(), creds, support(circuits = CircuitZkCircuitSource.fromManifest(manifest))).candidates.isEmpty())
    }

    @Test
    fun `a circuit declaring no functions and no capabilities supports no plan`() {
        val bare = CircuitZkCircuit("sys", "c1", setOf(doctype))
        assertFalse(bare.supports(plan, doctype))
        assertFalse(bare.supports(plan.copy(functions = emptyList()), doctype))
        assertTrue(CircuitZkCircuit("sys", "c1", setOf(doctype), functions = setOf("fn-a")).supports(plan, doctype))
    }

    @Test
    fun `a descriptor's capabilities reach the circuit as JSON, and a credential type is never derived`() {
        val d = descriptor("a").copy(capabilities = json.parseToJsonElement("""{"schema":1,"functions":[]}""").jsonObject)
        val circuits = CircuitZkCircuitSource.fromManifest(ZkManifest(circuits = listOf(d, descriptor("b"))))
        assertEquals(json.parseToJsonElement("""{"schema":1,"functions":[]}"""), json.parseToJsonElement(circuits[0].capabilities!!))
        assertNull(circuits[1].capabilities)
        assertNull(circuits[0].credentialType)
    }

    @Test
    fun `the doctypes served through circuit_zk are derived from the circuit table`() {
        val source = CircuitZkCircuitSource { listOf(circuit("a", docTypes = setOf("x", "y")), circuit("b", docTypes = setOf("z"))) }
        assertEquals(setOf("x", "y", "z"), source.docTypes())
        assertEquals(emptySet<String>(), CircuitZkCircuitSource { emptyList() }.docTypes())
    }

    // ---- circuits the matcher constrains (capabilities / credential_type) ----

    private val capabilities = """{"schema":1,"presentation":"zkp_req","credential":{"format":"mso_mdoc","type":"$doctype"},"functions":[{"id":"fn-a"}]}"""

    private fun constrained(id: String = "c1") = CircuitZkCircuit("sys", id, setOf(doctype), capabilities = capabilities)

    private fun matchWith(circuits: List<CircuitZkCircuit>, serving: CircuitZkServing?) =
        match(query(), listOf(mdoc(1, doctype)), CircuitZkSupport(FakePlanner { CircuitZkPlanResult.Plan(plan) }, CircuitZkRequestValidator.PERMISSIVE, { circuits }, serving))

    @Test
    fun `a circuit with capabilities is not unrestricted - without the matcher's yes it is not selected`() {
        assertTrue(matchWith(listOf(constrained()), null).candidates.isEmpty())
        assertTrue(matchWith(listOf(constrained()), CircuitZkServing { _, _, _ -> null }).candidates.isEmpty())
        assertTrue(matchWith(listOf(constrained()), CircuitZkServing { _, _, _ -> false }).candidates.isEmpty())
        assertTrue(matchWith(listOf(constrained()), CircuitZkServing { _, _, _ -> error("boom") }).candidates.isEmpty())
        assertEquals(listOf(1L), matchWith(listOf(constrained()), CircuitZkServing { _, _, _ -> true }).candidates.map { it.id })
    }

    @Test
    fun `a circuit with a credential_type is judged by the matcher too`() {
        val typed = CircuitZkCircuit("sys", "c1", setOf(doctype), credentialType = doctype)
        assertTrue(matchWith(listOf(typed), null).candidates.isEmpty())
        assertEquals(listOf(1L), matchWith(listOf(typed), CircuitZkServing { _, _, _ -> true }).candidates.map { it.id })
    }

    @Test
    fun `the matcher is asked with the circuit, the doctype and the query, and its legacy functions are not read`() {
        val asked = mutableListOf<Triple<String, String, JsonObject>>()
        val raw = json.parseToJsonElement("""{"id":"q"}""").jsonObject
        val c = constrained().copy(functions = setOf("something-else"))
        val p = CircuitZkPlan(listOf(CircuitZkFunction("fn-a", "h")), raw = raw)
        val serving = CircuitZkServing { circuit, docType, q -> asked += Triple(circuit.circuitId, docType, q); true }
        assertTrue(c.supports(p, doctype, serving))
        assertEquals(listOf(Triple("c1", doctype, raw)), asked)
        // The two-argument form has no matcher to ask: it never treats the circuit as unrestricted.
        assertFalse(c.supports(p, doctype))
        assertFalse(c.supports(p, "other", serving))
    }

    @Test
    fun `the verifier's circuit list still applies before the matcher is asked`() {
        var asked = 0
        val p = CircuitZkPlan(plan.functions, circuitFilter = CircuitZkCircuitFilter(null, listOf("other-id")))
        assertFalse(constrained().supports(p, doctype, CircuitZkServing { _, _, _ -> asked++; true }))
        assertEquals(0, asked)
    }

    @Test
    fun `an unrestricted circuit is unchanged and never asks the matcher`() {
        var asked = 0
        assertEquals(listOf(1L), matchWith(listOf(circuit()), CircuitZkServing { _, _, _ -> asked++; false }).candidates.map { it.id })
        assertEquals(0, asked)
    }

    /**
     * The matcher's v0.10.0 capability vectors, replayed as the matcher's answers: for every case,
     * the circuits the vector says are served (`expect`) are exactly the circuits selection takes,
     * through both selection paths. The rule itself is the matcher's and is exercised by the
     * device test `SirosCredentialRegistryCapabilityVectorsTest`; this proves selection consumes
     * the answer instead of deciding.
     */
    @Test
    fun `selection takes exactly the circuits the matcher vectors say are served`() {
        val f = java.io.File("../../spec/circuit-capabilities-vectors/match.json")
        require(f.isFile) { "vector file not found at ${f.absolutePath}" }
        val cases = json.parseToJsonElement(f.readText()).jsonObject["cases"]!!.let { it as kotlinx.serialization.json.JsonArray }.map { it.jsonObject }
        assertTrue(cases.size >= 40)
        var withServed = 0
        var withNone = 0
        var rejectedCases = 0
        for (case in cases) {
            val name = (case["name"] as kotlinx.serialization.json.JsonPrimitive).content
            val expect = (case["expect"] as? kotlinx.serialization.json.JsonArray)?.map { (it as kotlinx.serialization.json.JsonPrimitive).content }?.toSet().orEmpty()
            val circuits = (case["circuits"] as kotlinx.serialization.json.JsonArray).map { it.jsonObject }.map { c ->
                CircuitZkCircuit(
                    system = (c["system"] as kotlinx.serialization.json.JsonPrimitive).content,
                    circuitId = (c["id"] as kotlinx.serialization.json.JsonPrimitive).content,
                    docTypes = setOf(doctype),
                    capabilities = c["capabilities"]?.toString() ?: "{}",
                )
            }
            // `expectRejected`: the matcher must not parse these capabilities, so it serves nothing.
            val rejected = (case["expectRejected"] as? kotlinx.serialization.json.JsonPrimitive)?.content == "true"
            if (rejected) {
                assertTrue("$name: a rejected case expects nothing", expect.isEmpty())
                rejectedCases++
            }
            val serving = CircuitZkServing { circuit, _, _ -> !rejected && circuit.circuitId in expect }
            val p = CircuitZkPlan(plan.functions, raw = query().let { (it["credentials"] as kotlinx.serialization.json.JsonArray)[0].jsonObject })
            val selected = circuits.filter { it.supports(p, doctype, serving) }.map { it.circuitId }.toSet()
            assertEquals(name, if (rejected) emptySet() else circuits.map { it.circuitId }.toSet().intersect(expect), selected)
            val matched = matchWith(circuits, serving).candidates
            assertEquals(name, selected.isNotEmpty(), matched.isNotEmpty())
            if (selected.isEmpty()) withNone++ else withServed++
        }
        assertTrue("some cases serve, some do not ($withServed/$withNone)", withServed > 5 && withNone > 5)
        assertTrue("expectRejected cases went missing: $rejectedCases", rejectedCases >= 2)
    }

    // ---- no claims registered ----

    @Test
    fun `a circuit_zk doctype registers zero claims, other types keep theirs`() {
        val claimless = StoredCredential(id = 1, format = "mso_mdoc", raw = mdocRaw(doctype), batchId = 1, instanceId = 0)
        val other = StoredCredential(id = 2, format = "mso_mdoc", raw = mdocRaw("other"), batchId = 2, instanceId = 0)
        assertTrue("fixture carries claims", SharedDcqlMatcher.buildFfiClaims(claimless).isNotEmpty())
        assertTrue(SharedDcqlMatcher.buildFfiClaims(claimless, setOf(doctype)).isEmpty())
        assertTrue(SharedDcqlMatcher.buildFfiClaims(other, setOf(doctype)).isNotEmpty())
        assertTrue(CredentialUtils.isOfDocTypes(claimless, setOf(doctype)))
        assertFalse(CredentialUtils.isOfDocTypes(other, setOf(doctype)))
        assertFalse(CredentialUtils.isOfDocTypes(sdJwt(3), setOf(doctype)))
        assertFalse(CredentialUtils.isOfDocTypes(claimless, emptySet()))
        assertNotNull(SharedDcqlMatcher.buildFfiClaims(other, setOf(doctype)))
    }
}
