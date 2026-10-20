package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The part of [SharedCircuitZkPlanner] that runs without the native matcher: reading its plan JSON into the SDK's
 * plan. What the matcher answers is checked on a device, against its own vectors
 * (`SharedCircuitZkPlannerInstrumentedTest`).
 */
class SharedCircuitZkPlannerTest {
    private fun obj(s: String): JsonObject = Json.parseToJsonElement(s).jsonObject

    private fun plan(filter: String?) = SharedCircuitZkPlanner.toPlan(
        obj(
            """{"functions":[{"function_id":"age_check","handle":"h","params":{"ge":"2008-10-10","source":{"path":["birth_date"]}}}],
               ${filter?.let { "\"system_filter\":$it," } ?: ""} "meta_doctype":"d","raw":{"id":"q"}}""",
        ),
    )

    @Test
    fun functionsKeepIdHandleAndParamsAsPlanned() {
        val f = plan("{}").functions.single()
        assertEquals("age_check", f.id)
        assertEquals("h", f.handle)
        assertEquals(obj("""{"ge":"2008-10-10","source":{"path":["birth_date"]}}"""), f.params)
        assertEquals(obj("""{"id":"q"}"""), plan("{}").raw)
    }

    @Test
    fun aListNotSentIsNoConstraintAndAListSentEmptyAdmitsNothing() {
        assertNull(plan("{}").circuitFilter)
        assertNull(plan(null).circuitFilter)
        assertEquals(CircuitZkCircuitFilter(null, emptyList()), plan("""{"system_ids":[]}""").circuitFilter)
        assertEquals(CircuitZkCircuitFilter(listOf("s"), emptyList()), plan("""{"proof_systems":["s"],"system_ids":[]}""").circuitFilter)
        val c = CircuitZkCircuit("s", "c1", setOf("d"))
        assertTrue(!plan("""{"system_ids":[]}""").circuitFilter!!.admits(c))
        assertTrue(!plan("""{"proof_systems":[]}""").circuitFilter!!.admits(c))
    }

    @Test
    fun twoIndependentListsStayTwoLists() {
        assertEquals(CircuitZkCircuitFilter(listOf("s1", "s2"), null), plan("""{"proof_systems":["s1","s2"]}""").circuitFilter)
        assertEquals(CircuitZkCircuitFilter(null, listOf("c1")), plan("""{"system_ids":["c1"]}""").circuitFilter)
        assertEquals(
            CircuitZkCircuitFilter(listOf("s1", "s2"), listOf("c1", "c2")),
            plan("""{"proof_systems":["s1","s2"],"system_ids":["c1","c2"]}""").circuitFilter,
        )
    }

    /** The lists admit exactly what the matcher admits: system in the first list AND id in the second. */
    @Test
    fun theListsAdmitWhatTheMatcherAdmits() {
        fun circuit(system: String, id: String) = CircuitZkCircuit(system, id, setOf("d"))
        val p = plan("""{"proof_systems":["s1","s2"],"system_ids":["c1","c2"]}""")
        fun admits(c: CircuitZkCircuit) = p.circuitFilter!!.admits(c)
        assertTrue(admits(circuit("s1", "c2")))
        assertTrue(admits(circuit("s2", "c1")))
        assertTrue(!admits(circuit("s3", "c1")))
        assertTrue(!admits(circuit("s1", "c3")))
    }

    /**
     * Both lists are verifier-controlled and read before the trust decision. 10,000 x 10,000 entries
     * must not become 100 million pairs (a heap exhaustion from an untrusted request): the plan keeps
     * the two lists, and the answer is the same.
     */
    @Test
    fun aHugeRequestIsNotExpandedIntoTheProductOfItsLists() {
        val n = 10_000
        fun array(prefix: String) = (0 until n).joinToString(",", "[", "]") { "\"$prefix$it\"" }
        val started = System.nanoTime()
        val p = plan("""{"proof_systems":${array("s")},"system_ids":${array("c")}}""")
        val filter = p.circuitFilter!!
        assertEquals(n, filter.proofSystems!!.size)
        assertEquals(n, filter.circuitIds!!.size)
        assertTrue(filter.admits(CircuitZkCircuit("s9999", "c0", setOf("d"))))
        assertTrue(!filter.admits(CircuitZkCircuit("s9999", "other", setOf("d"))))
        assertTrue(!filter.admits(CircuitZkCircuit("other", "c9999", setOf("d"))))
        assertTrue("planning took ${(System.nanoTime() - started) / 1_000_000} ms", System.nanoTime() - started < 10_000_000_000L)
    }

    @Test
    fun anUnreadablePlanIsRejected() {
        assertThrows(IllegalArgumentException::class.java) { SharedCircuitZkPlanner.toPlan(obj("""{"raw":{}}""")) }
        assertThrows(IllegalArgumentException::class.java) {
            SharedCircuitZkPlanner.toPlan(obj("""{"functions":[{"function_id":1,"handle":"h"}],"raw":{}}"""))
        }
        assertThrows(IllegalArgumentException::class.java) {
            SharedCircuitZkPlanner.toPlan(obj("""{"functions":[],"system_filter":{"system_ids":[1]},"raw":{}}"""))
        }
    }

    /** The plan JSON the matcher's own vectors state (rulebook v0.4) is read into the SDK's plan: names and shape agree. */
    @Test
    fun theMatchersVectorPlansAreReadAsTheyAre() {
        val dir = java.io.File("../../spec/zkp-req-vectors/zkp_req")
        val ok = dir.listFiles { f -> f.name.startsWith("ok_") && f.extension == "json" }!!.sortedBy { it.name }
        assertTrue(ok.size >= 10)
        for (f in ok) {
            val v = obj(f.readText())
            val expected = v["expect"]!!.jsonObject["plan"]!!.jsonObject
            val plan = SharedCircuitZkPlanner.toPlan(JsonObject(expected + ("raw" to v["query"]!!)))
            assertEquals(f.name, expected["functions"]!!.let { (it as kotlinx.serialization.json.JsonArray).size }, plan.functions.size)
            val lists = expected["system_filter"] as? JsonObject
            val want = lists?.let {
                CircuitZkCircuitFilter(
                    (it["proof_systems"] as? kotlinx.serialization.json.JsonArray)?.map { x -> (x as kotlinx.serialization.json.JsonPrimitive).content },
                    (it["system_ids"] as? kotlinx.serialization.json.JsonArray)?.map { x -> (x as kotlinx.serialization.json.JsonPrimitive).content },
                )
            }?.takeIf { it.proofSystems != null || it.circuitIds != null }
            assertEquals(f.name, want, plan.circuitFilter)
            assertEquals(f.name, (expected["source_format"] as kotlinx.serialization.json.JsonPrimitive).content, plan.sourceFormat)
        }
    }
}
