package org.siros.sdk.transport.engine

import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * A data class's property order is part of its binary API (componentN, copy, the constructor). New properties are appended,
 * so the positions existing consumers destructure or construct by never move.
 */
class EngineTypesBinaryShapeTest {
    private fun components(o: Any): List<Any?> {
        val n = o.javaClass.methods.count { Regex("component\\d+").matches(it.name) }
        return (1..n).map { o.javaClass.getMethod("component$it").invoke(o) }
    }

    @Test
    fun `sign response keeps timestamp where it was and appends the refusal fields after it`() {
        val c = components(SignResponseMessage(flowId = "f", timestamp = "TS", errorCode = "EC", error = "ER"))
        assertEquals(listOf("TS", "EC", "ER"), c.takeLast(3))
    }

    @Test
    fun `sign request params appends client_metadata last`() {
        val c = components(SignRequestParams(clientMetadata = JsonPrimitive("CM"), credentialIssuer = "CI"))
        // After everything main already had (including the engine-blind encryption members); credential_issuer keeps its position.
        // Everything appended after client_metadata (the auxiliary-data field) comes last; client_metadata keeps its position before it.
        assertEquals(null, c.last())
        assertEquals(JsonPrimitive("CM"), c[c.size - 2])
        assertEquals("CI", c[c.indexOfFirst { it == "CI" }])
        assertEquals(null, c[c.size - 3])
    }
}
