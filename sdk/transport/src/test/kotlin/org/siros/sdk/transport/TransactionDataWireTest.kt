package org.siros.sdk.transport

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.siros.sdk.transport.engine.FlowStartMessage
import org.siros.sdk.transport.engine.SignRequestMessage
import org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams
import org.siros.sdk.transport.wmp.openid4x.TransactionData

/**
 * The `transaction_data` members of both wire formats: go-wmp
 * `openid4x.TransactionData` / `SignSubFlowParams` (WMP) and the legacy engine
 * WebSocket `sign_request.params`. A decode failure of a sign request is
 * dropped by the callers, so a member that fails to decode stalls the flow;
 * these tests pin the shapes the backend sends.
 */
class TransactionDataWireTest {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private val entry = """
        {"type":"urn:eudi:sca:payment:1","raw":"eyJ0eXBlIjoieCJ9",
         "payload":{"transaction_id":"tx-1","amount":"1.00"},
         "credential_ids":["pay"],"transaction_data_hashes_alg":%s}
    """.trimIndent()

    @Test
    fun `entry carries raw, payload and the algorithm array`() {
        val td = json.decodeFromString(TransactionData.serializer(), entry.format("""["sha-256","sha-512"]"""))

        assertEquals("eyJ0eXBlIjoieCJ9", td.raw)
        assertEquals("urn:eudi:sca:payment:1", td.type)
        assertEquals(listOf("pay"), td.credentialIds)
        assertEquals("tx-1", td.payload!!.jsonObject["transaction_id"]!!.jsonPrimitive.content)
        assertEquals(listOf("sha-256", "sha-512"), td.transactionDataHashesAlg)
    }

    @Test
    fun `a bare string algorithm from an older peer is read as a one-element list`() {
        val td = json.decodeFromString(TransactionData.serializer(), entry.format("\"sha-384\""))

        assertEquals(listOf("sha-384"), td.transactionDataHashesAlg)
    }

    @Test
    fun `an entry from an orchestrator that predates raw has none`() {
        val td = json.decodeFromString(
            TransactionData.serializer(),
            """{"type":"urn:eudi:sca:payment:1","payload":{},"credential_ids":["pay"]}""",
        )

        assertNull(td.raw)
        assertNull(td.transactionDataHashesAlg)
    }

    @Test
    fun `a malformed algorithm member fails to decode instead of being coerced`() {
        for (bad in listOf("5", "{}", "[1]", "[\"sha-256\",null]", "true")) {
            assertThrows(bad, SerializationException::class.java) {
                json.decodeFromString(TransactionData.serializer(), entry.format(bad))
            }
        }
    }

    @Test
    fun `the algorithm list is written as an array`() {
        val td = TransactionData(type = "t", raw = "r", transactionDataHashesAlg = listOf("sha-256"))

        val out = json.encodeToString(TransactionData.serializer(), td)

        assertEquals(
            """["sha-256"]""",
            json.parseToJsonElement(out).jsonObject["transaction_data_hashes_alg"].toString(),
        )
    }

    @Test
    fun `WMP sign sub-flow carries response_mode and the entries`() {
        val params = json.decodeFromString(
            SignSubFlowParams.serializer(),
            """{"action":"sign_presentation","nonce":"n","audience":"a","response_mode":"direct_post.jwt",
                "verifier_session_id":"vs-1",
                "credentials_to_include":[{"credential_id":"7","credential_query_id":"q1"}],
                "transaction_data":[${entry.format("""["sha-256"]""")}]}""",
        )

        assertEquals("direct_post.jwt", params.responseMode)
        assertEquals("vs-1", params.verifierSessionId)
        assertEquals("q1", params.credentialsToInclude!!.single().credentialQueryId)
        assertEquals("eyJ0eXBlIjoieCJ9", params.transactionData!!.single().raw)
    }

    @Test
    fun `legacy engine sign_request carries response_mode and the entries`() {
        val msg = json.decodeFromString(
            SignRequestMessage.serializer(),
            """{"type":"sign_request","flow_id":"f","action":"sign_presentation",
                "params":{"audience":"a","nonce":"n","response_mode":"direct_post",
                "credentials_to_include":[{"credential_id":"7","credential_query_id":"q1"}],
                "transaction_data":[${entry.format("""["sha-256"]""")}]}}""",
        )

        assertEquals("direct_post", msg.params.responseMode)
        assertEquals("eyJ0eXBlIjoieCJ9", msg.params.transactionData!!.single().raw)
        assertEquals(listOf("sha-256"), msg.params.transactionData!!.single().transactionDataHashesAlg)
        assertEquals("q1", msg.params.credentialsToInclude!!.single().credentialQueryId)
    }

    @Test
    fun `a sign_request without transaction_data decodes with none`() {
        val msg = json.decodeFromString(
            SignRequestMessage.serializer(),
            """{"type":"sign_request","flow_id":"f","action":"sign_presentation","params":{"audience":"a","nonce":"n"}}""",
        )

        assertNull(msg.params.transactionData)
        assertNull(msg.params.responseMode)
    }

    @Test
    fun `flow_start declares features only when given`() {
        val none = json.encodeToString(FlowStartMessage.serializer(), FlowStartMessage(protocol = "oid4vp"))
        val declared = json.encodeToString(
            FlowStartMessage.serializer(),
            FlowStartMessage(protocol = "oid4vp", features = listOf(FlowStartMessage.FEATURE_TRANSACTION_DATA_V1)),
        )

        assertEquals(false, none.contains("transaction_data.v1"))
        assertEquals(
            """["transaction_data.v1"]""",
            json.parseToJsonElement(declared).jsonObject["features"].toString(),
        )
    }
}
