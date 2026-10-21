package org.siros.sdk.transport.engine

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test

/** The sign-stage refusal is a `sign_response` with `error_code` SIGN_REFUSED that echoes the request's `message_id` (wmp spec 3.2.6). */
class SignRefusalWireShapeTest {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true } // as WalletEngineSession encodes

    @Test
    fun aRefusalCarriesTheCodeTheEchoedMessageIdAndNoVpToken() {
        val wire = json.encodeToString(
            SignResponseMessage.serializer(),
            SignResponseMessage(flowId = "f1", messageId = "m1", errorCode = SignResponseMessage.SIGN_REFUSED, error = "trust"),
        )
        val o = Json.parseToJsonElement(wire).jsonObject
        assertEquals("sign_response", o["type"]?.jsonPrimitive?.content)
        assertEquals("f1", o["flow_id"]?.jsonPrimitive?.content)
        assertEquals("m1", o["message_id"]?.jsonPrimitive?.content)
        assertEquals("SIGN_REFUSED", o["error_code"]?.jsonPrimitive?.content)
        assertEquals("trust", o["error"]?.jsonPrimitive?.content)
        assertEquals(kotlinx.serialization.json.JsonNull, o["vp_token"] ?: kotlinx.serialization.json.JsonNull)
    }

    @Test
    fun anOrdinaryResponseCarriesNoErrorMembers() {
        val o = Json.parseToJsonElement(
            json.encodeToString(SignResponseMessage.serializer(), SignResponseMessage(flowId = "f1", messageId = "m1", vpToken = "t")),
        ).jsonObject
        assertEquals(kotlinx.serialization.json.JsonNull, o["error_code"] ?: kotlinx.serialization.json.JsonNull)
        assertEquals(kotlinx.serialization.json.JsonNull, o["error"] ?: kotlinx.serialization.json.JsonNull)
    }
}
