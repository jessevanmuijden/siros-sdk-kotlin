package org.siros.sdk.transport.engine

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The encrypted-presentation answer on the wire: `{response_jwe}` and nothing that could shadow it. */
class SignResponseJweWireShapeTest {
    private val json = Json { encodeDefaults = false }

    @Test
    fun aResponseJweIsTheOnlyResultMember() {
        val out = json.encodeToString(SignResponseMessage.serializer(), SignResponseMessage(flowId = "f1", messageId = "m1", responseJwe = "a.b.c.d.e")).let {
            Json.parseToJsonElement(it).jsonObject
        }
        assertEquals("a.b.c.d.e", out["response_jwe"]!!.toString().trim('"'))
        for (member in listOf("vp_token", "error", "error_code", "proof_jwt")) assertFalse(member, member in out)
    }

    @Test
    fun aResponseJweNeverTravelsWithAnErrorOrARefusal() {
        for (build in listOf<() -> SignResponseMessage>(
            { SignResponseMessage(flowId = "f", responseJwe = "j", error = "x") },
            { SignResponseMessage(flowId = "f", responseJwe = "j", errorCode = SignResponseMessage.SIGN_REFUSED) },
        )) {
            try {
                build()
                fail("accepted a response_jwe together with an error")
            } catch (_: IllegalArgumentException) {
                assertTrue(true)
            }
        }
    }

    @Test
    fun theRequestParametersDecodeResponseEncryptionStateAndTheVerifiedClientId() {
        val p = Json { ignoreUnknownKeys = true }.decodeFromString(
            SignRequestParams.serializer(),
            """{"audience":"a","response_encryption":{"jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y","kid":"k"},"alg":"ECDH-ES","enc":"A128GCM"},"state":"s","verified_request":{"client_id":"cid","unknown":1}}""",
        )
        assertEquals("ECDH-ES", p.responseEncryption!!.alg)
        assertEquals("A128GCM", p.responseEncryption!!.enc)
        assertEquals("s", p.state)
        assertEquals("cid", p.verifiedRequest!!.clientId)
    }
}
