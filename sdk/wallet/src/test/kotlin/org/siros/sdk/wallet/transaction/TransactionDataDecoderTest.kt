package org.siros.sdk.wallet.transaction

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.transport.wmp.openid4x.TransactionData
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.b64
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.raw

class TransactionDataDecoderTest {

    private fun refusal(entry: TransactionDataEntry): TransactionDataReason =
        (runCatching { TransactionDataDecoder.decode(entry) }.exceptionOrNull() as? TransactionDataError)?.reason
            ?: throw AssertionError("expected a TransactionDataError")

    private fun invalid(raw: String) = assertEquals(TransactionDataReason.INVALID_ENTRY, refusal(TransactionDataEntry(raw)))

    @Test
    fun `decodes the entry's own members`() {
        val d = TransactionDataDecoder.decode(TransactionDataEntry(raw(algs = """["sha-384","sha-256"]""")))

        assertEquals("urn:eudi:sca:payment:1", d.type)
        assertEquals(listOf("pay"), d.credentialIds)
        assertEquals("tx-0001", (d.payload["transaction_id"] as kotlinx.serialization.json.JsonPrimitive).content)
        assertEquals(listOf("sha-384", "sha-256"), d.hashAlgs)
    }

    @Test
    fun `padding is optional and a bare string algorithm is read as a list`() {
        val json = """{"type":"t","credential_ids":["a"],"payload":{},"transaction_data_hashes_alg":"sha-512"}"""
        val padded = java.util.Base64.getUrlEncoder().encodeToString(json.toByteArray())

        assertEquals(listOf("sha-512"), TransactionDataDecoder.decode(TransactionDataEntry(padded)).hashAlgs)
        assertEquals(listOf("sha-512"), TransactionDataDecoder.decode(TransactionDataEntry(b64(json))).hashAlgs)
    }

    @Test
    fun `an entry with no algorithm list has none`() {
        assertNull(TransactionDataDecoder.decode(TransactionDataEntry(raw())).hashAlgs)
    }

    @Test
    fun `raw that is not base64url is refused`() {
        invalid("")
        invalid("not base64url!")
        invalid("ab+/")                       // standard alphabet, not URL-safe
        invalid(raw().chunked(10).joinToString("\n"))  // whitespace
        invalid("a")                          // impossible length
        invalid("x".repeat(TransactionDataDecoder.MAX_RAW_CHARS + 1))
    }

    @Test
    fun `raw that is not a UTF-8 JSON object is refused`() {
        invalid(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(byteArrayOf(0x7b, 0xff.toByte(), 0x7d)))
        invalid(b64("[1]"))
        invalid(b64("\"x\""))
        invalid(b64("{not json}"))
        invalid(b64("""{"type":"t"} {"x":1}"""))
    }

    @Test
    fun `invalid UTF-8 inside an otherwise valid JSON string is refused, not repaired`() {
        val head = """{"type":"t","credential_ids":["a"],"payload":{"x":"""".toByteArray()
        val bytes = head + byteArrayOf(0xff.toByte()) + """"}}""".toByteArray()

        invalid(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes))
    }

    @Test
    fun `an oversized entry is refused even when it is otherwise valid`() {
        invalid(raw(payload = """{"transaction_id":"t","note":"${"a".repeat(TransactionDataDecoder.MAX_RAW_CHARS)}"}"""))
    }

    @Test
    fun `a repeated member name is refused, so both parsers see the same entry`() {
        invalid(b64("""{"type":"t","credential_ids":["a"],"payload":{"amount":1,"amount":9999}}"""))
        invalid(b64("""{"type":"t","type":"u","credential_ids":["a"],"payload":{}}"""))
    }

    @Test
    fun `required members are checked`() {
        invalid(b64("""{"credential_ids":["a"],"payload":{}}"""))
        invalid(b64("""{"type":"","credential_ids":["a"],"payload":{}}"""))
        invalid(b64("""{"type":5,"credential_ids":["a"],"payload":{}}"""))
        invalid(b64("""{"type":"t","payload":{}}"""))
        invalid(b64("""{"type":"t","credential_ids":[],"payload":{}}"""))
        invalid(b64("""{"type":"t","credential_ids":["a",""],"payload":{}}"""))
        invalid(b64("""{"type":"t","credential_ids":["a",1],"payload":{}}"""))
        invalid(b64("""{"type":"t","credential_ids":"a","payload":{}}"""))
        invalid(b64("""{"type":"t","credential_ids":["a"]}"""))
        invalid(b64("""{"type":"t","credential_ids":["a"],"payload":[]}"""))
        invalid(b64("""{"type":"t","credential_ids":["a"],"payload":"x"}"""))
    }

    @Test
    fun `a malformed hash algorithm list is refused`() {
        for (bad in listOf("5", "{}", "[]", "[1]", "\"\"", "[\"sha-256\",null]", "true")) {
            invalid(b64("""{"type":"t","credential_ids":["a"],"payload":{},"transaction_data_hashes_alg":$bad}"""))
        }
    }

    private fun hint(
        type: String? = "urn:eudi:sca:payment:1",
        ids: List<String>? = listOf("pay"),
        payload: String? = TransactionTestFixtures.PAYMENT_PAYLOAD,
        algs: List<String>? = null,
    ) = TransactionDataHint(type, ids, payload?.let { Json.parseToJsonElement(it) }, algs)

    @Test
    fun `a hint that agrees is accepted, an absent one too`() {
        TransactionDataDecoder.decode(TransactionDataEntry(raw(), hint()))
        TransactionDataDecoder.decode(TransactionDataEntry(raw(), hint(type = null, ids = null, payload = null)))
        TransactionDataDecoder.decode(TransactionDataEntry(raw(algs = """["sha-256"]"""), hint(algs = listOf("sha-256"))))
    }

    @Test
    fun `a hint that disagrees with the entry is refused member by member`() {
        fun inconsistent(h: TransactionDataHint, member: String) {
            val e = runCatching { TransactionDataDecoder.decode(TransactionDataEntry(raw(), h)) }.exceptionOrNull()
            assertTrue("$member: $e", e is TransactionDataError)
            assertEquals(member, TransactionDataReason.INCONSISTENT_WITH_ORCHESTRATOR, (e as TransactionDataError).reason)
        }
        inconsistent(hint(type = "urn:eudi:sca:login_risk_transaction:1"), "type")
        inconsistent(hint(ids = listOf("other")), "credential_ids")
        inconsistent(hint(ids = listOf("pay", "pay2")), "credential_ids")
        inconsistent(hint(payload = TransactionTestFixtures.PAYMENT_PAYLOAD.replace("49.99", "4.99")), "payload")
        inconsistent(hint(algs = listOf("sha-256")), "alg (none in the entry)")
    }

    @Test
    fun `an orchestrator that sent no raw cannot be bound to`() {
        val e = runCatching {
            TransactionDataEntry.fromWire(TransactionData(type = "urn:eudi:sca:payment:1", credentialIds = listOf("pay")))
        }.exceptionOrNull() as TransactionDataError

        assertEquals(TransactionDataReason.INVALID_ENTRY, e.reason)
    }

    @Test
    fun `a wire entry becomes an entry with the orchestrator's hint`() {
        val wire = TransactionData(
            type = "urn:eudi:sca:payment:1", raw = raw(), credentialIds = listOf("pay"),
            payload = Json.parseToJsonElement(TransactionTestFixtures.PAYMENT_PAYLOAD),
        )

        val entry = TransactionDataEntry.fromWire(wire)

        assertEquals(raw(), entry.raw)
        assertEquals("urn:eudi:sca:payment:1", entry.hint!!.type)
        TransactionDataDecoder.decode(entry)
    }

    @Test
    fun `hostile nesting and bad escapes surface as an invalid entry, never as an Error or raw exception`() {
        val deepArray = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("[".repeat(45_000).toByteArray())
        invalid(deepArray)
        invalid(b64("""{"type":"t","credential_ids":["a"],"payload":{"x":"\uZZZZ"}}"""))
        invalid(b64("""{"type":"t","credential_ids":["a"],"payload":""" + "[".repeat(40_000)))
        invalid(b64("""{"type":"t","credential_ids":["a"],"payload":{"a":""" + "{\"a\":".repeat(5_000)))
    }
}
