package org.siros.sdk.wallet.transaction

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class Ts12SchemasTest {
    private fun sha256(text: String) = MessageDigest.getInstance("SHA-256").digest(text.toByteArray())
        .joinToString("") { "%02x".format(it) }

    private fun valid(type: String, payload: String) =
        TransactionSchemas.validateBuiltIn(type, Json.parseToJsonElement(payload)).isEmpty()

    @Test
    fun `the embedded schemas are the spec's files, byte for byte`() {
        // Hashes of docs/technical-specifications/api/ts12-urn-eudi-sca-*-data-model.json at
        // eudi-doc-standards-and-technical-specifications@ee91a294.
        assertEquals("fbc788b6d39941ae969e49208ce91129dd1558ccd780175ce4a68958aa97df24", sha256(Ts12Schemas.PAYMENT))
        assertEquals("b1ac923b1df7707fb58b35737b27bee80834c01f581a4335a805dfc33bf3ba20", sha256(Ts12Schemas.LOGIN_RISK))
        assertEquals("b11cb79168eb9bdf64b365b2b27f815d5455833567f9b4ab3ccabc1889e94cad", sha256(Ts12Schemas.ACCOUNT_ACCESS))
        assertEquals("7e27182efc4a479d7051884aade820dc6a4f1957728ef87f9e101b1d925a5034", sha256(Ts12Schemas.EMANDATE))
    }

    @Test
    fun `exactly the four built-in types are known`() {
        assertEquals(
            setOf(
                "urn:eudi:sca:payment:1", "urn:eudi:sca:login_risk_transaction:1",
                "urn:eudi:sca:account_access:1", "urn:eudi:sca:emandate:1",
            ),
            Ts12Schemas.BY_TYPE.keys,
        )
        assertFalse(TransactionSchemas.isBuiltIn("urn:eudi:sca:payment:2"))
    }

    @Test
    fun `payment accepts a compliant payload and rejects the usual faults`() {
        val p = "urn:eudi:sca:payment:1"
        assertTrue(valid(p, TransactionTestFixtures.PAYMENT_PAYLOAD))
        // required members
        assertFalse(valid(p, """{"payee":{"name":"a","id":"b"},"currency":"EUR","amount":1}"""))
        assertFalse(valid(p, """{"transaction_id":"t","currency":"EUR","amount":1}"""))
        assertFalse(valid(p, """{"transaction_id":"t","payee":{"name":"a"},"currency":"EUR","amount":1}"""))
        // types and patterns
        assertFalse(valid(p, """{"transaction_id":"t","payee":{"name":"a","id":"b"},"currency":"eur","amount":1}"""))
        assertFalse(valid(p, """{"transaction_id":"t","payee":{"name":"a","id":"b"},"currency":"EUR","amount":"1.00"}"""))
        // additionalProperties: false at the top level
        assertFalse(valid(p, """{"transaction_id":"t","payee":{"name":"a","id":"b"},"currency":"EUR","amount":1,"x":1}"""))
        // transaction_id length
        assertFalse(valid(p, """{"transaction_id":"${"x".repeat(37)}","payee":{"name":"a","id":"b"},"currency":"EUR","amount":1}"""))
        // recurrence frequency enum
        assertFalse(valid(p, """{"transaction_id":"t","payee":{"name":"a","id":"b"},"currency":"EUR","amount":1,"recurrence":{"frequency":"HOURLY"}}"""))
        assertTrue(valid(p, """{"transaction_id":"t","payee":{"name":"a","id":"b"},"currency":"EUR","amount":1,"recurrence":{"frequency":"MNTH"}}"""))
    }

    @Test
    fun `format is an annotation, so a date-only execution_date validates`() {
        assertTrue(
            valid(
                "urn:eudi:sca:payment:1",
                """{"transaction_id":"t","payee":{"name":"a","id":"b"},"currency":"EUR","amount":1,"execution_date":"2026-10-06"}""",
            ),
        )
    }

    @Test
    fun `login, account access and e-mandate`() {
        assertTrue(valid("urn:eudi:sca:login_risk_transaction:1", """{"transaction_id":"t","action":"Log in"}"""))
        assertFalse(valid("urn:eudi:sca:login_risk_transaction:1", """{"transaction_id":"t"}"""))
        assertTrue(valid("urn:eudi:sca:account_access:1", """{"transaction_id":"t","aisp":{"legal_name":"a","brand_name":"b","domain_name":"c"}}"""))
        assertFalse(valid("urn:eudi:sca:account_access:1", """{"transaction_id":"t","aisp":{"legal_name":"a"}}"""))
        assertTrue(valid("urn:eudi:sca:emandate:1", """{"transaction_id":"t","purpose":"Pay monthly bill"}"""))
        assertFalse(valid("urn:eudi:sca:emandate:1", """{"transaction_id":"t","purpose":"${"x".repeat(1001)}"}"""))
    }

    @Test
    fun `e-mandate resolves its reference to the payment schema`() {
        val good = """{"transaction_id":"t","payment_payload":${TransactionTestFixtures.PAYMENT_PAYLOAD}}"""
        val bad = """{"transaction_id":"t","payment_payload":{"transaction_id":"t","currency":"EUR","amount":1}}"""

        assertTrue(valid("urn:eudi:sca:emandate:1", good))
        assertFalse("payment_payload must satisfy the payment schema", valid("urn:eudi:sca:emandate:1", bad))
    }

    @Test
    fun `a schema that references anything unregistered is unusable, not fetched`() {
        val schema = Json.parseToJsonElement("""{"${'$'}ref":"https://evil.example/schema.json"}""")

        val failure = runCatching { TransactionSchemas.validate(schema, Json.parseToJsonElement("{}")) }.exceptionOrNull()

        assertTrue(failure.toString(), failure is TransactionSchemas.UnusableSchema)
    }

    @Test
    fun `the wmp golden vector payloads do not satisfy the official payment schema`() {
        // transaction-data-hashes.json (leifj/wmp) uses "amount":"49.99", a string; the spec's
        // schema says number. The vectors are fine as HASH vectors but are not valid SCA payloads.
        assertFalse(
            valid(
                "urn:eudi:sca:payment:1",
                """{"amount":"49.99","currency":"EUR","execution_date":"2026-10-06","payee":{"id":"SE1234567890","name":"Shop AB"},"transaction_id":"tx-0001"}""",
            ),
        )
    }
}
