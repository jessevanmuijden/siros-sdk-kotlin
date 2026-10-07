package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.wallet.TransactionConsentRequest
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.FakeSource
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.PAYMENT
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.PAYMENT_TYPES
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.metadata
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.raw
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.request

class TransactionDisplayBuilderTest {
    private fun model(
        types: String? = PAYMENT_TYPES,
        locale: String = "en-GB",
        documents: Map<String, String> = emptyMap(),
        payload: String = TransactionTestFixtures.PAYMENT_PAYLOAD,
        signed: Boolean? = null,
    ): TransactionConsentRequest = runBlocking {
        val source = FakeSource(metadata(types = types), documents)
        val validated = TransactionDataValidator(source).validate(request(listOf(TransactionDataEntry(raw(payload = payload)))))
        TransactionDisplayBuilder(source, locale).build(validated, "Shop AB (verifier)", signed)
    }

    private fun refusal(block: () -> Unit): TransactionDataReason =
        runCatching(block).exceptionOrNull().let { e ->
            (e as? TransactionDataError)?.reason ?: throw AssertionError("expected a refusal, got $e")
        }

    @Test
    fun `fields carry labels and levels, ordered level 1 first, payload order within a level`() {
        val e = model().entries.single()

        assertEquals(
            listOf("Payee" to 1, "Currency" to 1, "Amount" to 1, "Transaction ID" to 2, "Payee ID" to 2),
            e.fields.map { it.label to it.level },
        )
        assertEquals("Shop AB", e.fields.first().value)
        assertEquals("49.99", e.fields.first { it.label == "Amount" }.value)
    }

    private val customTypes = """{"https://bank.example/trx":{"schema":{"type":"object"},
        "claims":[{"path":["payload","note"],"display":[{"lang":"en","label":"Note"}]},
                  {"path":["payload","ref"],"visualisation":4,"display":[{"lang":"en","label":"Ref"}]},
                  {"path":["payload","hidden"],"visualisation":4}],
        "ui_labels":{"affirmative_action_label":[{"lang":"en","value":"OK"}]}}}"""

    private fun customModel(payload: String, types: String = customTypes): TransactionConsentRequest = runBlocking {
        val source = FakeSource(metadata(types = types))
        val v = TransactionDataValidator(source).validate(
            request(listOf(TransactionDataEntry(raw(type = "https://bank.example/trx", payload = payload)))),
        )
        TransactionDisplayBuilder(source, "en").build(v, "V", null)
    }

    @Test
    fun `an unset visualisation defaults to 3, and a custom type may omit what the issuer marks level 4`() {
        val e = customModel("""{"note":"hello","ref":"r","hidden":"h"}""").entries.single()

        assertEquals(listOf("Note" to 3, "Ref" to 4), e.fields.map { it.label to it.level })
    }

    @Test
    fun `UI elements and request metadata come through`() {
        val m = model(signed = false)
        val e = m.entries.single()

        assertEquals("Confirm Payment", e.affirmativeLabel)
        assertEquals("Cancel Payment", e.denialLabel)
        assertEquals("Confirm your payment", e.title)
        assertEquals("Check the amount", e.securityHint)
        assertEquals("Payment Confirmation", e.typeName)
        assertEquals(false, m.requestSigned)
        assertEquals("Shop AB (verifier)", m.verifier)
        assertEquals("Pay Card", m.credentialName)
        assertEquals("en-GB", m.locale)
    }

    @Test
    fun `labels follow the locale, then the language, then English`() {
        assertEquals("Mottagare", model(locale = "sv-SE").entries.single().fields.first().label)
        assertEquals("Bekräfta betalning", model(locale = "sv").entries.single().affirmativeLabel)
        assertEquals("Payee", model(locale = "de-DE").entries.single().fields.first().label)
        assertEquals("Mottagare", model(locale = "sv_SE").entries.single().fields.first().label)
    }

    @Test
    fun `optional UI elements may be absent, the required one may not`() {
        val onlyRequired = PAYMENT_TYPES.replace(
            Regex(""""denial_action_label":\[[^\]]*\],\s*"transaction_title":\[[^\]]*\],\s*"security_hint":\[[^\]]*\]"""), "\"x\":[]",
        )
        val e = model(types = onlyRequired).entries.single()
        assertNull(e.denialLabel)
        assertNull(e.title)
        assertNull(e.securityHint)

        val noAffirmative = PAYMENT_TYPES.replace("\"affirmative_action_label\"", "\"other\"")
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = noAffirmative) })
    }

    @Test
    fun `a parameter without a localised name stops the transaction, unless the issuer marked it omittable`() {
        val noAmountLabel = PAYMENT_TYPES.replace(
            """{"path":["payload","amount"],"visualisation":1,"display":[{"lang":"en","label":"Amount"}]}""",
            """{"path":["payload","amount"],"visualisation":1}""",
        )
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = noAmountLabel) })

        val noClaimAtAll = PAYMENT_TYPES.replace(
            """{"path":["payload","currency"],"visualisation":2,"display":[{"lang":"en","label":"Currency"}]},""", "",
        )
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = noClaimAtAll) })

        // an issuer may mark a custom type's field level 4 and leave it unlabelled; a built-in's required
        // members can never be hidden that way (see the floor tests)
        assertTrue(customModel("""{"note":"x","hidden":"h"}""").entries.single().fields.none { it.label == "hidden" })
    }

    @Test
    fun `no metadata entry, or malformed claim metadata, refuses`() {
        // a built-in type validates without a metadata entry, but then nothing can be labelled
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = "{}") })
        assertEquals(
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal { model(types = PAYMENT_TYPES.replace("\"visualisation\":2", "\"visualisation\":7")) },
        )
        assertEquals(
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal { model(types = """{"$PAYMENT":{"claims":5,"ui_labels":{}}}""") },
        )
    }

    @Test
    fun `claims_uri and ui_labels_uri are fetched, and may not be given alongside the inline form`() {
        val claims = """[{"path":["payload","transaction_id"],"visualisation":4,"display":[{"lang":"en","label":"Id"}]},{"path":["payload","payee","name"],"display":[{"lang":"en","label":"Payee"}]},
            {"path":["payload","payee","id"],"visualisation":4,"display":[{"lang":"en","label":"PId"}]},{"path":["payload","currency"],"display":[{"lang":"en","label":"Cur"}]},{"path":["payload","amount"],"display":[{"lang":"en","label":"Amt"}]}]"""
        val labels = """{"affirmative_action_label":[{"lang":"en","value":"OK"}]}"""
        val types = """{"$PAYMENT":{"claims_uri":"https://bank.example/c.json","ui_labels_uri":"https://bank.example/l.json"}}"""
        val docs = mapOf("https://bank.example/c.json" to claims, "https://bank.example/l.json" to labels)

        val e = model(types = types, documents = docs).entries.single()
        assertEquals("OK", e.affirmativeLabel)
        assertEquals(listOf("Payee", "Cur", "Amt", "Id", "PId"), e.fields.map { it.label })

        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = types) }) // not fetchable
        assertEquals(
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal { model(types = types, documents = docs + ("https://bank.example/l.json" to "<html>")) },
        )
        assertEquals(
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal { model(types = """{"$PAYMENT":{"claims":[],"claims_uri":"https://bank.example/c.json","ui_labels":{}}}""", documents = docs) },
        )
    }

    @Test
    fun `what is shown is derived from raw, so a hint cannot change it`() {
        // The pipeline decodes raw itself and refuses a disagreeing hint; the model is built from the decoded payload.
        val e = model(payload = """{"transaction_id":"t","payee":{"name":"Real Payee","id":"1"},"currency":"EUR","amount":5}""").entries.single()
        assertEquals("Real Payee", e.fields.first { it.label == "Payee" }.value)
    }

    // ── floor for the built-in types (unauthenticated metadata cannot hide the amount) ──

    private fun allLevel4(types: String = PAYMENT_TYPES) = types
        .replace("\"visualisation\":1", "\"visualisation\":4").replace("\"visualisation\":2", "\"visualisation\":4")
        .replace("{\"path\":[\"payload\",\"payee\",\"id\"],", "{\"path\":[\"payload\",\"payee\",\"id\"],\"visualisation\":4,")

    @Test
    fun `metadata cannot push a built-in type's required members below the floor`() {
        val e = model(types = allLevel4()).entries.single()
        val level = e.fields.associate { it.label to it.level }

        assertEquals(1, level["Amount"]); assertEquals(1, level["Currency"]); assertEquals(1, level["Payee"])
        assertEquals(2, level["Payee ID"]); assertEquals(2, level["Transaction ID"])
        assertTrue(e.fields.all { it.level <= 2 })
    }

    @Test
    fun `a floor member that metadata marks omittable and leaves unlabelled is refused, not dropped`() {
        val hidden = allLevel4().replace(
            """{"path":["payload","amount"],"visualisation":4,"display":[{"lang":"en","label":"Amount"}]}""",
            """{"path":["payload","amount"],"visualisation":4}""",
        )
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = hidden) })
    }

    @Test
    fun `a custom type that names a built-in schema gets that built-in's floor`() {
        val types = """{"https://standardsbody.org/eudiw-trx/payment":{"schema":"urn:eudi:sca:payment:1","claims":[
            {"path":["payload","transaction_id"],"visualisation":4,"display":[{"lang":"en","label":"Id"}]},
            {"path":["payload","payee","name"],"visualisation":4,"display":[{"lang":"en","label":"Payee"}]},
            {"path":["payload","payee","id"],"visualisation":4,"display":[{"lang":"en","label":"PId"}]},
            {"path":["payload","currency"],"visualisation":4,"display":[{"lang":"en","label":"Cur"}]},
            {"path":["payload","amount"],"visualisation":4,"display":[{"lang":"en","label":"Amt"}]}],
            "ui_labels":{"affirmative_action_label":[{"lang":"en","value":"OK"}]}}}"""
        val source = FakeSource(metadata(types = types))
        val v = TransactionDataValidator(source).validate0(
            request(listOf(TransactionDataEntry(raw(type = "https://standardsbody.org/eudiw-trx/payment")))),
        )
        val e = runBlocking { TransactionDisplayBuilder(source, "en").build(v, "V", null) }.entries.single()

        assertEquals(1, e.fields.first { it.label == "Amt" }.level)
        assertTrue(e.fields.none { it.level == 4 })
    }

    private fun TransactionDataValidator.validate0(r: TransactionDataRequest) = runBlocking { validate(r) }

    @Test
    fun `the floor table covers the schema-required members of the four built-in types`() {
        assertEquals(setOf(listOf("amount"), listOf("currency"), listOf("payee", "name"), listOf("payee", "id"), listOf("transaction_id")), BuiltInFloor.of("urn:eudi:sca:payment:1", null).keys)
        assertEquals(setOf(listOf("action"), listOf("transaction_id")), BuiltInFloor.of("urn:eudi:sca:login_risk_transaction:1", null).keys)
        assertEquals(setOf(listOf("transaction_id")), BuiltInFloor.of("urn:eudi:sca:account_access:1", null).keys)
        assertEquals(setOf(listOf("transaction_id")), BuiltInFloor.of("urn:eudi:sca:emandate:1", null).keys)
        assertEquals(emptyMap<List<String>, Int>(), BuiltInFloor.of("https://custom/x", null))
    }

    // ── nothing spoofable reaches the screen ──────────────────────

    @Test
    fun `values with control, format or bidi characters, or over-long, are refused not shown`() {
        val nasty = listOf(
            "Shop\nPay 1.00 to Mallory", "a\tb", "x\u202Egnp.exe", "\u2066hidden\u2069", "a\u200Bb", "a\u00ADb", "a\u0000b", "a\u2028b", "\uFEFFx",
            "x\uE000y", "x\u0378y", "a".repeat(DisplayText.MAX_VALUE + 1),
        )
        for (name in nasty) {
            val payload = """{"transaction_id":"t","payee":{"name":${kotlinx.serialization.json.JsonPrimitive(name)},"id":"1"},"currency":"EUR","amount":1}"""
            assertEquals(name.take(12), TransactionDataReason.INVALID_ENTRY, refusal { model(payload = payload) })
        }
    }

    @Test
    fun `an unpaired surrogate escape in a value is refused`() {
        val payload = "{\"transaction_id\":\"t\",\"payee\":{\"name\":\"x\\ud800y\",\"id\":\"1\"},\"currency\":\"EUR\",\"amount\":1}"
        assertEquals(TransactionDataReason.INVALID_ENTRY, refusal { model(payload = payload) })
    }

    @Test
    fun `ordinary text, spaces, non-latin scripts and symbols are shown as they are`() {
        for (ok in listOf("Åkesson & Söner AB", "日本語の店", "Café\u00A0Noir", "Pay € 12 345,67", "Shop \uD83D\uDE00", "a".repeat(DisplayText.MAX_VALUE))) {
            val payload = """{"transaction_id":"t","payee":{"name":${kotlinx.serialization.json.JsonPrimitive(ok)},"id":"1"},"currency":"EUR","amount":1}"""
            assertEquals(ok, model(payload = payload).entries.single().fields.first { it.label == "Payee" }.value)
        }
    }

    @Test
    fun `labels, titles, hints, credential and verifier names are checked the same way`() {
        val originals = mapOf(
            "affirmative_action_label" to "Confirm Payment", "denial_action_label" to "Cancel Payment",
            "transaction_title" to "Confirm your payment", "security_hint" to "Check the amount",
        )
        for ((key, text) in originals) {
            assertTrue(PAYMENT_TYPES.contains(text))
            assertEquals(key, TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = PAYMENT_TYPES.replace(text, "ok\\u202Eevil")) })
        }
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = PAYMENT_TYPES.replace("\"label\":\"Amount\"", "\"label\":\"Am\\u200Bount\"")) })
        val source = FakeSource(metadata(types = PAYMENT_TYPES))
        val v = TransactionDataValidator(source).validate0(request(listOf(TransactionDataEntry(raw()))))
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { runBlocking { TransactionDisplayBuilder(source, "en").build(v, "Shop\u202E", null) } })
    }

    // ── attributes shown with the transaction (TS12 3.3.1) ────────

    @Test
    fun `the disclosed attributes come through, sanitised`() {
        val source = FakeSource(metadata(types = PAYMENT_TYPES))
        val v = TransactionDataValidator(source).validate0(request(listOf(TransactionDataEntry(raw()))))
        val d = listOf(
            org.siros.sdk.wallet.TransactionDisclosure("Pay Card", listOf("pan_last_four"), true),
            org.siros.sdk.wallet.TransactionDisclosure("Age", null, false),
        )

        val m = runBlocking { TransactionDisplayBuilder(source, "en").build(v, "V", null, d) }

        assertEquals(d, m.disclosures)
        assertEquals(
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal { runBlocking { TransactionDisplayBuilder(source, "en").build(v, "V", null, listOf(org.siros.sdk.wallet.TransactionDisclosure("x", listOf("a\u202Eb"), false))) } },
        )
    }

    // ── several credentials, one document fetch ───────────────────

    @Test
    fun `an entry bound to several credentials needs them to agree, and all names are shown`() {
        val c1 = TransactionTestFixtures.credential(1)
        val c2 = TransactionTestFixtures.credential(2)
        val other = PAYMENT_TYPES.replace("\"label\":\"Amount\"", "\"label\":\"Betrag\"")
        fun run(types2: String): TransactionConsentRequest = runBlocking {
            val source = FakeSource(perCredential = { c -> metadata(types = if (c.id == 1L) PAYMENT_TYPES else types2) })
            val v = TransactionDataValidator(source).validate(
                request(listOf(TransactionDataEntry(raw(credentialIds = """["a","b"]"""))), mapOf("a" to listOf(c1), "b" to listOf(c2))),
            )
            TransactionDisplayBuilder(source, "en").build(v, "V", null)
        }

        assertEquals("Pay Card", run(PAYMENT_TYPES).credentialName)
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { run(other) })
    }

    @Test
    fun `referenced documents are fetched once per validation however many entries use them`() {
        val claims = """[{"path":["payload","transaction_id"],"visualisation":4,"display":[{"lang":"en","label":"Id"}]},{"path":["payload","payee","name"],"display":[{"lang":"en","label":"Payee"}]},
            {"path":["payload","payee","id"],"display":[{"lang":"en","label":"PId"}]},{"path":["payload","currency"],"display":[{"lang":"en","label":"Cur"}]},{"path":["payload","amount"],"display":[{"lang":"en","label":"Amt"}]}]"""
        val types = """{"$PAYMENT":{"claims_uri":"https://bank.example/c.json","ui_labels_uri":"https://bank.example/l.json"}}"""
        val src = FakeSource(metadata(types = types), mapOf("https://bank.example/c.json" to claims, "https://bank.example/l.json" to """{"affirmative_action_label":[{"lang":"en","value":"OK"}]}"""))
        val e1 = TransactionDataEntry(raw())
        val e2 = TransactionDataEntry(raw(payload = """{"transaction_id":"t2","payee":{"name":"B","id":"2"},"currency":"EUR","amount":2}"""))
        val e3 = TransactionDataEntry(raw(payload = """{"transaction_id":"t3","payee":{"name":"C","id":"3"},"currency":"EUR","amount":3}"""))

        val v = TransactionDataValidator(src).validate0(request(listOf(e1, e2, e3)))
        runBlocking { TransactionDisplayBuilder(src, "en").build(v, "V", null) }

        assertEquals(src.fetched.toString(), 2, src.fetched.size)
    }

    @Test
    fun `no label in the user's language or English refuses instead of showing a language they may not read`() {
        val frOnly = PAYMENT_TYPES.replace("{\"lang\":\"sv\",\"label\":\"Mottagare\"},{\"lang\":\"en\",\"label\":\"Payee\"}", "{\"lang\":\"fr\",\"label\":\"Beneficiaire\"}")
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = frOnly, locale = "de-DE") })
        assertEquals("Beneficiaire", model(types = frOnly, locale = "fr-CA").entries.single().fields.first().label)
    }
}
