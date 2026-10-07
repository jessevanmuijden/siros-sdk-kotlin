package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.keystore.AuthenticationCategory
import org.siros.sdk.keystore.AuthenticationFactor
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.FakeSource
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.PAYMENT
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.credential
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.metadata
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.raw
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.request

class TransactionDataValidatorTest {

    private fun validate(
        req: TransactionDataRequest,
        source: TransactionMetadataSource = FakeSource(),
    ): ValidatedTransactionData = runBlocking { TransactionDataValidator(source).validate(req) }

    private fun refusal(
        req: TransactionDataRequest,
        source: TransactionMetadataSource = FakeSource(),
    ): TransactionDataReason {
        val e = runCatching { validate(req, source) }.exceptionOrNull()
        return (e as? TransactionDataError)?.reason ?: throw AssertionError("expected a refusal, got $e")
    }

    private fun entry(
        type: String = PAYMENT,
        ids: String = """["pay"]""",
        payload: String = TransactionTestFixtures.PAYMENT_PAYLOAD,
        algs: String? = null,
    ) = TransactionDataEntry(raw(type, ids, payload, algs))

    // ── the happy paths ────────────────────────────────────────────

    @Test
    fun `a compliant payment validates and is hashed over raw`() {
        val e = entry()
        val v = validate(request(listOf(e)))

        assertEquals(1, v.entries.size)
        assertEquals(PAYMENT, v.entries.single().type)
        val h = v.hashesFor("pay")!!
        assertEquals("sha-256", h.hashAlg)
        assertEquals(listOf(TransactionDataHashing.hash(e.raw, "sha-256")), h.hashes)
        assertEquals("direct_post", v.responseMode)
        assertNull(v.hashesFor("someone-else"))
    }

    @Test
    fun `all four built-in types validate against their own schemas`() {
        val src = FakeSource()
        for ((type, payload) in listOf(
            "urn:eudi:sca:login_risk_transaction:1" to """{"transaction_id":"t","action":"Log in"}""",
            "urn:eudi:sca:account_access:1" to """{"transaction_id":"t"}""",
            "urn:eudi:sca:emandate:1" to """{"transaction_id":"t","purpose":"p"}""",
        )) {
            assertEquals(type, 1, validate(request(listOf(entry(type = type, payload = payload))), src).entries.size)
        }
    }

    @Test
    fun `a custom type declared by the metadata validates against its embedded schema`() {
        val types = """{"https://bank.example/trx":{"schema":{"type":"object","required":["n"],"properties":{"n":{"type":"integer"}}}}}"""
        val src = FakeSource(metadata(types = types))
        val ok = entry(type = "https://bank.example/trx", payload = """{"n":3}""")
        val bad = entry(type = "https://bank.example/trx", payload = """{"n":"three"}""")

        validate(request(listOf(ok)), src)
        assertEquals(TransactionDataReason.SCHEMA_VIOLATION, refusal(request(listOf(bad)), src))
    }

    @Test
    fun `the metadata may name a built-in schema by URN, as the spec's example does`() {
        val types = """{"https://standardsbody.org/eudiw-trx/payment":{"schema":"urn:eudi:sca:payment:1"}}"""
        val src = FakeSource(metadata(types = types))

        validate(request(listOf(entry(type = "https://standardsbody.org/eudiw-trx/payment"))), src)
        assertEquals(
            TransactionDataReason.SCHEMA_VIOLATION,
            refusal(request(listOf(entry(type = "https://standardsbody.org/eudiw-trx/payment", payload = """{"transaction_id":"t"}"""))), src),
        )
    }

    @Test
    fun `a schema_uri is fetched, and honoured against the credential's integrity claim`() {
        val schema = """{"type":"object","required":["n"]}"""
        val types = """{"https://bank.example/trx":{"schema_uri":"https://bank.example/schema.json"}}"""
        val src = FakeSource(metadata(types = types), mapOf("https://bank.example/schema.json" to schema))
        val e = entry(type = "https://bank.example/trx", payload = """{"n":1}""")

        validate(request(listOf(e)), src)
        assertEquals(listOf("https://bank.example/schema.json"), src.fetched)

        val digest = java.util.Base64.getEncoder().encodeToString(
            java.security.MessageDigest.getInstance("SHA-256").digest(schema.toByteArray()),
        )
        fun pinned(sri: String) = credential(
            claims = """{"vct":"https://pay.example.com/card","transaction_data_types['https://bank.example/trx'].schema_uri#integrity":"$sri"}""",
        )
        validate(request(listOf(e), mapOf("pay" to listOf(pinned("sha256-$digest")))), src)
        assertEquals(
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal(request(listOf(e), mapOf("pay" to listOf(pinned("sha256-AAAA")))), src),
        )
    }

    // ── contract section 4, one refusal each ───────────────────────

    @Test
    fun `step 1 and 2, the entry itself`() {
        assertEquals(TransactionDataReason.INVALID_ENTRY, refusal(request(emptyList())))
        assertEquals(
            TransactionDataReason.INVALID_ENTRY,
            refusal(request(List(TransactionDataValidator.MAX_ENTRIES + 1) { entry() })),
        )
        assertEquals(TransactionDataReason.INVALID_ENTRY, refusal(request(listOf(TransactionDataEntry("###")))))
        assertEquals(TransactionDataReason.INVALID_ENTRY, refusal(request(listOf(entry(ids = """["unknown"]""")))))
        assertEquals(
            "a query nothing answers",
            TransactionDataReason.INVALID_ENTRY,
            refusal(request(listOf(entry()), mapOf("pay" to emptyList()))),
        )
        assertEquals(TransactionDataReason.INVALID_ENTRY, refusal(request(listOf(entry()), responseMode = null)))
        assertEquals(TransactionDataReason.INVALID_ENTRY, refusal(request(listOf(entry()), responseMode = " ")))
    }

    @Test
    fun `step 3, only SD-JWT VC`() {
        for (format in listOf("mso_mdoc", "jwt_vc_json", "jwp")) {
            assertEquals(
                format,
                TransactionDataReason.UNSUPPORTED_FORMAT,
                refusal(request(listOf(entry()), mapOf("pay" to listOf(credential(format = format))))),
            )
        }
        validate(request(listOf(entry()), mapOf("pay" to listOf(credential(format = "vc+sd-jwt")))))
    }

    @Test
    fun `step 4, the credential must be an SCA attestation`() {
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal(request(listOf(entry())), FakeSource(metadata = null)))
        assertEquals(TransactionDataReason.NOT_SCA_ATTESTATION, refusal(request(listOf(entry())), FakeSource(metadata(category = null))))
        assertEquals(TransactionDataReason.NOT_SCA_ATTESTATION, refusal(request(listOf(entry())), FakeSource(metadata(category = "urn:other"))))
    }

    @Test
    fun `step 5, an unknown type is refused`() {
        assertEquals(TransactionDataReason.UNSUPPORTED_TYPE, refusal(request(listOf(entry(type = "urn:eudi:sca:payment:2")))))
        assertEquals(
            "one unknown type among known ones refuses the whole request",
            TransactionDataReason.UNSUPPORTED_TYPE,
            refusal(request(listOf(entry(), entry(type = "https://nobody.example/x")))),
        )
        assertEquals(
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal(request(listOf(entry())), FakeSource(metadata(types = "[]"))),
        )
        assertEquals(
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal(request(listOf(entry())), FakeSource(metadata(types = """{"$PAYMENT":5}"""))),
        )
    }

    @Test
    fun `step 6, schema violations and unusable schemas`() {
        assertEquals(
            TransactionDataReason.SCHEMA_VIOLATION,
            refusal(request(listOf(entry(payload = """{"transaction_id":"t","currency":"EUR","amount":1}""")))),
        )
        val custom = "https://bank.example/trx"
        fun withType(body: String) = FakeSource(metadata(types = """{"$custom":$body}"""))
        val e = entry(type = custom, payload = "{}")
        assertEquals(
            "both schema and schema_uri",
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal(request(listOf(e)), withType("""{"schema":{},"schema_uri":"https://x.example/s"}""")),
        )
        assertEquals(
            "a bare URI in schema is ambiguous",
            TransactionDataReason.UNSUPPORTED_TYPE,
            refusal(request(listOf(e)), withType("""{"schema":"https://x.example/s"}""")),
        )
        assertEquals(
            "no schema at all for a custom type",
            TransactionDataReason.UNSUPPORTED_TYPE,
            refusal(request(listOf(e)), withType("{}")),
        )
        assertEquals(
            "schema_uri not reachable",
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal(request(listOf(e)), withType("""{"schema_uri":"https://x.example/s"}""")),
        )
        assertEquals(
            "schema_uri that is not JSON",
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal(
                request(listOf(e)),
                FakeSource(metadata(types = """{"$custom":{"schema_uri":"https://x.example/s"}}"""), mapOf("https://x.example/s" to "<html>")),
            ),
        )
        assertEquals(
            "a schema that references something remote",
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal(request(listOf(e)), withType("""{"schema":{"${'$'}ref":"https://x.example/other.json"}}""")),
        )
        assertEquals(
            "schema of the wrong JSON type",
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal(request(listOf(e)), withType("""{"schema":5}""")),
        )
    }

    @Test
    fun `step 7, algorithm choice`() {
        // none supported
        assertEquals(TransactionDataReason.UNSUPPORTED_HASH_ALGORITHM, refusal(request(listOf(entry(algs = """["md5","sha3-256"]""")))))
        // first supported one, in the verifier's order
        assertEquals("sha-512", validate(request(listOf(entry(algs = """["md5","sha-512","sha-256"]""")))).hashesFor("pay")!!.hashAlg)
        // absent list: sha-256
        assertEquals("sha-256", validate(request(listOf(entry()))).hashesFor("pay")!!.hashAlg)
        // a bare string
        assertEquals("sha-384", validate(request(listOf(entry(algs = "\"sha-384\"")))).hashesFor("pay")!!.hashAlg)
    }

    @Test
    fun `entries bound to one credential share one algorithm, or the request is refused`() {
        val a = entry(algs = """["sha-512","sha-256"]""")
        val b = entry(algs = """["sha-256","sha-512"]""")
        val onlyA = entry(algs = """["sha-512"]""")
        val none = entry() // accepts sha-256 only

        assertEquals("sha-512", validate(request(listOf(a, b))).hashesFor("pay")!!.hashAlg)
        assertEquals(
            "sha-256",
            validate(request(listOf(a, none))).hashesFor("pay")!!.hashAlg,
        )
        assertEquals(TransactionDataReason.UNSUPPORTED_HASH_ALGORITHM, refusal(request(listOf(onlyA, none))))
    }

    // ── what goes into which credential's KB-JWT ───────────────────

    @Test
    fun `each query gets the hashes of the entries naming it, in verifier order`() {
        val creds = mapOf("pay" to listOf(credential(1)), "age" to listOf(credential(2)))
        val e1 = entry(ids = """["pay"]""")
        val e2 = entry(ids = """["age"]""", payload = """{"transaction_id":"tx-2","payee":{"name":"B","id":"2"},"currency":"EUR","amount":1}""")
        val e3 = entry(ids = """["pay","age"]""", payload = """{"transaction_id":"tx-3","payee":{"name":"C","id":"3"},"currency":"EUR","amount":2}""")

        val v = validate(request(listOf(e1, e2, e3), creds))

        fun h(e: TransactionDataEntry) = TransactionDataHashing.hash(e.raw, "sha-256")
        assertEquals(listOf(h(e1), h(e3)), v.hashesFor("pay")!!.hashes)
        assertEquals(listOf(h(e2), h(e3)), v.hashesFor("age")!!.hashes)
    }

    @Test
    fun `a credential in the same request that no entry names is not bound`() {
        val creds = mapOf("pay" to listOf(credential(1)), "age" to listOf(credential(2)))

        val v = validate(request(listOf(entry(ids = """["pay"]""")), creds))

        assertNull(v.hashesFor("age"))
        assertNull(v.bindingFor("age", emptyList()))
    }

    @Test
    fun `the binding needs two authentication categories`() {
        val v = validate(request(listOf(entry())))
        val pin = AuthenticationFactor(AuthenticationCategory.KNOWLEDGE, "other")
        val key = AuthenticationFactor(AuthenticationCategory.POSSESSION, "key_in_remote_wscd")

        val ok = v.bindingFor("pay", listOf(pin, key))!!
        assertEquals("sha-256", ok.hashAlg)
        assertEquals("direct_post", ok.responseMode)
        assertEquals(v.hashesFor("pay")!!.hashes, ok.hashes)

        for (factors in listOf(emptyList(), listOf(pin), listOf(pin, pin))) {
            val e = runCatching { v.bindingFor("pay", factors) }.exceptionOrNull() as TransactionDataError
            assertEquals(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, e.reason)
        }
    }

    @Test
    fun `metadata is resolved once per credential however many entries name it`() {
        val src = FakeSource()

        validate(request(listOf(entry(), entry(payload = """{"transaction_id":"t2","payee":{"name":"B","id":"2"},"currency":"EUR","amount":1}"""))), src)

        assertEquals(1, src.metadataCalls)
        assertTrue(src.fetched.isEmpty())
    }

    // ── malformed integrity claims refuse ──────────────────────────

    @Test
    fun `a schema_uri integrity claim that is present but not a string refuses`() {
        val types = """{"https://bank.example/trx":{"schema_uri":"https://bank.example/schema.json"}}"""
        val src = FakeSource(metadata(types = types), mapOf("https://bank.example/schema.json" to """{"type":"object"}"""))
        val e = entry(type = "https://bank.example/trx", payload = """{"n":1}""")
        for (bad in listOf("null", "{}", "[]", "[\"sha256-x\"]", "5", "true")) {
            val cred = credential(
                claims = """{"vct":"https://pay.example.com/card","transaction_data_types['https://bank.example/trx'].schema_uri#integrity":$bad}""",
            )
            assertEquals(bad, TransactionDataReason.METADATA_UNAVAILABLE, refusal(request(listOf(e), mapOf("pay" to listOf(cred))), src))
        }
    }

    // ── the unpinned-metadata warning ─────────────────────────────

    private class Capture : timber.log.Timber.Tree() {
        val lines = mutableListOf<Pair<Int, String>>()
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) { lines += priority to (message + (t?.toString() ?: "")) }
    }

    private fun <T> capturing(block: (Capture) -> T): T {
        val tree = Capture()
        timber.log.Timber.plant(tree)
        try { return block(tree) } finally { timber.log.Timber.uproot(tree) }
    }

    private val distinctiveType = """{"urn:eudi:sca:payment:1":{"schema":"urn:eudi:sca:payment:1"}}"""

    @Test
    fun `unpinned metadata warns exactly once per validation, however many entries and documents`() {
        val payload2 = """{"transaction_id":"tx-SECRET-2","payee":{"name":"Distinctive Payee","id":"2"},"currency":"EUR","amount":98765.43}"""
        capturing { log ->
            validate(request(listOf(entry(), entry(payload = payload2), entry(payload = payload2))), FakeSource(metadata(types = distinctiveType)))

            val warnings = log.lines.filter { it.first == android.util.Log.WARN }
            assertEquals(log.lines.toString(), 1, warnings.size)
            assertEquals(MetadataTrust.WARNING, warnings.single().second)
        }
    }

    @Test
    fun `a pinned type metadata and pinned documents do not warn`() {
        val schema = """{"type":"object"}"""
        val types = """{"https://bank.example/trx":{"schema_uri":"https://bank.example/schema.json"}}"""
        val digest = java.util.Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(schema.toByteArray()))
        val cred = credential(
            claims = """{"vct":"https://pay.example.com/card","vct#integrity":"sha256-AAAA","transaction_data_types['https://bank.example/trx'].schema_uri#integrity":"sha256-$digest"}""",
        )
        capturing { log ->
            validate(
                request(listOf(entry(type = "https://bank.example/trx", payload = "{}")), mapOf("pay" to listOf(cred))),
                FakeSource(metadata(types = types), mapOf("https://bank.example/schema.json" to schema)),
            )
            assertTrue(log.lines.toString(), log.lines.none { it.second.contains("unpinned") })
        }
    }

    @Test
    fun `a pinned type metadata with an unpinned fetched document still warns once`() {
        val types = """{"https://bank.example/trx":{"schema_uri":"https://bank.example/schema.json"}}"""
        val cred = credential(claims = """{"vct":"https://pay.example.com/card","vct#integrity":"sha256-AAAA"}""")
        capturing { log ->
            validate(
                request(listOf(entry(type = "https://bank.example/trx", payload = "{}")), mapOf("pay" to listOf(cred))),
                FakeSource(metadata(types = types), mapOf("https://bank.example/schema.json" to """{"type":"object"}""")),
            )
            assertEquals(1, log.lines.count { it.second == MetadataTrust.WARNING })
        }
    }

    @Test
    fun `nothing sensitive is logged while validating, warning or not`() {
        val payload = """{"transaction_id":"tx-SECRET-1","payee":{"name":"Distinctive Payee","id":"PAYEE-ID-777"},"currency":"EUR","amount":98765.43}"""
        val e = entry(payload = payload)
        val secretCred = credential(claims = """{"vct":"https://pay.example.com/card","iss":"https://distinctive-issuer.example"}""")
            .copy(credentialIssuerIdentifier = "https://distinctive-issuer.example")
        val sensitive = listOf(
            "pay.example.com", "distinctive-issuer", "tx-SECRET-1", "Distinctive Payee", "PAYEE-ID-777", "98765.43",
            e.raw, TransactionDataHashing.hash(e.raw, "sha-256"), "Pay Card",
        )
        capturing { log ->
            validate(request(listOf(e), mapOf("pay" to listOf(secretCred))), FakeSource(metadata(types = distinctiveType)))
            val text = log.lines.joinToString("\n") { it.second }
            assertTrue(text, text.isNotEmpty())
            for (secret in sensitive) assertTrue("log contains '$secret': $text", !text.contains(secret))
        }
    }
}
