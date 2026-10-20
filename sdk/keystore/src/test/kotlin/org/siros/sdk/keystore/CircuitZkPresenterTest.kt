package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkCircuitSource
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CircuitZkRequestValidator
import org.siros.sdk.credentials.CircuitZkVerdict
import org.siros.sdk.credentials.NymPseudonym
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.ZkWitnessSigner
import timber.log.Timber

/** [CircuitZkPresenter] with the fake prover, a fake signer and a fixed-root seed source. */
class CircuitZkPresenterTest {
    private val docType = "eu.europa.ec.eudi.nym_auth.1"
    private val root = ByteArray(32) { (it * 3).toByte() }
    private val seeds = PrivateSeed(object : RootSecret {
        override fun deriveSecret(info: ByteArray, length: Int) = hkdf(root, info, length)
    })

    /** An independent HKDF-SHA256 (RFC 5869), not the keystore's. */
    private fun hkdf(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(ByteArray(32), "HmacSHA256")) }.doFinal(ikm)
        val t1 = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(prk, "HmacSHA256")) }.doFinal(info + byteArrayOf(1))
        return t1.copyOf(length)
    }

    /** The credential's Credential Issuer Identifier exactly as stored; the device seed is per issuer (privatedata-spec 2.7). */
    private val issuerId = "https://issuer-a.example.com"

    /** An independent `lp(x)`: 2-byte big-endian length, then the UTF-8 bytes. */
    private fun lp(x: String) = x.toByteArray().let { byteArrayOf((it.size shr 8).toByte(), it.size.toByte()) + it }

    private fun seedFor(issuer: String) = hkdf(root, "org.siros.private_seed/v2".toByteArray() + lp(docType) + lp(issuer), 16)

    private val seed16 get() = seedFor(issuerId)
    private val goodPsc get() = MessageDigest.getInstance("SHA-256").digest(seed16)
    private val cert = ByteArray(40) { (it + 7).toByte() }

    private fun cbor(o: Any) = CBORObject.FromObject(o)

    private fun item(id: Int, name: String, value: CBORObject): CBORObject {
        val m = CBORObject.NewMap()
        m[cbor("digestID")] = cbor(id.toLong())
        m[cbor("random")] = cbor(ByteArray(16))
        m[cbor("elementIdentifier")] = cbor(name)
        m[cbor("elementValue")] = value
        return CBORObject.FromObjectAndTag(m.EncodeToBytes(), 24)
    }

    private fun credential(
        docType: String = this.docType,
        birth: String? = "2000-06-15",
        psc: ByteArray? = goodPsc,
        withX5chain: Boolean = true,
        /** Namespace holding the claims; the credential's doctype by default. */
        claimsNamespace: String = docType,
        /** Elements of a namespace that precedes the claims namespace (a decoy). */
        decoyFirst: List<CBORObject> = emptyList(),
        /** Repeat birth_date inside the claims namespace. */
        duplicateBirth: Boolean = false,
        /** The `ssc` value; null leaves the element out. */
        ssc: CBORObject? = cbor(ByteArray(32) { 9 }),
        /** Repeat ssc inside the claims namespace, with this value. */
        duplicateSsc: CBORObject? = null,
        /** The issuer chain as an `x5chain` array (leaf first) instead of the single certificate. */
        chain: List<ByteArray>? = null,
    ): ByteArray {
        val items = CBORObject.NewArray()
        var id = 0
        if (birth != null) items.Add(item(id++, "birth_date", CBORObject.FromObjectAndTag(birth, 1004)))
        if (ssc != null) items.Add(item(id++, "ssc", ssc))
        if (duplicateSsc != null) items.Add(item(91, "ssc", duplicateSsc))
        if (psc != null) items.Add(item(id, "psc", cbor(psc)))
        if (duplicateBirth) items.Add(item(90, "birth_date", CBORObject.FromObjectAndTag("2000-06-15", 1004)))
        val ns = CBORObject.NewMap()
        if (decoyFirst.isNotEmpty()) ns[cbor("org.example.decoy")] = CBORObject.NewArray().also { a -> decoyFirst.forEach { a.Add(it) } }
        ns[cbor(claimsNamespace)] = items
        val mso = CBORObject.NewMap()
        mso[cbor("docType")] = cbor(docType)
        val unprotected = CBORObject.NewMap()
        if (chain != null) {
            unprotected[cbor(33)] = CBORObject.NewArray().also { a -> chain.forEach { a.Add(cbor(it)) } }
        } else if (withX5chain) {
            unprotected[cbor(33)] = cbor(cert)
        }
        val auth = CBORObject.NewArray()
        auth.Add(cbor(ByteArray(0)))
        auth.Add(unprotected)
        auth.Add(cbor(CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()))
        auth.Add(cbor(ByteArray(64)))
        val signed = CBORObject.NewMap()
        signed[cbor("nameSpaces")] = ns
        signed[cbor("issuerAuth")] = auth
        return signed.EncodeToBytes()
    }

    private fun params(json: String): JsonObject = Json.parseToJsonElement(json).jsonObject
    private fun pseudonymFn(config: String = "known-offender-matching-psc", handle: String = "n") =
        CircuitZkFunction("pseudonym", handle, params("""{"config":"$config","ver":1,"prf":"sha-256"}"""))
    private fun ageFn(json: String = """{"ge":"1990-01-01"}""", handle: String = "a") = CircuitZkFunction("age_check", handle, params(json))
    private fun plan(vararg fns: CircuitZkFunction, doctype: String = docType) = CircuitZkPlan(
        functions = fns.toList(),
        // The request offers the test circuit: a response states a circuit_id and proof_system from the request's lists.
        circuitFilter = org.siros.sdk.credentials.CircuitZkCircuitFilter(listOf("sys"), listOf("circuit-1")),
        raw = params("""{"id":"q","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"$doctype"}}"""),
    )

    private val circuit = CircuitZkCircuit("sys", "circuit-1", setOf(docType), functions = setOf("pseudonym", "age_check"))
    private val signer = ZkWitnessSigner { _, _ -> error("the fake prover never asks for a signature") }

    private class CountingProver(val inner: CircuitZkProver, val override: (() -> CircuitZkProveOutput)? = null) : CircuitZkProver {
        var calls = 0
        override val isFake get() = inner.isFake
        override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
            calls++
            return override?.invoke() ?: inner.prove(input)
        }
    }

    private fun presenter(
        prover: CircuitZkProver = FakeCircuitZkProver.optIn(),
        circuits: List<CircuitZkCircuit> = listOf(circuit),
        validator: CircuitZkRequestValidator = CircuitZkRequestValidator.PERMISSIVE,
        userValue: ByteArray? = null,
    ) = CircuitZkPresenter(prover, { circuits }, validator, HolderWitnessProvider(seeds, userValue))

    private fun request(
        cred: ByteArray = credential(),
        p: CircuitZkPlan = plan(pseudonymFn(), ageFn()),
        verifierId: String? = "rp.example",
        secretSeed: ByteArray? = null,
        verifierContext: String? = null,
        issuer: String? = issuerId,
    ) = CircuitZkPresenter.Request(cred, p, verifierId, verifierContext, byteArrayOf(1, 2, 3), secretSeed, issuer)

    /** A delivered secret_seed (16 bytes) and the ssc it opens; independent of the presenter. */
    private val secretSeedA get() = ByteArray(16) { it.toByte() }
    private val secretSeedB get() = ByteArray(16) { (0xA0 + it).toByte() }
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    private fun sscCred(seed: ByteArray = secretSeedA, ssc: CBORObject? = cbor(sha256(seed))) = credential(ssc = ssc)
    private val sscPlan get() = plan(pseudonymFn("known-offender-matching-ssc"), ageFn())

    private fun present(pr: CircuitZkPresenter, r: CircuitZkPresenter.Request) = runBlocking { pr.present(r, signer) }

    private fun assertDenied(step: CircuitZkStep, block: () -> Unit) {
        try {
            block()
            fail("expected a refusal at $step")
        } catch (e: CircuitZkError.AccessDenied) {
            assertEquals(step, e.step)
            assertEquals("circuit_zk request refused", e.message)
        }
    }

    // -------- logs --------

    private val logs = mutableListOf<String>()
    private val tree = object : Timber.Tree() {
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
            logs += message + (t?.toString() ?: "")
        }
    }

    @Before fun plant() = Timber.plant(tree)

    @After fun uproot() = Timber.uproot(tree)

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    // -------- the happy path --------

    @Test
    fun `a presentation decodes and its pseudonym equals an independent recompute`() {
        val result = present(presenter(), request())
        val decoded = result.presentation

        val expected = NymPseudonym.derive("known-offender-matching-psc", seed16, verifierId = "rp.example")
        assertEquals(ResultValue.Pseudonym(expected), decoded.results["n"])
        assertEquals(ResultValue.Predicate, decoded.results["a"])
        assertEquals("circuit-1", decoded.systemId)
        assertEquals("circuit-1", result.systemId)
        assertArrayEquals(FakeCircuitZkProver.DUMMY_PROOF, decoded.proof)
        assertEquals(1, decoded.issuerKeySet.size)
        assertArrayEquals(cert, decoded.issuerKeySet.single())
        // proof_time is required for mso_mdoc: the exact 20-byte form.
        assertEquals(20, decoded.proofTime!!.toByteArray(Charsets.US_ASCII).size)
        assertTrue(org.siros.sdk.credentials.ProofTime.isValid(decoded.proofTime!!))
    }

    @Test
    fun `results keys are exactly the plan's handles`() {
        val p = plan(pseudonymFn(handle = "h-nym"), ageFn(handle = "h-age"))
        val decoded = present(presenter(), request(p = p)).presentation
        assertEquals(setOf("h-nym", "h-age"), decoded.results.keys)
    }

    @Test
    fun `an age_check alone needs no seed and no psc`() {
        val decoded = present(presenter(), request(cred = credential(psc = null), p = plan(ageFn()))).presentation
        assertEquals(setOf("a"), decoded.results.keys)
    }

    @Test
    fun `age bounds are inclusive`() {
        val b = credential(birth = "2000-06-15")
        for (json in listOf("""{"ge":"2000-06-15"}""", """{"le":"2000-06-15"}""", """{"ge":"2000-06-15","le":"2001-06-14"}""")) {
            present(presenter(), request(cred = b, p = plan(ageFn(json))))
        }
    }

    @Test
    fun `the circuit is the first that supports the plan`() {
        val circuits = listOf(
            CircuitZkCircuit("sys", "wrong-doctype", setOf("other")),
            CircuitZkCircuit("sys", "no-age", setOf(docType), functions = setOf("pseudonym")),
            CircuitZkCircuit("sys", "right", setOf(docType), functions = setOf("pseudonym", "age_check")),
        )
        val offered = plan(pseudonymFn(), ageFn()).copy(circuitFilter = org.siros.sdk.credentials.CircuitZkCircuitFilter(listOf("sys"), listOf("wrong-doctype", "no-age", "right")))
        assertEquals("right", present(presenter(circuits = circuits), request(p = offered)).systemId)
    }

    // -------- the response shape: offered circuit and proof system, issuer chain --------

    @Test
    fun `a request that offered no system_id cannot be answered and nothing is proved`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        for (filter in listOf(null, org.siros.sdk.credentials.CircuitZkCircuitFilter(null, null), org.siros.sdk.credentials.CircuitZkCircuitFilter(listOf("sys"), null))) {
            assertDenied(CircuitZkStep.CIRCUIT) { present(presenter(prover), request(p = plan(pseudonymFn(), ageFn()).copy(circuitFilter = filter))) }
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `proof_system_values is optional, system_id_values is not`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        val noSystems = plan(pseudonymFn(), ageFn()).copy(circuitFilter = org.siros.sdk.credentials.CircuitZkCircuitFilter(null, listOf("circuit-1")))
        assertEquals("circuit-1", present(presenter(prover), request(p = noSystems)).systemId)
        assertEquals(1, prover.calls)
    }

    @Test
    fun `a proof system the request did not offer is refused`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        val other = plan(pseudonymFn(), ageFn()).copy(circuitFilter = org.siros.sdk.credentials.CircuitZkCircuitFilter(listOf("another-system"), listOf("circuit-1")))
        assertDenied(CircuitZkStep.CIRCUIT) { present(presenter(prover), request(p = other)) }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `an alias the request offered is the system_id stated`() {
        val aliased = CircuitZkCircuit("sys", "circuit-1", setOf(docType), functions = setOf("pseudonym", "age_check"), aliases = setOf("urn:alias"))
        val p = plan(pseudonymFn(), ageFn()).copy(circuitFilter = org.siros.sdk.credentials.CircuitZkCircuitFilter(listOf("sys"), listOf("urn:alias")))
        val result = present(presenter(circuits = listOf(aliased)), request(p = p))
        assertEquals("urn:alias", result.systemId)
    }

    @Test
    fun `the issuer key set is the credentials own x5chain, leaf first, and the whole presentation validates`() {
        val ca = ByteArray(30) { (it + 100).toByte() }
        val result = present(presenter(), request(cred = credential(chain = listOf(cert, ca))))
        assertEquals(2, result.presentation.issuerKeySet.size)
        assertArrayEquals(cert, result.presentation.issuerKeySet[0])
        assertArrayEquals(ca, result.presentation.issuerKeySet[1])
        val p = plan(pseudonymFn(), ageFn())
        val token = JsonObject(mapOf("q" to kotlinx.serialization.json.JsonArray(listOf(result.json)))).toString()
        assertNull(org.siros.sdk.credentials.CircuitZkResponseValidator.validate(p, token))
    }

    @Test
    fun `an issuer chain outside the wire limits is refused before any proof is made`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        assertDenied(CircuitZkStep.BUILD) { present(presenter(prover), request(cred = credential(chain = List(9) { cert }))) }
        assertDenied(CircuitZkStep.BUILD) { present(presenter(prover), request(cred = credential(chain = listOf(ByteArray(4097))))) }
        assertEquals(0, prover.calls)
        // The limits are inclusive.
        present(presenter(prover), request(cred = credential(chain = List(8) { ByteArray(4096) })))
        assertEquals(1, prover.calls)
    }

    // -------- refusals --------

    @Test
    fun `a psc mismatch is refused and nothing is proved`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        assertDenied(CircuitZkStep.COMMITMENT) { present(presenter(prover), request(cred = credential(psc = ByteArray(32)))) }
        assertDenied(CircuitZkStep.COMMITMENT) { present(presenter(prover), request(cred = credential(psc = null))) }
        assertDenied(CircuitZkStep.COMMITMENT) { present(presenter(prover), request(cred = credential(psc = goodPsc.copyOf(31)))) }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a decoy namespace listed first is refused and nothing is proved`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        val decoyBirth = item(70, "birth_date", CBORObject.FromObjectAndTag("2015-01-01", 1004))
        assertDenied(CircuitZkStep.NAMESPACE) {
            present(presenter(prover), request(cred = credential(decoyFirst = listOf(decoyBirth)), p = plan(ageFn("""{"le":"2005-01-01"}"""))))
        }
        val decoyPsc = item(71, "psc", cbor(goodPsc))
        assertDenied(CircuitZkStep.NAMESPACE) {
            present(presenter(prover), request(cred = credential(psc = ByteArray(32), decoyFirst = listOf(decoyPsc))))
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a credential without the doctype namespace is refused`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        assertDenied(CircuitZkStep.NAMESPACE) { present(presenter(prover), request(cred = credential(claimsNamespace = "org.example.other"))) }
        assertDenied(CircuitZkStep.NAMESPACE) {
            present(presenter(prover), request(cred = credential(claimsNamespace = "org.example.other"), p = plan(ageFn())))
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a claim repeated inside the doctype namespace is refused`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        assertDenied(CircuitZkStep.PREDICATE) { present(presenter(prover), request(cred = credential(duplicateBirth = true), p = plan(ageFn()))) }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a false predicate yields no presentation`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        assertDenied(CircuitZkStep.PREDICATE) { present(presenter(prover), request(p = plan(pseudonymFn(), ageFn("""{"ge":"2010-01-01"}""")))) }
        assertDenied(CircuitZkStep.PREDICATE) { present(presenter(prover), request(p = plan(ageFn("""{"le":"1999-12-31"}""")))) }
        assertDenied(CircuitZkStep.PREDICATE) { present(presenter(prover), request(cred = credential(birth = null), p = plan(ageFn()))) }
        assertDenied(CircuitZkStep.PREDICATE) { present(presenter(prover), request(p = plan(ageFn("""{}""")))) }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a validator failure is refused`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        assertDenied(CircuitZkStep.VALIDATE) {
            present(presenter(prover, validator = { CircuitZkVerdict.AccessDenied("secret-rule") }), request())
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a wrong doctype is refused`() {
        assertDenied(CircuitZkStep.DOCTYPE) { present(presenter(), request(p = plan(pseudonymFn(), doctype = "other.doctype"))) }
        assertDenied(CircuitZkStep.DOCTYPE) { present(presenter(), request(cred = credential(docType = "other.doctype"))) }
        assertDenied(CircuitZkStep.DOCTYPE) {
            present(presenter(), request(p = CircuitZkPlan(listOf(ageFn()), raw = params("""{"meta":{}}"""))))
        }
    }

    @Test
    fun `no fitting circuit is refused`() {
        assertDenied(CircuitZkStep.CIRCUIT) { present(presenter(circuits = emptyList()), request()) }
        assertDenied(CircuitZkStep.CIRCUIT) { present(presenter(circuits = listOf(CircuitZkCircuit("s", "c", setOf("other")))), request()) }
        assertDenied(CircuitZkStep.CIRCUIT) {
            present(presenter(circuits = listOf(CircuitZkCircuit("s", "c", setOf(docType), functions = setOf("age_check")))), request())
        }
        assertDenied(CircuitZkStep.CIRCUIT) {
            val withFilter = request(p = plan(pseudonymFn(), ageFn()).copy(circuitFilter = org.siros.sdk.credentials.CircuitZkCircuitFilter(listOf("sys"), listOf("other"))))
            present(presenter(), withFilter)
        }
    }

    @Test
    fun `a witness the wallet cannot supply is refused, including every secret-seed config without a seed`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        for (config in listOf("known-offender-matching-ssc", "account-recovery-ssc", "user-managed-pseudonym-xsite-ssc", "made-up")) {
            assertDenied(CircuitZkStep.WITNESS) { present(presenter(prover), request(p = plan(pseudonymFn(config)))) }
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a prover that returns other handles, fails, or refuses is refused`() {
        val wrong = CountingProver(FakeCircuitZkProver.optIn(), override = { CircuitZkProveOutput(ByteArray(1), mapOf("zzz" to ResultValue.Predicate)) })
        assertDenied(CircuitZkStep.PROVE) { present(presenter(wrong), request(p = plan(ageFn()))) }
        val extra = CountingProver(FakeCircuitZkProver.optIn(), override = {
            CircuitZkProveOutput(ByteArray(1), mapOf("a" to ResultValue.Predicate, "extra" to ResultValue.Predicate))
        })
        assertDenied(CircuitZkStep.PROVE) { present(presenter(extra), request(p = plan(ageFn()))) }
        val boom = CountingProver(FakeCircuitZkProver.optIn(), override = { error("native crash with seed ${hex(seed16)}") })
        assertDenied(CircuitZkStep.PROVE) { present(presenter(boom), request(p = plan(ageFn()))) }
    }

    @Test
    fun `a cancelled prover is cancellation, not a refusal, while any other failure stays a silent refusal`() {
        val cancelled = CountingProver(FakeCircuitZkProver.optIn(), override = { throw kotlinx.coroutines.CancellationException("cancelled") })
        try {
            present(presenter(cancelled), request(p = plan(ageFn())))
            fail("cancellation must propagate")
        } catch (e: kotlinx.coroutines.CancellationException) {
            // expected
        }
        assertEquals(1, cancelled.calls)
        val boom = CountingProver(FakeCircuitZkProver.optIn(), override = { error("x") })
        assertDenied(CircuitZkStep.PROVE) { present(presenter(boom), request(p = plan(ageFn()))) }
    }

    @Test
    fun `a credential without an x5chain is refused`() {
        assertDenied(CircuitZkStep.BUILD) { present(presenter(), request(cred = credential(withX5chain = false))) }
    }

    @Test
    fun `malformed requests are InvalidRequest`() {
        fun invalid(block: () -> Unit) {
            try {
                block()
                fail()
            } catch (e: CircuitZkError.InvalidRequest) {
                assertEquals("circuit_zk request invalid", e.message)
            }
        }
        invalid { present(presenter(), request(cred = byteArrayOf(1, 2, 3))) }
        invalid { present(presenter(), request(p = plan())) }
        invalid { present(presenter(), request(p = plan(ageFn(handle = "x"), ageFn("""{"le":"2020-01-01"}""", handle = "x")))) }
        invalid { present(presenter(), request(p = plan(CircuitZkFunction("future_fn", "f", JsonObject(emptyMap()))))) }
    }

    // -------- secrecy --------

    @Test
    fun `no seed or psc bytes appear in logs, messages or the witness`() {
        val secrets = listOf(hex(seed16), hex(goodPsc))
        try {
            present(presenter(), request(cred = credential(psc = ByteArray(32))))
        } catch (e: CircuitZkError) {
            for (s in secrets) {
                assertFalse(e.toString().contains(s))
                assertFalse(e.message!!.contains(s))
            }
        }
        val boom = CountingProver(FakeCircuitZkProver.optIn(), override = { error("x") })
        runCatching { present(presenter(boom), request()) }
        present(presenter(), request())
        for (line in logs) for (s in secrets) assertFalse(line, line.contains(s))
        assertEquals("CircuitZkFunctionWitness(redacted)", CircuitZkFunctionWitness(seed16).toString())
    }

    // -------- secret_seed (issuer-delivered), checked against ssc --------

    private fun sscRequest(
        seed: ByteArray? = secretSeedA,
        cred: ByteArray = sscCred(),
        config: String = "known-offender-matching-ssc",
    ) = request(cred = cred, p = plan(pseudonymFn(config), ageFn()), secretSeed = seed)

    @Test
    fun `each secret-seed config presents with a seed that opens ssc and equals an independent recompute`() {
        val seed = secretSeedA
        val kom = present(presenter(), sscRequest(seed)).presentation
        assertEquals(
            ResultValue.Pseudonym(NymPseudonym.derive("known-offender-matching-ssc", seed, verifierId = "rp.example")),
            kom.results["n"],
        )
        val recovery = present(
                presenter(),
                request(sscCred(), plan(pseudonymFn("account-recovery-ssc"), ageFn()), secretSeed = seed, verifierContext = "ctx-1"),
            ).presentation
        assertEquals(
            ResultValue.Pseudonym(NymPseudonym.derive("account-recovery-ssc", seed, verifierId = "rp.example", verifierContext = "ctx-1")),
            recovery.results["n"],
        )
        val userValue = byteArrayOf(5, 6, 7)
        val xsite = present(
                presenter(userValue = userValue),
                request(sscCred(), plan(pseudonymFn("user-managed-pseudonym-xsite-ssc"), ageFn()), verifierId = null, secretSeed = seed),
            ).presentation
        assertEquals(
            ResultValue.Pseudonym(NymPseudonym.derive("user-managed-pseudonym-xsite-ssc", seed, proverInput = userValue)),
            xsite.results["n"],
        )
    }

    @Test
    fun `a secret-seed config without a seed, or with a seed of the wrong length, is refused at the witness step`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        for (bad in listOf<ByteArray?>(null, ByteArray(0), ByteArray(15), ByteArray(17), ByteArray(32))) {
            assertDenied(CircuitZkStep.WITNESS) { present(presenter(prover), sscRequest(bad)) }
        }
        // The xsite config also needs the user value; a missing one is a witness refusal as well.
        assertDenied(CircuitZkStep.WITNESS) {
            present(presenter(prover), sscRequest(secretSeedA, config = "user-managed-pseudonym-xsite-ssc"))
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a seed that does not open ssc is refused and the prover is never called`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        // The seed of another credential, a flipped bit, and an ssc that is the seed itself.
        assertDenied(CircuitZkStep.SECRET_COMMITMENT) { present(presenter(prover), sscRequest(secretSeedB)) }
        val flipped = secretSeedA.also { it[3] = (it[3].toInt() xor 1).toByte() }
        assertDenied(CircuitZkStep.SECRET_COMMITMENT) { present(presenter(prover), sscRequest(flipped)) }
        assertDenied(CircuitZkStep.SECRET_COMMITMENT) {
            present(presenter(prover), sscRequest(cred = sscCred(ssc = cbor(ByteArray(32)))))
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `an ssc that is absent, not a bstr, the wrong length or duplicated is refused and nothing is proved`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        val good = sha256(secretSeedA)
        val cases = mapOf(
            "absent" to credential(ssc = null),
            "text" to credential(ssc = cbor(hex(good))),
            "31 bytes" to credential(ssc = cbor(good.copyOf(31))),
            "33 bytes" to credential(ssc = cbor(good + byteArrayOf(0))),
            "empty" to credential(ssc = cbor(ByteArray(0))),
            "duplicate, both valid" to credential(ssc = cbor(good), duplicateSsc = cbor(good)),
            "duplicate, decoy second" to credential(ssc = cbor(good), duplicateSsc = cbor(ByteArray(32))),
        )
        for ((name, cred) in cases) {
            try {
                present(presenter(prover), sscRequest(cred = cred))
                fail("$name: expected a refusal")
            } catch (e: CircuitZkError.AccessDenied) {
                assertEquals(name, CircuitZkStep.SECRET_COMMITMENT, e.step)
            }
        }
        assertEquals(0, prover.calls)
    }

    /** `spec/secret-seed-commitment-vectors.json`, from tools/gen_secret_seed_commitment_vectors.py (hashlib only). */
    private val sscVectors: JsonObject by lazy {
        val f = java.io.File("../../spec/secret-seed-commitment-vectors.json")
        require(f.isFile) { "vector file not found at ${f.absolutePath}" }
        Json.parseToJsonElement(f.readText()).jsonObject
    }

    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun vec(e: kotlinx.serialization.json.JsonElement, key: String) =
        unhex((e.jsonObject.getValue(key) as kotlinx.serialization.json.JsonPrimitive).content)

    @Test
    fun `every shared ssc commitment vector is presented`() {
        val vectors = sscVectors.getValue("vectors") as kotlinx.serialization.json.JsonArray
        assertTrue(vectors.size >= 4)
        for (v in vectors) {
            val seed = vec(v, "seed_hex")
            val ssc = vec(v, "ssc_hex")
            assertArrayEquals(sha256(seed), ssc) // the vector itself is the relation
            val out = present(presenter(), sscRequest(seed, credential(ssc = cbor(ssc))))
            val decoded = out.presentation
            assertEquals(
                ResultValue.Pseudonym(NymPseudonym.derive("known-offender-matching-ssc", seed, verifierId = "rp.example")),
                decoded.results["n"],
            )
        }
    }

    @Test
    fun `every shared ssc commitment rejection is refused at its step and never proved`() {
        val rejections = sscVectors.getValue("rejections") as kotlinx.serialization.json.JsonArray
        assertTrue(rejections.size >= 10)
        val steps = mutableSetOf<String>()
        for (r in rejections) {
            val prover = CountingProver(FakeCircuitZkProver.optIn())
            val step = (r.jsonObject.getValue("step") as kotlinx.serialization.json.JsonPrimitive).content
            steps += step
            val name = (r.jsonObject.getValue("name") as kotlinx.serialization.json.JsonPrimitive).content
            try {
                present(presenter(prover), sscRequest(vec(r, "seed_hex"), credential(ssc = cbor(vec(r, "ssc_hex")))))
                fail("$name: expected a refusal")
            } catch (e: CircuitZkError.AccessDenied) {
                assertEquals(name, CircuitZkStep.valueOf(step), e.step)
            }
            assertEquals(name, 0, prover.calls)
        }
        assertEquals(setOf("WITNESS", "SECRET_COMMITMENT"), steps)
    }

    @Test
    fun `an ssc in another namespace is never consulted`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        val decoySsc = item(72, "ssc", cbor(sha256(secretSeedA)))
        assertDenied(CircuitZkStep.NAMESPACE) {
            present(presenter(prover), sscRequest(cred = credential(ssc = cbor(ByteArray(32)), decoyFirst = listOf(decoySsc))))
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a supplied seed does not weaken a psc config and is not used by it`() {
        // A psc request still needs the right psc, whatever seed rides along.
        assertDenied(CircuitZkStep.COMMITMENT) {
            present(presenter(), request(cred = credential(psc = ByteArray(32)), secretSeed = secretSeedA))
        }
        val witnessSeen = mutableListOf<CircuitZkFunctionWitness>()
        val spy = object : CircuitZkProver {
            override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
                witnessSeen += input.witnesses.getValue("n")
                return FakeCircuitZkProver.optIn().prove(input)
            }
        }
        present(presenter(spy), request(secretSeed = secretSeedA))
        assertNull(witnessSeen.single().secretSeed)
    }

    @Test
    fun `the presenter zeroes its copy of the seed and leaves the caller's array alone`() {
        val callers = secretSeedA
        val seen = mutableListOf<ByteArray>()
        val spy = object : CircuitZkProver {
            override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
                val s = input.witnesses.getValue("n").secretSeed!!
                assertArrayEquals(secretSeedA, s) // live while proving
                seen += s
                return FakeCircuitZkProver.optIn().prove(input)
            }
        }
        present(presenter(spy), sscRequest(callers))
        assertEquals(1, seen.size)
        assertTrue(seen.single().all { it == 0.toByte() })
        assertArrayEquals(secretSeedA, callers)
        assertTrue(seen.single() !== callers)
        // The copy is zeroed on a failing prover as well.
        val seen2 = mutableListOf<ByteArray>()
        val boom = object : CircuitZkProver {
            override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
                seen2 += input.witnesses.getValue("n").secretSeed!!
                error("prover crash")
            }
        }
        assertDenied(CircuitZkStep.PROVE) { present(presenter(boom), sscRequest(secretSeedA)) }
        assertTrue(seen2.single().all { it == 0.toByte() })
    }

    @Test
    fun `the secret seed and its hex appear in no log, error, witness or token`() {
        val seed = secretSeedA
        val secrets = listOf(hex(seed), hex(seed).uppercase(), java.util.Base64.getEncoder().encodeToString(seed))
        val boom = CountingProver(FakeCircuitZkProver.optIn(), override = { error("x") })
        val results = mutableListOf<String>()
        for (r in listOf(sscRequest(secretSeedB), sscRequest(seed.copyOf(15)), sscRequest(seed, boom.let { sscCred(ssc = null) }))) {
            try {
                present(presenter(), r)
            } catch (e: CircuitZkError) {
                results += e.toString() + (e.message ?: "")
            }
        }
        try { present(presenter(boom), sscRequest(seed)) } catch (e: CircuitZkError) { results += e.toString() }
        val ok = present(presenter(), sscRequest(seed))
        results += ok.json.toString()
        results += ok.results.toString()
        results += CircuitZkFunctionWitness(secretSeed = seed).toString()
        results += logs
        for (line in results) for (s in secrets) assertFalse(line, line.contains(s))
        // The seed is not even in the encoded presentation bytes.
        val raw = ok.json.toString().toByteArray()
        assertTrue(indexOf(raw, seed) < 0)
    }

    private fun indexOf(hay: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..hay.size - needle.size) {
            for (j in needle.indices) if (hay[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    @Test
    fun `witness needs name the seed kind of each config and the default provider never supplies a secret seed`() {
        fun needs(config: String) = PseudonymFunctionHandler.witnessNeeds(pseudonymFn(config))
        assertEquals(setOf(CircuitZkWitnessKind.PRIVATE_SEED), needs("known-offender-matching-psc"))
        assertEquals(setOf(CircuitZkWitnessKind.SECRET_SEED), needs("known-offender-matching-ssc"))
        assertEquals(setOf(CircuitZkWitnessKind.SECRET_SEED), needs("account-recovery-ssc"))
        assertEquals(setOf(CircuitZkWitnessKind.SECRET_SEED, CircuitZkWitnessKind.USER_VALUE), needs("user-managed-pseudonym-xsite-ssc"))
        assertEquals(setOf(CircuitZkWitnessKind.NOT_HELD_BY_WALLET), needs("made-up"))
        val provider = HolderWitnessProvider(seeds, byteArrayOf(1))
        assertNull(provider.witness(pseudonymFn("known-offender-matching-ssc"), setOf(CircuitZkWitnessKind.SECRET_SEED), docType, null))
        assertNull(provider.witness(pseudonymFn("known-offender-matching-ssc"), setOf(CircuitZkWitnessKind.NOT_HELD_BY_WALLET), docType, null))
    }

    @Test
    fun `a witness has identity equality so two witnesses with one seed are not equal`() {
        val a = CircuitZkFunctionWitness(secretSeed = secretSeedA)
        val b = CircuitZkFunctionWitness(secretSeed = secretSeedA)
        assertFalse(a == b)
        assertTrue(a == a)
    }

    @Test
    fun `an error never names a rule or a reason`() {
        for (e in listOf<CircuitZkError>(CircuitZkError.AccessDenied(CircuitZkStep.PREDICATE), CircuitZkError.InvalidRequest())) {
            assertFalse(e.toString().contains("PREDICATE"))
            assertFalse(e.toString().contains("rule"))
        }
        try {
            present(presenter(validator = { CircuitZkVerdict.AccessDenied("secret-rule-77") }), request())
        } catch (e: CircuitZkError) {
            assertFalse(e.toString().contains("secret-rule-77"))
        }
        assertTrue(logs.none { it.contains("secret-rule-77") })
    }

    // -------- the fake --------

    @Test
    fun `the fake prover exists only by explicit opt-in and says it is fake`() {
        assertTrue(FakeCircuitZkProver::class.constructors.none { it.visibility == kotlin.reflect.KVisibility.PUBLIC })
        val fake = FakeCircuitZkProver.optIn()
        assertTrue(fake.isFake)
        assertTrue(presenter(fake).usesFakeProver)
        val real = object : CircuitZkProver {
            override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput = error("unused")
        }
        assertFalse(presenter(real).usesFakeProver)
    }

    @Test
    fun `the fake refuses a config whose seed is not in the witness even when called directly`() {
        fun prove(config: String, w: CircuitZkFunctionWitness) = runBlocking {
            FakeCircuitZkProver.optIn().prove(
                CircuitZkProveInput(circuit, plan(pseudonymFn(config)), credential(), byteArrayOf(), "v", null, mapOf("n" to w), signer),
            )
        }
        // An ssc config given only the private seed, a psc config given only the secret seed, and no seed at all.
        for ((config, w) in listOf(
            "known-offender-matching-ssc" to CircuitZkFunctionWitness(privateSeed = seed16),
            "known-offender-matching-psc" to CircuitZkFunctionWitness(secretSeed = secretSeedA),
            "known-offender-matching-ssc" to CircuitZkFunctionWitness(),
        )) {
            try {
                prove(config, w)
                fail("$config")
            } catch (e: CircuitZkError.AccessDenied) {
                assertEquals(CircuitZkStep.PROVE, e.step)
            }
        }
        // And it derives from the right seed.
        val ok = prove("known-offender-matching-ssc", CircuitZkFunctionWitness(secretSeed = secretSeedA))
        assertEquals(
            ResultValue.Pseudonym(NymPseudonym.derive("known-offender-matching-ssc", secretSeedA, verifierId = "v")),
            ok.results["n"],
        )
    }

    @Test
    fun `releaseProvers releases the shared residency`() {
        val residency = ZkProverResidency()
        CircuitZkPresenter(FakeCircuitZkProver.optIn(), { listOf(circuit) }, CircuitZkRequestValidator.PERMISSIVE,
            HolderWitnessProvider(seeds), residency = residency).releaseProvers()
        presenter().releaseProvers()
    }

    @Test
    fun `a new function is a new handler`() {
        val custom = object : CircuitZkFunctionHandler {
            override val functionId = "custom_fn"
            override fun witnessNeeds(function: CircuitZkFunction) = emptySet<CircuitZkWitnessKind>()
            override fun holds(function: CircuitZkFunction, credential: org.siros.sdk.credentials.mdoc.DocumentMdoc) = true
        }
        val prover = CountingProver(FakeCircuitZkProver.optIn(), override = { CircuitZkProveOutput(ByteArray(2), mapOf("c" to ResultValue.Predicate)) })
        val pr = CircuitZkPresenter(prover, { listOf(CircuitZkCircuit("sys", "circuit-1", setOf(docType), functions = setOf("custom_fn"))) }, CircuitZkRequestValidator.PERMISSIVE, HolderWitnessProvider(seeds),
            handlers = listOf(custom))
        val out = present(pr, request(p = plan(CircuitZkFunction("custom_fn", "c", JsonObject(emptyMap())))))
        assertEquals(setOf("c"), out.results.keys)
    }

    // -------- red team: the presenter checks what any prover returns --------

    private fun okResults(pseudonym: ByteArray) = mapOf("n" to ResultValue.Pseudonym(pseudonym), "a" to ResultValue.Predicate)

    private fun expectedPsc() = NymPseudonym.derive("known-offender-matching-psc", seed16, verifierId = "rp.example")

    @Test
    fun `an empty proof is refused by the presenter itself`() {
        val empty = CountingProver(FakeCircuitZkProver.optIn(), override = { CircuitZkProveOutput(ByteArray(0), okResults(expectedPsc())) })
        assertDenied(CircuitZkStep.PROVE) { present(presenter(empty), request()) }
    }

    @Test
    fun `an empty verifier id is an invalid request`() {
        try {
            present(presenter(), request(verifierId = ""))
            fail("expected an invalid request")
        } catch (e: CircuitZkError.InvalidRequest) {
            // expected
        }
    }

    @Test
    fun `an OutOfMemoryError or a missing native library in the prover is a refusal, not a crash`() {
        for (t in listOf<Throwable>(OutOfMemoryError("hostile artifact"), UnsatisfiedLinkError("no lib"))) {
            val boom = CountingProver(FakeCircuitZkProver.optIn(), override = { throw t })
            assertDenied(CircuitZkStep.PROVE) { present(presenter(boom), request()) }
        }
    }

    @Test
    fun `the derived private_seed is zeroed once the proof is over`() {
        var held: ByteArray? = null
        val provider = object : CircuitZkWitnessProvider {
            override fun witness(function: CircuitZkFunction, needs: Set<CircuitZkWitnessKind>, credentialType: String, issuer: String?) =
                CircuitZkFunctionWitness(privateSeed = seed16.also { held = it })

            override fun privateSeedMatches(credentialType: String, issuer: String?, psc: ByteArray) = true
        }
        val pr = CircuitZkPresenter(FakeCircuitZkProver.optIn(), { listOf(circuit) }, CircuitZkRequestValidator.PERMISSIVE, provider)
        present(pr, request())
        assertTrue(held!!.all { it == 0.toByte() })
        // ...and also when the proof fails.
        held = null
        val boom = CountingProver(FakeCircuitZkProver.optIn(), override = { error("x") })
        val pr2 = CircuitZkPresenter(boom, { listOf(circuit) }, CircuitZkRequestValidator.PERMISSIVE, provider)
        assertDenied(CircuitZkStep.PROVE) { present(pr2, request()) }
        assertTrue(held!!.all { it == 0.toByte() })
    }

    // -------- the handler hooks: nothing outside the handlers names a claim, a commitment or a namespace --------

    /** A function the presenter has never heard of, driven only by its hooks. */
    private class HookHandler(
        val admits: Boolean = true,
        val commitment: CircuitZkCommitmentCheck = CircuitZkCommitmentCheck.HOLDS,
    ) : CircuitZkFunctionHandler {
        override val functionId = "custom_fn"
        var checked = 0
        override fun witnessNeeds(function: CircuitZkFunction) = emptySet<CircuitZkWitnessKind>()
        override fun holds(function: CircuitZkFunction, credential: org.siros.sdk.credentials.mdoc.DocumentMdoc) = true
        override fun admitsCredential(function: CircuitZkFunction, credential: org.siros.sdk.credentials.mdoc.DocumentMdoc) = admits
        override fun commitmentCheck(
            function: CircuitZkFunction,
            credential: org.siros.sdk.credentials.mdoc.DocumentMdoc,
            witness: CircuitZkFunctionWitness,
            provider: CircuitZkWitnessProvider,
            issuer: String?,
        ): CircuitZkCommitmentCheck {
            checked++
            return commitment
        }
    }

    private fun hookPresenter(h: HookHandler) = CircuitZkPresenter(
        CountingProver(FakeCircuitZkProver.optIn(), override = { CircuitZkProveOutput(ByteArray(2), mapOf("c" to ResultValue.Predicate)) }),
        { listOf(CircuitZkCircuit("sys", "circuit-1", setOf(docType), functions = setOf("custom_fn"))) },
        CircuitZkRequestValidator.PERMISSIVE, HolderWitnessProvider(seeds), handlers = listOf(h),
    )

    private fun hookRequest() = request(p = plan(CircuitZkFunction("custom_fn", "c", JsonObject(emptyMap()))))

    @Test
    fun `a function's own hooks decide the credential structure and the commitment, whatever its name`() {
        val ok = HookHandler()
        assertEquals(setOf("c"), present(hookPresenter(ok), hookRequest()).results.keys)
        assertEquals(1, ok.checked)
        assertDenied(CircuitZkStep.NAMESPACE) { present(hookPresenter(HookHandler(admits = false)), hookRequest()) }
        val device = HookHandler(commitment = CircuitZkCommitmentCheck.DEVICE_COMMITMENT_FAILS)
        assertDenied(CircuitZkStep.COMMITMENT) { present(hookPresenter(device), hookRequest()) }
        val delivered = HookHandler(commitment = CircuitZkCommitmentCheck.DELIVERED_COMMITMENT_FAILS)
        assertDenied(CircuitZkStep.SECRET_COMMITMENT) { present(hookPresenter(delivered), hookRequest()) }
    }

    @Test
    fun `the nym_auth handlers declare what the wallet needs, and the commitment checks are theirs`() {
        fun fn(config: String) = CircuitZkFunction("pseudonym", "n", params("""{"config":"$config","verifier_context":"ctx"}"""))
        val ssc = fn("known-offender-matching-ssc")
        val psc = fn("known-offender-matching-psc")
        assertTrue(PseudonymFunctionHandler.needsVerifierId(ssc))
        assertTrue(PseudonymFunctionHandler.needsSecretSeed(ssc))
        assertFalse(PseudonymFunctionHandler.needsSecretSeed(psc))
        assertFalse(PseudonymFunctionHandler.needsVerifierId(fn("user-managed-pseudonym-xsite-ssc")))
        assertEquals("ctx", PseudonymFunctionHandler.verifierContext(ssc))
        val ageHandler = DEFAULT_CIRCUIT_ZK_HANDLERS.single { it.functionId == "age_check" }
        assertNull(ageHandler.verifierContext(ageFn()))
        assertFalse(ageHandler.needsVerifierId(ageFn()))
        assertFalse(ageHandler.needsSecretSeed(ageFn()))
        // The legacy disclosure needs a verifier id only for its pseudonym.
        val spec = """[{"id":"c","system":"s"}]"""
        fun legacy(extra: String) = CircuitZkFunction(org.siros.sdk.credentials.CircuitZkLegacyDisclosure.FUNCTION_ID, "d", params("""{"claims":["a"],"systems":$spec$extra}"""))
        assertFalse(LegacyDisclosureFunctionHandler.needsVerifierId(legacy("")))
        assertTrue(LegacyDisclosureFunctionHandler.needsVerifierId(legacy(""","pseudonym":true""")))
    }

    @Test
    fun `neither the presenter nor the wallet names a nym_auth claim, commitment or function`() {
        val names = Regex(""""(birth_date|ssc|psc)"|age_check|"pseudonym"|CircuitZkRuleSet\.(PSEUDONYM|AGE_CHECK)""")
        val files = listOf(
            java.io.File("src/main/kotlin/org/siros/sdk/keystore/CircuitZkPresenter.kt"),
            java.io.File("../wallet/src/main/kotlin/org/siros/sdk/wallet/SirosWallet.kt"),
        )
        for (f in files) {
            val code = f.readLines().filter { l -> val t = l.trimStart(); !t.startsWith("*") && !t.startsWith("//") && !t.startsWith("/*") }
            val hits = code.filter { names.containsMatchIn(it) }
            // The fake prover is test-only and names the rulebook functions it fakes.
            val nonFake = if (f.name == "CircuitZkPresenter.kt") hits.filterNot { it.contains("PseudonymFunctionHandler.functionId") } else hits
            assertTrue("${f.name} names a nym_auth detail: $nonFake", nonFake.isEmpty())
        }
    }

    // -------- the device seed is per issuer: the issuer string exactly as stored --------

    @Test
    fun `the device commitment is checked for the issuer exactly as stored - a trailing slash is another psc`() {
        // The credential commits to the seed of "https://issuer-a.example.com" (the stored identifier).
        assertEquals(setOf("n", "a"), present(presenter(), request()).results.keys)
        // The same issuer with a trailing slash derives another seed, so another psc: refused, never silently accepted.
        assertDenied(CircuitZkStep.COMMITMENT) { present(presenter(), request(issuer = "$issuerId/")) }
        assertDenied(CircuitZkStep.COMMITMENT) { present(presenter(), request(issuer = "https://ISSUER-A.example.com")) }
        // A credential that committed with the slash form is proved only for that exact string.
        val slash = "$issuerId/"
        val cred = credential(psc = MessageDigest.getInstance("SHA-256").digest(seedFor(slash)))
        assertEquals(setOf("n", "a"), present(presenter(), request(cred = cred, issuer = slash)).results.keys)
        assertDenied(CircuitZkStep.COMMITMENT) { present(presenter(), request(cred = cred, issuer = issuerId)) }
    }

    @Test
    fun `a function that needs the device seed is refused without an issuer, or with one the derivation refuses`() {
        assertDenied(CircuitZkStep.WITNESS) { present(presenter(), request(issuer = null)) }
        assertDenied(CircuitZkStep.WITNESS) { present(presenter(), request(issuer = "")) }
        assertDenied(CircuitZkStep.WITNESS) { present(presenter(), request(issuer = "a".repeat(65536))) }
        // A function that needs no device seed does not care.
        assertEquals(setOf("a"), present(presenter(), request(p = plan(ageFn()), issuer = null)).results.keys)
    }
}
