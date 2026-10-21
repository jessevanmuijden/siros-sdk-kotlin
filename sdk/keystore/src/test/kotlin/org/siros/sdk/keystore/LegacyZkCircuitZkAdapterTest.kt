// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import java.util.Base64
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkLegacyDisclosure
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CircuitZkRequestValidator
import org.siros.sdk.credentials.CredentialDocument
import org.siros.sdk.credentials.CredentialFormat
import org.siros.sdk.credentials.CredentialTypeRef
import org.siros.sdk.credentials.PseudonymOutcome
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.VerifierIdentity
import org.siros.sdk.credentials.ZkArtifact
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import org.siros.sdk.credentials.ZkProofResult
import org.siros.sdk.credentials.ZkProofSystem
import org.siros.sdk.credentials.ZkProofSystemRegistry
import org.siros.sdk.credentials.ZkSystemSpec
import org.siros.sdk.credentials.ZkWitnessSigner
import timber.log.Timber

/**
 * The legacy adapter through the real [ZkMdocPresentation] (so the real ZK DeviceResponse wrapping) over a fake
 * proof system that records what it is asked. The real Longfellow and Vega systems need their native
 * libraries and run in the instrumented tests (`CircuitZkLegacyVectorTest`).
 */
class LegacyZkCircuitZkAdapterTest {
    private val docType = "org.iso.18013.5.1.mDL"
    private val namespace = "org.iso.18013.5.1"
    private val circuitId = "longfellow-libzk-v1_8_2_4307_2945"
    private val cert = Base64.getDecoder().decode(
        "MIIBijCCAS+gAwIBAgIUc5kinXWPR/mEhg00FOMiuOvJzuYwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPbnltLXRlc3QtaXNzdWVyMB4XDTI2MTAxOTE4MjI1NVoXDTM2MTAxNjE4MjI1NVow" +
            "GjEYMBYGA1UEAwwPbnltLXRlc3QtaXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAHCT1HH7jonPRv7lBWsSUOw8jD1k25uygRBfWwI5XB9w/CZW8CY81+NUWWaztts+fohlYnJz" +
            "yf/xayZE91ZPWKNTMFEwHQYDVR0OBBYEFDDWXf48O2A+ka3yN1PMghPLRe4dMB8GA1UdIwQYMBaAFDDWXf48O2A+ka3yN1PMghPLRe4dMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID" +
            "SQAwRgIhANb4r2Otb/PSLPkhxyUoFDEkeNBh9LKqrMcvU9AxGvVIAiEA0YnS8etU8QWH29rAS5dNlFUbvFUWBONZkOas5TJiGeA=",
    )

    /** A system standing in for Longfellow: same ids, records the request, optionally returns a pseudonym. */
    private class FakeLegacy(val systemId_: String = "longfellow-libzk-v1", val pseudonym: ByteArray? = null) : ZkProofSystem {
        override val systemId = systemId_
        override val supportedCredentialTypes = setOf(CredentialTypeRef(CredentialFormat.MSO_MDOC, "org.iso.18013.5.1.mDL"))
        var calls = 0
        var claims: List<String>? = null
        var identity: VerifierIdentity? = null
        var spec: ZkSystemSpec? = null
        var transcript: ByteArray? = null

        override fun matchingSpec(requestedSpecs: List<ZkSystemSpec>, numAttributes: Int): ZkSystemSpec? =
            requestedSpecs.firstOrNull { it.system == systemId }

        override suspend fun generateProof(
            spec: ZkSystemSpec,
            document: CredentialDocument,
            sessionTranscript: ByteArray,
            requestedClaims: List<String>,
            verifierIdentity: VerifierIdentity?,
            signer: ZkWitnessSigner,
            priorState: ByteArray?,
        ): ZkProofResult {
            calls++
            claims = requestedClaims
            identity = verifierIdentity
            this.spec = spec
            transcript = sessionTranscript
            return ZkProofResult(
                proofBytes = byteArrayOf(9, 8, 7),
                pseudonym = pseudonym,
                pseudonymOutcome = if (pseudonym != null) PseudonymOutcome.PROVIDED else PseudonymOutcome.NOT_SUPPORTED_BY_SYSTEM,
                timestamp = "2026-10-19T12:00:00Z",
            )
        }
    }

    private fun cbor(o: Any) = CBORObject.FromObject(o)

    private fun item(id: Int, name: String, value: String): CBORObject {
        val m = CBORObject.NewMap()
        m[cbor("digestID")] = cbor(id)
        m[cbor("random")] = cbor(ByteArray(16) { it.toByte() })
        m[cbor("elementIdentifier")] = cbor(name)
        m[cbor("elementValue")] = cbor(value)
        return CBORObject.FromObjectAndTag(m.EncodeToBytes(), 24)
    }

    private fun credential(): ByteArray {
        val items = CBORObject.NewArray()
        items.Add(item(0, "family_name", "Doe"))
        items.Add(item(1, "given_name", "Jane"))
        val ns = CBORObject.NewMap()
        ns[cbor(namespace)] = items
        val unprotected = CBORObject.NewMap()
        unprotected[cbor(33)] = cbor(cert)
        val mso = CBORObject.NewMap()
        mso[cbor("docType")] = cbor(docType)
        val auth = CBORObject.NewArray()
        auth.Add(cbor(ByteArray(0)))
        auth.Add(unprotected)
        auth.Add(cbor(CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()))
        auth.Add(cbor(ByteArray(64)))
        val signed = CBORObject.NewMap()
        signed[cbor("nameSpaces")] = ns
        signed[cbor("issuerAuth")] = auth
        val doc = CBORObject.NewMap()
        doc[cbor("docType")] = cbor(docType)
        doc[cbor("issuerSigned")] = signed
        val env = CBORObject.NewMap()
        env[cbor("documents")] = CBORObject.NewArray().also { it.Add(doc) }
        env[cbor("status")] = cbor(0)
        return env.EncodeToBytes()
    }

    private fun params(json: String): JsonObject = Json.parseToJsonElement(json).jsonObject

    private fun specJson(id: String = circuitId, system: String = "longfellow-libzk-v1") =
        """{"id":"$id","system":"$system","params":{"num_attributes":"2"}}"""

    private fun disclosure(
        claims: String = """["family_name","given_name"]""",
        systems: String = "[${specJson()}]",
        extra: String = "",
        handle: String = "d",
    ) = CircuitZkFunction(CircuitZkLegacyDisclosure.FUNCTION_ID, handle, params("""{"claims":$claims,"systems":$systems$extra}"""))

    private fun plan(vararg fns: CircuitZkFunction) = CircuitZkPlan(
        fns.toList(),
        circuitFilter = org.siros.sdk.credentials.CircuitZkCircuitFilter(listOf("longfellow"), listOf(circuitId)),
        raw = params("""{"id":"q","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"$docType"}}"""),
    )

    private fun descriptor(
        id: String = circuitId,
        system: String = "longfellow",
        version: String = "8",
        status: String = "active",
        published: Boolean = true,
        deprecatedAt: String? = null,
    ) = ZkCircuitDescriptor(
        id = id, system = system, systemVersion = version, proofSystem = "proof-$system", docTypes = listOf(docType), published = published,
        status = status, deprecatedAt = deprecatedAt, artifact = ZkArtifact(hash = "sha256:00"),
    )

    private fun circuit(system: String = "longfellow", version: String? = "8", id: String = circuitId) =
        CircuitZkCircuit(system, id, setOf(docType), functions = setOf(CircuitZkLegacyDisclosure.FUNCTION_ID), systemVersion = version)

    private fun client(d: ZkCircuitDescriptor?) = ZkCircuitClient(
        sources = listOf("https://catalog.test"),
        httpGet = { url -> if (d != null && url.endsWith("/v1/circuits/${d.id}.json")) Json.encodeToString(ZkCircuitDescriptor.serializer(), d) else null },
        httpGetBytes = { null },
    )

    private val signer = ZkWitnessSigner { _, _ -> error("the legacy path asks for no signature here") }
    private val transcript = byteArrayOf(0x80.toByte())

    private fun prover(system: ZkProofSystem, d: ZkCircuitDescriptor? = descriptor()): CatalogCircuitZkProver {
        val presentation = ZkMdocPresentation(ZkProofSystemRegistry(listOf(system)))
        return CatalogCircuitZkProver(
            client(d),
            CircuitZkSystemRegistry(listOf(LegacyZkCircuitZkAdapter(presentation))),
        )
    }

    private fun input(p: CircuitZkPlan, c: CircuitZkCircuit = circuit(), verifierId: String? = "rp.example", context: String? = null) =
        CircuitZkProveInput(c, p, credential(), transcript, verifierId, context, emptyMap(), signer)

    private fun run(pr: CircuitZkProver, i: CircuitZkProveInput) = runBlocking { pr.prove(i) }

    private fun assertRefused(block: () -> Unit) {
        try {
            block()
            fail("expected a refusal")
        } catch (e: CircuitZkError.AccessDenied) {
            assertEquals(CircuitZkStep.PROVE, e.step)
        }
    }

    private val logs = mutableListOf<String>()
    private val tree = object : Timber.Tree() {
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) { logs += message }
    }

    @Before fun plant() = Timber.plant(tree)

    @After fun uproot() = Timber.uproot(tree)

    // -------- end to end through the presenter --------

    private fun presenter(prover: CircuitZkProver, circuits: List<CircuitZkCircuit>) = CircuitZkPresenter(
        prover, { circuits }, CircuitZkRequestValidator.PERMISSIVE,
        object : CircuitZkWitnessProvider {
            override fun witness(function: CircuitZkFunction, needs: Set<CircuitZkWitnessKind>, credentialType: String, issuer: String?) =
                CircuitZkFunctionWitness()

            override fun privateSeedMatches(credentialType: String, issuer: String?, psc: ByteArray) = false
        },
    )

    @Test
    fun `a claim disclosure is proved through the legacy system and presented with the zk DeviceResponse as its proof`() {
        val fake = FakeLegacy()
        val result = runBlocking {
            presenter(prover(fake), listOf(circuit())).present(
                CircuitZkPresenter.Request(credential(), plan(disclosure()), "rp.example", null, transcript),
                signer,
            )
        }
        val decoded = result.presentation
        assertEquals(circuitId, decoded.systemId)
        assertEquals(ResultValue.Predicate, decoded.results["d"])
        assertEquals(setOf("d"), decoded.results.keys)
        // The proof is the zk DeviceResponse, carrying the system's proof bytes and only the disclosed claims.
        val response = CBORObject.DecodeFromBytes(decoded.proof)
        val zkDocument = response["zkDocuments"][0]
        assertArrayEquals(byteArrayOf(9, 8, 7), zkDocument["proof"].GetByteString())
        val data = CBORObject.DecodeFromBytes(zkDocument["documentData"].UntagOne().GetByteString())
        assertEquals(docType, data["docType"].AsString())
        assertEquals(circuitId, data["zkSystemId"].AsString())
        assertEquals(2, data["issuerSigned"][CBORObject.FromObject(namespace)].size())
        assertEquals(listOf("family_name", "given_name"), fake.claims)
        assertNull(fake.identity)
        assertArrayEquals(transcript, fake.transcript)
    }

    @Test
    fun `a pseudonym request carries the verifier identity, counts the pseudonym slot, and returns the legacy pseudonym`() {
        val pseudonym = ByteArray(32) { 0x55 }
        val fake = FakeLegacy(pseudonym = pseudonym)
        val out = run(
            prover(fake),
            input(plan(disclosure(extra = ""","pseudonym":true,"verifier_context":"ctx" """.trim())), context = "ignored-because-the-function-names-one"),
        )
        assertEquals(ResultValue.Pseudonym(pseudonym), out.results["d"])
        assertEquals(listOf("family_name", "given_name", LongfellowZkProofSystem.PSEUDONYM_CLAIM), fake.claims)
        assertEquals(VerifierIdentity("rp.example", "ctx"), fake.identity)
        // Without a context in the function, the request's own is used.
        run(prover(fake), input(plan(disclosure(extra = ""","pseudonym":true""")), context = "from-request"))
        assertEquals(VerifierIdentity("rp.example", "from-request"), fake.identity)
    }

    @Test
    fun `a pseudonym the system cannot return, or no verifier id for one, is refused`() {
        assertRefused { run(prover(FakeLegacy(pseudonym = null)), input(plan(disclosure(extra = ""","pseudonym":true""")))) }
        assertRefused { run(prover(FakeLegacy(pseudonym = ByteArray(32))), input(plan(disclosure(extra = ""","pseudonym":true""")), verifierId = null)) }
        assertRefused { run(prover(FakeLegacy(pseudonym = ByteArray(16))), input(plan(disclosure(extra = ""","pseudonym":true""")))) }
    }

    // -------- the narrowing and the gates --------

    @Test
    fun `the proof is made with the circuit the presenter chose, never another one the verifier listed`() {
        val fake = FakeLegacy()
        val twoSpecs = "[${specJson(id = "other-circuit")},${specJson()}]"
        run(prover(fake), input(plan(disclosure(systems = twoSpecs))))
        assertEquals(circuitId, fake.spec?.id)
        // A verifier list that does not name the chosen circuit is refused, with no proof attempted.
        val none = FakeLegacy()
        assertRefused { run(prover(none), input(plan(disclosure(systems = "[${specJson(id = "other-circuit")}]")))) }
        assertEquals(0, none.calls)
    }

    @Test
    fun `a proof system that resolves a spec outside the narrowed list is refused`() {
        val rogue = object : ZkProofSystem by FakeLegacy() {
            override fun matchingSpec(requestedSpecs: List<ZkSystemSpec>, numAttributes: Int) =
                ZkSystemSpec("some-other-circuit", "longfellow-libzk-v1")
        }
        assertRefused { run(prover(rogue), input(plan(disclosure()))) }
    }

    @Test
    fun `a proof system other than the one the catalog system stands for is refused`() {
        val fake = FakeLegacy()
        assertRefused { run(prover(fake), input(plan(disclosure(systems = "[${specJson(system = "vega-mc-p256-v1")}]")))) }
        assertEquals(0, fake.calls)
    }

    @Test
    fun `an unclaimed system or version, an inactive or deprecated circuit, and an unknown one are refused`() {
        val p = plan(disclosure())
        for (d in listOf(
            descriptor(version = "9"),
            descriptor(system = "longfellow-nymauth", version = "8"),
            descriptor(status = "deprecated"),
            descriptor(published = false),
            descriptor(deprecatedAt = "2026-01-01T00:00:00Z"),
        )) {
            val fake = FakeLegacy()
            assertRefused { run(prover(fake, d), input(p, c = circuit(system = d.system, version = d.systemVersion))) }
            assertEquals(0, fake.calls)
        }
        val fake = FakeLegacy()
        assertRefused { run(prover(fake, null), input(p)) }
        // A circuit that says another version than the catalog does.
        assertRefused { run(prover(fake), input(p, c = circuit(version = "7"))) }
        assertEquals(0, fake.calls)
    }

    @Test
    fun `only a single well-formed claim disclosure is proved, and the pseudonym claim is never named by the verifier`() {
        val fake = FakeLegacy()
        val p = prover(fake)
        assertRefused { run(p, input(plan(disclosure(), disclosure(handle = "e")))) }
        assertRefused { run(p, input(plan(CircuitZkFunction("age_check", "a", params("""{"ge":"2000-01-01"}"""))))) }
        assertRefused { run(p, input(plan(disclosure(claims = """["family_name","${LongfellowZkProofSystem.PSEUDONYM_CLAIM}"]""")))) }
        assertRefused { run(p, input(plan(CircuitZkFunction(CircuitZkLegacyDisclosure.FUNCTION_ID, "d", params("""{"claims":[],"systems":[]}"""))))) }
        assertEquals(0, fake.calls)
    }

    @Test
    fun `a claim the credential does not hold is refused by the presenter before any proof`() {
        val fake = FakeLegacy()
        try {
            runBlocking {
                presenter(prover(fake), listOf(circuit())).present(
                    CircuitZkPresenter.Request(credential(), plan(disclosure(claims = """["family_name","nope"]""")), "rp.example", null, transcript),
                    signer,
                )
            }
            fail("expected a refusal")
        } catch (e: CircuitZkError.AccessDenied) {
            assertEquals(CircuitZkStep.PREDICATE, e.step)
        }
        assertEquals(0, fake.calls)
    }

    // -------- admits, and choosing among circuits --------

    @Test
    fun `the registry admits a legacy circuit only for a legacy plan whose systems name it and the proof system resolves`() {
        val registry = CircuitZkSystemRegistry(listOf(LegacyZkCircuitZkAdapter(ZkMdocPresentation(ZkProofSystemRegistry(listOf(FakeLegacy()))))))
        assertTrue(registry.admits(circuit(), plan(disclosure())))
        assertFalse(registry.admits(circuit(), plan(disclosure(systems = "[${specJson(id = "other")}]"))))
        assertFalse(registry.admits(circuit(), plan(CircuitZkFunction("age_check", "a", params("""{"ge":"2000-01-01"}""")))))
        // A circuit that does not serve the plan's credential type is not admitted, whatever the proof system could do.
        assertFalse(registry.admits(CircuitZkCircuit("longfellow", circuitId, setOf("other.doctype"), functions = setOf(CircuitZkLegacyDisclosure.FUNCTION_ID), systemVersion = "8"), plan(disclosure())))
        assertFalse(registry.admits(circuit(version = "9"), plan(disclosure())))
        assertFalse(registry.admits(circuit(version = null), plan(disclosure())))
        assertFalse(registry.admits(circuit(system = "vega-mc", version = "12"), plan(disclosure())))
        // No system registered that could prove the credential type.
        val empty = CircuitZkSystemRegistry(listOf(LegacyZkCircuitZkAdapter(ZkMdocPresentation(ZkProofSystemRegistry(emptyList())))))
        assertFalse(empty.admits(circuit(), plan(disclosure())))
    }

    @Test
    fun `the presenter picks the circuit the prover admits, not just the first that fits`() {
        val fake = FakeLegacy()
        val other = circuit(id = "other-circuit")
        val result = runBlocking {
            presenter(prover(fake), listOf(other, circuit())).present(
                CircuitZkPresenter.Request(credential(), plan(disclosure()), "rp.example", null, transcript),
                signer,
            )
        }
        assertEquals(circuitId, result.systemId)
    }

    @Test
    fun `the registry refuses two adapters claiming one system`() {
        val a = LegacyZkCircuitZkAdapter(ZkMdocPresentation(ZkProofSystemRegistry(emptyList())))
        try {
            CircuitZkSystemRegistry(listOf(a, a))
            fail("expected a duplicate claim to be refused")
        } catch (e: IllegalArgumentException) {
            assertNotNull(e.message)
        }
    }

    @Test
    fun `manifest circuits are declared for the legacy function by the registry and for nothing else`() {
        val p = prover(FakeLegacy())
        val manifest = org.siros.sdk.credentials.ZkManifest(
            circuits = listOf(descriptor(), descriptor(id = "x", version = "9"), descriptor(id = "n", system = "longfellow-nymauth", version = "61a8a73")),
        )
        val circuits = p.circuitsOf(manifest)
        assertEquals(setOf(CircuitZkLegacyDisclosure.FUNCTION_ID), circuits[0].functions)
        assertNull(circuits[1].functions)
        assertNull(circuits[2].functions)
        assertEquals("8", circuits[0].systemVersion)
    }

    @Test
    fun `the standard prover reaches both the nymauth and the legacy circuits and shares the presentation's residency`() {
        val residency = ZkProverResidency()
        val presentation = ZkMdocPresentation(ZkProofSystemRegistry(listOf(FakeLegacy())), residency)
        assertEquals(residency, presentation.proverResidency)
        val standard = CatalogCircuitZkProver.standard(client(descriptor()), presentation)
        assertTrue(standard.admits(circuit(), plan(disclosure())))
        assertTrue(standard.canProve) // the legacy adapter is real even though the nymauth one has no native half
    }

    @Test
    fun `without a registered adapter nothing is proved and the fake is never substituted`() {
        val none = CatalogCircuitZkProver(client(descriptor()), CircuitZkSystemRegistry(emptyList()))
        assertFalse(none.isFake)
        assertRefused { run(none, input(plan(disclosure()))) }
        assertTrue(logs.any { it.contains("no adapter") })
    }

    @Test
    fun `a retired circuit drops the presentation's resident prover and derived state through the adapter`() {
        val residency = ZkProverResidency()
        val dropped = mutableListOf<String>()
        val presentation = ZkMdocPresentation(ZkProofSystemRegistry(listOf(FakeLegacy())), residency, dropDerivedState = { dropped += it.id })
        val p = CatalogCircuitZkProver(client(descriptor()), CircuitZkSystemRegistry(listOf(LegacyZkCircuitZkAdapter(presentation))))
        runBlocking { residency.use("longfellow-libzk-v1:$circuitId:2", { AutoCloseable {} }) { } }
        runBlocking { p.onCircuitRetired(descriptor(id = "other")) }
        assertEquals("longfellow-libzk-v1:$circuitId:2", residency.residentKey)
        runBlocking { p.onCircuitRetired(descriptor()) }
        assertNull(residency.residentKey)
        assertEquals(listOf("other", circuitId), dropped)
        // A system no adapter claims has nobody to tell.
        runBlocking { p.onCircuitRetired(descriptor(system = "unknown")) }
    }
}
