// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CircuitZkRequestValidator
import org.siros.sdk.credentials.NymPseudonym
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.ZkArtifact
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import org.siros.sdk.credentials.ZkUncompressed
import org.siros.sdk.credentials.ZkWitnessSigner
import timber.log.Timber

/**
 * [CatalogCircuitZkProver] against a catalog served from memory and a recording stand-in for the native
 * half. The stand-in sees exactly what a native binding would, so the assertions on its request are the ABI
 * the SDK commits to; nothing here proves anything cryptographically.
 */
class CatalogCircuitZkProverTest {
    private val docType = "eu.europa.ec.eudi.nym_auth.1"
    private val circuitId = "nymauth-longfellow-mdoc-v1"
    private val system = NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM
    private val seed = ByteArray(16) { it.toByte() }
    private val verifierId = "verifier.example"
    private val now = Instant.parse("2026-10-19T12:34:56.789Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    /** A self-signed P-256 certificate made with openssl; x has a leading zero byte, so coordinate padding is exercised. */
    private val certDer = Base64.getDecoder().decode(
        "MIIBijCCAS+gAwIBAgIUc5kinXWPR/mEhg00FOMiuOvJzuYwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPbnltLXRlc3QtaXNzdWVyMB4XDTI2MTAxOTE4MjI1NVoXDTM2MTAxNjE4MjI1NVow" +
            "GjEYMBYGA1UEAwwPbnltLXRlc3QtaXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAHCT1HH7jonPRv7lBWsSUOw8jD1k25uygRBfWwI5XB9w/CZW8CY81+NUWWaztts+fohlYnJz" +
            "yf/xayZE91ZPWKNTMFEwHQYDVR0OBBYEFDDWXf48O2A+ka3yN1PMghPLRe4dMB8GA1UdIwQYMBaAFDDWXf48O2A+ka3yN1PMghPLRe4dMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID" +
            "SQAwRgIhANb4r2Otb/PSLPkhxyUoFDEkeNBh9LKqrMcvU9AxGvVIAiEA0YnS8etU8QWH29rAS5dNlFUbvFUWBONZkOas5TJiGeA=",
    )
    private val qx = unhex("007093d471fb8e89cf46fee5056b1250ec3c8c3d64db9bb281105f5b02395c1f")
    private val qy = unhex("70fc2656f0263cd7e3545966b3b6db3e7e8865627273c9fff16b2644f7564f58")

    private fun unhex(h: String) = ByteArray(h.length / 2) { h.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    private fun cbor(o: Any) = CBORObject.FromObject(o)

    // -------- credential: the stored mdoc, as the presenter hands it over --------

    private fun item(id: Int, name: String, value: CBORObject): CBORObject {
        val m = CBORObject.NewMap()
        m[cbor("digestID")] = cbor(id.toLong())
        m[cbor("random")] = cbor(ByteArray(16))
        m[cbor("elementIdentifier")] = cbor(name)
        m[cbor("elementValue")] = value
        return CBORObject.FromObjectAndTag(m.EncodeToBytes(), 24)
    }

    private fun credential(withX5chain: Boolean = true, x5: ByteArray = certDer, chain: List<ByteArray>? = null): ByteArray {
        val items = CBORObject.NewArray()
        items.Add(item(0, "birth_date", CBORObject.FromObjectAndTag("2000-06-15", 1004)))
        items.Add(item(1, "ssc", cbor(sha256(seed))))
        val ns = CBORObject.NewMap()
        ns[cbor(docType)] = items
        val mso = CBORObject.NewMap()
        mso[cbor("docType")] = cbor(docType)
        val unprotected = CBORObject.NewMap()
        if (chain != null) unprotected[cbor(33)] = CBORObject.NewArray().also { a -> chain.forEach { a.Add(cbor(it)) } }
        else if (withX5chain) unprotected[cbor(33)] = cbor(x5)
        val auth = CBORObject.NewArray()
        auth.Add(cbor(CBORObject.NewMap().also { it[cbor(1)] = cbor(-7) }.EncodeToBytes()))
        auth.Add(unprotected)
        auth.Add(cbor(CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()))
        auth.Add(cbor(ByteArray(64) { 5 }))
        val signed = CBORObject.NewMap()
        signed[cbor("nameSpaces")] = ns
        signed[cbor("issuerAuth")] = auth
        return signed.EncodeToBytes()
    }

    // -------- the catalog, in memory --------

    private val circuitBytes = ByteArray(64) { (it * 7).toByte() }
    private val compressedPrefix = "ZSTD:".toByteArray()
    private fun compressed(plain: ByteArray = circuitBytes) = compressedPrefix + plain

    private var downloads = 0
    private var decompressions = 0
    private var servedBytes: ByteArray = compressed()

    private fun descriptor(
        id: String = circuitId,
        system: String = this.system,
        format: String = "mdoc",
        configuration: String = "known-offender-matching-ssc",
        published: Boolean = true,
        deprecatedAt: String? = null,
        uncompressedHash: String? = "sha256:" + hex(sha256(circuitBytes)),
        artifactHash: String = "sha256:" + hex(sha256(compressed())),
    ) = ZkCircuitDescriptor(
        id = id,
        system = system,
        systemVersion = "61a8a73",
        docTypes = listOf(docType),
        published = published,
        status = "active",
        deprecatedAt = deprecatedAt,
        params = Json.parseToJsonElement(
            """{"format":"$format","configuration":"$configuration","hash_circuit_id":"aa","sig_circuit_id":"bb","block_enc_hash":"6983","block_enc_sig":"4679"}""",
        ).jsonObject,
        artifact = ZkArtifact(
            url = "/v1/artifacts/sha256/x",
            hash = artifactHash,
            size = compressed().size.toLong(),
            compression = "zstd",
            uncompressed = uncompressedHash?.let { ZkUncompressed(hash = it, size = circuitBytes.size.toLong()) },
        ),
    )

    private fun client(d: ZkCircuitDescriptor? = descriptor()) = ZkCircuitClient(
        sources = listOf("https://catalog.test"),
        httpGet = { url -> if (d != null && url.endsWith("/v1/circuits/${d.id}.json")) Json.encodeToString(ZkCircuitDescriptor.serializer(), d) else null },
        httpGetBytes = { downloads++; servedBytes },
    )

    private val decompress: (ByteArray, ZkCircuitDescriptor) -> ByteBuffer = { bytes, _ ->
        decompressions++
        ByteBuffer.wrap(bytes.copyOfRange(compressedPrefix.size, bytes.size))
    }

    // -------- the native stand-in --------

    private class Recording(val respond: (NymAuthProveRequest) -> NymAuthProveResponse) : NymAuthNativeProver {
        var request: NymAuthProveRequest? = null
        var circuitSeen: ByteArray? = null
        var seedSeen: ByteArray? = null
        var calls = 0
        override suspend fun prove(request: NymAuthProveRequest): NymAuthProveResponse {
            calls++
            this.request = request
            seedSeen = request.secretSeed.copyOf()
            circuitSeen = ByteArray(request.circuit.remaining()).also { request.circuit.duplicate().get(it) }
            return respond(request)
        }
    }

    private val proofBytes = ByteArray(40) { 0x42 }

    /** A native side that reports the rulebook pseudonym for the seed and verifier input it was handed. */
    private fun honestNative() = Recording { r ->
        NymAuthProveResponse(proofBytes.copyOf(), NymPseudonym.derive("known-offender-matching-ssc", r.secretSeed, verifierId = verifierId))
    }

    private val deviceSignature = ByteArray(64) { (0x80 + it).toByte() }
    private var signedData: ByteArray? = null
    private var signerCalls = 0
    private var signatureToReturn: ByteArray = deviceSignature
    private val signer = ZkWitnessSigner { alg, data ->
        signerCalls++
        assertEquals(-7L, alg)
        signedData = data
        signatureToReturn
    }

    // -------- the request --------

    private fun params(json: String): JsonObject = Json.parseToJsonElement(json).jsonObject

    private fun pseudonymFn(config: String = "known-offender-matching-ssc") =
        CircuitZkFunction("pseudonym", "n", params("""{"config":"$config","ver":1,"prf":"sha-256"}"""))

    private fun ageFn(json: String = """{"ge":"1990-01-01","le":"2008-10-19"}""") = CircuitZkFunction("age_check", "a", params(json))

    private fun input(
        functions: List<CircuitZkFunction> = listOf(pseudonymFn(), ageFn()),
        cred: ByteArray = credential(),
        verifierId: String? = this.verifierId,
        seedBytes: ByteArray? = seed.copyOf(),
        circuit: CircuitZkCircuit = CircuitZkCircuit(system, circuitId, setOf(docType)),
        transcript: ByteArray = CBORObject.NewArray().also { it.Add(CBORObject.Null); it.Add(CBORObject.Null); it.Add(cbor("handover")) }.EncodeToBytes(),
    ) = CircuitZkProveInput(
        circuit = circuit,
        plan = CircuitZkPlan(functions, raw = params("""{"meta":{"source_format":"mso_mdoc","doctype_value":"$docType"}}""")),
        credentialBytes = cred,
        sessionTranscript = transcript,
        verifierId = verifierId,
        verifierContext = null,
        witnesses = mapOf("n" to CircuitZkFunctionWitness(secretSeed = seedBytes)),
        signer = signer,
    )

    private fun prover(native: NymAuthNativeProver?, c: ZkCircuitClient = client(), residency: ZkProverResidency = ZkProverResidency()) =
        CatalogCircuitZkProver(c, native, residency, clock, decompress)

    private fun prove(p: CircuitZkProver, i: CircuitZkProveInput) = runBlocking { p.prove(i) }

    private fun assertRefused(block: () -> Unit) {
        try {
            block()
            fail("expected a refusal")
        } catch (e: CircuitZkError.AccessDenied) {
            assertEquals(CircuitZkStep.PROVE, e.step)
            assertEquals("circuit_zk request refused", e.message)
        }
    }

    private val logs = mutableListOf<String>()
    private val tree = object : Timber.Tree() {
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
            logs += message + (t?.toString() ?: "")
        }
    }

    @Before fun plant() = Timber.plant(tree)

    @After fun uproot() = Timber.uproot(tree)

    // -------- the happy path --------

    @Test
    fun `a proof carries the circuit's proof, the rulebook pseudonym and the proof time`() {
        val native = honestNative()
        val out = prove(prover(native), input())

        assertArrayEquals(proofBytes, out.proof)
        assertEquals(
            ResultValue.Pseudonym(NymPseudonym.derive("known-offender-matching-ssc", seed, verifierId = verifierId)),
            out.results["n"],
        )
        assertEquals(ResultValue.Predicate, out.results["a"])
        assertEquals(setOf("n", "a"), out.results.keys)
        assertEquals(Instant.parse("2026-10-19T12:34:56Z"), out.proofTime)
        assertFalse(out.proof.contentEquals(FakeCircuitZkProver.DUMMY_PROOF))
    }

    @Test
    fun `the native side is handed the inputs the circuit specification defines`() {
        val native = honestNative()
        val i = input()
        prove(prover(native), i)
        val r = native.request!!

        assertEquals(system, r.system)
        assertEquals(circuitId, r.circuitId)
        assertEquals("known-offender-matching-ssc", r.circuitParams["configuration"]?.toString()?.trim('"'))
        // The circuit bytes are the decompressed artifact, whole.
        assertArrayEquals(circuitBytes, native.circuitSeen)
        assertTrue(r.circuit.isReadOnly)
        // Q is the x5chain leaf key, 32-byte big-endian coordinates, zero-padded.
        assertEquals(hex(qx), hex(r.issuerKeyX))
        assertEquals(hex(qy), hex(r.issuerKeyY))
        assertEquals(32, r.issuerKeyX.size)
        // T has no fractional seconds and is 20 characters; E and C come from the age_check bounds.
        assertEquals("2026-10-19T12:34:56Z", r.time)
        assertEquals("1990-01-01", r.earliest)
        assertEquals("2008-10-19", r.cutoff)
        assertEquals(hex(sha256(verifierId.toByteArray())), hex(r.verifierInput))
        assertEquals(hex(seed), hex(native.seedSeen!!))
        assertArrayEquals(i.sessionTranscript, r.transcriptSeed)
        assertArrayEquals(deviceSignature, r.deviceSignature)
    }

    @Test
    fun `with a leaf-plus-root x5chain the proof input Q is still the leaf key`() {
        val native = honestNative()
        prove(prover(native), input(cred = credential(chain = listOf(certDer, ByteArray(30) { (it + 100).toByte() }))))
        val r = native.request!!
        assertEquals(hex(qx), hex(r.issuerKeyX))
        assertEquals(hex(qy), hex(r.issuerKeyY))
    }

    @Test
    fun `e2 is the digest of exactly the COSE message the device key signed`() {
        val native = honestNative()
        val i = input()
        prove(prover(native), i)

        val expectedMessage = CBORObject.NewArray().also {
            it.Add(cbor("Signature1"))
            it.Add(cbor(byteArrayOf(0xA1.toByte(), 0x01, 0x26)))
            it.Add(cbor(ByteArray(0)))
            it.Add(cbor(MdocDeviceResponseBuilder.buildDeviceAuthentication(docType, i.sessionTranscript)))
        }.EncodeToBytes()
        assertArrayEquals(expectedMessage, signedData)
        assertEquals(hex(sha256(expectedMessage)), hex(native.request!!.challengeDigest))
        assertEquals(1, signerCalls)
    }

    @Test
    fun `the issuerSigned handed over keeps the original items and the issuer auth`() {
        val native = honestNative()
        prove(prover(native), input())
        val decoded = CBORObject.DecodeFromBytes(native.request!!.issuerSigned)
        val items = decoded["nameSpaces"][docType]
        assertEquals(2, items.size())
        assertTrue(items[0].HasMostOuterTag(24))
        assertEquals(4, decoded["issuerAuth"].size())
    }

    @Test
    fun `an age_check with only one bound opens the other end`() {
        val native = honestNative()
        prove(prover(native), input(functions = listOf(pseudonymFn(), ageFn("""{"ge":"1990-01-01"}"""))))
        assertEquals("1990-01-01", native.request!!.earliest)
        assertEquals("9999-12-31", native.request!!.cutoff)
        prove(prover(native), input(functions = listOf(pseudonymFn(), ageFn("""{"le":"2008-10-19"}"""))))
        assertEquals("0000-00-00", native.request!!.earliest)
        assertEquals("2008-10-19", native.request!!.cutoff)
    }

    @Test
    fun `a pseudonym alone is proved with both bounds open`() {
        val native = honestNative()
        val out = prove(prover(native), input(functions = listOf(pseudonymFn())))
        assertEquals("0000-00-00", native.request!!.earliest)
        assertEquals("9999-12-31", native.request!!.cutoff)
        assertEquals(setOf("n"), out.results.keys)
    }

    @Test
    fun `the seed copy given to the native side is zeroed afterwards and the witness seed is untouched`() {
        var seen: ByteArray? = null
        val native = Recording { r ->
            seen = r.secretSeed
            NymAuthProveResponse(proofBytes, NymPseudonym.derive("known-offender-matching-ssc", r.secretSeed, verifierId = verifierId))
        }
        val witnessSeed = seed.copyOf()
        prove(prover(native), input(seedBytes = witnessSeed))
        assertTrue(seen!!.all { it == 0.toByte() })
        assertArrayEquals(seed, witnessSeed)
    }

    @Test
    fun `the request renders redacted`() {
        val native = honestNative()
        prove(prover(native), input())
        assertEquals("NymAuthProveRequest(redacted)", native.request.toString())
        assertEquals("NymAuthProveResponse(redacted)", NymAuthProveResponse(proofBytes, proofBytes).toString())
    }

    // -------- end to end through the presenter: the real prover is what a presentation uses --------

    @Test
    fun `a presenter over the catalog prover produces a presentation with the circuit's proof, not the fake's`() {
        val circuit = CircuitZkCircuit(system, circuitId, setOf(docType), functions = setOf("pseudonym", "age_check"), systemVersion = "61a8a73")
        val presenter = CircuitZkPresenter(
            prover(honestNative()),
            { listOf(circuit) },
            CircuitZkRequestValidator.PERMISSIVE,
            object : CircuitZkWitnessProvider {
                override fun witness(function: CircuitZkFunction, needs: Set<CircuitZkWitnessKind>, credentialType: String, issuer: String?) =
                    CircuitZkFunctionWitness()

                override fun privateSeedMatches(credentialType: String, issuer: String?, psc: ByteArray) = false
            },
            serving = { _, _, _ -> true },
        )
        val plan = CircuitZkPlan(
            listOf(pseudonymFn(), ageFn()),
            circuitFilter = org.siros.sdk.credentials.CircuitZkCircuitFilter(listOf(system), listOf(circuitId)),
            raw = params("""{"id":"q","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"$docType"}}"""),
        )
        val result = runBlocking {
            presenter.present(
                CircuitZkPresenter.Request(credential(), plan, verifierId, null, byteArrayOf(0x80.toByte()), seed.copyOf()),
                signer,
            )
        }
        assertFalse(presenter.usesFakeProver)
        val decoded = result.presentation
        assertArrayEquals(proofBytes, decoded.proof)
    }

    // -------- fail closed --------

    @Test
    fun `without a native prover every request is refused and nothing is fetched or signed`() {
        val p = prover(null)
        assertFalse(p.canProve)
        assertRefused { prove(p, input()) }
        assertEquals(0, downloads)
        assertEquals(0, signerCalls)
        assertFalse(p.isFake)
    }

    @Test
    fun `a circuit of an unsupported system is refused before the artifact is downloaded or anything signed`() {
        val native = honestNative()
        val other = descriptor(system = "longfellow-libzk-v1")
        assertRefused { prove(prover(native, client(other)), input(circuit = CircuitZkCircuit(other.system, circuitId, setOf(docType)))) }
        assertEquals(0, native.calls)
        assertEquals(0, downloads)
        assertEquals(0, signerCalls)
    }

    @Test
    fun `an sd-jwt circuit is refused`() {
        val native = honestNative()
        assertRefused { prove(prover(native, client(descriptor(format = "sdjwt"))), input()) }
        assertEquals(0, native.calls)
        assertEquals(0, signerCalls)
    }

    @Test
    fun `a circuit built for another pseudonym configuration is refused`() {
        val native = honestNative()
        assertRefused { prove(prover(native, client(descriptor(configuration = "known-offender-matching-psc"))), input()) }
        assertEquals(0, native.calls)
    }

    @Test
    fun `an unpublished or deprecated circuit is refused`() {
        val native = honestNative()
        assertRefused { prove(prover(native, client(descriptor(published = false))), input()) }
        assertRefused { prove(prover(native, client(descriptor(deprecatedAt = "2026-10-01T00:00:00Z"))), input()) }
        assertEquals(0, native.calls)
    }

    @Test
    fun `a catalog answer for another id than the chosen circuit is refused`() {
        val native = honestNative()
        val c = ZkCircuitClient(
            sources = listOf("https://catalog.test"),
            httpGet = { Json.encodeToString(ZkCircuitDescriptor.serializer(), descriptor(id = "nymauth-vega-mdoc-v1", system = system)) },
            httpGetBytes = { servedBytes },
        )
        assertRefused { prove(prover(native, c), input()) }
        assertEquals(0, native.calls)
    }

    @Test
    fun `a circuit the catalog does not know is refused`() {
        val native = honestNative()
        assertRefused { prove(prover(native, client(null)), input()) }
        assertEquals(0, native.calls)
    }

    @Test
    fun `an artifact whose served bytes do not match the catalog hash is refused`() {
        val native = honestNative()
        servedBytes = compressed(ByteArray(64) { 1 })
        assertRefused { prove(prover(native), input()) }
        assertEquals(0, native.calls)
        assertEquals(0, signerCalls)
    }

    @Test
    fun `a decompressed artifact that does not match the catalog's uncompressed hash is refused`() {
        val native = honestNative()
        assertRefused { prove(prover(native, client(descriptor(uncompressedHash = "sha256:" + "00".repeat(32)))), input()) }
        assertEquals(0, native.calls)
        assertEquals(0, signerCalls)
    }

    @Test
    fun `an artifact without a published uncompressed hash is not trusted`() {
        val native = honestNative()
        assertRefused { prove(prover(native, client(descriptor(uncompressedHash = null))), input()) }
        assertEquals(0, native.calls)
    }

    @Test
    fun `a pseudonym the circuit reports that differs from the rulebook's is refused`() {
        val wrong = Recording { NymAuthProveResponse(proofBytes, ByteArray(32) { 3 }) }
        assertRefused { prove(prover(wrong), input()) }
        // A pseudonym for another verifier is the same refusal.
        val other = Recording { r -> NymAuthProveResponse(proofBytes, NymPseudonym.derive("known-offender-matching-ssc", r.secretSeed, verifierId = "other.example")) }
        assertRefused { prove(prover(other), input()) }
    }

    @Test
    fun `an empty proof is refused`() {
        val empty = Recording { r -> NymAuthProveResponse(ByteArray(0), NymPseudonym.derive("known-offender-matching-ssc", r.secretSeed, verifierId = verifierId)) }
        assertRefused { prove(prover(empty), input()) }
    }

    @Test
    fun `a device signature that is not 64 bytes is refused`() {
        val native = honestNative()
        signatureToReturn = ByteArray(70)
        assertRefused { prove(prover(native), input()) }
        assertEquals(0, native.calls)
    }

    @Test
    fun `plans this prover does not prove are refused`() {
        val native = honestNative()
        val p = prover(native)
        // No pseudonym, two pseudonyms, two age checks, another function, another config, extra age parameters.
        assertRefused { prove(p, input(functions = listOf(ageFn()))) }
        assertRefused { prove(p, input(functions = listOf(pseudonymFn(), pseudonymFn()))) }
        assertRefused { prove(p, input(functions = listOf(pseudonymFn(), ageFn(), ageFn()))) }
        assertRefused { prove(p, input(functions = listOf(pseudonymFn(), CircuitZkFunction("other", "o")))) }
        assertRefused { prove(p, input(functions = listOf(pseudonymFn("known-offender-matching-psc")))) }
        assertRefused { prove(p, input(functions = listOf(pseudonymFn("account-recovery-ssc")))) }
        assertRefused { prove(p, input(functions = listOf(pseudonymFn("user-managed-pseudonym-xsite-ssc")))) }
        assertRefused { prove(p, input(functions = listOf(pseudonymFn(), ageFn("""{"ge":"1990-01-01","gt":"1991-01-01"}""")))) }
        assertRefused { prove(p, input(functions = listOf(pseudonymFn(), ageFn("""{}""")))) }
        assertRefused { prove(p, input(functions = listOf(pseudonymFn(), ageFn("""{"ge":"1990-1-1"}""")))) }
        assertRefused { prove(p, input(functions = listOf(pseudonymFn(), ageFn("""{"ge":"0000-01-01"}""")))) }
        assertRefused { prove(p, input(functions = listOf(pseudonymFn(), ageFn("""{"ge":19900101}""")))) }
        assertEquals(0, native.calls)
        assertEquals(0, signerCalls)
    }

    @Test
    fun `missing or malformed witnesses and credential parts are refused`() {
        val native = honestNative()
        val p = prover(native)
        assertRefused { prove(p, input(verifierId = null)) }
        assertRefused { prove(p, input(seedBytes = null)) }
        assertRefused { prove(p, input(seedBytes = ByteArray(15))) }
        assertRefused { prove(p, input(cred = credential(withX5chain = false))) }
        assertRefused { prove(p, input(cred = credential(x5 = ByteArray(40)))) }
        assertRefused { prove(p, input(cred = byteArrayOf(1, 2, 3))) }
        assertEquals(0, native.calls)
        assertEquals(0, signerCalls)
    }

    @Test
    fun `an unsupported circuit leaves no trace of the seed in the log`() {
        val native = honestNative()
        assertRefused { prove(prover(native, client(descriptor(format = "sdjwt"))), input()) }
        logs.forEach { assertFalse(it.contains(hex(seed))) }
    }

    // -------- residency --------

    @Test
    fun `the verified circuit stays resident across proofs and is reloaded after a release`() {
        val native = honestNative()
        val p = prover(native, client(), ZkProverResidency())
        prove(p, input())
        prove(p, input())
        assertEquals(1, downloads)
        assertEquals(1, decompressions)
        assertEquals(2, native.calls)

        p.releaseProvers()
        prove(p, input())
        assertEquals(2, decompressions)
        assertNotEquals(0, downloads)
    }

    // -------- red team --------

    @Test
    fun `a throwable from the native side or the artifact path is a refusal, not a crash`() {
        for (t in listOf<Throwable>(OutOfMemoryError("hostile"), UnsatisfiedLinkError("no lib"), StackOverflowError())) {
            assertRefused { prove(prover(Recording { throw t }), input()) }
        }
        val boomDecompress: (ByteArray, ZkCircuitDescriptor) -> ByteBuffer = { _, _ -> throw OutOfMemoryError("frame says 4 GB") }
        assertRefused { prove(CatalogCircuitZkProver(client(), honestNative(), ZkProverResidency(), clock, boomDecompress), input()) }
    }

    @Test
    fun `an empty verifier id is refused`() {
        val native = honestNative()
        assertRefused { prove(prover(native), input(verifierId = "")) }
        assertEquals(0, native.calls)
    }

    // -------- catalog refresh: a retired circuit stops being usable --------

    @Test
    fun `a circuit the refresh retires is refused afterwards and its resident circuit is dropped`() {
        var current: ZkCircuitDescriptor = descriptor()
        val dir = java.nio.file.Files.createTempDirectory("nymrefresh").toFile().also { it.deleteOnExit() }
        val c = ZkCircuitClient(
            sources = listOf("https://catalog.test"),
            httpGet = { url ->
                when {
                    url.endsWith("/v1/manifest.json") -> Json.encodeToString(org.siros.sdk.credentials.ZkManifest.serializer(), org.siros.sdk.credentials.ZkManifest(circuits = listOf(current)))
                    url.endsWith("/v1/circuits/${current.id}.json") -> Json.encodeToString(ZkCircuitDescriptor.serializer(), current)
                    else -> null
                }
            },
            httpGetBytes = { downloads++; servedBytes },
            cacheDir = dir,
        )
        val native = honestNative()
        val residency = ZkProverResidency()
        val p = CatalogCircuitZkProver(c, native, residency, clock, decompress)
        prove(p, input())
        assertEquals(1, decompressions)
        assertTrue(residency.residentKey!!.contains(circuitId))
        assertTrue(c.isArtifactCached(current))

        // The catalog now says the circuit is deprecated; the refresh expunges it and tells the prover.
        current = descriptor(deprecatedAt = "2026-10-19T00:00:00Z")
        val result = runBlocking { org.siros.sdk.credentials.ZkCircuitCatalogRefresher(c, onRetired = p::onCircuitRetired).refreshOnce() }
        assertTrue(result is org.siros.sdk.credentials.ZkCircuitCatalogRefresher.Result.Refreshed)
        assertNull("the resident circuit is gone", residency.residentKey)
        assertFalse(c.isArtifactCached(current))
        assertRefused { prove(p, input()) }
        assertEquals(1, native.calls)
    }

    @Test
    fun `retiring another circuit leaves the resident one alone`() {
        val residency = ZkProverResidency()
        val native = honestNative()
        val p = CatalogCircuitZkProver(client(), native, residency, clock, decompress)
        prove(p, input())
        runBlocking { p.onCircuitRetired(descriptor(id = "nymauth-vega-mdoc-v1")) }
        assertNotNull(residency.residentKey)
        runBlocking { p.onCircuitRetired(descriptor()) }
        assertNull(residency.residentKey)
    }

    // -------- the native binding's typed errors --------

    private fun reasonOf(t: NymAuthNativeException, residency: ZkProverResidency = ZkProverResidency()): CircuitZkRefusalReason {
        try {
            prove(prover(Recording { throw t }, residency = residency), input())
            fail("expected a refusal")
        } catch (e: CircuitZkError.AccessDenied) {
            assertEquals(CircuitZkStep.PROVE, e.step)
            // The verifier-facing refusal is bare whatever the cause was.
            assertEquals("circuit_zk request refused", e.message)
            return e.reason
        }
        error("unreachable")
    }

    @Test
    fun `every native error maps deliberately to a refusal reason, Vega's and Longfellow's alike`() {
        val expected = mapOf(
            NymAuthNativeException.vega("InvalidInput") to CircuitZkRefusalReason.INVALID_INPUT,
            NymAuthNativeException.vega("InvalidShapes") to CircuitZkRefusalReason.INVALID_CIRCUIT,
            NymAuthNativeException.vega("UnknownCircuit") to CircuitZkRefusalReason.CIRCUIT_UNSUPPORTED_BY_APP,
            NymAuthNativeException.vega("Refused", "SeedMismatch") to CircuitZkRefusalReason.SEED_MISMATCH,
            NymAuthNativeException.vega("Refused", "IssuerSignature") to CircuitZkRefusalReason.ISSUER_SIGNATURE,
            NymAuthNativeException.vega("Refused", "DeviceSignature") to CircuitZkRefusalReason.DEVICE_SIGNATURE,
            NymAuthNativeException.vega("Refused", "Credential") to CircuitZkRefusalReason.CREDENTIAL,
            NymAuthNativeException.vega("Refused", "SomethingNew") to CircuitZkRefusalReason.UNSATISFIED,
            NymAuthNativeException.vega("ProverFailed") to CircuitZkRefusalReason.PROVER_FAILED,
            NymAuthNativeException.vega("ProofInvalid") to CircuitZkRefusalReason.PROOF_INVALID,
            NymAuthNativeException.vega("Mismatch") to CircuitZkRefusalReason.MISMATCH,
            NymAuthNativeException.vega("Internal") to CircuitZkRefusalReason.INTERNAL,
            NymAuthNativeException.vega("AVariantFromTheFuture") to CircuitZkRefusalReason.INTERNAL,
            NymAuthNativeException.longfellow("InvalidInput") to CircuitZkRefusalReason.INVALID_INPUT,
            NymAuthNativeException.longfellow("Circuit") to CircuitZkRefusalReason.INVALID_CIRCUIT,
            NymAuthNativeException.longfellow("UnsupportedCircuit") to CircuitZkRefusalReason.CIRCUIT_UNSUPPORTED_BY_APP,
            NymAuthNativeException.longfellow("Credential") to CircuitZkRefusalReason.CREDENTIAL,
            NymAuthNativeException.longfellow("Unsatisfied") to CircuitZkRefusalReason.UNSATISFIED,
            NymAuthNativeException.longfellow("Prover") to CircuitZkRefusalReason.PROVER_FAILED,
            NymAuthNativeException.longfellow("Verification") to CircuitZkRefusalReason.PROOF_INVALID,
            NymAuthNativeException.longfellow("AVariantFromTheFuture") to CircuitZkRefusalReason.INTERNAL,
        )
        for ((e, reason) in expected) assertEquals(e.message, reason, reasonOf(e))
    }

    @Test
    fun `an unsupported circuit is its own reason, is announced once, drops the resident circuit and leaks nothing`() {
        val announced = mutableListOf<String>()
        val residency = ZkProverResidency()
        val adapter = NymAuthCircuitZkAdapter(client(), Recording { throw NymAuthNativeException.vega("UnknownCircuit") }, residency, clock, decompress, announced::add)
        val p = CatalogCircuitZkProver(client(), CircuitZkSystemRegistry(listOf(adapter)))
        repeat(2) {
            try {
                prove(p, input())
                fail("expected a refusal")
            } catch (e: CircuitZkError.AccessDenied) {
                assertEquals(CircuitZkRefusalReason.CIRCUIT_UNSUPPORTED_BY_APP, e.reason)
                assertEquals("circuit_zk request refused", e.message)
            }
        }
        assertEquals(listOf(circuitId), announced)
        assertEquals(setOf(circuitId), adapter.unsupportedCircuits)
        assertNull("the circuit that cannot be proved is not kept resident", residency.residentKey)
        // Nothing but the kind and the circuit id reaches the log: no seed, no digest, no hex of either.
        assertTrue(logs.any { it.contains("not supported by this app version") })
        logs.forEach {
            assertFalse(it, it.contains(hex(seed)))
            assertFalse(it, it.contains(hex(sha256(circuitBytes))))
        }
    }

    @Test
    fun `a native error carries no message of the binding, and a refusal only its coarse code`() {
        val e = NymAuthNativeException.vega("Refused", "SeedMismatch")
        assertEquals(NymAuthNativeErrorKind.REFUSED, e.kind)
        assertEquals(NymAuthRefusal.SEED_MISMATCH, e.refusal)
        assertEquals("nymauth native prover: REFUSED (SEED_MISMATCH)", e.message)
        assertNull(NymAuthNativeException.vega("UnknownCircuit").refusal)
    }

    // -------- the prover runs the validator's rules --------

    private fun unsatVectors(): List<Pair<String, JsonObject>> {
        val dir = java.io.File("../../spec/zkp-req-vectors/zkp_req_unsat")
        require(dir.isDirectory) { "vector dir not found at ${dir.absolutePath}" }
        return dir.listFiles { f -> f.extension == "json" }!!.sortedBy { it.name }.map { it.name to Json.parseToJsonElement(it.readText()).jsonObject }
    }

    /**
     * For every unsatisfiable-request vector whose plan this adapter could prove at all (a known-offender-matching-ssc pseudonym
     * and, at most, an age_check, over mso_mdoc), the wallet's validator says Ok exactly when the adapter accepts the plan: the
     * adapter runs the validator's rules, so neither passes a plan the other refuses.
     */
    @Test
    fun `the validator and the nymauth adapter agree on every shared vector's plan`() {
        val adapter = NymAuthCircuitZkAdapter(client(), honestNative())
        val validator = org.siros.sdk.credentials.RulebookCircuitZkValidator()
        var compared = 0
        var refusedByBoth = 0
        for ((name, v) in unsatVectors()) {
            val query = v["query"]!!.jsonObject
            val fns = query["_req"]!!.jsonArray.map {
                val o = it.jsonObject
                CircuitZkFunction(o["fn_id"]!!.jsonPrimitive.content, o["return"]!!.jsonPrimitive.content, (o["params"] as? JsonObject) ?: JsonObject(emptyMap()))
            }
            val pseudonyms = fns.filter { it.id == "pseudonym" }
            val comparable = pseudonyms.isNotEmpty() &&
                pseudonyms.all { (it.params["config"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull == "known-offender-matching-ssc" } &&
                fns.all { it.id == "pseudonym" || it.id == "age_check" } &&
                (query["meta"]!!.jsonObject["source_format"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull == "mso_mdoc"
            if (!comparable) continue
            val p = CircuitZkPlan(fns, raw = query)
            val validatorOk = validator.validate(p) is org.siros.sdk.credentials.CircuitZkVerdict.Ok
            assertEquals(name, validatorOk, adapter.acceptsPlan(p))
            compared++
            if (!validatorOk) refusedByBoth++
        }
        assertTrue("compared $compared", compared >= 8)
        assertTrue("refused by both $refusedByBoth", refusedByBoth >= 3)
    }

    @Test
    fun `a short age span, an inverted range and a context are refused by the prover itself`() {
        val native = honestNative()
        val p = prover(native)
        // Span under 365 days, le before ge, a verifier_context the configuration forbids.
        assertRefused { prove(p, input(functions = listOf(pseudonymFn(), ageFn("""{"ge":"2000-01-01","le":"2000-06-01"}""")))) }
        assertRefused { prove(p, input(functions = listOf(pseudonymFn(), ageFn("""{"ge":"2010-01-01","le":"2000-01-01"}""")))) }
        assertRefused { prove(p, input(functions = listOf(CircuitZkFunction("pseudonym", "n", params("""{"config":"known-offender-matching-ssc","ver":1,"prf":"sha-256","verifier_context":"c"}""")), ageFn()))) }
        assertEquals(0, native.calls)
        // A span of exactly 365 days is allowed.
        prove(p, input(functions = listOf(pseudonymFn(), ageFn("""{"ge":"2000-01-01","le":"2000-12-30"}"""))))
        assertEquals(1, native.calls)
    }
}
