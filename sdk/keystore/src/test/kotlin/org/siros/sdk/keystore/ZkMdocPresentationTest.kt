package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.credentials.CredentialDocument
import org.siros.sdk.credentials.CredentialFormat
import org.siros.sdk.credentials.CredentialTypeRef
import org.siros.sdk.credentials.VerifierIdentity
import org.siros.sdk.credentials.ZkProofResult
import org.siros.sdk.credentials.ZkProofSystem
import org.siros.sdk.credentials.ZkProofSystemRegistry
import org.siros.sdk.credentials.ZkSystemSpec
import org.siros.sdk.credentials.ZkWitnessSigner

/**
 * The facade over a fake proof system: what reaches the prover, what comes
 * back, and that the assembled DeviceResponse is the one
 * [MdocDeviceResponseBuilder.buildZkDeviceResponse] produces. No native
 * prover runs here.
 */
class ZkMdocPresentationTest {

    private val docType = "org.iso.18013.5.1.mDL"
    private val namespace = "org.iso.18013.5.1"
    private val spec = ZkSystemSpec(id = "fake-3", system = "fake", params = mapOf("num_attributes" to "3"))

    /** Accepts exactly [accepted] claims for mDL, records what it was asked, and can demand a witness signature. */
    private class FakeSystem(
        private val accepted: Int,
        private val needsSignature: Boolean = false,
    ) : ZkProofSystem {
        override val systemId = "fake"
        override val supportedCredentialTypes = setOf(CredentialTypeRef(CredentialFormat.MSO_MDOC, "org.iso.18013.5.1.mDL"))
        var seenTranscript: ByteArray? = null
        var seenClaims: List<String>? = null
        var seenIdentity: VerifierIdentity? = null
        var seenPriorState: ByteArray? = null

        override fun matchingSpec(requestedSpecs: List<ZkSystemSpec>, numAttributes: Int): ZkSystemSpec? =
            requestedSpecs.firstOrNull { it.system == systemId && numAttributes == accepted }

        override suspend fun generateProof(
            spec: ZkSystemSpec,
            document: CredentialDocument,
            sessionTranscript: ByteArray,
            requestedClaims: List<String>,
            verifierIdentity: VerifierIdentity?,
            signer: ZkWitnessSigner,
            priorState: ByteArray?,
        ): ZkProofResult {
            seenTranscript = sessionTranscript
            seenClaims = requestedClaims
            seenIdentity = verifierIdentity
            seenPriorState = priorState
            val witness = if (needsSignature) signer.sign(-7, byteArrayOf(9, 9, 9)) else ByteArray(0)
            return ZkProofResult(proofBytes = byteArrayOf(1, 2, 3) + witness, timestamp = "2026-09-10T00:00:00Z")
        }
    }

    private fun presentation(vararg systems: ZkProofSystem) = ZkMdocPresentation(ZkProofSystemRegistry(systems.toList()))

    private fun buildItem(digestId: Int, elementIdentifier: String, elementValue: String): CBORObject {
        val item = CBORObject.NewMap()
        item[CBORObject.FromObject("digestID")] = CBORObject.FromObject(digestId)
        item[CBORObject.FromObject("random")] = CBORObject.FromObject(ByteArray(16) { it.toByte() })
        item[CBORObject.FromObject("elementIdentifier")] = CBORObject.FromObject(elementIdentifier)
        item[CBORObject.FromObject("elementValue")] = CBORObject.FromObject(elementValue)
        return CBORObject.FromObjectAndTag(item.EncodeToBytes(), 24)
    }

    /** Same synthetic stored-credential envelope MdocDeviceResponseBuilderTest uses. */
    private fun storedCredential(): ByteArray {
        val items = CBORObject.NewArray()
        items.Add(buildItem(0, "family_name", "Doe"))
        items.Add(buildItem(1, "given_name", "Jane"))
        items.Add(buildItem(2, "issue_date", "2020-01-01"))
        val nameSpaces = CBORObject.NewMap()
        nameSpaces[CBORObject.FromObject(namespace)] = items
        val issuerAuth = CBORObject.NewArray()
        issuerAuth.Add(CBORObject.FromObject(ByteArray(0)))
        issuerAuth.Add(CBORObject.NewMap())
        issuerAuth.Add(CBORObject.FromObject(ByteArray(0)))
        issuerAuth.Add(CBORObject.FromObject(ByteArray(0)))
        val issuerSigned = CBORObject.NewMap()
        issuerSigned[CBORObject.FromObject("nameSpaces")] = nameSpaces
        issuerSigned[CBORObject.FromObject("issuerAuth")] = issuerAuth
        val document = CBORObject.NewMap()
        document[CBORObject.FromObject("docType")] = CBORObject.FromObject(docType)
        document[CBORObject.FromObject("issuerSigned")] = issuerSigned
        val documents = CBORObject.NewArray()
        documents.Add(document)
        val envelope = CBORObject.NewMap()
        envelope[CBORObject.FromObject("documents")] = documents
        envelope[CBORObject.FromObject("status")] = CBORObject.FromObject(0)
        return envelope.EncodeToBytes()
    }

    @Test
    fun `resolve matches on the credential's docType and the number of requested claims`() {
        val two = FakeSystem(accepted = 2)
        val p = presentation(two)
        assertNull(p.resolve(docType, listOf(spec), numClaims = 3))
        assertSame(two, p.resolve(docType, listOf(spec), numClaims = 2)?.first)
        assertNull(p.resolve("org.example.other", listOf(spec), numClaims = 2))
        assertEquals(listOf("fake"), p.systemIds)
    }

    @Test
    fun `present hands the prover exactly the request and wraps its proof as a zk DeviceResponse`() = runTest {
        val system = FakeSystem(accepted = 2)
        val p = presentation(system)
        val transcript = byteArrayOf(7, 7, 7)
        val identity = VerifierIdentity(clientId = "https://verifier.example", ppidContext = "ctx")
        val result = p.present(
            ZkMdocPresentation.Request(
                credentialBytes = storedCredential(),
                requestedSystems = listOf(spec),
                sessionTranscript = transcript,
                requestedClaims = listOf("family_name", "issue_date"),
                verifierIdentity = identity,
                priorState = byteArrayOf(4),
            ),
            signer = { _, _ -> fail("a system that needs no witness must not be asked for one"); ByteArray(0) },
        )
        assertArrayEquals(transcript, system.seenTranscript)
        assertEquals(listOf("family_name", "issue_date"), system.seenClaims)
        assertEquals(identity, system.seenIdentity)
        assertArrayEquals(byteArrayOf(4), system.seenPriorState)
        assertEquals(docType, result.docType)
        assertSame(system, result.system)
        assertEquals(spec, result.spec)

        val decoded = CBORObject.DecodeFromBytes(result.deviceResponse)
        val zkDocument = decoded["zkDocuments"][0]
        assertArrayEquals(byteArrayOf(1, 2, 3), zkDocument["proof"].GetByteString())
        val documentData = CBORObject.DecodeFromBytes(zkDocument["documentData"].UntagOne().GetByteString())
        assertEquals(docType, documentData["docType"].AsString())
        assertEquals("fake-3", documentData["zkSystemId"].AsString())
        // Only the two requested claims are disclosed.
        val disclosed = documentData["issuerSigned"][CBORObject.FromObject(namespace)]
        assertEquals(2, disclosed.size())
        assertEquals(setOf("family_name", "issue_date"), disclosed.values.map { it["elementIdentifier"].AsString() }.toSet())
        // And it is byte-for-byte what the builder produces for the same inputs.
        val expected = p.buildDeviceResponse(storedCredential(), docType, spec, listOf("family_name", "issue_date"), result.proof)
        assertArrayEquals(expected, result.deviceResponse)
    }

    @Test
    fun `the witness signer is the caller's, reached only when the prover asks`() = runTest {
        val system = FakeSystem(accepted = 1, needsSignature = true)
        var askedAlgorithm: Long? = null
        val result = presentation(system).present(
            ZkMdocPresentation.Request(
                credentialBytes = storedCredential(),
                requestedSystems = listOf(spec),
                sessionTranscript = ByteArray(0),
                requestedClaims = listOf("given_name"),
            ),
            signer = { algorithm, data ->
                askedAlgorithm = algorithm
                assertArrayEquals(byteArrayOf(9, 9, 9), data)
                byteArrayOf(0x51)
            },
        )
        assertEquals(-7L, askedAlgorithm)
        assertArrayEquals(byteArrayOf(1, 2, 3, 0x51), result.proof.proofBytes)
    }

    @Test
    fun `no matching system is a typed refusal naming the docType`() = runTest {
        try {
            presentation(FakeSystem(accepted = 1)).present(
                ZkMdocPresentation.Request(
                    credentialBytes = storedCredential(),
                    requestedSystems = listOf(spec),
                    sessionTranscript = ByteArray(0),
                    requestedClaims = listOf("family_name", "given_name"),
                ),
                signer = { _, _ -> ByteArray(0) },
            )
            fail("expected NoMatchingProofSystem")
        } catch (e: ZkMdocPresentation.NoMatchingProofSystem) {
            assertEquals(docType, e.docType)
            assertTrue(e.message!!.contains(docType))
        }
    }

    @Test
    fun `prewarmVega is a no-op when the resolved system is not Vega`() = runTest {
        // Must not throw, and (since FakeSystem isn't a VegaProofSystem)
        // there is nothing real to exercise - this just confirms the type
        // check actually gates the call rather than assuming every
        // registered system understands prewarm.
        presentation(FakeSystem(accepted = 2)).prewarmVega(
            ZkMdocPresentation.Request(
                credentialBytes = storedCredential(),
                requestedSystems = listOf(spec),
                sessionTranscript = ByteArray(0),
                requestedClaims = listOf("family_name", "issue_date"),
            ),
        )
    }

    @Test
    fun `prewarmVega is a no-op when nothing resolves`() = runTest {
        presentation(FakeSystem(accepted = 1)).prewarmVega(
            ZkMdocPresentation.Request(
                credentialBytes = storedCredential(),
                requestedSystems = listOf(spec),
                sessionTranscript = ByteArray(0),
                requestedClaims = listOf("family_name", "given_name"),
            ),
        )
    }

    @Test
    fun `the standard assembly registers the shipped mdoc systems in preference order`() {
        val circuitClient = org.siros.sdk.credentials.ZkCircuitClient(sources = emptyList())
        val p = ZkMdocPresentation.standard(circuitClient)
        assertEquals(listOf("longfellow-libzk-v1", VegaProofSystem.SYSTEM_ID), p.systemIds)
    }
}
