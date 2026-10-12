// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import org.siros.sdk.credentials.CredentialDocument
import org.siros.sdk.credentials.CredentialFormat
import org.siros.sdk.credentials.CredentialTypeRef
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkProofResult
import org.siros.sdk.credentials.ZkProofSystem
import org.siros.sdk.credentials.ZkProofSystemRegistry
import org.siros.sdk.credentials.ZkSystemSpec
import org.siros.sdk.credentials.ZkWitnessSigner
import org.siros.sdk.credentials.VerifierIdentity
import org.siros.sdk.credentials.mdoc.MdocCbor

/**
 * Zero-knowledge presentation of a stored mdoc credential, with no wallet
 * and no Activity: resolve the verifier's requested proof systems against
 * what this device can prove, run the prover, and assemble the
 * `{version, status, zkDocuments: [...]}` DeviceResponse-shaped CBOR that
 * verifiers (multipaz's `DeviceResponseParser` among them) accept as a
 * `vp_token` entry.
 *
 * Everything here existed already - the registry, the circuit client, the
 * proof systems, [MdocDeviceResponseBuilder.buildZkDeviceResponse] - but was
 * assembled only inside a private method of the wallet facade, which needs
 * an Activity and a logged-in session to construct. A host that is not the
 * sample app (a wrapper app around a web wallet, say, whose credentials and
 * device keys live elsewhere) could reach the parts but not the whole, and
 * would have had to reimplement the document assembly. This is that whole,
 * in one place, taking exactly what a proof needs and nothing the wallet
 * happens to have.
 *
 * The device key never comes here. A proof that binds one asks for a
 * signature through [ZkWitnessSigner] and the caller signs with whatever
 * holds the key - the SDK keystore, a web page's keystore across a bridge,
 * a hardware token. A proof system without a device-binding concept (Vega)
 * never calls it, so callers must not require a key up front.
 */
class ZkMdocPresentation(
    /** The proof systems this device can prove with, in preference order. */
    val registry: ZkProofSystemRegistry,
    /**
     * Where the proof systems keep their loaded prover, if they share one -
     * [standard] gives them one. Null when the systems were assembled by the
     * caller without a shared residency; [releaseProvers] is then a no-op
     * and residency is whatever each system does on its own.
     */
    private val residency: ZkProverResidency? = null,
) {

    /**
     * Drops the resident prover (a decompressed circuit or prover key, 100+
     * MB of native memory). Call when the host loses the foreground; the next
     * proof reloads from the on-device cache. Safe from any thread and while
     * a proof is running - that proof completes first.
     */
    fun releaseProvers() {
        residency?.release()
    }

    /** Identifiers of every proof system available here - what a host advertises as its ZK capability. */
    val systemIds: List<String> get() = registry.systemIds

    /**
     * One ZK presentation request. [requestedClaims] are element
     * identifiers within the credential's (single) namespace, and MUST
     * already include [LongfellowZkProofSystem.PSEUDONYM_CLAIM] when a
     * pairwise pseudonym is wanted - a circuit is compiled for a fixed
     * attribute count and the requested systems are matched against
     * `requestedClaims.size`, so the pseudonym slot has to be counted.
     * [verifierIdentity] is non-null only in that case: passing one
     * unconditionally makes the prover add and disclose the pseudonym even
     * when nobody asked (see [ZkProofSystem.generateProof]).
     */
    data class Request(
        /** The stored credential bytes, as the wallet persists them (`DeviceResponse{documents:[{docType, issuerSigned}]}`). */
        val credentialBytes: ByteArray,
        /** The verifier's `zk_system_type` list, in its order of preference. */
        val requestedSystems: List<ZkSystemSpec>,
        /** The ISO 18013-5 / OpenID4VP SessionTranscript the proof is bound to - see [MdocDeviceResponseBuilder]'s builders. */
        val sessionTranscript: ByteArray,
        val requestedClaims: List<String>,
        val verifierIdentity: VerifierIdentity? = null,
        /** Prover state carried from a previous presentation, for systems that keep one (see [ZkProofResult.nextState]). */
        val priorState: ByteArray? = null,
    )

    /** What a presentation produced, with enough about how for a caller to record it. */
    class Result(
        /** The ZK DeviceResponse CBOR - a complete `vp_token` entry once base64url-encoded. */
        val deviceResponse: ByteArray,
        val docType: String,
        val system: ZkProofSystem,
        val spec: ZkSystemSpec,
        val proof: ZkProofResult,
    )

    /** No registered proof system can satisfy the request. */
    class NoMatchingProofSystem(val docType: String) : Exception(
        "No registered ZK proof system satisfies the verifier's zk_system_type for $docType",
    )

    /**
     * The proof system and spec that would serve [docType] with
     * [requestedSystems] disclosing [numClaims] attributes, or null. Cheap
     * and side-effect free - a host can decide eligibility with it before
     * committing to a proof.
     */
    fun resolve(docType: String, requestedSystems: List<ZkSystemSpec>, numClaims: Int): Pair<ZkProofSystem, ZkSystemSpec>? =
        registry.resolve(CredentialTypeRef(CredentialFormat.MSO_MDOC, docType), requestedSystems, numClaims)

    /** [resolve] on the credential's own docType. */
    fun resolve(request: Request): Pair<ZkProofSystem, ZkSystemSpec>? =
        resolve(MdocCbor.parseStoredCredential(request.credentialBytes).docType, request.requestedSystems, request.requestedClaims.size)

    /**
     * Runs the resolved system's own precompute ahead of a real [present]
     * call, if (and only if) it resolves to [VegaProofSystem] - a no-op for
     * any other system, including a request that doesn't resolve to a
     * registered system at all (this is a speculative optimization, not a
     * correctness-bearing step; [present] still works without ever calling
     * this). See [VegaProofSystem.prewarm]'s own doc comment for when a
     * host should call this: as soon as a verifier's request names its
     * `zk_system_type`/claims (e.g. right after a QR scan, or at credential
     * issuance time for whichever disclosure combination a host already
     * expects to need), rather than waiting for the live `present()` call
     * that would otherwise run this same work in the user-visible path.
     */
    suspend fun prewarmVega(request: Request) {
        val docType = MdocCbor.parseStoredCredential(request.credentialBytes).docType
        val (system, spec) = resolve(docType, request.requestedSystems, request.requestedClaims.size) ?: return
        if (system is VegaProofSystem) {
            system.prewarm(spec, CredentialDocument.Mdoc(request.credentialBytes), request.requestedClaims)
        }
    }

    /**
     * Resolve, prove, and assemble. Multi-second native compute; callers
     * that show progress should signal it before calling.
     *
     * @throws NoMatchingProofSystem when nothing registered can serve the request.
     */
    suspend fun present(request: Request, signer: ZkWitnessSigner): Result {
        val docType = MdocCbor.parseStoredCredential(request.credentialBytes).docType
        val (system, spec) = resolve(docType, request.requestedSystems, request.requestedClaims.size)
            ?: throw NoMatchingProofSystem(docType)
        val proof = system.generateProof(
            spec = spec,
            document = CredentialDocument.Mdoc(request.credentialBytes),
            sessionTranscript = request.sessionTranscript,
            requestedClaims = request.requestedClaims,
            verifierIdentity = request.verifierIdentity,
            signer = signer,
            priorState = request.priorState,
        )
        val deviceResponse = buildDeviceResponse(
            credentialBytes = request.credentialBytes,
            docType = docType,
            spec = spec,
            disclosedClaimNames = request.requestedClaims,
            result = proof,
        )
        return Result(deviceResponse, docType, system, spec, proof)
    }

    /**
     * Wraps a raw ZK [result] into the full `{version, status, zkDocuments:
     * [...]}` DeviceResponse-shaped CBOR structure multipaz's own
     * `DeviceResponseParser` requires (confirmed via direct source read -
     * see [MdocDeviceResponseBuilder.buildZkDeviceResponse]'s doc comment).
     * Bare [result].proofBytes alone is not a valid `vp_token` entry - a
     * verifier that understands this format silently shows nothing for one,
     * since its parser never finds a `documents` or `zkDocuments` key at all.
     *
     * Public so a host that runs the prover itself (or replays a stored
     * proof) can still produce a well-formed response; [present] is the
     * ordinary route.
     */
    fun buildDeviceResponse(
        credentialBytes: ByteArray,
        docType: String,
        spec: ZkSystemSpec,
        disclosedClaimNames: List<String>,
        result: ZkProofResult,
    ): ByteArray {
        val document = MdocCbor.parseStoredCredential(credentialBytes)
        val namespace = document.issuerSigned.nameSpaces.keys.firstOrNull()
            ?: error("mdoc credential '$docType' has no disclosed namespaces")
        val storedItems = document.issuerSigned.nameSpaces[namespace].orEmpty()

        val disclosedClaims = linkedMapOf<String, CBORObject>()
        val digestIds = linkedMapOf<String, UInt>()
        val issuerSignedItemBytes = linkedMapOf<String, ByteArray>()
        disclosedClaimNames.forEach { claimName ->
            if (claimName == LongfellowZkProofSystem.PSEUDONYM_CLAIM) {
                result.pseudonym?.let {
                    disclosedClaims[claimName] = CBORObject.FromObject(it)
                }
            } else {
                storedItems.firstOrNull { it.item.elementIdentifier == claimName }?.let {
                    disclosedClaims[claimName] = it.item.elementValue
                    digestIds[claimName] = it.item.digestId.toUInt()
                    issuerSignedItemBytes[claimName] = it.original.EncodeToBytes()
                }
            }
        }

        // Vega-only (see MdocDeviceResponseBuilder.buildZkDeviceResponse's
        // doc comment on claimSlotDigestIds): storedItems is already in the
        // credential's own document order - the same order
        // VegaProofSystem.buildWitness assigns to FfiClaim slots - so its
        // digestIds, in this order, ARE the verifier-facing slot list.
        val claimSlotDigestIds = if (spec.system == VegaProofSystem.SYSTEM_ID) {
            storedItems.map { it.item.digestId.toUInt() }
        } else {
            null
        }

        return MdocDeviceResponseBuilder.buildZkDeviceResponse(
            proofBytes = result.proofBytes,
            zkSystemId = spec.id,
            docType = docType,
            timestamp = result.timestamp,
            namespace = namespace,
            disclosedClaims = disclosedClaims,
            issuerAuth = document.issuerSigned.issuerAuth,
            digestIds = digestIds,
            issuerSignedItemBytes = issuerSignedItemBytes,
            claimSlotDigestIds = claimSlotDigestIds,
        )
    }

    companion object {
        /**
         * The mdoc proof systems every SIROS wallet ships - Longfellow and
         * Vega - over one circuit client and one shared [ZkProverResidency].
         * BBS is not an mdoc system and is registered by the wallet
         * separately, where its holder state lives.
         */
        fun standard(
            circuitClient: ZkCircuitClient,
            extra: List<ZkProofSystem> = emptyList(),
            /** See [org.siros.sdk.wallet.WalletConfig.vegaProfilingEnabled]'s doc comment. Null (default) collects no profiling data. */
            vegaProfilingSink: VegaProfilingSink? = null,
        ): ZkMdocPresentation {
            // One residency for both systems: whichever proves next evicts
            // the other's prover, so the process holds one at a time.
            val residency = ZkProverResidency()
            return ZkMdocPresentation(
                ZkProofSystemRegistry(
                    listOf(
                        LongfellowZkProofSystem(circuitClient, residency = residency),
                        VegaProofSystem(circuitClient, residency = residency, profilingSink = vegaProfilingSink),
                    ) + extra,
                ),
                residency = residency,
            )
        }
    }
}
