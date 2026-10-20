// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.siros.sdk.credentials.COSE_ALG_ES256
import org.siros.sdk.credentials.CredentialDocument
import org.siros.sdk.credentials.CredentialFormat
import org.siros.sdk.credentials.CredentialTypeRef
import org.siros.sdk.credentials.DefaultZkPseudonymDeriver
import org.siros.sdk.credentials.VerifierIdentity
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import org.siros.sdk.credentials.ZkProofResult
import org.siros.sdk.credentials.ZkProofSystem
import org.siros.sdk.credentials.ZkPseudonymDeriver
import org.siros.sdk.credentials.ZkSystemSpec
import org.siros.sdk.credentials.ZkWitnessSigner
import org.siros.sdk.credentials.PseudonymOutcome
import org.siros.sdk.credentials.mdoc.MdocCbor
import uniffi.zk_cred_longfellow.CircuitVersion
import uniffi.zk_cred_longfellow.MdocZkProver
import uniffi.zk_cred_longfellow.initializeProver
import uniffi.zk_cred_longfellow.prove
import uniffi.zk_cred_longfellow.proveWithPpid
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Instant

/**
 * [ZkProofSystem] implementation wrapping the `zk-cred-longfellow` native
 * crate (V8 circuit + PPID support - see
 * `~/.claude/plans/silver-drifting-heron.md` for the full design/provenance
 * history). Fetches circuits on demand from [zkCircuitClient] (Phase 1),
 * caches initialized [MdocZkProver] instances per (circuit id, attribute
 * count) since circuit loading is expensive, and derives pseudonyms via
 * [pseudonymDeriver] (defaults to the real spec-faithful formula).
 *
 * **How the witness DeviceResponse is built** (confirmed 2026-08-14 via
 * `wallet-frontend`'s `feat/longfellow-zk` reference implementation
 * (`MdocProverService.ts`) and the crate's own `parse_device_response`):
 * the native prover needs a REAL, fully-signed DeviceResponse - the ZK proof
 * proves knowledge of a valid device signature, it doesn't replace the
 * signing mechanism. This is built locally via [MdocDeviceResponseBuilder]
 * (the exact same builder every non-ZK presentation already uses) with
 * `disclosedClaims = null` (full disclosure) since these bytes are a
 * private witness never transmitted to the verifier - the circuit itself
 * selects which claims [ZkProofSystem.generateProof]'s `requestedClaims`
 * actually reveals in the proof.
 */
class LongfellowZkProofSystem(
    private val zkCircuitClient: ZkCircuitClient,
    private val pseudonymDeriver: ZkPseudonymDeriver = DefaultZkPseudonymDeriver,
    /** Where loaded provers live; share one across proof systems so the process holds one at a time. */
    private val residency: ZkProverResidency = ZkProverResidency(),
) : ZkProofSystem {

    companion object {
        /**
         * Included in `requestedClaims` (and thus asserted/disclosed by the
         * proof) whenever a pseudonym is requested - confirmed via the
         * `feat/longfellow-zk` reference implementation, which always lists
         * it alongside real disclosed claims (e.g. `["age_over_18",
         * "pairwise_pseudonym"]`), not as a separate side-channel-only
         * concept the circuit is unaware of.
         */
        const val PSEUDONYM_CLAIM = "pairwise_pseudonym"

        /**
         * The actual mdoc namespace element that holds the raw seed value
         * (`PSEUDONYM_CLAIM` is the DERIVED/requested claim name a verifier
         * asks for in DCQL - it is never itself a stored element in the
         * credential). Confirmed live: looking this up by [PSEUDONYM_CLAIM]
         * instead of this constant always failed to find the item, leaving
         * [generateProof]'s own pseudonym derivation permanently unreachable
         * (pseudonymOutcome always NOT_SUPPORTED_BY_SYSTEM, regardless of
         * whether the proof itself succeeded).
         */
        private const val PSEUDONYM_SEED_ELEMENT = "pseudonym_seed"
    }

    override val systemId: String = "longfellow-libzk-v1"

    // mdoc only: this system proves over a DeviceResponse, and its native
    // prover parses CBOR. Declaring the format explicitly is what keeps an
    // SD-JWT VC or JWP credential of the same type from being routed here.
    override val supportedCredentialTypes: Set<CredentialTypeRef> = setOf(
        CredentialTypeRef(CredentialFormat.MSO_MDOC, "org.iso.18013.5.1.mDL"),
        CredentialTypeRef(CredentialFormat.MSO_MDOC, "eu.europa.ec.eudi.pid.1"),
    )

    /**
     * Residency key: (circuit id, attribute count) - a circuit is compiled
     * for a FIXED number of attributes (e.g. `..._8_2_...` proves exactly 2),
     * so two requests against the same circuit id but different claim counts
     * are genuinely different prover instances, not the same resident one.
     */
    private fun residencyKey(spec: ZkSystemSpec, numAttributes: Int) = "$systemId:${spec.id}:$numAttributes"

    /**
     * Matches any requested spec declaring `system == "longfellow-libzk-v1"`
     * (this system's own [systemId] - confirmed live against
     * multipaz-verifier-server's actual DCQL `zk_system_type` output, which
     * sends `"system": "longfellow-libzk-v1"`, not the shorter `"longfellow"`
     * this comparison incorrectly used before - a real bug, unit-tested only
     * against our own self-consistent test fixtures, never against the real
     * wire value, so it went unnoticed until a live device presentation)
     * AND whose own `num_attributes` param equals [numAttributes] - see
     * [ZkProofSystem.matchingSpec]'s doc comment for why a circuit's
     * attribute count is fixed at compile time and can't be ignored.
     * Mirrors [org.siros.sdk.wallet.WscdSelectionPolicy]'s "nominal
     * capability" convention (a static declaration, not a live probe):
     * whether the specific circuit [ZkSystemSpec.id] names is actually
     * fetchable is only verified lazily, in [generateProof] - `matchingSpec`
     * itself can't do network I/O (it's a plain, synchronous function, used
     * during request-vs-capability matching before any proof generation is
     * committed to).
     */
    override fun matchingSpec(requestedSpecs: List<ZkSystemSpec>, numAttributes: Int): ZkSystemSpec? =
        requestedSpecs.firstOrNull {
            it.system == systemId && it.getParam("num_attributes")?.toIntOrNull() == numAttributes
        }

    /**
     * The vendored UniFFI bindings' `&[u8]` parameters need a DIRECT
     * `ByteBuffer` - `ByteBuffer.wrap(byteArray)` produces a heap-backed
     * buffer with no stable native address, which throws
     * `IllegalArgumentException("UniFFI zero-copy &[u8] requires a direct
     * ByteBuffer")` at the JNI boundary. Confirmed via a real androidTest
     * run on a Pixel - this only surfaces on-device (JVM unit tests can't
     * load the native library at all, so they never reach this check).
     */
    private fun directByteBuffer(bytes: ByteArray): ByteBuffer =
        ByteBuffer.allocateDirect(bytes.size).put(bytes).apply { flip() }

    override suspend fun generateProof(
        spec: ZkSystemSpec,
        document: CredentialDocument,
        sessionTranscript: ByteArray,
        requestedClaims: List<String>,
        verifierIdentity: VerifierIdentity?,
        signer: ZkWitnessSigner,
        priorState: ByteArray?,
    ): ZkProofResult {
        val effectiveClaims = if (verifierIdentity != null && PSEUDONYM_CLAIM !in requestedClaims) {
            requestedClaims + PSEUDONYM_CLAIM
        } else {
            requestedClaims
        }

        // Reject rather than assume: a caller bypassing the registry could
        // hand us a format whose bytes are not a DeviceResponse at all, and
        // the native prover's failure would say nothing useful.
        val credentialBytes = (document as? CredentialDocument.Mdoc)?.bytes
            ?: throw IllegalArgumentException(
                "$systemId proves over mdoc only, got ${document::class.simpleName}"
            )
        val mdoc = MdocCbor.parseStoredCredential(credentialBytes)
        val namespace = mdoc.issuerSigned.nameSpaces.keys.firstOrNull()
            ?: error("mdoc credential '${mdoc.docType}' has no disclosed namespaces")

        return residency.use(
            key = residencyKey(spec, effectiveClaims.size),
            load = { loadProver(spec, effectiveClaims.size) },
        ) { prover ->
            // Private witness only - see this class's doc comment for why this
            // must be a REAL, fully-signed DeviceResponse, and why it's built
            // with full disclosure rather than pre-filtered to requestedClaims.
            // buildForProximity is transport-agnostic despite its name: it just
            // takes a pre-computed session transcript directly, which is exactly
            // what's needed here regardless of which real transport the caller
            // is presenting over.
            val witnessDeviceResponse = MdocDeviceResponseBuilder(credentialBytes)
                .buildPrivateWitnessResponse(
                    sessionTranscript,
                    signer = { data -> signer.sign(COSE_ALG_ES256, data) },
                )

            // The native prover requires an exact 20-byte RFC 3339 timestamp
            // ("YYYY-MM-DDTHH:MM:SSZ", no fractional seconds) - confirmed live
            // ("current time is not correctly formatted, must be 20 bytes
            // long"). Instant.now().toString() includes a variable-precision
            // fractional-seconds component whenever it's non-zero, so it's
            // rarely exactly 20 bytes. Truncating to whole seconds first makes
            // Instant.toString() omit the fractional part entirely, always
            // producing the fixed-width form the prover expects.
            val time = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString()

            // prove/proveWithPpid are synchronous, CPU-bound native calls -
            // running them on whatever dispatcher the caller happens to be on
            // (often Dispatchers.Main for a UI-triggered presentation flow)
            // blocks the UI thread for their full duration, freezing any
            // in-progress animation (e.g. a spinner). See VegaProofSystem's
            // identical fix/comment for the same reasoning.
            if (verifierIdentity == null) {
                val proofBytes = withContext(Dispatchers.Default) {
                    prove(
                        prover = prover,
                        deviceResponse = directByteBuffer(witnessDeviceResponse),
                        namespace = namespace,
                        requestedClaims = effectiveClaims,
                        sessionTranscript = directByteBuffer(sessionTranscript),
                        time = time,
                    )
                }
                return@use ZkProofResult(proofBytes = proofBytes, timestamp = time)
            }

            val verifierContext = pseudonymDeriver.deriveVerifierContext(verifierIdentity)
            val proofBytes = withContext(Dispatchers.Default) {
                proveWithPpid(
                    prover = prover,
                    deviceResponse = directByteBuffer(witnessDeviceResponse),
                    namespace = namespace,
                    requestedClaims = effectiveClaims,
                    sessionTranscript = directByteBuffer(sessionTranscript),
                    time = time,
                    verifierContext = directByteBuffer(verifierContext),
                )
            }

            // The native API returns only proof bytes - the pseudonym itself
            // (SHA256(pseudonym_seed || verifier_context), the same formula the
            // circuit itself asserts) is computed locally so the caller can
            // display/track it, mirroring the feat/longfellow-zk reference's own
            // separate computePPID() step.
            val seedItem = mdoc.issuerSigned.nameSpaces[namespace]
                ?.firstOrNull { it.item.elementIdentifier == PSEUDONYM_SEED_ELEMENT }
            val pseudonym = seedItem?.let { sha256(it.item.elementValue.GetByteString() + verifierContext) }

            return@use ZkProofResult(
                proofBytes = proofBytes,
                pseudonym = pseudonym,
                pseudonymOutcome = if (pseudonym != null) PseudonymOutcome.PROVIDED else PseudonymOutcome.NOT_SUPPORTED_BY_SYSTEM,
                timestamp = time,
            )
        }
    }

    private suspend fun loadProver(spec: ZkSystemSpec, numAttributes: Int): MdocZkProver {
        val descriptor = zkCircuitClient.fetchCircuit(spec.id)
            ?: error("Longfellow circuit '${spec.id}' not found in any configured zk-circuits source")
        val compressedBytes = zkCircuitClient.downloadArtifact(descriptor)
        val circuitBuffer = decompressZkCircuitArtifact(compressedBytes, descriptor)
        val circuitVersion = circuitVersionOf(descriptor)
        return initializeProver(
            circuit = circuitBuffer,
            circuitVersion = circuitVersion,
            numAttributes = numAttributes.toUByte(),
        )
    }

    private fun circuitVersionOf(descriptor: ZkCircuitDescriptor): CircuitVersion =
        when (descriptor.systemVersion) {
            "6" -> CircuitVersion.V6
            "7" -> CircuitVersion.V7
            "8" -> CircuitVersion.V8
            else -> error("Longfellow circuit '${descriptor.id}' has unsupported systemVersion '${descriptor.systemVersion}'")
        }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
}
