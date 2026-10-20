// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.nio.ByteBuffer
import java.time.Clock
import kotlinx.serialization.json.JsonObject
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import timber.log.Timber

/**
 * The proving ABI of the `nymauth-*` circuits, as the circuit authors define it (`SPEC.md` of their
 * `nym-auth-circuits` archive: §3 and §L3-L6 for Longfellow, §V3-V5 for Vega): one narrow call that takes
 * the verified circuit bytes and the already-assembled inputs and returns the proof and the pseudonym.
 *
 * This is the seam where native code is needed and none is shipped yet: the vendored `zk_cred_longfellow`
 * and `zk_cred_vega` bindings expose the generic mdoc/age circuits only, with no entry point that builds the
 * nymauth witnesses (Longfellow's hash-circuit semantic bits and signature-circuit ECDSA trace, Vega's table
 * and core witness) or runs the two-circuit / multi-circuit proof. The circuit authors' reference
 * implementations (`longfellow/reference`, `vega/reference`) are Rust. Until a binding implements this
 * interface the [NymAuthCircuitZkAdapter] refuses every request; it never substitutes another proof.
 *
 * An implementation must not log or retain any argument: [NymAuthProveRequest.secretSeed] is the issuer-delivered
 * seed and the circuit input is private.
 */
fun interface NymAuthNativeProver {
    /**
     * Proves [request]; any failure is an exception, which [CatalogCircuitZkProver] turns into a refusal. A failure of
     * the binding itself is a [NymAuthNativeException].
     */
    suspend fun prove(request: NymAuthProveRequest): NymAuthProveResponse
}

/**
 * An optional extension of [NymAuthNativeProver] for a prover that keeps native state resident between proofs (Vega's
 * keys and Longfellow's loaded circuits are hundreds of MB): the adapter tells it when to let go.
 */
interface ResidentNymAuthNativeProver : NymAuthNativeProver {
    /** Drops the resident native state (memory pressure, the host leaving the foreground). Never throws. */
    fun release()

    /** Drops the resident native state if it belongs to the circuit [circuitId] (a retired one). Never throws. */
    fun releaseCircuit(circuitId: String)
}

/** The coarse reason a native prover refused to make a proof (never the broken rule, never a value). */
enum class NymAuthRefusal { SEED_MISMATCH, ISSUER_SIGNATURE, DEVICE_SIGNATURE, CREDENTIAL, UNSATISFIED }

/** The kinds of failure a native nymauth binding reports: a superset of the Vega and the Longfellow error types. */
enum class NymAuthNativeErrorKind {
    /** An argument has the wrong size, format or range (Vega `InvalidInput`, Longfellow `InvalidInput`). */
    INVALID_INPUT,

    /** The circuit artifact is malformed or past its budget (Vega `InvalidShapes`, Longfellow `Circuit`). */
    INVALID_CIRCUIT,

    /**
     * The circuit is well formed but not one this build knows (Vega `UnknownCircuit`, whose message is the shapes'
     * digest; Longfellow `UnsupportedCircuit`): this app version does not support this circuit build.
     */
    UNSUPPORTED_CIRCUIT,

    /** The inputs break a rule; see [NymAuthRefusal] (Vega `Refused{code}`, Longfellow `Credential` and `Unsatisfied`). */
    REFUSED,

    /** The prover failed (Vega `ProverFailed`, Longfellow `Prover`). */
    PROVER_FAILED,

    /** The proof does not verify (Vega `ProofInvalid`, Longfellow `Verification`). */
    PROOF_INVALID,

    /** The proof verifies, but not for the named values (Vega `Mismatch`). */
    MISMATCH,

    /** A bug in the binding (Vega `Internal`, a caught panic). */
    INTERNAL,
}

/**
 * What a [NymAuthNativeProver] throws for a failure of the binding. It carries a [kind] and, for [NymAuthNativeErrorKind.REFUSED],
 * a coarse [refusal], and NO message: the bindings' own messages can hold a circuit digest or a rule, and
 * nothing of them is kept. A binding's glue maps its own error type here (see [vega] and [longfellow]).
 */
class NymAuthNativeException(val kind: NymAuthNativeErrorKind, val refusal: NymAuthRefusal? = null) :
    Exception("nymauth native prover: $kind" + (refusal?.let { " ($it)" } ?: "")) {

    companion object {
        /** The Vega binding's error by variant name and, for `Refused`, its coarse `code` (`SeedMismatch`, ...). */
        fun vega(variant: String, refusedCode: String? = null): NymAuthNativeException = when (variant) {
            "InvalidInput" -> NymAuthNativeException(NymAuthNativeErrorKind.INVALID_INPUT)
            "InvalidShapes" -> NymAuthNativeException(NymAuthNativeErrorKind.INVALID_CIRCUIT)
            "UnknownCircuit" -> NymAuthNativeException(NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT)
            "Refused" -> NymAuthNativeException(NymAuthNativeErrorKind.REFUSED, refusalOf(refusedCode))
            "ProverFailed" -> NymAuthNativeException(NymAuthNativeErrorKind.PROVER_FAILED)
            "ProofInvalid" -> NymAuthNativeException(NymAuthNativeErrorKind.PROOF_INVALID)
            "Mismatch" -> NymAuthNativeException(NymAuthNativeErrorKind.MISMATCH)
            else -> NymAuthNativeException(NymAuthNativeErrorKind.INTERNAL)
        }

        /** The Longfellow binding's `NymAuthError` by variant name. */
        fun longfellow(variant: String): NymAuthNativeException = when (variant) {
            "InvalidInput" -> NymAuthNativeException(NymAuthNativeErrorKind.INVALID_INPUT)
            "Circuit" -> NymAuthNativeException(NymAuthNativeErrorKind.INVALID_CIRCUIT)
            "UnsupportedCircuit" -> NymAuthNativeException(NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT)
            "Credential" -> NymAuthNativeException(NymAuthNativeErrorKind.REFUSED, NymAuthRefusal.CREDENTIAL)
            "Unsatisfied" -> NymAuthNativeException(NymAuthNativeErrorKind.REFUSED, NymAuthRefusal.UNSATISFIED)
            "Prover" -> NymAuthNativeException(NymAuthNativeErrorKind.PROVER_FAILED)
            "Verification" -> NymAuthNativeException(NymAuthNativeErrorKind.PROOF_INVALID)
            else -> NymAuthNativeException(NymAuthNativeErrorKind.INTERNAL)
        }

        private fun refusalOf(code: String?) = when (code) {
            "SeedMismatch" -> NymAuthRefusal.SEED_MISMATCH
            "IssuerSignature" -> NymAuthRefusal.ISSUER_SIGNATURE
            "DeviceSignature" -> NymAuthRefusal.DEVICE_SIGNATURE
            "Credential" -> NymAuthRefusal.CREDENTIAL
            // A code this build does not know is still a refusal; it is not guessed at.
            else -> NymAuthRefusal.UNSATISFIED
        }
    }
}

/**
 * What [NymAuthNativeProver.prove] receives. Everything here is derived by the SDK from the stored
 * credential, the verifier's request and the device signer; the native side does not parse the request.
 *
 * @property system The catalog `system` of the circuit: [NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM] or
 *   [NymAuthCircuitZkAdapter.VEGA_SYSTEM].
 * @property circuitParams The catalog descriptor's `params` (Longfellow: `block_enc_hash`, `block_enc_sig`,
 *   `hash_circuit_id`, `sig_circuit_id`), verbatim.
 * @property circuit The decompressed circuit artifact, its hash verified against the catalog (Longfellow:
 *   the two LFC2 circuits, signature then hash; Vega: the bincode `(STEP, CORE)` shapes, from which the native
 *   side derives its keys). Read-only; do not retain it past the call.
 * @property issuerSigned The credential's `IssuerSigned` structure as CBOR.
 * @property secretSeed The 16-byte issuer-delivered `secret_seed`, already checked against `ssc`.
 * @property issuerKeyX Big-endian x of the issuer key Q (the `x5chain` leaf), 32 bytes.
 * @property time `T`: `YYYY-MM-DDThh:mm:ssZ`, 20 ASCII characters.
 * @property earliest `E`: `YYYY-MM-DD`, `0000-00-00` for no lower bound.
 * @property cutoff `C`: `YYYY-MM-DD`, `9999-12-31` for no upper bound.
 * @property challengeDigest `e2`: SHA-256 of the COSE `Signature1` message the device key signed.
 * @property deviceSignature The device key's ES256 signature on that message, `r || s`, 64 bytes.
 * @property verifierInput `SHA-256(verifier_id)`, 32 bytes.
 * @property transcriptSeed The SessionTranscript the proof is bound to (Longfellow's Fiat-Shamir seed).
 */
class NymAuthProveRequest(
    val system: String,
    val circuitId: String,
    /** The catalog artifact hash the [circuit] bytes were verified against: with [circuitId], what a resident native state is keyed by. */
    val artifactHash: String,
    val circuitParams: JsonObject,
    val circuit: ByteBuffer,
    val issuerSigned: ByteArray,
    val secretSeed: ByteArray,
    val issuerKeyX: ByteArray,
    val issuerKeyY: ByteArray,
    val time: String,
    val earliest: String,
    val cutoff: String,
    val challengeDigest: ByteArray,
    val deviceSignature: ByteArray,
    val verifierInput: ByteArray,
    val transcriptSeed: ByteArray,
) {
    override fun toString() = "NymAuthProveRequest(redacted)"
}

/** What [NymAuthNativeProver.prove] returns: the proof bytes as the circuit's own verifier reads them, and the pseudonym it reports. */
class NymAuthProveResponse(val proof: ByteArray, val pseudonym: ByteArray) {
    override fun toString() = "NymAuthProveResponse(redacted)"
}


/**
 * The real [CircuitZkProver]: proves a `circuit_zk` request with the circuit of the go-zk-circuits catalog it
 * names, through the [CircuitZkSystemAdapter] registered for that circuit's (system, systemVersion).
 *
 * The dispatcher itself only does what is common to every system, refusing (an [CircuitZkError.AccessDenied],
 * never a fallback to the fake prover, never a default adapter) at the first thing that fails:
 * 1. the catalog descriptor is fetched and must be the circuit the presenter chose, published, `active` and
 *    not deprecated;
 * 2. its (system, systemVersion) must be claimed by an adapter in [registry]: an unknown system, or a known
 *    one at a version nobody has vetted, is refused;
 * 3. the adapter proves; see [NymAuthCircuitZkAdapter] (the `nymauth-*` circuits, behind the native seam) and
 *    [LegacyZkCircuitZkAdapter] (Longfellow and Vega-mc, through the shared proof systems).
 *
 * [admits] lets the presenter choose among circuits only those an adapter can serve for the plan.
 */
class CatalogCircuitZkProver(
    private val circuitClient: ZkCircuitClient,
    private val registry: CircuitZkSystemRegistry,
) : CircuitZkProver {

    /** The nymauth adapter alone, with [native] as its seam; the legacy systems are not reachable. */
    constructor(
        circuitClient: ZkCircuitClient,
        native: NymAuthNativeProver?,
        residency: ZkProverResidency = ZkProverResidency(),
        clock: Clock = Clock.systemUTC(),
        decompress: (ByteArray, ZkCircuitDescriptor) -> ByteBuffer = ::decompressZkCircuitArtifact,
    ) : this(
        circuitClient,
        CircuitZkSystemRegistry(listOf(NymAuthCircuitZkAdapter(circuitClient, native, residency, clock, decompress))),
    )

    /**
     * The circuits of a catalog manifest as this prover can serve them: legacy entries that declare no
     * functions get the ones their adapter claims (everything else is offered for no plan).
     */
    fun circuitsOf(manifest: org.siros.sdk.credentials.ZkManifest): List<CircuitZkCircuit> =
        org.siros.sdk.credentials.CircuitZkCircuitSource.fromManifest(manifest, registry::declaredFunctions)

    /** What a catalog-backed circuit table should declare for [descriptor]: the functions its adapter claims it for (null: none). */
    fun declaredFunctions(descriptor: ZkCircuitDescriptor): Set<String>? = registry.declaredFunctions(descriptor)

    /** Whether some adapter can produce a proof; false means every request is refused. */
    val canProve: Boolean get() = registry.canProve

    /** A catalog refresh retired [descriptor]'s circuit: drop what is resident for it (see [ZkCircuitCatalogRefresher]). */
    suspend fun onCircuitRetired(descriptor: ZkCircuitDescriptor) {
        registry.retire(descriptor)
    }

    /** Drops every adapter's resident prover memory. */
    fun releaseProvers() {
        registry.release()
    }

    override fun admits(circuit: CircuitZkCircuit, plan: CircuitZkPlan): Boolean = registry.admits(circuit, plan)

    override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
        try {
            return proveInternal(input)
        } catch (e: CircuitZkError) {
            throw e
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Throwable) {
            // Throwable, not Exception: an OutOfMemoryError from a hostile artifact or an UnsatisfiedLinkError from a
            // missing native library is a refusal, not a crash of the host.
            Timber.w("circuit_zk: proving failed (${e.javaClass.simpleName}); refusing")
            throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
        }
    }

    private suspend fun proveInternal(input: CircuitZkProveInput): CircuitZkProveOutput {
        val circuit = input.circuit
        // NOTE: the proof time is the wallet's clock and is not bounded here; the verifier enforces the tolerance it
        // accepts on proof_time. A wallet-side sanity window (or a trusted time source) is deferred.
        val descriptor = circuitClient.fetchCircuit(circuit.circuitId) ?: run {
            Timber.w("circuit_zk: no catalog descriptor for the chosen circuit; refusing")
            throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
        }
        val current = descriptor.id == circuit.circuitId && descriptor.system == circuit.system &&
            (circuit.systemVersion == null || circuit.systemVersion == descriptor.systemVersion) &&
            descriptor.published && descriptor.deprecatedAt == null && descriptor.status == "active"
        val adapter = if (current) registry.adapterFor(descriptor.system, descriptor.systemVersion) else null
        if (adapter == null) {
            Timber.w("circuit_zk: no adapter for the chosen circuit's system or it is not an active circuit; refusing")
            throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
        }
        return adapter.prove(descriptor, input)
    }

    companion object {
        /**
         * The standard registry: the nymauth circuits behind [native] and the legacy Longfellow and Vega-mc
         * circuits through [presentation], all sharing [presentation]'s residency when it has one.
         */
        fun standard(
            circuitClient: ZkCircuitClient,
            presentation: ZkMdocPresentation,
            native: NymAuthNativeProver? = null,
            clock: Clock = Clock.systemUTC(),
        ): CatalogCircuitZkProver = CatalogCircuitZkProver(
            circuitClient,
            CircuitZkSystemRegistry(
                listOf(
                    NymAuthCircuitZkAdapter(circuitClient, native, presentation.proverResidency ?: ZkProverResidency(), clock),
                    LegacyZkCircuitZkAdapter(presentation),
                ),
            ),
        )
    }
}
