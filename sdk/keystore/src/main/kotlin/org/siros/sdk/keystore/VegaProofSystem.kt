// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.jsonPrimitive
import org.siros.sdk.credentials.CredentialDocument
import org.siros.sdk.credentials.CredentialFormat
import org.siros.sdk.credentials.CredentialTypeRef
import org.siros.sdk.credentials.PseudonymOutcome
import org.siros.sdk.credentials.VerifierIdentity
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import org.siros.sdk.credentials.ZkProofResult
import org.siros.sdk.credentials.ZkProofSystem
import org.siros.sdk.credentials.ZkSystemSpec
import org.siros.sdk.credentials.ZkWitnessSigner
import org.siros.sdk.credentials.mdoc.MdocCbor
import org.siros.sdk.keystore.mdoc.MdocCose
import timber.log.Timber
import uniffi.zk_cred_vega.FfiClaim
import uniffi.zk_cred_vega.FfiEcdsaWitness
import uniffi.zk_cred_vega.FfiMsoBodyWitness
import uniffi.zk_cred_vega.VegaProverKey
import uniffi.zk_cred_vega.prepProve
import uniffi.zk_cred_vega.prove
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * [ZkProofSystem] implementation wrapping the `zk-cred-vega` native crate -
 * see `~/.claude/plans/zk-cred-vega-sdk-handoff.md` for the full
 * design/provenance history and current crate status.
 *
 * **Do not present this to a real relying party yet.** `zk-cred-vega` is
 * public and tagged (`v0.0.5` as of the nonce/public-IO circuit revision), and
 * its own expert security review is running in parallel with SDK-side
 * testing rather than gating it - but that review hasn't landed, so nothing
 * here should be trusted as a real trust anchor yet. This class is for
 * early-testing end-to-end use (own prover verified by own verifier, plus
 * real wallet <-> verifier interop against `sirosfoundation/vc`), same
 * caveat Longfellow shipped under before its own multipaz interop testing.
 * The `go-zk-circuits` catalog's `vega-mc-p256-v1-{prover,verifier}-key-r12`
 * entries are published for early testing ([zkCircuitClient] can fetch them
 * directly), carrying the same "PUBLISHED FOR EARLY TESTING ONLY" notice.
 * Every earlier revision (r2 through r11) has since been unpublished or
 * revoked - see the go-zk-circuits catalog's own notes for why each one
 * was retired.
 *
 * `buildWitness` is real (ECDSA witness from `issuerAuth`'s x5chain +
 * signature, MSO body from `issuerAuth`'s payload, fixed 4-slot claim
 * selection) - see its own doc comment for the slot-selection policy this
 * session settled on. Everything else (the `prep_prove`/`prove` FFI wiring,
 * fold-and-reuse state threading, pseudonym handling) mirrors
 * [LongfellowZkProofSystem]'s own shape.
 */
class VegaProofSystem(
    private val zkCircuitClient: ZkCircuitClient,
    /** Where the loaded prover key lives; share one across proof systems so the process holds one prover at a time. */
    private val residency: ZkProverResidency = ZkProverResidency(),
    /** Caches `prep_prove` output per (credential, exact disclosure combination) - see [VegaProofCache]'s own doc comment. */
    private val proofCache: VegaProofCache = VegaProofCache(),
    /**
     * Optional structured timing sink - null (default, matching
     * [org.siros.sdk.wallet.WalletConfig.vegaProfilingEnabled]'s default)
     * collects no profiling data beyond the [Timber] log line this class
     * already emits. See [VegaProfilingEntry]/[VegaProfilingFileSink].
     */
    private val profilingSink: VegaProfilingSink? = null,
) : ZkProofSystem {

    companion object {
        /**
         * The circuit's fixed claim-slot count (`MAX_CLAIMS_V1` in the Rust
         * crate) - VEGA's v1 circuit is compiled for exactly this many claim
         * slots, unlike Longfellow's own per-attribute-count circuit
         * variants. A request for more claims than this can't be satisfied
         * by this system at all.
         */
        const val MAX_CLAIMS_V1 = 4

        /**
         * This system's [ZkSystemSpec.system] value - exposed so callers
         * outside this class (e.g. [MdocDeviceResponseBuilder]'s Vega-only
         * `claimSlotDigestIds` wire field) can identify a Vega presentation
         * without hardcoding the string a second time.
         */
        const val SYSTEM_ID = "vega-mc-p256-v1"

        /** COSE algorithm identifier for ES256 (RFC 8152 §8.1) - the only alg [buildEcdsaWitness] accepts. */
        private const val COSE_ALG_ES256 = -7L

        /** COSE_Key EC2 type-specific parameter labels (RFC 8152 §13.1.1). */
        private const val COSE_KEY_LABEL_X = -2L
        private const val COSE_KEY_LABEL_Y = -3L

        /** P-256 field-element/coordinate width in bytes. */
        private const val P256_COORDINATE_BYTES = 32

        /** P-256 (secp256r1) curve order `n`, per SEC 2 §2.4.2. */
        private val P256_ORDER = BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            16,
        )
    }

    override val systemId: String = SYSTEM_ID

    /**
     * The circuit itself is docType-agnostic (buildWitness just walks
     * whatever single namespace the mdoc has, with no docType-specific
     * logic) - the real constraint is [MAX_CLAIMS_V1]'s exact-4-elements
     * requirement, not docType. `eu.europa.ec.eudi.pid.1` is included
     * alongside the real mDL doctype because this stack's `pid_mdoc` scope
     * (fixtures/vc-config.yaml) already issues an exactly-4-claim mdoc
     * (family_name, given_name, age_over_18, pseudonym_seed) - a real,
     * already-issuable credential to test Vega end-to-end against, unlike
     * the full ISO 18013-5 mDL scope's 11+ mandatory claims. Mdoc-only, same
     * as Longfellow - VEGA's broader circuit ambitions (e.g. SD-JWT VC) are
     * a planned future circuit, not this one.
     */
    override val supportedCredentialTypes: Set<CredentialTypeRef> = setOf(
        CredentialTypeRef(CredentialFormat.MSO_MDOC, "org.iso.18013.5.1.mDL"),
        CredentialTypeRef(CredentialFormat.MSO_MDOC, "eu.europa.ec.eudi.pid.1"),
    )

    /** Residency key: circuit/spec id - a single prover key handle serves every presentation with that circuit. */
    private fun residencyKey(spec: ZkSystemSpec) = "$systemId:${spec.id}"

    /**
     * Runs [block] with this (coroutine worker) thread's priority temporarily
     * raised, restoring the prior value afterward regardless of how [block]
     * exits. `Dispatchers.Default`'s pooled threads run at the normal Linux
     * "nice" priority Android gives a background/non-UI thread by default -
     * on a big.LITTLE device, its energy-aware scheduler (EAS) keeps threads
     * at that priority off the big/performance cores entirely, even while
     * the app is the one the user is actively looking at. Measured on real
     * hardware (a Pixel 10a) with `zk-cred-vega`'s own `perf_profile_traced`
     * example, `taskset`-pinned: `prep_prove`/`prove` both run roughly 2.2x
     * slower confined to the small cores (`taskset -c 0-3`: 1.56s/2.73s)
     * than the big ones (`taskset -c 4-7`: 0.59s/1.24s) - and the small-core
     * numbers match this SDK's own in-app Timber-logged timings almost
     * exactly, meaning every real presentation has been paying this tax.
     * An app cannot set its own thread's CPU affinity directly (`sched_setaffinity`
     * is blocked for regular apps), but raising thread *priority* is
     * something EAS already uses as its own placement signal, and is the
     * standard Android technique for pulling a short-lived, latency-sensitive
     * background computation onto a big core (the same trick audio/camera
     * pipelines use) - this does not request realtime/FIFO scheduling, only
     * a priority hint, so it cannot starve the UI thread's own (separately
     * boosted) top-app scheduling.
     */
    private inline fun <T> withBoostedThreadPriority(block: () -> T): T {
        val tid = android.os.Process.myTid()
        val priorPriority = try {
            android.os.Process.getThreadPriority(tid)
        } catch (e: Exception) {
            Timber.d(e, "Could not read thread priority before ZK proving - leaving it alone")
            return block()
        }
        return try {
            android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_AUDIO)
            block()
        } finally {
            try {
                android.os.Process.setThreadPriority(tid, priorPriority)
            } catch (e: Exception) {
                Timber.w(e, "Could not restore ZK proving thread's prior priority ($priorPriority)")
            }
        }
    }

    /**
     * Matches any requested spec declaring `system == systemId` for a proof
     * over AT MOST [MAX_CLAIMS_V1] claims - unlike Longfellow's exact-match
     * requirement (a circuit compiled per attribute count), VEGA's circuit
     * is fixed-shape at [MAX_CLAIMS_V1] slots regardless of how many claims
     * a given presentation actually discloses (unused slots are filled from
     * the credential's own other elements, not left blank - see
     * [buildWitness]'s doc comment for why that's still an open question).
     */
    override fun matchingSpec(requestedSpecs: List<ZkSystemSpec>, numAttributes: Int): ZkSystemSpec? {
        if (numAttributes > MAX_CLAIMS_V1) return null
        return requestedSpecs.firstOrNull { it.system == systemId }
    }

    override suspend fun generateProof(
        spec: ZkSystemSpec,
        document: CredentialDocument,
        sessionTranscript: ByteArray,
        requestedClaims: List<String>,
        verifierIdentity: VerifierIdentity?,
        signer: ZkWitnessSigner,
        priorState: ByteArray?,
    ): ZkProofResult {
        val credentialBytes = (document as? CredentialDocument.Mdoc)?.bytes
            ?: throw IllegalArgumentException("$systemId proves over mdoc only, got ${document::class.simpleName}")
        val mdoc = MdocCbor.parseStoredCredential(credentialBytes)
        return residency.use(
            key = residencyKey(spec),
            load = { loadProverKey(spec) },
        ) { proverKey ->
            val (claims, ecdsaWitness, msoBody) = buildWitness(mdoc, requestedClaims)

            // An explicit caller-supplied priorState (a host that persists
            // ZkProofResult.nextState itself across process restarts, say)
            // always wins; otherwise consult this system's own in-memory
            // cache - see VegaProofCache's doc comment for why a cache keyed
            // on (credential, EXACT disclosed-claims set) exists at all,
            // and why disclosedClaims here must be requestedClaims, never a
            // normalized/reordered copy of it.
            val cachedState = priorState ?: proofCache.priorStateFor(credentialBytes, requestedClaims)
            val usedCachedState = cachedState != null

            // prep_prove/prove are synchronous, CPU-bound native calls -
            // running them on whatever dispatcher the caller happens to be
            // on (often Dispatchers.Main for a UI-triggered presentation
            // flow) blocks the UI thread for their full duration, freezing
            // any in-progress animation (e.g. a spinner). Dispatchers.Default
            // moves the blocking work off the calling thread so the
            // coroutine genuinely suspends here instead.
            val result = withContext(Dispatchers.Default) {
                val prepStart = System.nanoTime()
                val state = cachedState ?: withBoostedThreadPriority { prepProve(proverKey, claims, ecdsaWitness, msoBody) }
                val prepMs = (System.nanoTime() - prepStart) / 1_000_000
                val proveStart = System.nanoTime()
                val proveResult = withBoostedThreadPriority { prove(proverKey, claims, ecdsaWitness, msoBody, state) }
                val proveMs = (System.nanoTime() - proveStart) / 1_000_000
                Timber.i(
                    "Vega prepProve took ${prepMs}ms (${if (usedCachedState) "cache hit, skipped" else "ran fresh"}), " +
                        "prove took ${proveMs}ms",
                )
                profilingSink?.record(
                    VegaProfilingEntry(
                        timestampMs = System.currentTimeMillis(),
                        event = "generateProof",
                        usedCachedState = usedCachedState,
                        prepProveMs = if (usedCachedState) null else prepMs,
                        proveMs = proveMs,
                        deviceModel = android.os.Build.MODEL,
                        abi = android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown",
                    ),
                )
                proveResult
            }

            proofCache.record(credentialBytes, requestedClaims, result.nextState, usedCachedState)

            return@use ZkProofResult(
                proofBytes = result.proofBytes,
                nextState = result.nextState,
                // VEGA has no pseudonym-derivation concept at all (confirmed in
                // the handoff doc's own design research) - always report this,
                // regardless of whether verifierIdentity was supplied, rather
                // than silently dropping a pseudonym request.
                pseudonymOutcome = PseudonymOutcome.NOT_SUPPORTED_BY_SYSTEM,
            )
        }
    }

    /**
     * Runs `prep_prove` for [requestedClaims] ahead of time and caches the
     * result, so the first REAL presentation disclosing that exact
     * combination skips straight to `prove()` - the credential-issuance-time
     * precompute this class's own cache exists to make possible. Produces no
     * proof and touches no verifier-specific data (there is none at this
     * point - [generateProof]'s `sessionTranscript`/`verifierIdentity` never
     * reach `prep_prove`/`prove` at all, confirmed against the real crate).
     *
     * Safe to call speculatively (e.g. right after issuance, or the moment a
     * presentation REQUEST names its claims but before the user has approved
     * it) - a redundant call for a combination already cached is a cheap
     * no-op below the native layer, since [VegaProofCache.priorStateFor]
     * would be consulted by the next real [generateProof] regardless of
     * whether this ran again. Callers that don't know which claims will be
     * requested can skip this entirely; [generateProof] still warms the
     * cache for whatever combination a real presentation actually used, for
     * next time.
     */
    suspend fun prewarm(spec: ZkSystemSpec, document: CredentialDocument, requestedClaims: List<String>) {
        val credentialBytes = (document as? CredentialDocument.Mdoc)?.bytes
            ?: throw IllegalArgumentException("$systemId proves over mdoc only, got ${document::class.simpleName}")
        if (proofCache.priorStateFor(credentialBytes, requestedClaims) != null) return
        val mdoc = MdocCbor.parseStoredCredential(credentialBytes)
        residency.use(key = residencyKey(spec), load = { loadProverKey(spec) }) { proverKey ->
            val (claims, ecdsaWitness, msoBody) = buildWitness(mdoc, requestedClaims)
            val prepStart = System.nanoTime()
            val state = withContext(Dispatchers.Default) { withBoostedThreadPriority { prepProve(proverKey, claims, ecdsaWitness, msoBody) } }
            val prepMs = (System.nanoTime() - prepStart) / 1_000_000
            profilingSink?.record(
                VegaProfilingEntry(
                    timestampMs = System.currentTimeMillis(),
                    event = "prewarm",
                    usedCachedState = false,
                    prepProveMs = prepMs,
                    proveMs = null,
                    deviceModel = android.os.Build.MODEL,
                    abi = android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown",
                ),
            )
            proofCache.record(credentialBytes, requestedClaims, state, usedCachedState = false)
        }
    }

    /**
     * Loads this circuit's prover key into the shared [residency] without
     * proving anything - for a host that wants the ~150MB key already
     * resident (not just the much smaller prep-chain cache warm) before the
     * user reaches a presentation, e.g. as soon as a QR code is scanned or a
     * proximity session starts, so a cold key load never stacks on top of a
     * live `prove()` call.
     */
    suspend fun warmResidency(spec: ZkSystemSpec) {
        residency.use(key = residencyKey(spec), load = { loadProverKey(spec) }) { }
    }

    /**
     * Builds this presentation's witness data from a real, stored mdoc
     * credential.
     *
     * **ECDSA witness**: `qx`/`qy` (the issuer's public key) come from the
     * leaf certificate in `issuerAuth`'s x5chain (COSE header label 33),
     * reusing [MdocCose.extractX5Chain] rather than reinventing it. `r`/`s`
     * are `issuerAuth`'s own COSE_Sign1 signature bytes (first/second
     * 32-byte half - this class only supports ES256/P-256, matching
     * [supportedCredentialTypes]' single circuit). `sInv` is a real
     * `BigInteger.modInverse` against the P-256 curve order - get this wrong
     * and proofs fail to verify with no clear error, same class of mistake
     * `zk-cred-vega`'s own `ecdsa.rs` module doc warns about for the
     * *circuit* side of this same computation.
     *
     * **MSO body witness**: [MdocCbor.decodeMso] (added alongside this
     * class - no earlier wallet-side use case needed real MSO field access)
     * gives `deviceKeyInfo.deviceKey.{x,y}` and
     * `validityInfo.{signed,validFrom,validUntil}`, each reformatted to the
     * exact 20-byte ASCII RFC 3339 form `mso::TIMESTAMP_LEN` requires -
     * mirrors [LongfellowZkProofSystem.generateProof]'s own `time` handling
     * (`Instant...truncatedTo(SECONDS)`), since an MSO's own timestamp
     * string isn't guaranteed to already be exactly 20 bytes.
     *
     * **Fixed-slot-count claim selection** (this session's own resolution
     * of what the handoff doc had left open): the circuit has EXACTLY
     * [MAX_CLAIMS_V1] claim slots, each bound to a genuine credential
     * element - no blank/padding slots. This requires the credential's
     * single disclosed namespace to have EXACTLY [MAX_CLAIMS_V1] elements
     * (a real v1 scope limit, not a bug - VEGA's circuit is sized for
     * small, fixed-shape credentials like the real 4-claim mDL test vector,
     * not arbitrarily large ones; a future circuit sized for a real mDL/PID/
     * photoID credential whose claim count vastly exceeds [MAX_CLAIMS_V1]
     * will need this to become "select the circuit's designated slot
     * claims out of a larger namespace" rather than "the whole namespace,
     * positionally" - not yet done, since no such circuit is deployed yet).
     * Slot assignment is the namespace's own document order (stable per
     * credential, independent of which claims a given presentation
     * discloses) - `disclose` only varies per slot based on membership in
     * [requestedClaims].
     *
     * **This does NOT make [ZkProofResult.nextState] reuse valid across
     * presentations disclosing a DIFFERENT subset of the same credential -
     * an earlier version of this comment claimed it did, and that claim was
     * never actually verified against the real crate.** Confirmed
     * empirically (flip every `disclose` flag between a `prep_prove` call
     * and the `prove()` call consuming its state, same claims otherwise):
     * the native call fails outright, the same "Step circuit N public
     * values changed between prep_prove and prove" class of error
     * `zk-cred-vega`'s own `fresh_nonce()` doc describes for a changed
     * nonce - `disclose` is baked into the step circuit's public values at
     * `prep_prove` time right alongside the nonce, not a free per-`prove()`
     * choice. [VegaProofCache] keys on the exact disclosed-claims SET for
     * exactly this reason; see its own doc comment.
     */
    private fun buildWitness(
        document: org.siros.sdk.credentials.mdoc.DocumentMdoc,
        requestedClaims: List<String>,
    ): Triple<List<FfiClaim>, FfiEcdsaWitness, FfiMsoBodyWitness> {
        val issuerAuth = document.issuerSigned.issuerAuth
        val namespaceItems = document.issuerSigned.nameSpaces.values.firstOrNull()
            ?: error("VegaProofSystem: mdoc credential '${document.docType}' has no disclosed namespaces")
        require(namespaceItems.size == MAX_CLAIMS_V1) {
            "VegaProofSystem requires the credential's namespace to have exactly $MAX_CLAIMS_V1 " +
                "elements (VEGA v1's circuit is fixed-shape, no padding slots) - found ${namespaceItems.size}"
        }

        val claims = namespaceItems.map { entry ->
            FfiClaim(
                issuerSignedItemBytes = entry.original.EncodeToBytes(),
                disclose = entry.item.elementIdentifier in requestedClaims,
                digestId = entry.item.digestId.toUInt(),
            )
        }

        val ecdsaWitness = buildEcdsaWitness(issuerAuth)
        val msoBody = buildMsoBodyWitness(issuerAuth)

        return Triple(claims, ecdsaWitness, msoBody)
    }

    /** See [buildWitness]'s "ECDSA witness" section for the reasoning here. */
    private fun buildEcdsaWitness(issuerAuth: CBORObject): FfiEcdsaWitness {
        val protectedHeaders = CBORObject.DecodeFromBytes(issuerAuth[0].GetByteString())
        val alg = protectedHeaders[CBORObject.FromObject(1L)]?.AsInt64Value()
        require(alg == COSE_ALG_ES256) {
            "VegaProofSystem only supports ES256/P-256 issuerAuth signatures, got COSE alg $alg"
        }

        val leafCertBytes = MdocCose.extractX5Chain(issuerAuth).firstOrNull()
            ?: error("VegaProofSystem: issuerAuth has no x5chain to extract the issuer's public key from")
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(leafCertBytes))
        val publicKey = cert.publicKey as? ECPublicKey
            ?: error("VegaProofSystem: issuerAuth's leaf certificate is not an EC public key")

        val signature = issuerAuth[3].GetByteString()
        require(signature.size == P256_COORDINATE_BYTES * 2) {
            "VegaProofSystem: expected a ${P256_COORDINATE_BYTES * 2}-byte raw ECDSA signature, got ${signature.size}"
        }
        val r = BigInteger(1, signature.copyOfRange(0, P256_COORDINATE_BYTES))
        val s = BigInteger(1, signature.copyOfRange(P256_COORDINATE_BYTES, signature.size))
        val sInv = s.modInverse(P256_ORDER)

        return FfiEcdsaWitness(
            qx = pad32(publicKey.w.affineX),
            qy = pad32(publicKey.w.affineY),
            r = pad32(r),
            s = pad32(s),
            sInv = pad32(sInv),
        )
    }

    /** See [buildWitness]'s "MSO body witness" section for the reasoning here. */
    private fun buildMsoBodyWitness(issuerAuth: CBORObject): FfiMsoBodyWitness {
        val mso = MdocCbor.decodeMso(issuerAuth)
        val deviceKey = mso["deviceKeyInfo"]["deviceKey"]
        val deviceX = deviceKey[CBORObject.FromObject(COSE_KEY_LABEL_X)].GetByteString()
        val deviceY = deviceKey[CBORObject.FromObject(COSE_KEY_LABEL_Y)].GetByteString()

        val validity = mso["validityInfo"]
        fun timestamp(field: String): ByteArray {
            val raw = validity[field]
            val iso = if (raw.HasOneTag(0)) raw.UntagOne().AsString() else raw.AsString()
            return Instant.parse(iso).truncatedTo(ChronoUnit.SECONDS).toString().toByteArray(Charsets.US_ASCII)
        }

        return FfiMsoBodyWitness(
            deviceX = deviceX,
            deviceY = deviceY,
            signedTs = timestamp("signed"),
            validFromTs = timestamp("validFrom"),
            validUntilTs = timestamp("validUntil"),
        )
    }

    /** Unsigned big-endian, left-padded/truncated to exactly [P256_COORDINATE_BYTES]. */
    private fun pad32(value: BigInteger): ByteArray {
        val unpadded = value.toByteArray().let {
            // BigInteger.toByteArray() may carry a leading 0x00 sign byte for
            // an otherwise-32-byte unsigned value - strip it so padding below
            // doesn't overflow past P256_COORDINATE_BYTES.
            if (it.size > P256_COORDINATE_BYTES && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it
        }
        require(unpadded.size <= P256_COORDINATE_BYTES) {
            "value does not fit in $P256_COORDINATE_BYTES bytes"
        }
        val padded = ByteArray(P256_COORDINATE_BYTES)
        System.arraycopy(unpadded, 0, padded, P256_COORDINATE_BYTES - unpadded.size, unpadded.size)
        return padded
    }

    private suspend fun loadProverKey(spec: ZkSystemSpec): VegaProverKey {
        val descriptor = zkCircuitClient.fetchCircuit(spec.id)
            ?: error(
                "Vega prover key '${spec.id}' not found in any configured zk-circuits source - " +
                    "see VegaProofSystem's doc comment for the catalog gating",
            )
        validateCircuitParams(descriptor)
        val compressedBytes = zkCircuitClient.downloadArtifact(descriptor)
        val keyBuffer = decompressZkCircuitArtifact(compressedBytes, descriptor)
        return uniffi.zk_cred_vega.deserializeProverKey(keyBuffer)
    }

    /**
     * Checks the catalog's own published `params` for this circuit against
     * what this class hardcodes (P-256, exactly [MAX_CLAIMS_V1] claim
     * slots) *before* spending a real download+decompress (a 100+MB
     * artifact) on a circuit this implementation can't actually use -
     * failing fast, locally, with a clear diagnostic naming the mismatch,
     * instead of discovering a circuit-shape change only via an opaque
     * native prove()/verify() failure much later. Doesn't yet check
     * `maxClaimBytes` against real witness byte lengths - unlike
     * `curve`/`numClaims`, a per-claim-byte-count mismatch surfaces at the
     * native layer with its own clear error already, since it's the
     * issuer's claim content (not a circuit-shape assumption this class
     * makes) that would be at fault.
     *
     * Only validates fields the catalog already publishes today
     * (`curve`, `numClaims` - confirmed via the real r12 manifest entry);
     * a `saltBytes` field doesn't exist there yet
     * (sirosfoundation/go-zk-circuits#29 tracks adding it - once it does,
     * this is the natural place to also validate a stored credential's
     * salt length against it, per siros-sdk-kotlin#243).
     */
    internal fun validateCircuitParams(descriptor: ZkCircuitDescriptor) {
        val curve = descriptor.params["curve"]?.jsonPrimitive?.content
        require(curve == "P-256") {
            "Vega circuit '${descriptor.id}' declares curve '$curve', but $systemId only supports P-256"
        }
        val numClaims = descriptor.params["numClaims"]?.jsonPrimitive?.content?.toIntOrNull()
        require(numClaims == MAX_CLAIMS_V1) {
            "Vega circuit '${descriptor.id}' declares numClaims=$numClaims, but $systemId is built for exactly $MAX_CLAIMS_V1 claim slots"
        }
    }

}
