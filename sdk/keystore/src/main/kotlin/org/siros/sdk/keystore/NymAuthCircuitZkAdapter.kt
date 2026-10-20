// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPublicKey
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.COSE_ALG_ES256
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkLegacyDisclosure
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.RulebookCircuitZkValidator
import org.siros.sdk.credentials.CircuitZkVerdict
import org.siros.sdk.credentials.CircuitZkRuleSet
import org.siros.sdk.credentials.NymPseudonym
import org.siros.sdk.credentials.ProofTime
import org.siros.sdk.credentials.NymSeedKind
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.ZkArtifactException
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import org.siros.sdk.keystore.mdoc.MdocCose
import org.siros.sdk.credentials.mdoc.MdocCbor
import timber.log.Timber

/**
 * The circuit decoded from the catalog and kept resident: the verified, decompressed artifact. Closing it
 * drops the reference; the memory is the garbage collector's (Longfellow circuits are about 1 MB, Vega
 * shapes 12-23 MB, far below a prover key).
 */
private class LoadedNymAuthCircuit(val descriptor: ZkCircuitDescriptor, @Volatile var bytes: ByteBuffer?) : AutoCloseable {
    override fun close() {
        bytes = null
    }
}

/**
 * The adapter for the `nymauth-*` circuits (systems [LONGFELLOW_SYSTEM] and [VEGA_SYSTEM]): proves the
 * rulebook's `pseudonym` (configuration `known-offender-matching-ssc`) and `age_check`.
 *
 * What it does itself, in this order, refusing (an [CircuitZkError.AccessDenied], never a fallback to the
 * fake prover) at the first thing it cannot do:
 * 1. Only what the `nymauth-*` circuits prove is accepted: one `pseudonym` with the config the
 *    circuit was built for and at most one `age_check` with only `ge`/`le`; the credential an mdoc.
 * 2. The circuit's catalog descriptor (already checked by the dispatcher to be the chosen, active circuit)
 *    must be of format `mdoc` and of the configuration the circuit was built for.
 * 3. The artifact is downloaded with its SHA-256 verified ([ZkCircuitClient.downloadArtifact]), decompressed,
 *    and the decompressed bytes checked against the catalog's `uncompressed.hash`; it stays resident in
 *    [residency] (one at a time) until released.
 * 4. The device key signs the challenge through the [org.siros.sdk.credentials.ZkWitnessSigner]; the digest of
 *    exactly the signed bytes is `e2`. The key never reaches this class.
 * 5. The inputs are assembled (issuer key, `T`, `E`, `C`, verifier input) and handed to [native].
 * 6. The pseudonym [native] reports must equal the one [NymPseudonym] derives from the same inputs;
 *    anything else (a circuit that disagrees with the rulebook, a corrupted run) is refused.
 *
 * What it does not do: build the circuit witnesses and run the proof system. That is [native], see
 * [NymAuthNativeProver]; with none supplied every request is refused. SD-JWT VC credentials and circuits are
 * refused too: the presenter holds mdoc credentials, and the SD-JWT challenge needs the request's nonce,
 * client id and origin, which [CircuitZkProveInput] does not carry.
 */
class NymAuthCircuitZkAdapter(
    private val circuitClient: ZkCircuitClient,
    /** Builds the witnesses and proves; null means this build has no native prover and every request is refused. */
    private val native: NymAuthNativeProver? = null,
    /** Keeps the loaded circuit; share one with the other proof systems to hold a single prover at a time. */
    private val residency: ZkProverResidency = ZkProverResidency(),
    private val clock: Clock = Clock.systemUTC(),
    /** Decompresses a downloaded artifact; replaceable only because the zstd binding is native. */
    private val decompress: (ByteArray, ZkCircuitDescriptor) -> ByteBuffer = ::decompressZkCircuitArtifact,
    /**
     * Called with the circuit id when the native side says this app build does not support the circuit (its shapes are
     * not on the approved list): a wallet can use it to say "update the app". The request is refused as always.
     */
    private val onUnsupportedCircuit: (String) -> Unit = {},
) : CircuitZkSystemAdapter {

    private val unsupported = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    /** The circuits the native side has refused as not supported by this build (this process). */
    val unsupportedCircuits: Set<String> get() = unsupported.toSet()


    override val systems: Set<CircuitZkSystemKey> = setOf(
        CircuitZkSystemKey(LONGFELLOW_SYSTEM, "61a8a73"),
        CircuitZkSystemKey(VEGA_SYSTEM, "c0ee259"),
    )

    /** Whether a native prover is wired in; false means every request is refused. */
    override val canProve: Boolean get() = native != null

    override fun release() {
        residency.release()
        (native as? ResidentNymAuthNativeProver)?.release()
    }

    override suspend fun retire(descriptor: ZkCircuitDescriptor) {
        residency.releaseCircuit(descriptor.id)
        (native as? ResidentNymAuthNativeProver)?.releaseCircuit(descriptor.id)
    }

    override fun admits(circuit: CircuitZkCircuit, plan: CircuitZkPlan): Boolean =
        plan.functions.none { it.id == CircuitZkLegacyDisclosure.FUNCTION_ID }

    override suspend fun prove(descriptor: ZkCircuitDescriptor, input: CircuitZkProveInput): CircuitZkProveOutput {
        val native = native ?: run {
            Timber.w("circuit_zk: no nymauth native prover is wired in; refusing")
            throw refuse()
        }

        // 1. What the circuits prove.
        val (pseudonymFn, ageFn, config) = planParts(input.plan)
        val info = NymPseudonym.describe(config)
        if (info == null || info.seedKind != NymSeedKind.SECRET || info.userValue || !info.verifierId || info.verifierContext) throw refuse()
        val witness = input.witnesses[pseudonymFn.handle] ?: throw refuse()
        val seed = witness.secretSeed?.takeIf { it.size == SECRET_SEED_BYTES } ?: throw refuse()
        // An empty verifier id is no identity (every verifier-less request would share its pseudonym).
        val verifierId = input.verifierId?.takeIf { it.isNotEmpty() } ?: throw refuse()
        val (earliest, cutoff) = ageBounds(ageFn)

        // 2. The circuit.
        if (!isSupported(descriptor)) throw refuse()
        val artifact = descriptor.artifact ?: throw refuse()

        val document = try {
            MdocCbor.parseStoredCredential(input.credentialBytes)
        } catch (e: Exception) {
            throw refuse()
        }
        val issuerAuth = document.issuerSigned.issuerAuth
        val issuerKey = issuerKey(issuerAuth) ?: throw refuse()
        val issuerSigned = encodeIssuerSigned(document)

        // 3. Load (or reuse) the verified circuit, 4. sign the challenge, 5. prove.
        val residencyKey = "${descriptor.system}:${descriptor.id}:${artifact.hash}"
        // The proof's time input. UNDECIDED upstream (verification time T): until it is decided this is the device clock, and
        // this is the one place T plugs in (a value carried by CircuitZkProveInput would replace it here).
        val time = Instant.now(clock).truncatedTo(ChronoUnit.SECONDS)
        val timeText = try { ProofTime.render(time) } catch (e: org.siros.sdk.credentials.ProofTimeException) { throw refuse() }

        val verifierInput = sha256(verifierId.toByteArray(Charsets.UTF_8))
        val deviceAuthBytes = MdocDeviceResponseBuilder.buildDeviceAuthentication(document.docType, input.sessionTranscript)
        val response = residency.use(
            key = residencyKey,
            load = { loadCircuit(descriptor) },
            block = { loaded ->
                val circuit = loaded.bytes ?: throw refuse()
                // Signed only now: the device key is not asked until the circuit is loaded and verified.
                var challengeDigest: ByteArray? = null
                val signed = MdocCose.sign1Detached("ES256", deviceAuthBytes) { toBeSigned ->
                    // e2 is the digest of exactly what the key signs, not of a second construction of it.
                    challengeDigest = sha256(toBeSigned)
                    input.signer.sign(COSE_ALG_ES256, toBeSigned)
                }
                val deviceSignature = signed[3].GetByteString()
                val e2 = challengeDigest
                if (deviceSignature.size != SIGNATURE_BYTES || e2 == null) throw refuse()
                val seedCopy = seed.copyOf()
                try {
                    native.prove(
                        NymAuthProveRequest(
                            system = descriptor.system,
                            circuitId = descriptor.id,
                            artifactHash = artifact.hash,
                            circuitParams = descriptor.params,
                            circuit = circuit.asReadOnlyBuffer(),
                            issuerSigned = issuerSigned,
                            secretSeed = seedCopy,
                            issuerKeyX = issuerKey.first,
                            issuerKeyY = issuerKey.second,
                            time = timeText,
                            earliest = earliest,
                            cutoff = cutoff,
                            challengeDigest = e2,
                            deviceSignature = deviceSignature,
                            verifierInput = verifierInput,
                            transcriptSeed = input.sessionTranscript,
                        ),
                    )
                } catch (e: NymAuthNativeException) {
                    throw mapNativeError(descriptor, e)
                } finally {
                    seedCopy.fill(0)
                }
            },
        )

        // 6. The circuit's pseudonym must be the rulebook's.
        val expected = NymPseudonym.derive(config = config, seed = seed, verifierId = verifierId)
        val agrees = MessageDigest.isEqual(expected, response.pseudonym)
        response.pseudonym.fill(0)
        if (!agrees || response.proof.isEmpty()) throw refuse()

        val results = LinkedHashMap<String, ResultValue>()
        results[pseudonymFn.handle] = ResultValue.Pseudonym(expected)
        if (ageFn != null) results[ageFn.handle] = ResultValue.Predicate
        return CircuitZkProveOutput(proof = response.proof, results = results, proofTime = time)
    }

    private fun refuse() = CircuitZkError.AccessDenied(CircuitZkStep.PROVE)

    /**
     * The rulebook rules this adapter proves with: the very rules the wallet's validator applies, restricted to the one
     * configuration the circuit is built for. The prover therefore refuses everything the validator refuses (a
     * `verifier_context` where none is allowed, an age span under 365 days, `le` before `ge`, ...), on top of its own
     * shape checks below.
     */
    private val validator = RulebookCircuitZkValidator(
        CircuitZkRuleSet.rulebookV04(
            listOf(CircuitZkRuleSet.Companion.PseudonymConfig(SUPPORTED_CONFIG, usesVerifierInput = true, requiresVerifierContext = false)),
        ),
    )

    /** The pseudonym function, the optional age check and the pseudonym config of [plan], or a refusal. */
    private fun planParts(plan: CircuitZkPlan): Triple<CircuitZkFunction, CircuitZkFunction?, String> {
        if (validator.validate(plan) !is CircuitZkVerdict.Ok) throw refuse()
        val pseudonymFn = plan.functions.singleOrNull { it.id == PseudonymFunctionHandler.functionId } ?: throw refuse()
        val ageFn = plan.functions.filter { it.id == org.siros.sdk.credentials.PredicateFunctions.AGE_CHECK.id }.also { if (it.size > 1) throw refuse() }.firstOrNull()
        if (plan.functions.any { it !== pseudonymFn && it !== ageFn }) throw refuse()
        val config = (pseudonymFn.params["config"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw refuse()
        if (config != SUPPORTED_CONFIG) throw refuse()
        return Triple(pseudonymFn, ageFn, config)
    }

    /** Whether [plan] is one this adapter proves (the shape only; the data is checked when proving). */
    internal fun acceptsPlan(plan: CircuitZkPlan): Boolean = try {
        planParts(plan)
        true
    } catch (e: CircuitZkError.AccessDenied) {
        false
    }

    /**
     * Each native failure is a refusal, none a crash and none a leak: the verifier sees the bare `access_denied`,
     * the log sees the kind and the circuit id and nothing the binding said (a circuit digest, a rule, a value).
     * An unsupported circuit is the one with a meaning of its own: this build of the app cannot prove it.
     */
    private fun mapNativeError(descriptor: ZkCircuitDescriptor, e: NymAuthNativeException): CircuitZkError.AccessDenied {
        val reason = when (e.kind) {
            NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT -> CircuitZkRefusalReason.CIRCUIT_UNSUPPORTED_BY_APP
            NymAuthNativeErrorKind.INVALID_INPUT -> CircuitZkRefusalReason.INVALID_INPUT
            NymAuthNativeErrorKind.INVALID_CIRCUIT -> CircuitZkRefusalReason.INVALID_CIRCUIT
            NymAuthNativeErrorKind.PROVER_FAILED -> CircuitZkRefusalReason.PROVER_FAILED
            NymAuthNativeErrorKind.PROOF_INVALID -> CircuitZkRefusalReason.PROOF_INVALID
            NymAuthNativeErrorKind.MISMATCH -> CircuitZkRefusalReason.MISMATCH
            NymAuthNativeErrorKind.INTERNAL -> CircuitZkRefusalReason.INTERNAL
            NymAuthNativeErrorKind.REFUSED -> when (e.refusal) {
                NymAuthRefusal.SEED_MISMATCH -> CircuitZkRefusalReason.SEED_MISMATCH
                NymAuthRefusal.ISSUER_SIGNATURE -> CircuitZkRefusalReason.ISSUER_SIGNATURE
                NymAuthRefusal.DEVICE_SIGNATURE -> CircuitZkRefusalReason.DEVICE_SIGNATURE
                NymAuthRefusal.CREDENTIAL -> CircuitZkRefusalReason.CREDENTIAL
                else -> CircuitZkRefusalReason.UNSATISFIED
            }
        }
        if (reason == CircuitZkRefusalReason.CIRCUIT_UNSUPPORTED_BY_APP) {
            Timber.w("circuit_zk: circuit '${descriptor.id}' is not supported by this app version; refusing")
            residency.releaseCircuit(descriptor.id)
            (native as? ResidentNymAuthNativeProver)?.releaseCircuit(descriptor.id)
            if (unsupported.add(descriptor.id)) {
                try {
                    onUnsupportedCircuit(descriptor.id)
                } catch (t: Exception) {
                    Timber.w("circuit_zk: the unsupported-circuit listener threw (${t.javaClass.simpleName})")
                }
            }
        } else {
            Timber.w("circuit_zk: the native prover refused (${reason.name}) for circuit '${descriptor.id}'")
        }
        return CircuitZkError.AccessDenied(CircuitZkStep.PROVE, reason)
    }

    /** The descriptor is a circuit of a format and configuration this adapter can drive. */
    private fun isSupported(descriptor: ZkCircuitDescriptor): Boolean {
        val format = (descriptor.params["format"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        val configuration = (descriptor.params["configuration"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        return format == "mdoc" && configuration == SUPPORTED_CONFIG && descriptor.artifact != null
    }

    private suspend fun loadCircuit(descriptor: ZkCircuitDescriptor): LoadedNymAuthCircuit {
        val compressed = try {
            circuitClient.downloadArtifact(descriptor)
        } catch (e: ZkArtifactException) {
            throw refuse()
        }
        val bytes = decompress(compressed, descriptor)
        val expected = descriptor.artifact?.uncompressed?.hash?.removePrefix("sha256:")
        val digest = MessageDigest.getInstance("SHA-256").apply { update(bytes.duplicate()) }.digest()
        // The catalog publishes the decompressed hash for every nymauth circuit; one without it is not trusted.
        if (expected.isNullOrEmpty() || !hex(digest).equals(expected, ignoreCase = true)) {
            Timber.w("circuit_zk: decompressed circuit '${descriptor.id}' does not match the catalog hash")
            throw refuse()
        }
        return LoadedNymAuthCircuit(descriptor, bytes)
    }

    /** `E` and `C` of the `age_check` (inclusive bounds); the open ends are `0000-00-00` and `9999-12-31`. */
    private fun ageBounds(age: CircuitZkFunction?): Pair<String, String> {
        if (age == null) return NO_LOWER_BOUND to NO_UPPER_BOUND
        // A parameter this circuit does not prove must not be silently dropped.
        if (org.siros.sdk.credentials.PredicateFunctions.AGE_CHECK.parse(age) == null) throw refuse()
        fun bound(key: String): String? {
            val p = age.params[key] ?: return null
            val text = (p as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw refuse()
            val date = try { LocalDate.parse(text) } catch (e: DateTimeParseException) { throw refuse() }
            // The circuit compares ten ASCII characters: only a four-digit year is representable.
            if (date.year !in 1..9998 || date.toString() != text) throw refuse()
            return text
        }
        val ge = bound("ge")
        val le = bound("le")
        if (ge == null && le == null) throw refuse()
        return (ge ?: NO_LOWER_BOUND) to (le ?: NO_UPPER_BOUND)
    }

    /** The issuer key Q: the P-256 key of the `x5chain` leaf, as 32-byte big-endian coordinates. */
    private fun issuerKey(issuerAuth: CBORObject): Pair<ByteArray, ByteArray>? {
        val leaf = MdocCose.extractX5Chain(issuerAuth).firstOrNull() ?: return null
        val key = try {
            CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(leaf)).publicKey as? ECPublicKey
        } catch (e: Exception) {
            null
        } ?: return null
        if (key.params.order.bitLength() != 256 || key.params.curve.field.fieldSize != 256) return null
        return unsigned32(key.w.affineX) to unsigned32(key.w.affineY)
    }

    private fun unsigned32(v: java.math.BigInteger): ByteArray {
        val raw = v.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        require(raw.size <= 32)
        return ByteArray(32 - raw.size) + raw
    }

    /** `IssuerSigned` = `{nameSpaces, issuerAuth}`; the items keep their original encoding, the digests depend on it. */
    private fun encodeIssuerSigned(document: org.siros.sdk.credentials.mdoc.DocumentMdoc): ByteArray {
        val nameSpaces = CBORObject.NewMap()
        for ((ns, items) in document.issuerSigned.nameSpaces) {
            val array = CBORObject.NewArray()
            items.forEach { array.Add(it.original) }
            nameSpaces[CBORObject.FromObject(ns)] = array
        }
        val issuerSigned = CBORObject.NewMap()
        issuerSigned[CBORObject.FromObject("nameSpaces")] = nameSpaces
        issuerSigned[CBORObject.FromObject("issuerAuth")] = document.issuerSigned.issuerAuth
        return issuerSigned.EncodeToBytes()
    }

    private fun sha256(data: ByteArray) = MessageDigest.getInstance("SHA-256").digest(data)

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    companion object {
        /** Catalog `system` of the Longfellow `nymauth-longfellow-*` circuits. */
        const val LONGFELLOW_SYSTEM = "longfellow-nymauth"

        /** Catalog `system` of the Vega `nymauth-vega-*` circuits. */
        const val VEGA_SYSTEM = "vega-nymauth"

        /** The only pseudonym configuration the `nymauth-*` circuits are built for. */
        const val SUPPORTED_CONFIG = "known-offender-matching-ssc"

        private const val SECRET_SEED_BYTES = 16
        private const val SIGNATURE_BYTES = 64
        private const val NO_LOWER_BOUND = "0000-00-00"
        private const val NO_UPPER_BOUND = "9999-12-31"
    }
}
