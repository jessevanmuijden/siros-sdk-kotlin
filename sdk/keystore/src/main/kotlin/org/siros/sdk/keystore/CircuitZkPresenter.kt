// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import java.time.Instant
import java.time.LocalDate
import java.time.format.DateTimeParseException
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkCircuitSource
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CircuitZkResponsePresentation
import org.siros.sdk.credentials.ProofTime
import org.siros.sdk.credentials.CircuitZkRequestValidator
import org.siros.sdk.credentials.CircuitZkVerdict
import org.siros.sdk.credentials.NymPseudonym
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.SirosException
import org.siros.sdk.credentials.ZkWitnessSigner
import org.siros.sdk.credentials.mdoc.DocumentMdoc
import org.siros.sdk.credentials.mdoc.MdocCbor
import timber.log.Timber

/**
 * Why a `circuit_zk` presentation was not produced. A refusal carries no
 * description and nothing that identifies a rule or a reason: the rulebook
 * answers with `access_denied` and no `error_description`, and what a verifier
 * could learn from a reason (that a predicate is false, say) must not leave
 * the wallet.
 */
sealed class CircuitZkError(message: String, errorCode: String) : SirosException(message, errorCode = errorCode) {
    /** The request is malformed in a way that is independent of the holder's data. */
    class InvalidRequest internal constructor() : CircuitZkError("circuit_zk request invalid", "circuit_zk_invalid_request")

    /** Everything else: answered with `access_denied`, no description. */
    class AccessDenied internal constructor(
        /** The step that refused. Internal: for local diagnostics and tests, never part of the message. */
        internal val step: CircuitZkStep,
        /** Why, when a prover knows. Internal like [step]: the verifier only ever sees the bare refusal. */
        internal val reason: CircuitZkRefusalReason = CircuitZkRefusalReason.GENERIC,
    ) : CircuitZkError("circuit_zk request refused", "circuit_zk_access_denied")
}

/**
 * Why a prover refused, for local diagnostics and for a wallet that wants to tell the user something (never sent
 * to the verifier, which gets the bare `access_denied`). No value is ever attached.
 */
internal enum class CircuitZkRefusalReason {
    GENERIC,

    /** The circuit is well-formed but this build of the app cannot prove it (its shapes/circuit are not on the approved list): "update the app". */
    CIRCUIT_UNSUPPORTED_BY_APP,
    INVALID_INPUT, INVALID_CIRCUIT, SEED_MISMATCH, ISSUER_SIGNATURE, DEVICE_SIGNATURE, CREDENTIAL, UNSATISFIED,
    PROVER_FAILED, PROOF_INVALID, MISMATCH, INTERNAL,

    /** The credential's `x5chain` has no usable Document Signer certificate (absent, empty, or its first element is empty or oversized). */
    ISSUER_KEY_UNUSABLE,
}

private const val SECRET_SEED_BYTES = 16

/** The steps of [CircuitZkPresenter.present], in order. Internal. */
internal enum class CircuitZkStep { VALIDATE, DOCTYPE, NAMESPACE, WITNESS, COMMITMENT, SECRET_COMMITMENT, PREDICATE, CIRCUIT, ISSUER_KEY, PROVE, BUILD }

/** What kind of wallet-held private input a function needs. */
enum class CircuitZkWitnessKind {
    /** The holder's `private_seed` for the credential's type: derived on the device, opened from `psc`. */
    PRIVATE_SEED,

    /**
     * The issuer-delivered `secret_seed` of the credential: opened from `ssc`, not derivable from any
     * wallet key. The presenter takes it from [CircuitZkPresenter.Request.secretSeed] and checks
     * `SHA256(seed) == ssc` itself before it reaches a prover; a [CircuitZkWitnessProvider] is never
     * asked for it (it is removed from the `needs` a provider sees).
     */
    SECRET_SEED,

    /** The user-supplied value. */
    USER_VALUE,

    /**
     * An input that no provider and no request can supply, for example because the function's config is
     * unknown to this SDK. Always refused.
     */
    NOT_HELD_BY_WALLET,
}

/**
 * The private inputs for one planned function. Never logged or inspected by
 * the presenter; [toString] is redacted and there is no value-based `equals`
 * (identity only), so no seed reaches a string or a comparison.
 *
 * @property secretSeed The issuer-delivered `secret_seed`, set by the presenter only after it verified
 *   `SHA256(secretSeed) == ssc`; a provider never sets it. The presenter zeroes it once proving ends.
 */
class CircuitZkFunctionWitness(
    val privateSeed: ByteArray? = null,
    val userValue: ByteArray? = null,
    val secretSeed: ByteArray? = null,
) {
    override fun toString() = "CircuitZkFunctionWitness(redacted)"

    override fun equals(other: Any?) = other is CircuitZkFunctionWitness && this === other

    override fun hashCode() = System.identityHashCode(this)
}

/** Supplies the wallet-held private inputs a function needs, or null when it cannot. */
interface CircuitZkWitnessProvider {
    /**
     * The witness for [function], or null when [needs] includes something this provider cannot supply.
     * [needs] never contains [CircuitZkWitnessKind.SECRET_SEED]: the issuer-delivered seed is not derivable
     * from key material and comes with the request, so the presenter handles it itself.
     */
    fun witness(function: CircuitZkFunction, needs: Set<CircuitZkWitnessKind>, credentialType: String, issuer: String?): CircuitZkFunctionWitness?

    /** Whether [psc] is the commitment this provider's `private_seed` has for [credentialType]. */
    fun privateSeedMatches(credentialType: String, issuer: String?, psc: ByteArray): Boolean
}

/**
 * The default provider: the K-S `private_seed` per credential type, and the user-supplied value if any.
 * The `secret_seed` is not derivable from the main key (the issuer delivers it), so this provider returns
 * null for [CircuitZkWitnessKind.SECRET_SEED]; the presenter supplies it from the request.
 */
class HolderWitnessProvider internal constructor(
    private val seeds: PrivateSeed,
    private val userValue: ByteArray? = null,
) : CircuitZkWitnessProvider {
    override fun witness(function: CircuitZkFunction, needs: Set<CircuitZkWitnessKind>, credentialType: String, issuer: String?): CircuitZkFunctionWitness? {
        if (CircuitZkWitnessKind.NOT_HELD_BY_WALLET in needs || CircuitZkWitnessKind.SECRET_SEED in needs) return null
        if (CircuitZkWitnessKind.USER_VALUE in needs && userValue == null) return null
        return CircuitZkFunctionWitness(
            privateSeed = if (CircuitZkWitnessKind.PRIVATE_SEED in needs) derive(credentialType, issuer ?: return null) ?: return null else null,
            userValue = if (CircuitZkWitnessKind.USER_VALUE in needs) userValue else null,
        )
    }

    /** The seed for the type at the issuer, or null when either is refused (empty or over 65535 bytes): no seed is derived. */
    private fun derive(credentialType: String, issuer: String): ByteArray? = try {
        seeds.derive(credentialType, issuer)
    } catch (e: IllegalArgumentException) {
        null
    }

    override fun privateSeedMatches(credentialType: String, issuer: String?, psc: ByteArray): Boolean =
        issuer != null && try {
            seeds.matchesCommitment(credentialType, issuer, psc)
        } catch (e: IllegalArgumentException) {
            false
        }
}

/**
 * The per-function part of the presenter, looked up by function id in a
 * registry, so another function is another handler.
 */
interface CircuitZkFunctionHandler {
    /** The function id this handles. */
    val functionId: String

    /** The wallet-held private inputs [function] needs. */
    fun witnessNeeds(function: CircuitZkFunction): Set<CircuitZkWitnessKind>

    /** The data-dependent check of [function] against the credential; false means no presentation. */
    fun holds(function: CircuitZkFunction, credential: DocumentMdoc): Boolean

    /**
     * Whether the credential's STRUCTURE is one [function] can be proved over; false refuses the request (before any
     * private input is looked at). A function whose circuit binds a particular namespace layout checks it here.
     */
    fun admitsCredential(function: CircuitZkFunction, credential: DocumentMdoc): Boolean = true

    /**
     * Checks the credential's commitments against what the wallet holds for [function] ([witness], and [provider] for
     * values only it can check); anything but [CircuitZkCommitmentCheck.HOLDS] refuses before a prover runs.
     */
    fun commitmentCheck(
        function: CircuitZkFunction,
        credential: DocumentMdoc,
        witness: CircuitZkFunctionWitness,
        provider: CircuitZkWitnessProvider,
        issuer: String?,
    ): CircuitZkCommitmentCheck = CircuitZkCommitmentCheck.HOLDS

    /** Whether answering [function] needs the verifier's identifier (resolved by the wallet's verifier-id registry). */
    fun needsVerifierId(function: CircuitZkFunction): Boolean = false

    /** Whether answering [function] needs the issuer-delivered `secret_seed` of the credential (fetched by the wallet). */
    fun needsSecretSeed(function: CircuitZkFunction): Boolean = false

    /** The verifier context [function] names itself, or null. */
    fun verifierContext(function: CircuitZkFunction): String? = null
}

/** The outcome of [CircuitZkFunctionHandler.commitmentCheck]. */
enum class CircuitZkCommitmentCheck {
    HOLDS,

    /** The commitment to a value derived on this device does not match. */
    DEVICE_COMMITMENT_FAILS,

    /** The commitment to a value the issuer delivered does not match. */
    DELIVERED_COMMITMENT_FAILS,
}

/**
 * The PROPOSED legacy claim-disclosure function ([org.siros.sdk.credentials.CircuitZkLegacyDisclosure]): needs
 * no wallet-held private input, and holds when every claim it names is an element of the credential's one
 * namespace. The proof systems apply the non-disclosure guard themselves when they prove.
 */
object LegacyDisclosureFunctionHandler : CircuitZkFunctionHandler {
    override val functionId = org.siros.sdk.credentials.CircuitZkLegacyDisclosure.FUNCTION_ID

    override fun witnessNeeds(function: CircuitZkFunction): Set<CircuitZkWitnessKind> = emptySet()

    override fun holds(function: CircuitZkFunction, credential: DocumentMdoc): Boolean {
        val request = org.siros.sdk.credentials.CircuitZkLegacyDisclosure.parse(function) ?: return false
        val namespaces = credential.issuerSigned.nameSpaces.values
        if (namespaces.size != 1) return false
        val present = namespaces.single().map { it.item.elementIdentifier }.toSet()
        return request.claims.all { it in present }
    }

    /** The proof system's own pseudonym is bound to the verifier's identity. */
    override fun needsVerifierId(function: CircuitZkFunction) =
        org.siros.sdk.credentials.CircuitZkLegacyDisclosure.parse(function)?.pseudonym == true
}

/**
 * The handler of a predicate function, generic over its declaration ([org.siros.sdk.credentials.PredicateFunction]):
 * the same declaration that drives consent, the local pre-check, the cross-query rule and the validator's rules. It
 * needs no wallet-held private input, and holds when the declared comparison holds for the credential's own claim value
 * ([org.siros.sdk.credentials.PredicateFunctions.holdsFor] over an mdoc claim reader; a claim the reader cannot read is
 * not judged here, the prover decides). One per declared function, so a function the user was asked about can also be
 * presented. The handler registry itself keeps only hook-style functions (the pseudonym, the legacy disclosure).
 */
class PredicateFunctionHandler(private val declaration: org.siros.sdk.credentials.PredicateFunction) : CircuitZkFunctionHandler {
    private val functions = org.siros.sdk.credentials.PredicateFunctions(listOf(declaration))

    override val functionId: String get() = declaration.id

    override fun witnessNeeds(function: CircuitZkFunction): Set<CircuitZkWitnessKind> = emptySet()

    // A circuit that binds the doctype namespace never proves a credential with a decoy or extra namespace.
    override fun admitsCredential(function: CircuitZkFunction, credential: DocumentMdoc): Boolean =
        !declaration.doctypeNamespaceOnly || credential.issuerSigned.nameSpaces.keys == setOf(credential.docType)

    override fun holds(function: CircuitZkFunction, credential: DocumentMdoc): Boolean =
        functions.holdsFor(function, org.siros.sdk.credentials.PredicateFunctions.mdocReader(credential))

    companion object {
        /** The hook-style handlers (the pseudonym, the legacy disclosure) plus one [PredicateFunctionHandler] per function [functions] declares. */
        fun handlersFor(functions: org.siros.sdk.credentials.PredicateFunctions): List<CircuitZkFunctionHandler> =
            HOOK_CIRCUIT_ZK_HANDLERS + functions.ids.map { PredicateFunctionHandler(functions[it]!!) }
    }
}

/** The hook-style handlers: functions that are not declared predicates. */
val HOOK_CIRCUIT_ZK_HANDLERS: List<CircuitZkFunctionHandler> = listOf(PseudonymFunctionHandler, LegacyDisclosureFunctionHandler)

/** The handlers a presenter has unless it is given others: the hook-style ones plus the rulebook's declared predicates. */
val DEFAULT_CIRCUIT_ZK_HANDLERS: List<CircuitZkFunctionHandler> =
    PredicateFunctionHandler.handlersFor(org.siros.sdk.credentials.PredicateFunctions.DEFAULT)

/** Input of [CircuitZkProver.prove]. The witness values are private: the prover must not log them. */
class CircuitZkProveInput(
    val circuit: CircuitZkCircuit,
    val plan: CircuitZkPlan,
    val credentialBytes: ByteArray,
    val sessionTranscript: ByteArray,
    /** The opaque verifier id, as resolved by the caller; null when no planned function uses one. */
    val verifierId: String?,
    val verifierContext: String?,
    /** Private inputs per function handle. */
    val witnesses: Map<String, CircuitZkFunctionWitness>,
    val signer: ZkWitnessSigner,
)

/** Output of [CircuitZkProver.prove]. */
class CircuitZkProveOutput(
    val proof: ByteArray,
    /** One result per planned function handle. */
    val results: Map<String, ResultValue>,
    /** The time the circuit used for validity checks, when it checks validity. */
    val proofTime: Instant? = null,
)

/** The proof system behind the presenter; its ABI is not defined here. */
interface CircuitZkProver {
    /** Whether this prover is a fake that produces no real proof. */
    val isFake: Boolean get() = false

    /**
     * Whether this prover can serve [plan] with [circuit]; the presenter only picks among circuits that pass.
     * Defaults to true: a prover that is not bound to a catalog registry has nothing to add.
     */
    fun admits(circuit: CircuitZkCircuit, plan: CircuitZkPlan): Boolean = true

    /** Proves [input]. A refusal or failure is an exception; the presenter turns any into a silent refusal. */
    suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput
}

/**
 * Answers a validated `circuit_zk` request: assembles and encodes the
 * `CircuitZkPresentation` for the `vp_token`. Modelled on [ZkMdocPresentation]:
 * the device key never comes here (a proof that binds one calls the
 * [ZkWitnessSigner]), and [releaseProvers] drops resident prover memory.
 *
 * Every step fails closed with a [CircuitZkError] that carries no
 * description, and no private input is logged.
 */
class CircuitZkPresenter(
    private val prover: CircuitZkProver,
    private val circuits: CircuitZkCircuitSource,
    private val validator: CircuitZkRequestValidator,
    private val witnessProvider: CircuitZkWitnessProvider,
    handlers: List<CircuitZkFunctionHandler> = DEFAULT_CIRCUIT_ZK_HANDLERS,
    private val residency: ZkProverResidency? = null,
    private val serving: org.siros.sdk.credentials.CircuitZkServing? = org.siros.sdk.credentials.SharedCircuitZkServing,
) {
    private val handlersById = handlers.associateBy { it.functionId }

    private var proofSystemPreference: List<String> = emptyList()

    /**
     * The app's ordered allow-list of proof systems ([org.siros.sdk.credentials.ZkProofSystemPreference]); empty (the default) is the
     * catalog order. Returns this presenter.
     */
    fun withProofSystemPreference(preference: List<String>): CircuitZkPresenter {
        proofSystemPreference = preference.toList()
        return this
    }

    /** True when the prover is a fake: a host reports this in its capability descriptor. */
    val usesFakeProver: Boolean get() = prover.isFake

    /** See [ZkMdocPresentation.releaseProvers]. */
    fun releaseProvers() {
        residency?.release()
    }

    /** One request. */
    class Request(
        /** The stored credential bytes (an mdoc, as the wallet persists it). */
        val credentialBytes: ByteArray,
        val plan: CircuitZkPlan,
        /** The opaque `verifier_id`, already resolved by a verifier-id source. */
        val verifierId: String?,
        val verifierContext: String? = null,
        /** The session transcript the proof is bound to, built by the caller. */
        val sessionTranscript: ByteArray,
        /**
         * The credential's issuer-delivered `secret_seed` (16 bytes), for the configs that derive from it;
         * null when the wallet holds none. The presenter does not trust it: it refuses unless
         * `SHA256(secretSeed)` equals the credential's `ssc`, works on its own copy and zeroes that copy
         * afterwards. The caller owns this array and should zero it after [present]. Never put it in a
         * log, a history record or a response.
         */
        val secretSeed: ByteArray? = null,
        /**
         * The Credential Issuer Identifier of the credential EXACTLY as the wallet stored it at issuance
         * (`credentialIssuerIdentifier`, no normalisation): the holder's `private_seed` depends on it, so a different
         * string (a trailing slash) is a different `psc`. Null refuses a function that needs the device seed.
         */
        val issuer: String? = null,
    ) {
        override fun toString() = "CircuitZkPresenter.Request(redacted)"
    }

    /** A presentation: the `vp_token` array element and what it carries. */
    class Result(
        /** The `ZkpPresentation` (rulebook v0.4): `{system_id, proof, issuer_key_set, proof_time, results}`. */
        val presentation: CircuitZkResponsePresentation,
    ) {
        /** The JSON string to put in the `vp_token` array of the query: base64url (no padding) of the CBOR presentation. */
        val json: kotlinx.serialization.json.JsonPrimitive get() = presentation.toJson()
        val results: Map<String, ResultValue> get() = presentation.results

        /** The `system_id` stated. */
        val systemId: String get() = presentation.systemId
    }

    /**
     * Validates, proves and assembles.
     *
     * @throws CircuitZkError.InvalidRequest for a request that is malformed independently of the holder's data.
     * @throws CircuitZkError.AccessDenied for every other refusal, with no description.
     */
    suspend fun present(request: Request, signer: ZkWitnessSigner): Result {
        try {
            return presentInternal(request, signer)
        } catch (e: CircuitZkError) {
            throw e
        } catch (e: kotlinx.coroutines.CancellationException) {
            // A cancelled or timed-out caller gets cancellation, not a refusal.
            throw e
        } catch (e: Throwable) {
            // Any failure of a collaborator (prover, witness provider, circuit source) is a silent refusal; an
            // OutOfMemoryError or a missing native library included, never a crash of the host.
            Timber.w("circuit_zk presentation failed (${e.javaClass.simpleName})")
            throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
        }
    }

    private suspend fun presentInternal(request: Request, signer: ZkWitnessSigner): Result {
        // Our own copy of the seed, zeroed on every exit path (the caller's array is theirs to zero).
        val seed = request.secretSeed?.copyOf()
        try {
            return presentWithSeed(request, seed, signer)
        } finally {
            seed?.fill(0)
        }
    }

    private suspend fun presentWithSeed(request: Request, seed: ByteArray?, signer: ZkWitnessSigner): Result {
        val plan = request.plan
        if (plan.functions.isEmpty() || plan.functions.map { it.handle }.toSet().size != plan.functions.size) {
            throw CircuitZkError.InvalidRequest()
        }
        val document = try {
            MdocCbor.parseStoredCredential(request.credentialBytes)
        } catch (e: Exception) {
            throw CircuitZkError.InvalidRequest()
        }
        // An empty verifier id is no identity: it would hash to a pseudonym every verifier-less request shares.
        if (request.verifierId != null && request.verifierId.isEmpty()) throw CircuitZkError.InvalidRequest()
        val functionHandlers = plan.functions.map { handlersById[it.id] ?: throw CircuitZkError.InvalidRequest() }

        // 1. Defence in depth: the validator already ran at matching time.
        if (validator.validate(plan) !is CircuitZkVerdict.Ok) refuse(CircuitZkStep.VALIDATE)

        // 2. The credential must be the type the plan asked for.
        val wanted = ((plan.raw["meta"] as? kotlinx.serialization.json.JsonObject)?.get("doctype_value")
            as? kotlinx.serialization.json.JsonPrimitive)?.content
        if (wanted == null || wanted != document.docType) refuse(CircuitZkStep.DOCTYPE)

        // 2b. Each function checks that the credential's structure is one it can be proved over (a circuit that
        // binds a namespace layout refuses a decoy or extra namespace here, before anything private is touched).
        for ((function, handler) in plan.functions.zip(functionHandlers)) {
            if (!handler.admitsCredential(function, document)) refuse(CircuitZkStep.NAMESPACE)
        }

        // 3. Wallet-held private inputs; a function whose witness cannot be supplied is refused.
        val witnesses = LinkedHashMap<String, CircuitZkFunctionWitness>()
        val needs = LinkedHashMap<String, Set<CircuitZkWitnessKind>>()
        for ((function, handler) in plan.functions.zip(functionHandlers)) {
            val n = handler.witnessNeeds(function)
            needs[function.handle] = n
            // The secret seed comes with the request, not from the provider: it must be present and exactly
            // 16 bytes (its commitment is checked in step 4b).
            if (CircuitZkWitnessKind.SECRET_SEED in n && (seed == null || seed.size != SECRET_SEED_BYTES)) refuse(CircuitZkStep.WITNESS)
            val fromProvider = witnessProvider.witness(function, n - CircuitZkWitnessKind.SECRET_SEED, document.docType, request.issuer) ?: refuse(CircuitZkStep.WITNESS)
            witnesses[function.handle] = if (CircuitZkWitnessKind.SECRET_SEED in n) {
                CircuitZkFunctionWitness(fromProvider.privateSeed, fromProvider.userValue, seed)
            } else {
                fromProvider
            }
        }

        // 4. The credential's commitments must be the ones this wallet holds: each function checks its own (a
        // value derived on this device, or one the issuer delivered: never used on trust, a mismatch refuses
        // before any prover runs).
        for ((function, handler) in plan.functions.zip(functionHandlers)) {
            when (handler.commitmentCheck(function, document, witnesses.getValue(function.handle), witnessProvider, request.issuer)) {
                CircuitZkCommitmentCheck.HOLDS -> Unit
                CircuitZkCommitmentCheck.DEVICE_COMMITMENT_FAILS -> refuse(CircuitZkStep.COMMITMENT)
                CircuitZkCommitmentCheck.DELIVERED_COMMITMENT_FAILS -> refuse(CircuitZkStep.SECRET_COMMITMENT)
            }
        }

        // 5. Data-dependent predicates: a false one means no presentation.
        for ((function, handler) in plan.functions.zip(functionHandlers)) {
            if (!handler.holds(function, document)) refuse(CircuitZkStep.PREDICATE)
        }

        // 6. A circuit that fits the plan, and that the request OFFERED: a response states a `system_id` from the request's
        // `system_id_values` (and a proof system the request accepts), so a request that offered none (or none of ours) cannot be answered.
        val filter = plan.circuitFilter ?: refuse(CircuitZkStep.CIRCUIT)
        val offered = circuits.circuits().filter {
            it.supports(plan, document.docType, serving) && prover.admits(it, plan) && filter.offeredCircuitId(it) != null && filter.offersProofSystem(it)
        }
        // The app's preference narrows and orders the verifier's offered set; it never widens it.
        val circuit = org.siros.sdk.credentials.ZkProofSystemPreference.order(offered, proofSystemPreference).firstOrNull()
            ?: refuse(CircuitZkStep.CIRCUIT)
        Timber.i("circuit_zk proof system chosen: ${circuit.offeredProofSystem} (circuit ${circuit.circuitId}); preference in force: $proofSystemPreference")

        // 6b. The issuer key set the response must carry: ONLY the Document Signer (leaf) certificate, the first of the
        // credential's x5chain (rulebook v0.4: a set of DS certificates, not a chain; the circuits take one issuer key Q, the
        // leaf's). Never the intermediates or the root. Checked before any proof is made.
        val leaf = issuerChain(document)?.firstOrNull()
            ?.takeIf { it.size in 1..CircuitZkResponsePresentation.MAX_KEY_BYTES }
            ?: run {
                Timber.w("circuit_zk presentation refused (step=${CircuitZkStep.ISSUER_KEY})")
                throw CircuitZkError.AccessDenied(CircuitZkStep.ISSUER_KEY, CircuitZkRefusalReason.ISSUER_KEY_UNUSABLE)
            }
        val chain = listOf(leaf)

        // 7. Prove.
        val output = try {
            val out = prover.prove(
                CircuitZkProveInput(
                    circuit = circuit,
                    plan = plan,
                    credentialBytes = request.credentialBytes,
                    sessionTranscript = request.sessionTranscript,
                    verifierId = request.verifierId,
                    verifierContext = request.verifierContext,
                    witnesses = witnesses,
                    signer = signer,
                ),
            )
            if (out.proof.isEmpty()) refuse(CircuitZkStep.PROVE)
            if (out.results.keys != plan.functions.map { it.handle }.toSet()) refuse(CircuitZkStep.PROVE)
            out
        } finally {
            // The derived private_seed (and the user value) live only for this proof.
            witnesses.values.forEach { it.privateSeed?.fill(0) }
        }

        // 8. Assemble. Every planned function has a result (none skipped), and the DS certificate travels with the proof:
        // the verifier validates it through its trust evaluation and takes the issuer key from it.
        val handles = plan.functions.map { it.handle }.toSet()
        if (output.results.keys != handles) refuse(CircuitZkStep.BUILD)
        val presentation = try {
            CircuitZkResponsePresentation(
                systemId = filter.offeredCircuitId(circuit) ?: refuse(CircuitZkStep.BUILD),
                proof = output.proof,
                issuerKeySet = chain,
                // The prover's own time input when it has one (it proved with it); else the one function that renders the
                // device clock. Required for mso_mdoc, optional for other source formats.
                proofTime = output.proofTime?.let(ProofTime::render)
                    ?: if (plan.sourceFormat == "mso_mdoc") ProofTime.render(Instant.now()) else null,
                results = output.results,
            )
        } catch (e: IllegalArgumentException) {
            refuse(CircuitZkStep.BUILD)
        }
        return Result(presentation)
    }

    private fun refuse(step: CircuitZkStep): Nothing {
        Timber.w("circuit_zk presentation refused (step=$step)")
        throw CircuitZkError.AccessDenied(step)
    }

    /** The Document Signer certificate chain: `issuerAuth`'s unprotected header `x5chain` (label 33). */
    private fun issuerChain(document: DocumentMdoc): List<ByteArray>? {
        val auth = document.issuerSigned.issuerAuth
        if (auth.type != CBORType.Array || auth.size() < 2) return null
        val unprotected = auth[1]
        if (unprotected.type != CBORType.Map) return null
        val x5chain: CBORObject = unprotected[CBORObject.FromObject(33)] ?: return null
        val certs = when (x5chain.type) {
            CBORType.ByteString -> listOf(x5chain.GetByteString())
            CBORType.Array -> (0 until x5chain.size()).map { i ->
                if (x5chain[i].type != CBORType.ByteString) return null
                x5chain[i].GetByteString()
            }
            else -> return null
        }
        return certs.takeIf { it.isNotEmpty() }
    }
}

/**
 * A prover that produces no real proof, for tests and development. It
 * computes the pseudonym with [NymPseudonym] for every config, from the
 * witness the presenter supplies: the holder's `private_seed` for the psc
 * configs, the (already commitment-checked) `secret_seed` for the ssc configs.
 * It reports the predicates as `true` (the presenter has already checked them)
 * and puts a recognisable dummy in `proof`. It refuses a config whose seed is
 * absent from the witness, and anything it does not know.
 *
 * Never registered by default: a host gets one only by calling [optIn], and
 * [isFake] (reported through [CircuitZkPresenter.usesFakeProver]) says so.
 */
class FakeCircuitZkProver private constructor(private val predicates: org.siros.sdk.credentials.PredicateFunctions) : CircuitZkProver {
    override val isFake: Boolean get() = true

    override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
        val results = LinkedHashMap<String, ResultValue>()
        for (function in input.plan.functions) {
            results[function.handle] = when (function.id) {
                PseudonymFunctionHandler.functionId -> {
                    val config = (function.params["config"] as? kotlinx.serialization.json.JsonPrimitive)?.content
                        ?: throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
                    val info = NymPseudonym.describe(config)
                    val witness = input.witnesses[function.handle]
                    val seed = when (info?.seedKind) {
                        org.siros.sdk.credentials.NymSeedKind.PRIVATE -> witness?.privateSeed
                        org.siros.sdk.credentials.NymSeedKind.SECRET -> witness?.secretSeed
                        null -> null
                    }
                    if (info == null || witness == null || seed == null) throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
                    ResultValue.Pseudonym(
                        NymPseudonym.derive(
                            config = config,
                            seed = seed,
                            proverInput = if (info.userValue) witness.userValue else null,
                            verifierId = if (info.verifierId) input.verifierId else null,
                            verifierContext = if (info.verifierContext) input.verifierContext else null,
                        ),
                    )
                }
                else -> if (function.id in predicates.ids) ResultValue.Predicate else throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
            }
        }
        return CircuitZkProveOutput(proof = DUMMY_PROOF.copyOf(), results = results)
    }

    companion object {
        /** The recognisable dummy placed in `proof`. */
        val DUMMY_PROOF: ByteArray = "FAKE-CIRCUIT-ZK-PROOF-NOT-A-PROOF".toByteArray(Charsets.US_ASCII)

        /** The only way to get a fake prover: an explicit opt-in, for tests and development only. */
        fun optIn(predicates: org.siros.sdk.credentials.PredicateFunctions = org.siros.sdk.credentials.PredicateFunctions.DEFAULT): FakeCircuitZkProver = FakeCircuitZkProver(predicates)
    }
}
