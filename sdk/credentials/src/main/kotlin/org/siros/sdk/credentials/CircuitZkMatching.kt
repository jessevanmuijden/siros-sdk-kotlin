// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/** One function of a `circuit_zk` request: its id, the handle its result is returned under, and its raw parameters. */
data class CircuitZkFunction(
    val id: String,
    val handle: String,
    val params: JsonObject = JsonObject(emptyMap()),
)

/**
 * A request's circuit list: the verifier's two independent lists
 * (`proof_system_values`, `system_id_values`), kept as two lists. A circuit is admitted when
 * its system is in [proofSystems] AND its id (or an alias of it) is in [circuitIds]; a list the
 * verifier did not send is null and constrains nothing, and a list sent empty admits nothing.
 *
 * They are deliberately not expanded into the pairs they imply: both lists are verifier-controlled
 * and planned before the trust decision, so their product is an allocation an untrusted request
 * could make arbitrarily large. Membership needs only the two lists.
 */
data class CircuitZkCircuitFilter(val proofSystems: List<String>?, val circuitIds: List<String>?) {
    /** Whether [circuit] is one this filter names (its id, or one of its aliases). */
    fun admits(circuit: CircuitZkCircuit): Boolean =
        (proofSystems == null || circuit.offeredProofSystem in proofSystems) &&
            (circuitIds == null || circuit.circuitId in circuitIds || circuit.aliases.any { it in circuitIds })

    /**
     * The `circuit_id` a response must state for [circuit]: one the request OFFERED (its id, else one of its aliases). Null when
     * the request stated no circuit-id list or names neither: a response states a value from the list, and a request that
     * offered nothing cannot be answered.
     */
    fun offeredCircuitId(circuit: CircuitZkCircuit): String? {
        val ids = circuitIds ?: return null
        return circuit.circuitId.takeIf { it in ids } ?: circuit.aliases.firstOrNull { it in ids }
    }

    /** Whether the request accepts [circuit]'s proof system: `proof_system_values` is OPTIONAL, so no list accepts any. */
    fun offersProofSystem(circuit: CircuitZkCircuit): Boolean = proofSystems?.contains(circuit.offeredProofSystem) ?: true
}

/**
 * What a `circuit_zk` credential query asks for, as plain data: the matcher's
 * plan, without its types. [circuitFilter] is the verifier's own list of
 * acceptable circuits: null means the verifier named none (any circuit fits),
 * and an EMPTY list in either of its two lists means it named an empty list, which no circuit satisfies
 * (the matcher's reading). [raw] is the credential query the plan was made from.
 */
data class CircuitZkPlan(
    val functions: List<CircuitZkFunction>,
    val circuitFilter: CircuitZkCircuitFilter? = null,
    val raw: JsonObject = JsonObject(emptyMap()),
) {
    /**
     * `meta.source_format`: the format of the attestation the proof is made over (`mso_mdoc`; `bbs_cd` is held). The planner
     * requires it; a hand-made plan without it is read as `mso_mdoc`, the only format this SDK stores.
     */
    val sourceFormat: String?
        get() = ((raw["meta"] as? JsonObject)?.get("source_format") as? JsonPrimitive)?.takeIf { it.isString }?.content ?: "mso_mdoc"
}

/** Result of [CircuitZkPlanner.plan]. */
sealed interface CircuitZkPlanResult {
    /** The query is a well-formed `circuit_zk` request. */
    class Plan(val plan: CircuitZkPlan) : CircuitZkPlanResult

    /** It is not. The wallet matches nothing. */
    object InvalidRequest : CircuitZkPlanResult
}

/**
 * Turns a `circuit_zk` credential query into a [CircuitZkPlan]. The default
 * implementation, backed by the shared matcher, is [SharedCircuitZkPlanner];
 * tests use a fake.
 */
fun interface CircuitZkPlanner {
    /** May throw; the matcher treats that as [CircuitZkPlanResult.InvalidRequest]. */
    fun plan(credentialQuery: JsonObject, clientMetadata: JsonObject?): CircuitZkPlanResult
}

/**
 * The wallet's verdict on a plan. [AccessDenied.ruleId] is for local logs and
 * tests only and never leaves the wallet.
 */
sealed interface CircuitZkVerdict {
    /** The plan is satisfiable. */
    object Ok : CircuitZkVerdict

    /** The plan is not; the request is answered with access-denied. */
    class AccessDenied(val ruleId: String? = null) : CircuitZkVerdict
}

/** Where the rulebook's satisfiability rules run in the wallet. Injected. */
fun interface CircuitZkRequestValidator {
    /** The verdict for [plan]. */
    fun validate(plan: CircuitZkPlan): CircuitZkVerdict

    companion object {
        /** Accepts every plan, until real rules are injected. */
        val PERMISSIVE = CircuitZkRequestValidator { CircuitZkVerdict.Ok }
    }
}

/**
 * A circuit this wallet can prove with. [functions] is null when the catalog
 * does not say which functions the circuit supports, in which case no
 * function filtering applies to it.
 *
 * [credentialType] and [capabilities] are opaque strings passed to the matcher
 * when the circuit is registered (siros-dc-matcher 0.10.0) and never read by
 * the SDK. [credentialType] restricts the circuit to a request naming that
 * doctype or vct. [capabilities] is the catalog's `capabilities` object as a
 * JSON string; when present the matcher applies its capability rule and reads
 * neither [functions] nor [credentialType]. A value the matcher cannot parse
 * leaves the circuit not offered. Both null: the circuit is registered as
 * before.
 */
data class CircuitZkCircuit(
    val system: String,
    val circuitId: String,
    val docTypes: Set<String>,
    val functions: Set<String>? = null,
    val aliases: Set<String> = emptySet(),
    val credentialType: String? = null,
    val capabilities: String? = null,
    /** The catalog `systemVersion`, for a prover that gates per (system, version); null when the source does not know it. */
    val systemVersion: String? = null,
    /**
     * The proof-system identity offered to verifiers (the catalog's `proofSystem`), registered with the matcher and compared with
     * `proof_system_values`. Null for a hand-made circuit: [system] is then the identity ([offeredProofSystem]).
     */
    val proofSystem: String? = null,
) {
    /** The proof system a verifier sees: [proofSystem], else [system]. */
    val offeredProofSystem: String get() = proofSystem ?: system

    /** Whether the matcher, not this SDK, decides if the circuit serves a request: it declares [capabilities] or a [credentialType]. */
    val constrainedByMatcher: Boolean get() = capabilities != null || credentialType != null

    /**
     * Whether this circuit can prove [plan] for a credential of [docType]: the
     * doctype is one it serves, it is in the verifier's circuit list (if any),
     * and it supports every planned function (if it declares any).
     *
     * A circuit that declares [capabilities] or a [credentialType] is never
     * treated as unrestricted: this overload has no matcher to ask, so such a
     * circuit does not fit. Use the overload taking a [CircuitZkServing].
     */
    fun supports(plan: CircuitZkPlan, docType: String): Boolean = supports(plan, docType, null)

    /**
     * As [supports], with [serving] to ask the matcher whether a circuit that declares
     * [capabilities] or a [credentialType] serves the request. The matcher is the only
     * judge of that rule; without an answer (`serving` null, or it returns null) the
     * circuit does not fit.
     */
    fun supports(plan: CircuitZkPlan, docType: String, serving: CircuitZkServing?): Boolean =
        docType in docTypes && CircuitZkMatching.fits(this, plan, docType, serving)
}

/**
 * Whether the matcher offers [circuit] for a `circuit_zk` credential [query] over a credential
 * of [docType]: its capability rule, asked rather than reimplemented. Null means the matcher
 * could not answer, which callers treat as "no" (fail closed).
 */
fun interface CircuitZkServing {
    /** [query] is the credential query (a plan's [CircuitZkPlan.raw]). */
    fun serves(circuit: CircuitZkCircuit, docType: String, query: JsonObject): Boolean?
}

/**
 * [CircuitZkServing] by the shared matcher, the engine the OS picker runs: the circuit and a
 * claimless credential of the doctype are registered in a throwaway blob, and the request is
 * matched against it. No capability rule lives in this SDK.
 */
object SharedCircuitZkServing : CircuitZkServing {
    /** The matcher registrations that declare [circuit]: one per id it answers to (its id, then each alias). */
    fun capabilities(circuit: CircuitZkCircuit): List<uniffi.siros_dc_matcher_ffi.FfiCapability> =
        (listOf(circuit.circuitId) + circuit.aliases.sorted()).distinct().map { id ->
            val params = buildMap {
                put("system_id", id)
                circuit.functions?.let { put("functions", it.sorted().joinToString(",")) }
                circuit.credentialType?.let { put("credential_type", it) }
                circuit.capabilities?.let { put("capabilities", it) }
            }
            uniffi.siros_dc_matcher_ffi.FfiCapability(circuit.offeredProofSystem, params)
        }

    override fun serves(circuit: CircuitZkCircuit, docType: String, query: JsonObject): Boolean? = try {
        val blob = uniffi.siros_dc_matcher_ffi.SirosBlobBuilder().use { builder ->
            capabilities(circuit).forEach(builder::addZkpReqSystem)
            builder.addCredential(
                uniffi.siros_dc_matcher_ffi.FfiCredential(
                    id = "1", format = "mso_mdoc", doctype = docType, vct = null,
                    title = docType, subtitle = "", iconId = null, claims = emptyList(),
                ),
            )
            builder.build()
        }
        val dcql = JsonObject(mapOf("credentials" to JsonArray(listOf(query)))).toString()
        val outcome = uniffi.siros_dc_matcher_ffi.matchDcqlWithContext(blob, dcql, null)
        outcome.satisfiable && outcome.matches.any { it.credentials.isNotEmpty() }
    } catch (e: Throwable) {
        // No native library, or a request the matcher rejects: no answer, which is a no.
        null
    }
}

/** The circuits the wallet can prove with, from the circuit catalog. */
fun interface CircuitZkCircuitSource {
    /** The current circuits. */
    fun circuits(): List<CircuitZkCircuit>

    companion object {
        /**
         * The circuits of a catalog [manifest]: published, not deprecated.
         * `functions`, when a descriptor's `params` carries a string array of
         * that name, is the circuit's declared function set; otherwise what [declare]
         * says for the descriptor (a registered prover adapter's claim), otherwise null,
         * and a circuit with neither functions nor capabilities is offered for no plan.
         */
        fun fromManifest(manifest: ZkManifest, declare: (ZkCircuitDescriptor) -> Set<String>? = { null }): List<CircuitZkCircuit> = manifest.circuits
            // An entry without a `proofSystem` is not offered for zkp_req: the verifier's proof_system_values cannot name it.
            .filter { it.published && it.deprecatedAt == null && !it.proofSystem.isNullOrEmpty() }
            .map { d ->
                CircuitZkCircuit(
                    system = d.system,
                    circuitId = d.id,
                    docTypes = d.docTypes.toSet(),
                    functions = (d.params["functions"] as? JsonArray)
                        ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }?.toSet()
                        ?: declare(d),
                    aliases = d.aliases.toSet(),
                    capabilities = d.capabilities?.toString(),
                    systemVersion = d.systemVersion.ifEmpty { null },
                    proofSystem = d.proofSystem,
                )
            }
    }
}

/** The document types served through `circuit_zk`: the doctypes of every circuit. */
fun CircuitZkCircuitSource.docTypes(): Set<String> = circuits().flatMapTo(HashSet()) { it.docTypes }

/**
 * Everything the matcher needs to answer a `circuit_zk` query. Absent
 * (null) means the feature is off, and a `circuit_zk` query matches nothing.
 */
class CircuitZkSupport(
    val planner: CircuitZkPlanner,
    val validator: CircuitZkRequestValidator = CircuitZkRequestValidator.PERMISSIVE,
    val circuits: CircuitZkCircuitSource,
    /** Asks the matcher whether a circuit with `capabilities` or a `credential_type` serves a request; null: none does. */
    val serving: CircuitZkServing? = SharedCircuitZkServing,
)

internal object CircuitZkMatching {
    /**
     * The credentials matching one `circuit_zk` [query], with the plan; fails
     * closed: any planner or validator failure, an invalid plan, or no fitting
     * circuit means no candidates, never a fallback.
     */
    fun match(
        query: JsonObject,
        clientMetadata: JsonObject?,
        credentials: List<StoredCredential>,
        support: CircuitZkSupport,
    ): Pair<CircuitZkPlan?, List<StoredCredential>> = evaluate(query, clientMetadata, credentials, support).let { it.plan to it.matched }

    /** What matching one query found: the plan, the matching credentials, and (when none match) the stable [refusal] code. */
    internal class Evaluation(val plan: CircuitZkPlan?, val matched: List<StoredCredential>, val refusal: String?)

    /** Stable, content-free reasons a `zkp_req` query matches nothing; see [Evaluation.refusal]. */
    internal object Refusal {
        const val INVALID_REQUEST = "invalid-request"
        const val REQUEST_REJECTED = "request-rejected"
        const val NO_CIRCUIT = "no-circuit"
        const val SOURCE_FORMAT = "source-format"
        const val NO_CREDENTIAL = "no-credential"
    }

    fun evaluate(
        query: JsonObject,
        clientMetadata: JsonObject?,
        credentials: List<StoredCredential>,
        support: CircuitZkSupport,
    ): Evaluation {
        val plan = try {
            when (val r = support.planner.plan(query, clientMetadata)) {
                is CircuitZkPlanResult.Plan -> r.plan
                CircuitZkPlanResult.InvalidRequest -> return Evaluation(null, emptyList(), Refusal.INVALID_REQUEST)
            }
        } catch (e: Exception) {
            return Evaluation(null, emptyList(), Refusal.INVALID_REQUEST)
        }
        val verdict = try {
            support.validator.validate(plan)
        } catch (e: Exception) {
            return Evaluation(plan, emptyList(), Refusal.REQUEST_REJECTED)
        }
        if (verdict !is CircuitZkVerdict.Ok) return Evaluation(plan, emptyList(), Refusal.REQUEST_REJECTED)

        // A doctype is served when some circuit fits the plan for it; a circuit the matcher
        // constrains is asked per doctype (never assumed unrestricted).
        val docTypes = try {
            support.circuits.circuits().flatMapTo(HashSet()) { c -> c.docTypes.filter { fits(c, plan, it, support.serving) } }
        } catch (e: Exception) {
            emptySet<String>()
        }
        val wantedDoctype = ((query["meta"] as? JsonObject)?.get("doctype_value") as? JsonPrimitive)?.contentOrNull
        // The attestation a proof is made over must be of the request's `source_format`. Only `mso_mdoc` attestations are
        // stored here (`bbs_cd` is held), so a request for any other source format is not offered, never answered with a
        // credential of another format.
        if (plan.sourceFormat != "mso_mdoc") return Evaluation(plan, emptyList(), Refusal.SOURCE_FORMAT)
        val matched = credentials.filter { cred ->
            cred.format.equals("mso_mdoc", ignoreCase = true) && run {
                val docType = CredentialUtils.parseMdocDocument(cred)?.docType ?: cred.metadata?.doctype
                docType != null && docType in docTypes && (wantedDoctype == null || wantedDoctype == docType)
            }
        }
        val wanted = wantedDoctype
        val circuitServes = if (wanted == null) docTypes.isNotEmpty() else wanted in docTypes
        return Evaluation(plan, matched, if (matched.isNotEmpty()) null else if (!circuitServes) Refusal.NO_CIRCUIT else Refusal.NO_CREDENTIAL)
    }

    /**
     * Whether [circuit] fits [plan] for a credential of [docType]. The verifier's circuit list is
     * applied here. A circuit that declares `capabilities` or a `credential_type` is judged by the
     * matcher alone ([serving]; no answer is a no), and its legacy `functions` are not read, as the
     * matcher does not read them. Any other circuit is filtered by its declared `functions`; one that declares none fits no plan.
     */
    internal fun fits(circuit: CircuitZkCircuit, plan: CircuitZkPlan, docType: String, serving: CircuitZkServing?): Boolean {
        val filter = plan.circuitFilter
        // Null: the verifier named no circuits. An empty list is a list nothing is in.
        if (filter != null && !filter.admits(circuit)) return false
        if (circuit.constrainedByMatcher) {
            return try {
                serving?.serves(circuit, docType, plan.raw) == true
            } catch (e: Exception) {
                false
            }
        }
        // A circuit that declares no functions and no capabilities fits nothing: it is not offered for
        // circuit_zk unless a registered adapter claims it (see CircuitZkCircuitSource.fromManifest).
        val declared = circuit.functions ?: return false
        return plan.functions.all { it.id in declared }
    }
}

/**
 * The wallet's choice among the proof systems a verifier OFFERS: an ordered ALLOW-list the app sets in its configuration
 * (`WalletConfig.zkProofSystemPreference`). Empty (the default) means no preference: every offered circuit stays a candidate, in
 * catalog order. A non-empty list narrows the candidates to the circuits it names and orders them by it, so a system that is not
 * listed is never chosen, and when none of the offered circuits is listed there is nothing to answer with (the caller refuses, as it
 * does when nothing is offered).
 *
 * An entry names a circuit by its id or one of its aliases (`urn:circuits:vega:nym_auth:v1`) or by its proof system
 * (`vega-v1`, `longfellow-libzk-v1`).
 */
object ZkProofSystemPreference {
    /** The identities this SDK's provers know; a preference entry outside them is refused when the configuration is built. */
    val KNOWN: Set<String> = setOf(
        "urn:circuits:longfellow:nym_auth:v1",
        "urn:circuits:vega:nym_auth:v1",
        "longfellow-libzk-v1",
        "vega-v1",
        "vega-mc-p256-v1",
    )

    /** Refuses a preference that is blank, repeats an entry, or names a system this SDK does not know. */
    fun require(preference: List<String>) {
        preference.forEach {
            require(it.isNotBlank()) { "zkProofSystemPreference must not contain a blank entry" }
            require(it in KNOWN) { "zkProofSystemPreference names a proof system this wallet does not know: $it" }
        }
        require(preference.toSet().size == preference.size) { "zkProofSystemPreference must not list a system twice" }
    }

    /** Whether [entry] names [circuit]. */
    fun names(entry: String, circuit: CircuitZkCircuit): Boolean =
        entry == circuit.circuitId || entry in circuit.aliases || entry == circuit.offeredProofSystem || entry == circuit.system

    /** [candidates] (already inside the verifier's offered set) as [preference] allows and orders them; stable. */
    fun order(candidates: List<CircuitZkCircuit>, preference: List<String>): List<CircuitZkCircuit> {
        if (preference.isEmpty()) return candidates
        val ranked = candidates.mapNotNull { c ->
            val rank = preference.indexOfFirst { names(it, c) }
            if (rank < 0) null else rank to c
        }
        return ranked.sortedBy { it.first }.map { it.second }
    }
}
