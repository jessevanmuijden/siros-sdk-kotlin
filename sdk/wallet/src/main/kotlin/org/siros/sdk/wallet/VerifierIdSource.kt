// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import org.siros.sdk.wallet.dcapi.DCAPIRequest

/**
 * What a [VerifierIdSource] may read: only authenticated inputs. The request
 * has had its signature verified (client id, `x5c` chain, `verifier_info`);
 * [trust] is the policy decision, including its response context; [origin] is
 * what the platform attested for the caller.
 */
class VerifierIdContext(
    val request: DCAPIRequest,
    val trust: TrustResult,
    val origin: String,
)

/**
 * Produces the opaque `verifier_id` string for one `verifier_id_type`. The
 * wallet does not know how verifiers are named: adding a source is
 * registering an implementation. A registered source is consulted only when
 * its [type] is in the wallet's supported-type list, after the default
 * [AuthZENSource] for that type.
 */
interface VerifierIdSource {
    /** The `verifier_id_type` this source can produce. */
    val type: String

    /** The identifier for [context], or null to decline (the next registered source is tried). */
    suspend fun resolve(context: VerifierIdContext): String?
}

/** A resolved `verifier_id`: the value, verbatim, and the `verifier_id_type` it was resolved under. */
data class ResolvedVerifierId(val type: String, val id: String)

/**
 * Resolves the opaque `verifier_id` for a pseudonym from the wallet's ORDERED
 * [supportedTypes] (see [VerifierIdTypeOrder]; the trust framework agrees the
 * type, the request does not choose it).
 *
 * For each type in order, the identifier is looked up in:
 *  1. the policy decision point's answer, [AuthZENSource] (the default source,
 *     built implicitly for every supported type), then
 *  2. any [extraSources] registered for that type, in the order given (for
 *     example a host's own source).
 * The first non-null identifier wins, and the first type that yields one ends
 * the search. A type for which nothing resolves (absent, or conflicting
 * DISTINCT values) is skipped and the next type is tried.
 *
 * Fail closed: with no supported type, or when no type resolves, the result is
 * null and the caller refuses. The type a request names is not an input.
 */
class VerifierIdRegistry(
    supportedTypes: List<String> = VerifierIdTypeOrder.DEFAULT,
    private val extraSources: List<VerifierIdSource> = emptyList(),
) {
    /** The supported types, in priority order. */
    val supportedTypes: List<String> = VerifierIdTypeOrder.require(supportedTypes).toList()

    /** The identifier (and its type) of the first supported type that resolves, or null. A source that throws is skipped. */
    suspend fun resolve(context: VerifierIdContext): ResolvedVerifierId? {
        for (type in supportedTypes) {
            for (source in sourcesFor(type)) {
                val id = try {
                    source.resolve(context)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    null
                }
                if (id != null) return ResolvedVerifierId(type, id)
            }
        }
        return null
    }

    private fun sourcesFor(type: String): List<VerifierIdSource> =
        listOf<VerifierIdSource>(AuthZENSource(type)) + extraSources.filter { it.type == type }
}

/**
 * Reads the identifier from the policy decision point's response. go-trust
 * (#203) returns `context.verifier_ids` as a LIST of objects
 * `{"verifier_id_type": ..., "verifier_id": ..., "basis": ...}` (`basis` is
 * informational and ignored here). The wallet does not narrow the PDP's answer
 * (no `context.verifier_id_type` is sent), so the list may hold every type the
 * PDP knows. Among the entries whose `verifier_id_type`
 * equals [type], duplicates of one value are one identifier; if several DISTINCT
 * values exist the source declines rather than choose, because the value is
 * hashed into a pseudonym and a guess would be a different pseudonym. Malformed
 * entries and empty `verifier_id`s are ignored. Declines when the context, the
 * member (not a list) or a matching entry is absent. Type names and value forms are
 * defined by the rulebook / trust framework, produced by the PDP, and opaque here (the
 * wallet hashes the value byte-for-byte and never lower-cases, trims or strips it): the names in the wallet's list must match what the
 * PDP returns, and go-trust is aligning to the trust framework (for `x509_san_dns` the
 * value is the PREFIXED Client Identifier, `x509_san_dns:<dns name>`, as in rulebook v0.4, derived by the PDP). The wallet derives
 * nothing itself from the request's client id or `x5c` chain; the PDP is the single
 * default source of verifier ids.
 */
class AuthZENSource(override val type: String) : VerifierIdSource {
    override suspend fun resolve(context: VerifierIdContext): String? {
        val ids = context.trust.context?.get("verifier_ids") as? JsonArray ?: return null
        return ids.asSequence()
            .mapNotNull { it as? JsonObject }
            .filter { (it["verifier_id_type"] as? JsonPrimitive)?.takeIf { p -> p.isString }?.contentOrNull == type }
            .mapNotNull { (it["verifier_id"] as? JsonPrimitive)?.takeIf { p -> p.isString }?.contentOrNull?.takeIf { v -> v.isNotEmpty() } }
            .distinct().toList().singleOrNull()
    }
}

/**
 * The wallet's default `circuit_zk` validator: the rulebook rules, which ignore a `verifier_id_type` the
 * request still carries. The wallet picks the type itself from [WalletConfig.circuitZkVerifierIdTypes], so the type
 * a request names is neither a selection input nor a reason to refuse.
 */
internal fun defaultCircuitZkValidator(
    circuits: org.siros.sdk.credentials.CircuitZkCircuitSource?,
    /** The predicate functions the wallet declares: their per-function rules come from the same declarations as consent. */
    predicates: org.siros.sdk.credentials.PredicateFunctions = org.siros.sdk.credentials.PredicateFunctions.DEFAULT,
): org.siros.sdk.credentials.CircuitZkRequestValidator =
    org.siros.sdk.credentials.RulebookCircuitZkValidator(
        // The rulebook rules plus the proposed legacy claim-disclosure function (see CircuitZkLegacyDisclosure).
        rules = org.siros.sdk.credentials.CircuitZkRuleSet.rulebookV04(predicates = predicates)
            .withFunction(org.siros.sdk.credentials.CircuitZkLegacyDisclosure.FUNCTION_ID, org.siros.sdk.credentials.CircuitZkLegacyDisclosure.RULES),
        circuits = circuits,
    )
