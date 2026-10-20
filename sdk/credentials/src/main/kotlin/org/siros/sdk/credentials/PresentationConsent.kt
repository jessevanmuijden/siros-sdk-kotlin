// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.time.LocalDate
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * How the verifier is named to the user and to a host, from authenticated sources only.
 *
 * @property label The display name: the trust entity name, else the verified client-id display name of a
 *   SIGNED request, else the platform-attested origin. Never an unauthenticated string.
 * @property trustFramework The trust framework that evaluated the verifier. For hosts and tests: it is
 *   technical and never part of the default dialog text.
 * @property trustIdentifier The normalized identifier the trust decision was about. Same remark.
 * @property verifierId The `verifier_id` the pseudonym is scoped to, verbatim; null when none is used.
 * @property verifierIdType The `verifier_id_type` of [verifierId]. Never part of the default dialog text.
 * @property intermediaryRisk The policy decision point flagged the verifier as acting for another party. PROVISIONAL:
 *   read from the PDP's `context.intermediary_risk` (boolean, optional) until go-trust defines the signal.
 */
data class ConsentVerifier(
    val label: String,
    val trustFramework: String? = null,
    val trustIdentifier: String? = null,
    val verifierId: String? = null,
    val verifierIdType: String? = null,
    val intermediaryRisk: Boolean = false,
)

/** The credential that will be proved: its display name and issuer name, when known. */
data class CredentialRef(val name: String?, val issuer: String?)

/** What the verifier will receive for one credential of the request. */
data class ConsentEntry(val credential: CredentialRef, val items: List<ConsentItem>)

/**
 * Everything a host needs to ask for consent to a `circuit_zk` presentation. It says what the verifier
 * will RECEIVE. It never carries a claim value, a seed, a proof or a pseudonym value.
 *
 * One request covers ALL queries of the DC API request: [entries] has one element per query, in order.
 *
 * The SDK owns the wording (see the wallet's `PresentationConsentText`); a host renders that text, or
 * builds its own from the items.
 */
data class PresentationConsentRequest(
    val verifier: ConsentVerifier,
    val entries: List<ConsentEntry>,
    /** Whether the DC API request was signed (a `circuit_zk` request must be); stated by the caller, never assumed by the builder. */
    val requestSigned: Boolean,
    /** The locale tag the SDK text was resolved for. */
    val locale: String,
)

/** The scope a pseudonym is derived under. */
enum class PseudonymScope(val wire: String) {
    /** One pseudonym per verifier (`verifier_id`). */
    PER_VERIFIER("per_verifier"),

    /** One pseudonym per verifier and `verifier_context`. */
    PER_VERIFIER_CONTEXT("per_verifier_context"),

    /** The same pseudonym at every verifier. */
    CROSS_SITE("cross_site"),
}

/** The age bound(s) of an `age_check`, in the form a user reads them; computed once here so hosts do not redo date maths. */
sealed interface AgeForm {
    /** Born from [from] to [to] (inclusive), that is [minYears]..[maxYears] years old. */
    data class Between(val from: String, val to: String, val minYears: Int, val maxYears: Int) : AgeForm

    /** At least [years] years old (only an upper bound on the birth date). */
    data class AtLeast(val years: Int) : AgeForm

    /** At most [years] years old (only a lower bound on the birth date). */
    data class AtMost(val years: Int) : AgeForm
}

/** One thing the verifier will receive. */
sealed interface ConsentItem {
    /** The value of a claim, disclosed (the legacy `zk-claim-disclosure-v1` function only). Carries the NAME, never the value. */
    data class Claim(val name: String) : ConsentItem

    /**
     * What the verifier LEARNS about [claim]: that the claim satisfies every one of [conditions] (all of one
     * [valueType]). Never the claim's value. [age] is set for a function declared as an age (`age_check`): the
     * human form (born between / at least / at most) computed once here, so hosts do not redo date maths.
     */
    data class Predicate(
        val functionId: String,
        val claim: ClaimRef,
        val valueType: ValueType,
        val conditions: List<Condition>,
        val age: AgeForm?,
    ) : ConsentItem

    /** A rulebook pseudonym under [config]; [verifierId] and [verifierContext] are what it is scoped by. */
    data class Pseudonym(
        val config: String,
        val scope: PseudonymScope,
        val remappableByIssuer: Boolean,
        val crossSite: Boolean,
        val verifierId: String?,
        val verifierContext: String?,
    ) : ConsentItem

    /** The legacy proof system's pseudonym (`zk-claim-disclosure-v1` with `pseudonym: true`). */
    data class LegacyPseudonym(val verifierContext: String?) : ConsentItem
}

/**
 * Builds a [PresentationConsentRequest] from what phase 1 of a `circuit_zk` request established. Pure.
 * The cross-SDK vectors (`spec/circuit-zk-consent-vectors.json`) pin its output.
 */
object ConsentRequests {
    /** One query of the request: its plan, the credential that will be proved, and the `verifier_id` resolved for it (null when unused). */
    class Query(
        val plan: CircuitZkPlan,
        val credential: CredentialRef,
        val verifierId: String?,
        /** The credential's own claim display metadata: labels for the claims a predicate is about. */
        val claims: List<ClaimMeta> = emptyList(),
        /** The credential's doctype namespace (the one a predicate's claim path is relative to), when known. */
        val namespace: String? = null,
    )

    /** What the trust decision said about the verifier; each field is null when the PDP did not supply it. */
    class Trust(val entityName: String?, val framework: String?, val identifier: String?, val intermediaryRisk: Boolean = false)

    /**
     * The display label: the trust entity name, else the verified client-id display name (pass null for an
     * unsigned request: its client id is unauthenticated), else the platform-attested origin.
     */
    fun label(entityName: String?, verifiedClientIdDisplayName: String?, attestedOrigin: String): String =
        entityName?.takeIf { it.isNotBlank() } ?: verifiedClientIdDisplayName?.takeIf { it.isNotBlank() } ?: attestedOrigin

    /**
     * The request for [queries], or null when [queries] is empty or any query holds something that cannot be shown
     * (see [ConsentItems.build]). [verifierIdType] is the type [Query.verifierId] was resolved under. [requestSigned]
     * is required: there is deliberately no default.
     */
    fun build(
        queries: List<Query>,
        trust: Trust,
        verifiedClientIdDisplayName: String?,
        attestedOrigin: String,
        verifierIdType: String?,
        requestSigned: Boolean,
        today: LocalDate,
        locale: String,
        predicates: PredicateFunctions = PredicateFunctions.DEFAULT,
    ): PresentationConsentRequest? {
        if (queries.isEmpty()) return null
        val entries = queries.map { q -> ConsentEntry(q.credential, ConsentItems.build(q.plan, q.verifierId, today, q.claims, predicates, q.namespace) ?: return null) }
        return PresentationConsentRequest(
            verifier = ConsentVerifier(
                label = label(trust.entityName, verifiedClientIdDisplayName, attestedOrigin),
                trustFramework = trust.framework,
                trustIdentifier = trust.identifier,
                verifierId = queries.firstNotNullOfOrNull { it.verifierId },
                verifierIdType = verifierIdType,
                intermediaryRisk = trust.intermediaryRisk,
            ),
            entries = entries,
            requestSigned = requestSigned,
            locale = locale,
        )
    }
}

/**
 * Builds the [ConsentItem]s of one `circuit_zk` plan. Pure: no credential, no clock but [today].
 *
 * Only the configs the wallet can answer are modelled; for any other function or config the result is
 * null and the caller refuses the request (it must not ask for consent to something it cannot do).
 */
object ConsentItems {
    private class Config(val scope: PseudonymScope, val remappable: Boolean)

    /** Per-verifier pseudonym configs the wallet answers. `-ssc` derives from an issuer-delivered seed, so the issuer can recompute it. */
    private val CONFIGS = mapOf(
        "known-offender-matching-ssc" to Config(PseudonymScope.PER_VERIFIER, remappable = true),
        "known-offender-matching-psc" to Config(PseudonymScope.PER_VERIFIER, remappable = false),
    )

    /** Whether [config] is one this builder models (and so the wallet will answer). */
    fun supportsConfig(config: String): Boolean = config in CONFIGS

    /** The items of [plan], in the plan's order, or null when any function is not one that can be shown. */
    fun build(
        plan: CircuitZkPlan,
        verifierId: String?,
        today: LocalDate,
        claims: List<ClaimMeta> = emptyList(),
        predicates: PredicateFunctions = PredicateFunctions.DEFAULT,
        namespace: String? = null,
    ): List<ConsentItem>? {
        val items = ArrayList<ConsentItem>()
        for (f in plan.functions) {
            when (f.id) {
                CircuitZkRuleSet.PSEUDONYM -> {
                    val config = text(f, "config") ?: return null
                    val c = CONFIGS[config] ?: return null
                    val context = text(f, "verifier_context")
                    if (c.scope == PseudonymScope.PER_VERIFIER && context != null) return null
                    if (verifierId.isNullOrEmpty()) return null
                    items += ConsentItem.Pseudonym(config, c.scope, c.remappable, c.scope == PseudonymScope.CROSS_SITE, verifierId, context)
                }
                CircuitZkLegacyDisclosure.FUNCTION_ID -> {
                    val legacy = CircuitZkLegacyDisclosure.parse(f) ?: return null
                    legacy.claims.forEach { items += ConsentItem.Claim(it) }
                    if (legacy.pseudonym) items += ConsentItem.LegacyPseudonym(legacy.verifierContext)
                }
                // Any other function must be a declared predicate function: one we cannot describe is refused.
                else -> items += predicates.item(f, claims, today, namespace) ?: return null
            }
        }
        return items.takeIf { it.isNotEmpty() }
    }

    private fun text(f: CircuitZkFunction, key: String): String? =
        (f.params[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
}
