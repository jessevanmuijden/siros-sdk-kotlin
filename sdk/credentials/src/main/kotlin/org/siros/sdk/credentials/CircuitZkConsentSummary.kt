// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/** A pseudonym is requested, under [config]. It carries no value. */
data class PseudonymSummary(val config: String)

/** An age range is requested: born on or after [ge] and/or on or before [le] (RFC 3339 full-dates, as requested). */
data class AgeRangeSummary(val ge: String?, val le: String?)

/**
 * What a host may show for a `circuit_zk` request: built from the plan, never
 * from the credential, so it contains no credential value.
 *
 * @property verifierLabel How the verifier is named to the user. The caller
 *   must take it from authenticated sources only (the trust decision, the
 *   verified client identifier, the platform-attested origin), never from
 *   unauthenticated request content.
 */
data class CircuitZkConsentSummary(
    val pseudonym: PseudonymSummary?,
    val ageRange: AgeRangeSummary?,
    val verifierLabel: String,
) {
    companion object {
        /** The summary of [plan] for a verifier named [verifierLabel]. */
        fun from(plan: CircuitZkPlan, verifierLabel: String): CircuitZkConsentSummary {
            fun str(f: CircuitZkFunction, key: String) = (f.params[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
            val pseudonym = plan.functions.firstOrNull { it.id == CircuitZkRuleSet.PSEUDONYM }
                ?.let { f -> str(f, "config")?.let(::PseudonymSummary) }
            val age = plan.functions.firstOrNull { it.id == CircuitZkRuleSet.AGE_CHECK }
                ?.let { f -> AgeRangeSummary(str(f, "ge"), str(f, "le")) }
            return CircuitZkConsentSummary(pseudonym, age, verifierLabel)
        }
    }
}
