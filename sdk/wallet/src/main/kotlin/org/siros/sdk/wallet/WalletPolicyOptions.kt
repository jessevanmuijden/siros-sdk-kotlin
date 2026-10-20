// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.CircuitZkCircuitSource
import org.siros.sdk.credentials.CircuitZkPlanner
import org.siros.sdk.credentials.NonDisclosurePolicy
import org.siros.sdk.keystore.FakeCircuitZkProver
import org.siros.sdk.wallet.dcapi.ExpectedOriginsMode

/** Which claims the wallet never matches, registers, presents or displays; see [WalletConfig.nonDisclosurePolicy]. */
enum class NonDisclosureMode(val policy: NonDisclosurePolicy) {
    /** The built-in protection of the nym_auth `ssc` and `psc`. */
    DEFAULT(NonDisclosurePolicy.DEFAULT),

    /** No protected claims anywhere. For testing only. */
    NONE(NonDisclosurePolicy.NONE),
}

/** Which DC API requests must be signed and name the calling origin; see [WalletConfig.dcApiRequiresSignedRequest]. */
enum class SignedRequestRule {
    /** Only a request with a `circuit_zk` query (the default). */
    CIRCUIT_ZK_ONLY,

    /** Every request. */
    ALWAYS,
}

/**
 * The wallet's request-handling policy as plain data, for a host that lets the
 * user (or a deployment) choose it: [applyTo] turns it into the [WalletConfig]
 * fields it governs. A wallet reads its [WalletConfig] once, at construction,
 * so a change takes effect on the next wallet a host builds.
 *
 * The defaults reproduce [WalletConfig]'s own defaults except [circuitZk],
 * which is off, as there.
 */
data class WalletPolicyOptions(
    val nonDisclosure: NonDisclosureMode = NonDisclosureMode.DEFAULT,
    /** Turn on `circuit_zk` (matching and presentation). Also needs a prover; see [fakeProver]. */
    val circuitZk: Boolean = false,
    val expectedOrigins: ExpectedOriginsMode = ExpectedOriginsMode.OFF,
    val signedRequest: SignedRequestRule = SignedRequestRule.CIRCUIT_ZK_ONLY,
    /**
     * Use [FakeCircuitZkProver], which produces NO real proof. For development
     * and testing only: a verifier cannot accept what it makes. Ignored unless [circuitZk].
     */
    val fakeProver: Boolean = false,
    /**
     * The ORDERED supported `verifier_id_type`s; see [WalletConfig.circuitZkVerifierIdTypes] and
     * [VerifierIdTypeOrder]. The first type for which the policy decision point supplies an identifier
     * is used. Empty means no pseudonym request can be answered. Must satisfy [VerifierIdTypeOrder.isValid].
     */
    val verifierIdTypes: List<String> = VerifierIdTypeOrder.DEFAULT,
) {
    init {
        VerifierIdTypeOrder.require(verifierIdTypes)
    }

    /**
     * [base] with this policy applied. [planner] and [circuits] are what
     * `circuit_zk` needs besides a prover; they are only used when [circuitZk]
     * is on. The prover of [base] is kept unless [fakeProver] selects the fake
     * one, so a host can combine these options with its own prover. With
     * neither the wallet's default applies, the catalog prover, which refuses every
     * request until a native prover is supplied ([WalletConfig.circuitZkNativeProver]).
     */
    fun applyTo(
        base: WalletConfig,
        planner: CircuitZkPlanner? = null,
        circuits: CircuitZkCircuitSource? = null,
    ): WalletConfig = base.copy(
        nonDisclosurePolicy = nonDisclosure.policy,
        dcApiExpectedOrigins = expectedOrigins,
        dcApiRequiresSignedRequest = when (signedRequest) {
            SignedRequestRule.CIRCUIT_ZK_ONLY -> org.siros.sdk.wallet.dcapi.DCAPIRequestRules.DEFAULT_REQUIRES_SIGNED_REQUEST
            SignedRequestRule.ALWAYS -> ALWAYS_SIGNED
        },
        circuitZk = circuitZk,
        circuitZkPlanner = if (circuitZk) planner else null,
        circuitZkCircuits = if (circuitZk) circuits else null,
        circuitZkProver = if (circuitZk && fakeProver) FakeCircuitZkProver.optIn() else base.circuitZkProver,
        circuitZkVerifierIdTypes = verifierIdTypes,
    )

    /**
     * The options as flat strings, for a host that persists them (shared
     * preferences, a settings file). [fromStored] reads them back.
     */
    fun toStored(): Map<String, String> = mapOf(
        KEY_NON_DISCLOSURE to nonDisclosure.name,
        KEY_CIRCUIT_ZK to circuitZk.toString(),
        KEY_EXPECTED_ORIGINS to expectedOrigins.name,
        KEY_SIGNED_REQUEST to signedRequest.name,
        KEY_FAKE_PROVER to fakeProver.toString(),
        KEY_VERIFIER_ID_TYPES to VerifierIdTypeOrder.toStored(verifierIdTypes),
    )

    companion object {
        private const val KEY_NON_DISCLOSURE = "non_disclosure"
        private const val KEY_CIRCUIT_ZK = "circuit_zk"
        private const val KEY_EXPECTED_ORIGINS = "expected_origins"
        private const val KEY_SIGNED_REQUEST = "signed_request"
        private const val KEY_FAKE_PROVER = "fake_prover"
        private const val KEY_VERIFIER_ID_TYPES = "verifier_id_types"

        private val ALWAYS_SIGNED: (kotlinx.serialization.json.JsonObject?) -> Boolean = { true }

        /**
         * Reads what [toStored] wrote, through [get]. A value that is missing or not
         * recognised falls back to the default for that one option, so a stale or
         * damaged setting never blocks the wallet from starting.
         */
        fun fromStored(get: (String) -> String?): WalletPolicyOptions {
            val d = WalletPolicyOptions()
            return WalletPolicyOptions(
                nonDisclosure = get(KEY_NON_DISCLOSURE).asEnum<NonDisclosureMode>() ?: d.nonDisclosure,
                circuitZk = get(KEY_CIRCUIT_ZK)?.toBooleanStrictOrNull() ?: d.circuitZk,
                expectedOrigins = get(KEY_EXPECTED_ORIGINS).asEnum<ExpectedOriginsMode>() ?: d.expectedOrigins,
                signedRequest = get(KEY_SIGNED_REQUEST).asEnum<SignedRequestRule>() ?: d.signedRequest,
                fakeProver = get(KEY_FAKE_PROVER)?.toBooleanStrictOrNull() ?: d.fakeProver,
                verifierIdTypes = VerifierIdTypeOrder.fromStored(get(KEY_VERIFIER_ID_TYPES)) ?: d.verifierIdTypes,
            )
        }

        private inline fun <reified E : Enum<E>> String?.asEnum(): E? =
            this?.let { name -> enumValues<E>().firstOrNull { it.name == name } }
    }
}
