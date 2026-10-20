// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.time.Instant
import java.time.format.DateTimeParseException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkLegacyDisclosure
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.PseudonymOutcome
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.VerifierIdentity
import org.siros.sdk.credentials.ZkCircuitDescriptor
import org.siros.sdk.credentials.ZkSystemSpec
import timber.log.Timber

/**
 * The adapter for the legacy catalog circuits, Longfellow (`longfellow`, versions 6 to 8) and Vega-mc
 * (`vega-mc`, version 12): it proves the PROPOSED [CircuitZkLegacyDisclosure] function through the same
 * [ZkMdocPresentation] the `mso_mdoc_zk` path uses, so the proof systems, their shared [ZkProverResidency],
 * circuit download and hash verification, and Vega's [VegaProofCache] are the existing ones, not copies.
 *
 * The plan must be exactly one claim-disclosure function. The verifier's `systems` are narrowed to the specs
 * naming the chosen circuit (its id or an alias), so the proof is made with the circuit the presenter picked,
 * and the resolved spec must be of the proof system that catalog system stands for. `proof` is the ZK
 * `DeviceResponse` the legacy path builds; the result is `true`, or the 32-byte legacy pseudonym when the
 * function asked for one (a system that returns none makes the request refused).
 */
class LegacyZkCircuitZkAdapter(private val presentation: ZkMdocPresentation) : CircuitZkSystemAdapter {

    override val systems: Set<CircuitZkSystemKey> = setOf(
        CircuitZkSystemKey(LONGFELLOW_CATALOG_SYSTEM, "6"),
        CircuitZkSystemKey(LONGFELLOW_CATALOG_SYSTEM, "7"),
        CircuitZkSystemKey(LONGFELLOW_CATALOG_SYSTEM, "8"),
        CircuitZkSystemKey(VEGA_CATALOG_SYSTEM, "12"),
    )

    override fun declaredFunctions(descriptor: ZkCircuitDescriptor): Set<String> = setOf(CircuitZkLegacyDisclosure.FUNCTION_ID)

    override fun release() {
        presentation.releaseProvers()
    }

    override suspend fun retire(descriptor: ZkCircuitDescriptor) {
        presentation.onCircuitRetired(descriptor)
    }

    override fun admits(circuit: CircuitZkCircuit, plan: CircuitZkPlan): Boolean {
        val request = request(plan) ?: return false
        val docType = docType(plan) ?: return false
        if (docType !in circuit.docTypes) return false
        val specs = specsFor(circuit.circuitId, circuit.aliases, circuit.system, request)
        if (specs.isEmpty()) return false
        return presentation.resolve(docType, specs, numClaims(request)) != null
    }

    override suspend fun prove(descriptor: ZkCircuitDescriptor, input: CircuitZkProveInput): CircuitZkProveOutput {
        val function = input.plan.functions.singleOrNull() ?: throw refuse()
        val request = request(input.plan) ?: throw refuse()
        val specs = specsFor(descriptor.id, descriptor.aliases.toSet(), descriptor.system, request)
        if (specs.isEmpty()) throw refuse()
        // The pseudonym slot is counted in the claims (a Longfellow circuit is compiled for a fixed count), and the
        // pseudonym claim is only ever added by the flag, never named by the verifier.
        if (LongfellowZkProofSystem.PSEUDONYM_CLAIM in request.claims) throw refuse()
        val claims = if (request.pseudonym) request.claims + LongfellowZkProofSystem.PSEUDONYM_CLAIM else request.claims
        val identity = if (request.pseudonym) {
            VerifierIdentity(
                clientId = input.verifierId?.takeIf { it.isNotEmpty() } ?: throw refuse(),
                ppidContext = request.verifierContext ?: input.verifierContext,
            )
        } else {
            null
        }
        val result = try {
            presentation.present(
                ZkMdocPresentation.Request(
                    credentialBytes = input.credentialBytes,
                    requestedSystems = specs,
                    sessionTranscript = input.sessionTranscript,
                    requestedClaims = claims,
                    verifierIdentity = identity,
                ),
                input.signer,
            )
        } catch (e: ZkMdocPresentation.NoMatchingProofSystem) {
            throw refuse()
        }
        if (result.spec.system != proofSystemFor(descriptor.system) || specs.none { it.id == result.spec.id }) throw refuse()

        val value: ResultValue = if (request.pseudonym) {
            val pseudonym = result.proof.pseudonym
            if (result.proof.pseudonymOutcome != PseudonymOutcome.PROVIDED || pseudonym == null || pseudonym.size != ResultValue.Pseudonym.SHA256_SIZE) {
                Timber.w("circuit_zk: the proof system returned no pseudonym; refusing")
                throw refuse()
            }
            ResultValue.Pseudonym(pseudonym)
        } else {
            ResultValue.Predicate
        }
        val time = try { Instant.parse(result.proof.timestamp) } catch (e: DateTimeParseException) { null }
        return CircuitZkProveOutput(proof = result.deviceResponse, results = mapOf(function.handle to value), proofTime = time)
    }

    private fun refuse() = CircuitZkError.AccessDenied(CircuitZkStep.PROVE)

    private fun request(plan: CircuitZkPlan): CircuitZkLegacyDisclosure.Request? =
        plan.functions.singleOrNull()?.let(CircuitZkLegacyDisclosure::parse)

    private fun numClaims(request: CircuitZkLegacyDisclosure.Request) = request.claims.size + if (request.pseudonym) 1 else 0

    private fun docType(plan: CircuitZkPlan): String? =
        ((plan.raw["meta"] as? JsonObject)?.get("doctype_value") as? JsonPrimitive)?.takeIf { it.isString }?.content

    /** The verifier's specs that name this circuit and the proof system its catalog system stands for. */
    private fun specsFor(
        circuitId: String,
        aliases: Set<String>,
        catalogSystem: String,
        request: CircuitZkLegacyDisclosure.Request,
    ): List<ZkSystemSpec> {
        val proofSystem = proofSystemFor(catalogSystem) ?: return emptyList()
        return request.systems.filter { (it.id == circuitId || it.id in aliases) && it.system == proofSystem }
    }

    companion object {
        /** Catalog `system` of the Longfellow `longfellow-libzk-v1_*` circuits. */
        const val LONGFELLOW_CATALOG_SYSTEM = "longfellow"

        /** Catalog `system` of the Vega `vega-mc-p256-v1-*` keys. */
        const val VEGA_CATALOG_SYSTEM = "vega-mc"

        private fun proofSystemFor(catalogSystem: String): String? = when (catalogSystem) {
            LONGFELLOW_CATALOG_SYSTEM -> "longfellow-libzk-v1"
            VEGA_CATALOG_SYSTEM -> VegaProofSystem.SYSTEM_ID
            else -> null
        }
    }
}
