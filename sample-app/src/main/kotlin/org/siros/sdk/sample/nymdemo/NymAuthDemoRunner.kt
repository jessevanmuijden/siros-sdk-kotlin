// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.nymdemo

import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkCircuitFilter
import org.siros.sdk.credentials.CircuitZkCircuitSource
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.NymPseudonym
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.RulebookCircuitZkValidator
import org.siros.sdk.credentials.ZkWitnessSigner
import org.siros.sdk.keystore.CircuitZkError
import org.siros.sdk.keystore.CircuitZkPresenter
import org.siros.sdk.keystore.FakeCircuitZkProver
import org.siros.sdk.keystore.FixedRootHolderWitnessSource

/**
 * Drives the wallet's circuit_zk presenter against a fixture credential, with
 * the fake prover. Nothing here is real: the issuer is a published demo key,
 * the root secret is a demo value, and the proof is a recognisable dummy.
 *
 * What it does exercise for real is the SDK code between the request and the
 * token: the rulebook validator, the private-seed commitment check, the age
 * predicate, circuit selection, the pseudonym derivation and the CBOR
 * encoding of the presentation.
 */
class NymAuthDemoRunner(
    private val rootKey: ByteArray,
    /** Source of the demo issuer's `secret_seed`s; a test replaces it to know the seed. */
    private val newSecretSeed: () -> ByteArray = NymAuthDemoIssuer::newSecretSeed,
) {
    private companion object {
        /** The label privatedata-spec fixes for the holder private seed; the demo recomputes with it independently. */
        const val PRIVATE_SEED_LABEL = "org.siros.private_seed/v2"
    }

    /** `lp(x)`: the 2-byte big-endian length of the UTF-8 bytes, then the bytes (privatedata-spec 5.4.1). */
    private fun lp(x: String): ByteArray = x.toByteArray(Charsets.UTF_8).let { byteArrayOf((it.size shr 8).toByte(), it.size.toByte()) + it }

    /** The demo's seed source: HKDF-SHA256 over a random per-install key. */
    private val source = FixedRootHolderWitnessSource(rootKey)

    data class Params(
        val birthDate: String,
        val ge: String,
        val le: String,
        val verifierId: String,
        /** Issue the credential with a `psc` that is not this wallet's, to show the commitment check refusing. */
        val foreignPsc: Boolean = false,
        /**
         * The pseudonym config to prove: the device `private_seed` (psc) one, or the issuer-delivered
         * `secret_seed` (ssc) one, for which the demo passes the seed through the presenter request.
         */
        val scenario: Scenario = Scenario.KNOWN_OFFENDER_PSC,
        /** ssc scenario only: deliver a seed that does not open the credential's `ssc` (must refuse). */
        val wrongSeed: Boolean = false,
    )

    enum class Scenario(val config: String) {
        KNOWN_OFFENDER_PSC("known-offender-matching-psc"),
        KNOWN_OFFENDER_SSC("known-offender-matching-ssc"),
    }

    sealed interface Outcome {
        class Presented(
            val circuitId: String,
            val token: String,
            val pseudonymHex: String,
            val recomputedHex: String,
            val ageResult: String,
            val proofAscii: String,
            val decodedHandles: List<String>,
        ) : Outcome {
            val pseudonymMatches get() = pseudonymHex == recomputedHex
        }

        /** The wallet refused. A refusal carries no description by design. */
        object Refused : Outcome

        class Failed(val message: String) : Outcome
    }

    suspend fun run(p: Params): Outcome {
        return try {
            val deviceKey = NymAuthDemoIssuer.newDeviceKey()
            // The issuer generates a random 16-byte secret_seed and commits to it: ssc = SHA256(seed).
            val issuerSeed = newSecretSeed()
            val ssc = NymAuthDemoIssuer.commitmentTo(issuerSeed)
            val psc = if (p.foreignPsc) ByteArray(32).also(java.security.SecureRandom()::nextBytes) else source.privateSeedCommitment(NymAuthDemoIssuer.DOC_TYPE, NymAuthDemoIssuer.ISSUER)
            val credential = NymAuthDemoIssuer.issue(p.birthDate, ssc, psc, deviceKey.public as ECPublicKey)

            val circuit = CircuitZkCircuit(
                system = "demo-fake",
                circuitId = "demo-fake-circuit-v1",
                docTypes = setOf(NymAuthDemoIssuer.DOC_TYPE),
                // A circuit that declares no functions fits no plan.
                functions = setOf("pseudonym", "age_check"),
            )
            val circuits = CircuitZkCircuitSource { listOf(circuit) }
            val presenter = source.circuitZkPresenter(
                // This stand-alone demo issues its own credential locally (a throwaway issuer, not the nym_auth issuance
                // profile the circuits require), so it can only run on the fake. The real path is the wallet's
                // circuit_zk flow over the DC API with the SDK's default prover (request policy: fake prover off).
                prover = FakeCircuitZkProver.optIn(),
                circuits = circuits,
                validator = RulebookCircuitZkValidator(circuits = circuits),
            )

            val config = p.scenario.config
            val plan = CircuitZkPlan(
                functions = listOf(
                    CircuitZkFunction(
                        id = "pseudonym",
                        handle = "nym",
                        params = buildJsonObject {
                            put("config", config)
                            put("ver", 1)
                            put("prf", "sha-256")
                        },
                    ),
                    CircuitZkFunction(
                        id = "age_check",
                        handle = "age",
                        params = buildJsonObject {
                            put("ge", p.ge)
                            put("le", p.le)
                        },
                    ),
                ),
                // The demo "verifier" offers exactly the demo circuit: a response states an offered circuit_id and proof_system.
                circuitFilter = CircuitZkCircuitFilter(proofSystems = listOf(circuit.system), circuitIds = listOf(circuit.circuitId)),
                raw = JsonObject(
                    mapOf("meta" to buildJsonObject { put("source_format", "mso_mdoc"); put("doctype_value", NymAuthDemoIssuer.DOC_TYPE) }),
                ),
            )

            val transcript = MessageDigest.getInstance("SHA-256").digest("demo-session".toByteArray())
            val signer = ZkWitnessSigner { alg, data ->
                require(alg == -7L) { "demo signer is ES256 only" }
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(deviceKey.private as ECPrivateKey)
                    update(data)
                    derToRaw(sign())
                }
            }

            // The wallet's copy of the delivered seed (the demo has no storage side yet): the real one, or
            // a different random seed to show the commitment check refusing.
            val delivered = when {
                p.scenario != Scenario.KNOWN_OFFENDER_SSC -> null
                p.wrongSeed -> newSecretSeed().also { if (it.contentEquals(issuerSeed)) it[0] = (it[0].toInt() xor 1).toByte() }
                else -> issuerSeed.copyOf()
            }
            val result = try {
                presenter.present(
                    CircuitZkPresenter.Request(
                        credentialBytes = credential,
                        plan = plan,
                        verifierId = p.verifierId,
                        sessionTranscript = transcript,
                        secretSeed = delivered,
                        issuer = NymAuthDemoIssuer.ISSUER,
                    ),
                    signer,
                )
            } finally {
                delivered?.fill(0)
            }

            // Look at what was produced, and recompute the pseudonym independently of the presenter.
            val decoded = result.presentation
            check(decoded.results.keys == setOf("nym", "age"))
            val pseudonym = (decoded.results["nym"] as ResultValue.Pseudonym)
            val seed = when (p.scenario) {
                Scenario.KNOWN_OFFENDER_PSC -> hkdf(rootKey, PRIVATE_SEED_LABEL.toByteArray(Charsets.UTF_8) + lp(NymAuthDemoIssuer.DOC_TYPE) + lp(NymAuthDemoIssuer.ISSUER), 16)
                Scenario.KNOWN_OFFENDER_SSC -> issuerSeed
            }
            val recomputed = NymPseudonym.derive(config = config, seed = seed, verifierId = p.verifierId)
            issuerSeed.fill(0)
            Outcome.Presented(
                circuitId = decoded.systemId,
                token = result.json.toString(),
                pseudonymHex = pseudonym.bytes.toHex(),
                recomputedHex = recomputed.toHex(),
                ageResult = if (decoded.results["age"] === ResultValue.Predicate) "true" else "unexpected",
                proofAscii = String(decoded.proof, Charsets.US_ASCII),
                decodedHandles = decoded.results.keys.toList(),
            )
        } catch (e: CircuitZkError) {
            Outcome.Refused
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Outcome.Failed("${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    private fun hkdf(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length <= 32)
        val prk = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
            doFinal(ikm)
        }
        return Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(prk, "HmacSHA256"))
            update(info)
            update(byteArrayOf(1))
            doFinal().copyOf(length)
        }
    }

    private fun derToRaw(der: ByteArray): ByteArray {
        var i = 2
        if (der[1].toInt() and 0x80 != 0) i = 2 + (der[1].toInt() and 0x7f)
        val rLen = der[i + 1].toInt() and 0xff
        val r = der.copyOfRange(i + 2, i + 2 + rLen)
        val sOff = i + 2 + rLen
        val sLen = der[sOff + 1].toInt() and 0xff
        val s = der.copyOfRange(sOff + 2, sOff + 2 + sLen)
        fun fix(b: ByteArray) = java.math.BigInteger(1, b).toByteArray().let {
            when {
                it.size == 32 -> it
                it.size > 32 -> it.copyOfRange(it.size - 32, it.size)
                else -> ByteArray(32 - it.size) + it
            }
        }
        return fix(r) + fix(s)
    }
}
