// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.nio.ByteBuffer
import kotlinx.serialization.json.JsonPrimitive
import uniffi.zk_cred_longfellow.NymAuthCircuitParams
import uniffi.zk_cred_longfellow.NymAuthException
import uniffi.zk_cred_longfellow.NymAuthProver
import uniffi.zk_cred_longfellow.nymauthInitializeProver
import uniffi.zk_cred_longfellow.nymauthProve
import uniffi.zk_cred_vega.NymAuthVegaException
import uniffi.zk_cred_vega.NymAuthVegaHolder
import uniffi.zk_cred_vega.NymAuthVegaKeys
import uniffi.zk_cred_vega.NymAuthVegaStatement
import uniffi.zk_cred_vega.nymauthChallengeDigest
import uniffi.zk_cred_vega.nymauthVegaLoadKeys
import uniffi.zk_cred_vega.nymauthVegaProve
import uniffi.zk_cred_longfellow.NymAuthProveRequest as LfProveRequest

/** A direct copy of the readable [ByteBuffer] [circuit]: the UniFFI `&[u8]` parameters need a direct buffer. */
private fun directCopy(circuit: ByteBuffer): ByteBuffer {
    val src = circuit.duplicate()
    return ByteBuffer.allocateDirect(src.remaining()).put(src).apply { flip() }
}

private fun bytes(circuit: ByteBuffer): ByteArray {
    val src = circuit.duplicate()
    return ByteArray(src.remaining()).also { src.get(it) }
}

/**
 * The Vega nymauth binding: `nymauthVegaLoadKeys(shapes)` runs key setup from the catalog artifact's shapes (the
 * resident, 100+ MB part), `nymauthVegaProve(keys, statement, holder)` proves. The binding approves only shapes on its
 * own list: others are `UnknownCircuit`, mapped to "not supported by this app version". It zeroes its copy of the seed.
 * Every binding error becomes a [NymAuthNativeException] carrying no message of the binding (not the digest, not a rule).
 */
internal object VegaNymAuthBinding : NymAuthBinding {
    override val system: String = NymAuthCircuitZkAdapter.VEGA_SYSTEM

    override fun load(request: NymAuthProveRequest): AutoCloseable = try {
        nymauthVegaLoadKeys(bytes(request.circuit))
    } catch (e: NymAuthVegaException) {
        throw mapped(e)
    }

    override fun prove(handle: AutoCloseable, request: NymAuthProveRequest): NymAuthProveResponse = try {
        // The circuit authors' own derivation of the challenge digest (e2) from the session transcript must be the digest of
        // the message the device key just signed; if not, the proof would never verify, so no proof is made.
        val expectedE2 = nymauthChallengeDigest(request.transcriptSeed, NYM_AUTH_DOCTYPE)
        if (!java.security.MessageDigest.isEqual(expectedE2, request.challengeDigest)) {
            throw NymAuthNativeException(NymAuthNativeErrorKind.INVALID_INPUT)
        }
        val proof = nymauthVegaProve(
            handle as NymAuthVegaKeys,
            NymAuthVegaStatement(
                issuerKeyX = request.issuerKeyX,
                issuerKeyY = request.issuerKeyY,
                time = request.time,
                earliest = request.earliest,
                cutoff = request.cutoff,
                challengeDigest = request.challengeDigest,
                verifierInput = request.verifierInput,
            ),
            NymAuthVegaHolder(
                issuerSigned = request.issuerSigned,
                secretSeed = request.secretSeed.copyOf(),
                deviceSignature = request.deviceSignature,
            ),
        )
        NymAuthProveResponse(proof.proof, proof.pseudonym)
    } catch (e: NymAuthVegaException) {
        throw mapped(e)
    }

    /** The variant name is the kind; a `Refused` variant's message is its coarse code (`SeedMismatch`, ...), the only message kept. */
    private fun mapped(e: NymAuthVegaException): NymAuthNativeException {
        val variant = e::class.simpleName.orEmpty()
        return NymAuthNativeException.vega(variant, if (variant == "Refused") e.message?.removePrefix("message=") else null)
    }

    private const val NYM_AUTH_DOCTYPE = "eu.europa.ec.eudi.nym_auth.1"
}

/**
 * The Longfellow nymauth binding: `nymauthInitializeProver(circuit, params)` loads the signature and hash circuits once
 * (the resident part; `params` are the catalog descriptor's `block_enc_hash`, `block_enc_sig`, `hash_circuit_id` and
 * `sig_circuit_id`), `nymauthProve(prover, request)` proves. A circuit id it has no witness map for is
 * `UnsupportedCircuit`. Every error becomes a [NymAuthNativeException] with no message of the binding.
 */
internal object LongfellowNymAuthBinding : NymAuthBinding {
    override val system: String = NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM

    override fun load(request: NymAuthProveRequest): AutoCloseable = try {
        val p = request.circuitParams
        fun text(key: String) = (p[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
        fun number(key: String): UInt = (p[key] as? JsonPrimitive)?.content?.toUIntOrNull()
            ?: throw NymAuthNativeException(NymAuthNativeErrorKind.INVALID_CIRCUIT)
        nymauthInitializeProver(
            directCopy(request.circuit),
            NymAuthCircuitParams(
                blockEncHash = number("block_enc_hash"),
                blockEncSig = number("block_enc_sig"),
                hashCircuitId = text("hash_circuit_id") ?: throw NymAuthNativeException(NymAuthNativeErrorKind.INVALID_CIRCUIT),
                sigCircuitId = text("sig_circuit_id") ?: throw NymAuthNativeException(NymAuthNativeErrorKind.INVALID_CIRCUIT),
            ),
        )
    } catch (e: NymAuthException) {
        throw mapped(e)
    }

    override fun prove(handle: AutoCloseable, request: NymAuthProveRequest): NymAuthProveResponse = try {
        // As for Vega: the binding's own derivation of e2 must equal the digest of what the device key signed.
        val expectedE2 = uniffi.zk_cred_longfellow.nymauthChallengeDigest(request.transcriptSeed, NYM_AUTH_DOCTYPE)
        if (!java.security.MessageDigest.isEqual(expectedE2, request.challengeDigest)) {
            throw NymAuthNativeException(NymAuthNativeErrorKind.INVALID_INPUT)
        }
        val response = nymauthProve(
            handle as NymAuthProver,
            LfProveRequest(
                issuerSigned = request.issuerSigned,
                secretSeed = request.secretSeed.copyOf(),
                issuerKeyX = request.issuerKeyX,
                issuerKeyY = request.issuerKeyY,
                time = request.time,
                earliest = request.earliest,
                cutoff = request.cutoff,
                challengeDigest = request.challengeDigest,
                deviceSignature = request.deviceSignature,
                verifierInput = request.verifierInput,
                transcriptSeed = request.transcriptSeed,
            ),
        )
        NymAuthProveResponse(response.proof, response.pseudonym)
    } catch (e: NymAuthException) {
        throw mapped(e)
    }

    private fun mapped(e: NymAuthException) = NymAuthNativeException.longfellow(e::class.simpleName.orEmpty())

    private const val NYM_AUTH_DOCTYPE = "eu.europa.ec.eudi.nym_auth.1"
}
