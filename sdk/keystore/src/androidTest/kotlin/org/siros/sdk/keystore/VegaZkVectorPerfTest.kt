// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.github.luben.zstd.Zstd
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.zk_cred_vega.FfiClaim
import uniffi.zk_cred_vega.FfiEcdsaWitness
import uniffi.zk_cred_vega.FfiMsoBodyWitness
import uniffi.zk_cred_vega.prepProve
import uniffi.zk_cred_vega.prove
import java.nio.ByteBuffer

/**
 * Real-device timing for `prep_prove`/`prove` against the exact same real
 * key/fixture [VegaZkVectorTest] uses - the on-device confirmation an
 * earlier project investigation explicitly flagged as never done (see the
 * `project_vega_e2e_working` session notes: x86_64 desktop timing was
 * measured and a real `vega-prover` perf bug was found and fixed there, but
 * "real on-device (Pixel) timing confirmation - only verified on x86_64
 * desktop so far" was left open, and the x86-desktop-vs-phone gap was never
 * independently explained).
 *
 * Mirrors `zk-cred-vega`'s own `examples/perf_profile.rs` (`setup`/
 * `prep_prove`/`prove` timed individually against the real fixture) closely
 * enough to compare numbers directly - `setup()` isn't repeated here since
 * it's one-time circuit compilation, never a per-presentation/wallet-side
 * cost, and [VegaZkVectorTest]'s own `loadProverKey`/`loadVerifierKey`
 * already do the equivalent of loading `setup()`'s *output* rather than
 * running it fresh.
 *
 * Not a performance gate (no fixed threshold asserted, pass/fail) - device
 * capability varies too much for a hardcoded bound to mean anything. Read
 * its `Log.i` output (`adb logcat -s VegaPerf`) for the real numbers;
 * sanity assertions here only catch degenerate zero/negative timings, which
 * would mean the measurement itself is broken, not that the circuit is
 * slow.
 */
@RunWith(AndroidJUnit4::class)
class VegaZkVectorPerfTest {

    companion object {
        private const val TAG = "VegaPerf"
        private const val PROVER_KEY_RESOURCE = "zk-cred-vega/vega-mc-p256-v1-prover-key.bin.zst"
        private const val TEST_VECTOR_RESOURCE = "zk-cred-vega/mdl_4claims_mixed_disclosure.json"
        private const val MIN_EXPECTED_KEY_SIZE = 100_000_000L
    }

    private fun loadResource(name: String): ByteArray {
        val stream = javaClass.classLoader!!.getResourceAsStream(name)
            ?: error("test resource not found: $name")
        return stream.use { it.readBytes() }
    }

    private fun directByteBuffer(bytes: ByteArray): ByteBuffer =
        ByteBuffer.allocateDirect(bytes.size).put(bytes).apply { flip() }

    private fun loadCompressedResource(name: String): ByteArray {
        val compressed = loadResource(name)
        val size = Zstd.getFrameContentSize(compressed)
        check(size >= MIN_EXPECTED_KEY_SIZE) { "zstd frame content size ($size) smaller than expected for a real setup key" }
        return Zstd.decompress(compressed, size.toInt())
    }

    private fun loadProverKey() = uniffi.zk_cred_vega.deserializeProverKey(directByteBuffer(loadCompressedResource(PROVER_KEY_RESOURCE)))

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private data class TestVector(
        val claims: List<FfiClaim>,
        val ecdsaWitness: FfiEcdsaWitness,
        val msoBody: FfiMsoBodyWitness,
    )

    private fun loadTestVector(): TestVector {
        val json = Json.parseToJsonElement(String(loadResource(TEST_VECTOR_RESOURCE))).jsonObject

        val claims = json["claims"]!!.jsonArray.map { claimJson ->
            val obj = claimJson.jsonObject
            FfiClaim(
                issuerSignedItemBytes = hexToBytes(obj["issuer_signed_item_bytes_hex"]!!.jsonPrimitive.content),
                disclose = obj["disclose"]!!.jsonPrimitive.boolean,
                digestId = obj["digest_id"]!!.jsonPrimitive.content.toUInt(),
            )
        }

        val ecdsa = json["ecdsa_witness"]!!.jsonObject
        val ecdsaWitness = FfiEcdsaWitness(
            qx = hexToBytes(ecdsa["qx_hex"]!!.jsonPrimitive.content),
            qy = hexToBytes(ecdsa["qy_hex"]!!.jsonPrimitive.content),
            r = hexToBytes(ecdsa["r_hex"]!!.jsonPrimitive.content),
            s = hexToBytes(ecdsa["s_hex"]!!.jsonPrimitive.content),
            sInv = hexToBytes(ecdsa["s_inv_hex"]!!.jsonPrimitive.content),
        )

        val mso = json["mso_body"]!!.jsonObject
        val msoBody = FfiMsoBodyWitness(
            deviceX = hexToBytes(mso["device_x_hex"]!!.jsonPrimitive.content),
            deviceY = hexToBytes(mso["device_y_hex"]!!.jsonPrimitive.content),
            signedTs = mso["signed_ts"]!!.jsonPrimitive.content.toByteArray(Charsets.US_ASCII),
            validFromTs = mso["valid_from_ts"]!!.jsonPrimitive.content.toByteArray(Charsets.US_ASCII),
            validUntilTs = mso["valid_until_ts"]!!.jsonPrimitive.content.toByteArray(Charsets.US_ASCII),
        )

        return TestVector(claims, ecdsaWitness, msoBody)
    }

    /** Timed prep_prove + prove, returning only the small bits a caller needs - see [timedWarmProve]'s doc comment for why. */
    private data class ColdRun(val prepMs: Long, val proveMs: Long, val nextState: ByteArray, val proofNonEmpty: Boolean)

    private fun timedColdRun(proverKey: uniffi.zk_cred_vega.VegaProverKey, vector: TestVector): ColdRun {
        val prepStart = System.nanoTime()
        val prepState = prepProve(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody)
        val prepMs = (System.nanoTime() - prepStart) / 1_000_000

        val proveStart = System.nanoTime()
        val proveResult = prove(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody, prepState)
        val proveMs = (System.nanoTime() - proveStart) / 1_000_000
        return ColdRun(prepMs, proveMs, proveResult.nextState, proveResult.proofBytes.isNotEmpty())
    }

    /**
     * Own function frame, same reasoning as [VegaZkVectorTest.firstProveNextState]:
     * a `prepState`/`FfiProveResult` from [timedColdRun] (~110MB each) plus
     * THIS call's own `FfiProveResult` held live simultaneously in one
     * method risks the same real on-device low-memory kill this file's own
     * [VegaZkVectorTest] docs already describe for two such arrays - three
     * timed stages (cold prep_prove, cold prove, warm prove) in one
     * un-scoped method would hold three.
     */
    private fun timedWarmProve(proverKey: uniffi.zk_cred_vega.VegaProverKey, vector: TestVector, priorState: ByteArray): Pair<Long, Boolean> {
        val warmProveStart = System.nanoTime()
        val warmProveResult = prove(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody, priorState)
        val warmProveMs = (System.nanoTime() - warmProveStart) / 1_000_000
        return warmProveMs to warmProveResult.proofBytes.isNotEmpty()
    }

    @Test
    fun prepProveAndProve_realTimingOnThisDevice() {
        val vector = loadTestVector()

        // .use{}: VegaProverKey is AutoCloseable over real native memory
        // (the prover key itself, ~150MB) - see VegaZkVectorTest's own
        // fix for why leaving this to eventual Cleaner-based finalization
        // caused a real silent on-device kill once more than one test
        // method in this process loaded its own prover key. cold.nextState
        // (~110MB) deliberately never escapes this block either, for the
        // same reason - only the small numbers/booleans do.
        data class Timings(val prepMs: Long, val proveMs: Long, val warmProveMs: Long, val coldProofOk: Boolean, val warmProofOk: Boolean)
        val timings = loadProverKey().use { proverKey ->
            val cold = timedColdRun(proverKey, vector)
            val (warmProveMs, warmProofOk) = timedWarmProve(proverKey, vector, cold.nextState)
            Timings(cold.prepMs, cold.proveMs, warmProveMs, cold.proofNonEmpty, warmProofOk)
        }

        assertTrue("prep_prove reported a non-positive duration - measurement is broken", timings.prepMs > 0)
        assertTrue("prove reported a non-positive duration - measurement is broken", timings.proveMs > 0)
        assertTrue("warm prove reported a non-positive duration - measurement is broken", timings.warmProveMs > 0)
        assertTrue("cold prove() produced an empty proof", timings.coldProofOk)
        assertTrue("warm prove() produced an empty proof", timings.warmProofOk)

        Log.i(
            TAG,
            "device=${android.os.Build.MODEL} abi=${android.os.Build.SUPPORTED_ABIS.firstOrNull()} " +
                "prep_prove=${timings.prepMs}ms prove_cold=${timings.proveMs}ms prove_warm_reusing_priorState=${timings.warmProveMs}ms " +
                "cold_total=${timings.prepMs + timings.proveMs}ms",
        )
    }
}
