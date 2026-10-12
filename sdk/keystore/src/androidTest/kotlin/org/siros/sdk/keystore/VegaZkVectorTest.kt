// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.github.luben.zstd.Zstd
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.zk_cred_vega.FfiClaim
import uniffi.zk_cred_vega.FfiEcdsaWitness
import uniffi.zk_cred_vega.FfiMsoBodyWitness
import uniffi.zk_cred_vega.prepProve
import uniffi.zk_cred_vega.prove
import uniffi.zk_cred_vega.verify
import java.nio.ByteBuffer

/**
 * Exercises the real, vendored `zk_cred_vega` UniFFI bindings directly
 * against the exact real setup keys (`dump_setup`, see this test's resource
 * README) and the native crate's own real, signed test vector
 * (`test-vectors/mdl_4claims_mixed_disclosure.json` - a genuinely realistic
 * mdoc credential with real CBOR framing, real ≥16-byte per-element salts,
 * and a real ECDSA-P256 signature over the real MSO `Sig_structure`, not a
 * self-fabricated toy fixture) - not through [VegaProofSystem], since that
 * class's own witness-extraction ([VegaProofSystem]'s `buildWitness`) is
 * deliberately unimplemented (see its doc comment for why). This instead
 * validates the exact same low-level calls a finished
 * [VegaProofSystem] would make (`deserializeProverKey`/`deserializeVerifierKey`,
 * `prep_prove`, `prove`, `verify`, `ByteBuffer` marshaling) against the real
 * native library, confirming the FFI wiring genuinely works end-to-end from
 * Kotlin - not just that it compiles. Mirrors [LongfellowZkVectorTest]'s
 * role and scope for the Longfellow crate.
 *
 * Instrumented (`androidTest`), not a plain unit test: the native
 * `zk_cred_vega` UniFFI library only loads on a real Android ABI, never in
 * a JVM unit test - same reasoning as [LongfellowZkVectorTest]. Run with
 * `./gradlew :sdk:keystore:connectedDebugAndroidTest`.
 *
 * Resources: `vega-mc-p256-v1-{prover,verifier}-key.bin.zst` are the exact
 * `zk_cred_vega::setup()` output (bincode-serialized `ProverKey`/`VerifierKey`),
 * zstd-compressed - matching `go-zk-circuits`'s
 * `vega-mc-p256-v1-{prover,verifier}-key-r12` catalog entries byte-for-byte
 * (confirmed via sha256, `zk-cred-vega@v0.0.5`'s `dump_setup`), so this test
 * bundles a static copy of exactly what [VegaProofSystem]'s own
 * `zkCircuitClient` would fetch at runtime rather than re-fetching one per
 * test run. `mdl_4claims_mixed_disclosure.json` is the crate's own
 * `test-vectors/` fixture, copied verbatim - regenerated alongside r12, so
 * its ECDSA witness/salts differ from earlier revisions' copies of this
 * same file.
 */
@RunWith(AndroidJUnit4::class)
class VegaZkVectorTest {

    companion object {
        private const val PROVER_KEY_RESOURCE = "zk-cred-vega/vega-mc-p256-v1-prover-key.bin.zst"
        private const val VERIFIER_KEY_RESOURCE = "zk-cred-vega/vega-mc-p256-v1-verifier-key.bin.zst"
        private const val TEST_VECTOR_RESOURCE = "zk-cred-vega/mdl_4claims_mixed_disclosure.json"

        /**
         * The setup keys' own uncompressed size (confirmed via `dump_setup`'s
         * own printed byte counts at generation time) - `Zstd.getFrameContentSize`
         * already reads this from the frame header, so this is only a sanity
         * floor, mirroring [LongfellowZkVectorTest]'s own decompression
         * convention.
         */
        private const val MIN_EXPECTED_KEY_SIZE = 100_000_000L
    }

    private fun loadResource(name: String): ByteArray {
        val stream = javaClass.classLoader!!.getResourceAsStream(name)
            ?: error("test resource not found: $name")
        return stream.use { it.readBytes() }
    }

    /**
     * The vendored UniFFI bindings' `&[u8]` parameters need a DIRECT
     * `ByteBuffer` - same requirement as [LongfellowZkProofSystem]'s own
     * `directByteBuffer`.
     */
    private fun directByteBuffer(bytes: ByteArray): ByteBuffer =
        ByteBuffer.allocateDirect(bytes.size).put(bytes).apply { flip() }

    private fun loadCompressedResource(name: String): ByteArray {
        val compressed = loadResource(name)
        val size = Zstd.getFrameContentSize(compressed)
        check(size >= MIN_EXPECTED_KEY_SIZE) { "zstd frame content size ($size) smaller than expected for a real setup key" }
        return Zstd.decompress(compressed, size.toInt())
    }

    /**
     * Decompresses and deserializes the prover key in its own call frame -
     * the ~110MB decompressed `ByteArray` becomes unreachable the instant
     * this function returns, rather than staying live for the rest of the
     * test method alongside the verifier key's own ~110MB array. The test
     * process's heap growth limit is 256MB; holding both decompressed keys
     * live at once (confirmed via a real `OutOfMemoryError` on-device before
     * this fix) exceeds that, even though each key alone fits comfortably -
     * neither key needs the other's raw bytes once its own native handle
     * exists, so there's no reason to hold both.
     */
    private fun loadProverKey() = uniffi.zk_cred_vega.deserializeProverKey(directByteBuffer(loadCompressedResource(PROVER_KEY_RESOURCE)))

    /** See [loadProverKey]'s doc comment for why this is its own function. */
    private fun loadVerifierKey() = uniffi.zk_cred_vega.deserializeVerifierKey(directByteBuffer(loadCompressedResource(VERIFIER_KEY_RESOURCE)))

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private data class TestVector(
        val claims: List<FfiClaim>,
        val disclosedElementIdentifiers: List<String>,
        val ecdsaWitness: FfiEcdsaWitness,
        val msoBody: FfiMsoBodyWitness,
    )

    private fun loadTestVector(): TestVector {
        val json = Json.parseToJsonElement(String(loadResource(TEST_VECTOR_RESOURCE))).jsonObject

        val disclosedIdentifiers = mutableListOf<String>()
        val claims = json["claims"]!!.jsonArray.map { claimJson ->
            val obj = claimJson.jsonObject
            val disclose = obj["disclose"]!!.jsonPrimitive.boolean
            if (disclose) disclosedIdentifiers.add(obj["element_identifier"]!!.jsonPrimitive.content)
            FfiClaim(
                issuerSignedItemBytes = hexToBytes(obj["issuer_signed_item_bytes_hex"]!!.jsonPrimitive.content),
                disclose = disclose,
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

        return TestVector(claims, disclosedIdentifiers, ecdsaWitness, msoBody)
    }

    /**
     * One entry per claim slot, in the same order as [TestVector.claims]:
     * the real `issuerSignedItemBytes` for a disclosed slot, empty for an
     * undisclosed one - the exact shape `verify()` now requires (see
     * `zk-cred-vega`'s `ffi_api::verify` doc: these travel beside the proof
     * rather than inside its public IO as of r12).
     */
    private fun disclosedBytesFor(vector: TestVector): List<ByteArray> =
        vector.claims.map { if (it.disclose) it.issuerSignedItemBytes else ByteArray(0) }

    /**
     * Full round trip against the real crate: `prep_prove` -> `prove` ->
     * `verify`, confirming the proof verifies and that disclosed/undisclosed
     * claims come back exactly as the test vector declared them (real
     * plaintext for `family_name`/`given_name`, all-zero for
     * `birth_date`/`age_over_18`) - mirrors the crate's own
     * `tests/real_mdoc_fixtures.rs` but from Kotlin, through the actual
     * `#[uniffi::export]` boundary.
     */
    @Test
    fun proveAndVerify_realMdocVector_succeeds() {
        val vector = loadTestVector()

        // .use{}, not .let{}: VegaProverKey is AutoCloseable over real
        // native memory (the prover key itself, ~150MB) - .let only scopes
        // the Kotlin-side reference, it does not free that. Three test
        // methods in this class each load their own prover key in one
        // instrumented process (AndroidJUnitRunner doesn't restart between
        // methods) - relying on eventual Cleaner-based finalization instead
        // of closing explicitly let all three keys stay simultaneously
        // resident, which is exactly what triggered a real on-device kill
        // (no tombstone, no OOM log - just silently gone, consistent with
        // the low-memory killer) once a third test method was added here.
        val proveResult = loadProverKey().use { proverKey ->
            val prepState = prepProve(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody)
            prove(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody, prepState)
        }

        assertTrue("proof must be non-empty", proveResult.proofBytes.isNotEmpty())
        assertTrue("nextState must be non-empty", proveResult.nextState.isNotEmpty())

        val verifyResult = verify(loadVerifierKey(), proveResult.proofBytes, disclosedBytesFor(vector))

        assertArrayEquals(vector.ecdsaWitness.qx, verifyResult.qx)
        assertArrayEquals(vector.ecdsaWitness.qy, verifyResult.qy)
        assertArrayEquals(vector.msoBody.deviceX, verifyResult.deviceX)
        assertArrayEquals(vector.msoBody.deviceY, verifyResult.deviceY)
        assertEquals(vector.claims.size, verifyResult.claims.size)

        for ((index, claim) in vector.claims.withIndex()) {
            val disclosed = verifyResult.claims[index]
            assertEquals("claim $index disclosed flag", claim.disclose, disclosed.disclosed)
            assertEquals("claim $index digestId", claim.digestId, disclosed.digestId)
            if (claim.disclose) {
                assertTrue("claim $index should have real plaintext when disclosed", disclosed.plaintext.isNotEmpty())
            } else {
                assertFalse(
                    "claim $index plaintext should be all-zero when undisclosed",
                    disclosed.plaintext.any { it != 0.toByte() },
                )
            }
        }
    }

    /**
     * Runs `prove` once and returns only its `nextState` bytes - its own
     * function frame so the ~105MB `prepState` input and the `FfiProveResult`
     * wrapper (holding both `proofBytes` and `nextState` live together)
     * become unreachable the instant this returns, mirroring
     * [loadProverKey]/[loadVerifierKey]'s own reasoning. Without this split,
     * [prove_reusingPriorState_stillVerifies] held `prepState` (~105MB) AND
     * `firstProve.nextState` (~105MB) live at once going into the second
     * `prove` call - confirmed via a real `OutOfMemoryError` on-device
     * ("109893015 byte allocation with 109763376 free bytes") right at the
     * edge of the ~105MB prep-state's own now-much-smaller footprint (see
     * this file's own doc comment on the crate-side fix that got it there
     * from ~356MB) rather than a reemergence of the original problem.
     */
    private fun firstProveNextState(
        proverKey: uniffi.zk_cred_vega.VegaProverKey,
        vector: TestVector,
    ): ByteArray {
        val prepState = prepProve(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody)
        return prove(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody, prepState).nextState
    }

    /**
     * Confirms fold-and-reuse works: a second `prove` call using the first
     * call's own `nextState` (skipping `prep_prove`) still produces a
     * verifiable proof - exactly the reuse path
     * [org.siros.sdk.credentials.ZkProofResult.nextState]/
     * [org.siros.sdk.credentials.ZkProofSystem.generateProof]'s `priorState`
     * exist for.
     */
    @Test
    fun prove_reusingPriorState_stillVerifies() {
        val vector = loadTestVector()

        val secondProve = loadProverKey().use { proverKey ->
            val nextState = firstProveNextState(proverKey, vector)
            prove(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody, nextState)
        }

        val verifyResult = verify(loadVerifierKey(), secondProve.proofBytes, disclosedBytesFor(vector))
        assertArrayEquals(vector.ecdsaWitness.qx, verifyResult.qx)
    }

    /**
     * Confirms the one correctness property [VegaProofCache] depends on: a
     * prep-chain is NOT reusable across a DIFFERENT disclosure combination,
     * even for the exact same credential. An earlier version of
     * [VegaProofSystem.buildWitness]'s own doc comment claimed the opposite
     * ("a later presentation disclosing a DIFFERENT subset still reuses the
     * same slot/witness identity... so reuse stays sound regardless") -
     * that claim was never actually checked against the real crate, and is
     * wrong: `disclose` is baked into each step circuit's public values at
     * `prep_prove` time (`ClaimDigestStepCircuit::new`'s own `disclose`
     * parameter feeds directly into its public-IO vector, confirmed by
     * reading `vega-prover`), the same way the blinding nonce is - so
     * changing it between `prep_prove` and a `prove()` reusing that state
     * hits the identical "Step circuit N public values changed" failure
     * class a changed nonce does.
     */
    @Test
    fun prove_withDifferentDisclosurePatternThanPrepProve_fails() {
        val vector = loadTestVector()
        val flipped = vector.claims.map { it.copy(disclose = !it.disclose) }

        loadProverKey().use { prover ->
            val prepState = prepProve(prover, vector.claims, vector.ecdsaWitness, vector.msoBody)
            try {
                prove(prover, flipped, vector.ecdsaWitness, vector.msoBody, prepState)
                org.junit.Assert.fail(
                    "expected prove() to reject a disclosure pattern that differs from what prep_prove committed to",
                )
            } catch (e: Exception) {
                // Expected - the native layer's own "Step circuit N public
                // values changed between prep_prove and prove" class of error.
            }
        }
    }
}
