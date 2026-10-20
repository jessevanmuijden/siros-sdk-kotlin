// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.github.luben.zstd.Zstd
import org.siros.sdk.credentials.ZkCircuitDescriptor
import timber.log.Timber
import java.nio.ByteBuffer

/**
 * Decompresses a zstd-compressed zk-circuits catalog artifact
 * (`ZkCircuitClient.downloadArtifact`'s raw, as-served bytes) straight into
 * a direct destination [ByteBuffer] - shared by [VegaProofSystem] and
 * [LongfellowZkProofSystem], whose prover/verifier keys and circuits are
 * both multi-hundred-MB.
 *
 * Sizes the destination to the catalog's published `uncompressed.size`, and
 * refuses unless the zstd frame header states exactly that size (the header is
 * attacker-influenced, so it never sizes an allocation on its own) and it is within
 * [MAX_DECOMPRESSED_BYTES]. There is no guessed fallback.
 *
 * zstd-jni's `Zstd.decompress(ByteBuffer, Int)` requires BOTH its source
 * and destination buffers to already be direct (confirmed via
 * `ZstdDecompressCtx.decompressDirectByteBuffer`'s own
 * `IllegalArgumentException` checks), so [compressedBytes] is first copied
 * into a small direct buffer - cheap, this is the compressed size, a few MB
 * at most - and the native call writes its result straight into a
 * destination buffer of exactly the resolved size. That destination buffer
 * IS the final result: no second, same-size copy. A prior per-class
 * decompress-to-heap-array-then-copy-to-direct-buffer path held two full
 * copies of a circuit key in memory simultaneously at the peak - confirmed
 * to OOM-crash a real device decompressing the ~157MB r11 Vega verifier
 * key.
 */
internal fun decompressZkCircuitArtifact(compressedBytes: ByteArray, descriptor: ZkCircuitDescriptor): ByteBuffer {
    // Everything that sizes the allocation is checked first, and the zstd frame header is untrusted: it must
    // state a content size, and that size must be the one the catalog published (uncompressed.size) and within
    // the ceiling. No guessed size, no truncation to Int.
    val published = checkedDecompressedSize(Zstd.getFrameContentSize(compressedBytes), descriptor)
    val directCompressed = ByteBuffer.allocateDirect(compressedBytes.size).put(compressedBytes).apply { flip() }
    val out = Zstd.decompress(directCompressed, published)
    check(out.remaining() == published) { "Circuit '${descriptor.id}' decompressed to an unexpected length" }
    return out
}

/**
 * The size to allocate for [descriptor]'s artifact given the zstd frame's own claim [frameSize]: the catalog's
 * published `uncompressed.size`, which must be positive, within [MAX_DECOMPRESSED_BYTES] and equal to [frameSize].
 */
internal fun checkedDecompressedSize(frameSize: Long, descriptor: ZkCircuitDescriptor): Int {
    val published = descriptor.artifact?.uncompressed?.size ?: 0L
    require(published in 1..MAX_DECOMPRESSED_BYTES) {
        "Circuit '${descriptor.id}' has no acceptable published uncompressed size ($published)"
    }
    require(frameSize == published) {
        "Circuit '${descriptor.id}' zstd frame states $frameSize bytes, the catalog says $published"
    }
    return published.toInt()
}

/** The most a decompressed circuit artifact may be (about 1.5 times the largest real one, a 136 MB Vega key). */
internal const val MAX_DECOMPRESSED_BYTES: Long = 200L * 1024 * 1024
