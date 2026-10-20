// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.credentials.ZkArtifact
import org.siros.sdk.credentials.ZkCircuitDescriptor
import org.siros.sdk.credentials.ZkUncompressed

/** The allocation size of a decompressed circuit comes from the catalog, never from the zstd frame header alone. */
class CircuitZkDecompressionTest {
    private fun descriptor(size: Long?) = ZkCircuitDescriptor(
        id = "c", artifact = ZkArtifact(hash = "sha256:00", size = 1, uncompressed = size?.let { ZkUncompressed("sha256:00", it) }),
    )

    private fun refused(frame: Long, size: Long?) {
        try {
            checkedDecompressedSize(frame, descriptor(size))
            fail("expected a refusal for frame=$frame published=$size")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `the published size is the allocation when the frame agrees and it is within the ceiling`() {
        assertEquals(1000, checkedDecompressedSize(1000, descriptor(1000)))
        assertEquals(MAX_DECOMPRESSED_BYTES.toInt(), checkedDecompressedSize(MAX_DECOMPRESSED_BYTES, descriptor(MAX_DECOMPRESSED_BYTES)))
    }

    @Test
    fun `a frame that disagrees with the catalog, or states nothing, is refused`() {
        refused(frame = 999, size = 1000)
        refused(frame = 1001, size = 1000)
        refused(frame = -1, size = 1000) // ZSTD_CONTENTSIZE_UNKNOWN
        refused(frame = -2, size = 1000) // ZSTD_CONTENTSIZE_ERROR
        refused(frame = 0, size = 1000)
    }

    @Test
    fun `an unpublished, non-positive or over-ceiling size is refused even if the frame agrees`() {
        refused(frame = 1000, size = null)
        refused(frame = 0, size = 0)
        refused(frame = -5, size = -5)
        refused(frame = MAX_DECOMPRESSED_BYTES + 1, size = MAX_DECOMPRESSED_BYTES + 1)
        // A size that would truncate when narrowed to Int.
        refused(frame = (1L shl 32) + 5, size = (1L shl 32) + 5)
    }
}
