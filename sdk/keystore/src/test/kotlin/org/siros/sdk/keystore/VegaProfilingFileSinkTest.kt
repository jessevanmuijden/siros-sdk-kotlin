// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * [VegaProfilingEntry] takes `deviceModel`/`abi` as plain constructor
 * arguments (not `android.os.Build`-backed defaults - see that class's own
 * doc comment for why), so these run as plain JVM unit tests like
 * [VegaProofCacheTest], no Robolectric/instrumented environment needed.
 */
class VegaProfilingFileSinkTest {

    @get:Rule
    val tmpFolder = TemporaryFolder()

    private fun entry(event: String, prepProveMs: Long?, proveMs: Long?) = VegaProfilingEntry(
        timestampMs = 1_700_000_000_000,
        event = event,
        usedCachedState = prepProveMs == null,
        prepProveMs = prepProveMs,
        proveMs = proveMs,
        deviceModel = "test-model",
        abi = "arm64-v8a",
    )

    @Test
    fun record_appendsOneJsonLinePerCall() = runTest {
        val file = tmpFolder.newFile("vega_profiling.jsonl")
        val sink = VegaProfilingFileSink(file)

        sink.record(entry("prewarm", prepProveMs = 1338, proveMs = null))
        sink.record(entry("generateProof", prepProveMs = null, proveMs = 3478))

        val lines = file.readLines()
        assertEquals(2, lines.size)
        val first = Json.decodeFromString(VegaProfilingEntry.serializer(), lines[0])
        val second = Json.decodeFromString(VegaProfilingEntry.serializer(), lines[1])
        assertEquals("prewarm", first.event)
        assertEquals(1338L, first.prepProveMs)
        assertEquals("generateProof", second.event)
        assertEquals(3478L, second.proveMs)
        assertEquals(true, second.usedCachedState)
    }

    @Test
    fun record_createsParentDirectoriesIfMissing() = runTest {
        val file = tmpFolder.root.resolve("nested/dir/vega_profiling.jsonl")
        VegaProfilingFileSink(file).record(entry("prewarm", prepProveMs = 10, proveMs = null))
        assertEquals(1, file.readLines().size)
    }
}
