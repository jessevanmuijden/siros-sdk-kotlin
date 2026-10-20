// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Test

class CredentialSecretSeedSourceTest {
    private val type = org.siros.sdk.credentials.SecretSeedDelivery.MEMBER
    private val ns = "org.siros.nym_auth"
    private val hex = NymTestCredentials.seedHex

    private fun entry(t: String, v: kotlinx.serialization.json.JsonElement) =
        buildJsonObject { put("type", JsonPrimitive(t)); put("value", v) }

    private fun seeds(vararg pairs: Pair<String, kotlinx.serialization.json.JsonElement>) = buildJsonObject { pairs.forEach { (k, v) -> put(k, v) } }

    private fun source(md: JsonArray?, namespace: String = ns) = KeystoreSecretSeedSource(namespace) { md }

    @Test
    fun noneHoldsNothing() = runTest {
        assertNull(CredentialSecretSeedSource.NONE.secretSeed(1L))
        assertNull(CredentialSecretSeedSource.NONE.secretSeed(Long.MAX_VALUE))
    }

    @Test
    fun readsTheSeedOfTheDesignatedNamespaceAsAFreshCopyEachTime() = runTest {
        val s = source(
            buildJsonArray {
                add(entry("other", JsonPrimitive("x")))
                add(entry(type, seeds("org.siros.other" to JsonPrimitive("ffeeddccbbaa99887766554433221100"), ns to JsonPrimitive(hex))))
            },
        )
        val a = s.secretSeed(1L)!!
        val b = s.secretSeed(1L)!!
        assertArrayEquals(NymTestCredentials.seed, a)
        assertNotSame(a, b)
        a.fill(0)
        assertArrayEquals("zeroing one copy must not affect the next", NymTestCredentials.seed, s.secretSeed(1L))
        // Another namespace is another seed.
        assertArrayEquals(ByteArray(16) { (0xff - it * 0x11).toByte() }, source(buildJsonArray { add(entry(type, seeds("org.siros.other" to JsonPrimitive("ffeeddccbbaa99887766554433221100")))) }, "org.siros.other").secretSeed(1L))
    }

    @Test
    fun failsClosed() = runTest {
        assertNull(source(null).secretSeed(1L))
        assertNull(source(JsonArray(emptyList())).secretSeed(1L))
        assertNull(source(buildJsonArray { add(entry("other", seeds(ns to JsonPrimitive(hex)))) }).secretSeed(1L))
        assertNull(source(buildJsonArray { add(entry(type, seeds(ns to JsonPrimitive(hex)))); add(entry(type, seeds(ns to JsonPrimitive(hex)))) }).secretSeed(1L))
        assertNull("no seed for the namespace", source(buildJsonArray { add(entry(type, seeds("org.siros.other" to JsonPrimitive(hex)))) }).secretSeed(1L))
        for (bad in listOf(hex.dropLast(2), hex.uppercase(), hex + "00", "0x$hex", "")) {
            assertNull(bad, source(buildJsonArray { add(entry(type, seeds(ns to JsonPrimitive(bad)))) }).secretSeed(1L))
        }
        assertNull(source(buildJsonArray { add(entry(type, seeds(ns to JsonPrimitive(5)))) }).secretSeed(1L))
        // The value must be the namespace map: a bare hex string is not a delivery.
        assertNull(source(buildJsonArray { add(entry(type, JsonPrimitive(hex))) }).secretSeed(1L))
        assertNull(source(buildJsonArray { add(JsonPrimitive("junk")) }).secretSeed(1L))
    }
}
