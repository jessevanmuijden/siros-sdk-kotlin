// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CredentialSecretSeedSourceTest {
    private val legacyType = "org.siros.secret_seed"
    private val hex = NymTestCredentials.seedHex

    private fun entry(t: String, v: kotlinx.serialization.json.JsonElement) =
        buildJsonObject { put("type", JsonPrimitive(t)); put("value", v) }

    private fun source(md: JsonArray?) = KeystoreSecretSeedSource { md }

    @Test
    fun noneHoldsNothing() = runTest {
        assertNull(CredentialSecretSeedSource.NONE.secretSeed(1L))
        assertNull(CredentialSecretSeedSource.NONE.secretSeed(Long.MAX_VALUE))
    }

    @Test
    fun failsClosed() = runTest {
        assertNull(source(null).secretSeed(1L))
        assertNull(source(JsonArray(emptyList())).secretSeed(1L))
        assertNull(source(buildJsonArray { add(entry("other", JsonPrimitive("x"))) }).secretSeed(1L))
        assertNull(source(buildJsonArray { add(JsonPrimitive("junk")) }).secretSeed(1L))
    }

    @Test
    fun aCredentialStoredWithTheSupersededSecretSeedEntryHasNoSeedAndNothingThrows() = runTest {
        // Credentials issued with the legacy seed delivery are orphaned: re-issue them. The entry is not interpreted.
        val md = buildJsonArray {
            add(entry(legacyType, buildJsonObject { put("org.siros.nym_auth", JsonPrimitive(hex)) }))
        }
        assertNull(source(md).secretSeed(1L))
        val withDisplay = buildJsonArray {
            add(entry("display", JsonArray(emptyList())))
            add(entry(legacyType, buildJsonObject { put("org.siros.nym_auth", JsonPrimitive(hex)) }))
        }
        assertNull(source(withDisplay).secretSeed(1L))
    }

    @Test
    fun v01_theSeedIsTheOpeningOfTheSscSlot_evenWhenTheResponseDeliveredMoreOpenings() = runTest {
        val seed = "8f3b2c9e41d07a65b1e2f4c3d9a08176".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val other = ByteArray(16) { 9 }
        val b64 = { x: ByteArray -> java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(x) }
        fun slot(path: String, opening: ByteArray) = """{"type":"hash_commitment","alg":"sha-256","path":$path,"opening":"${b64(opening)}"}"""
        val md = buildJsonArray {
            add(entry(org.siros.sdk.credentials.AuxiliaryDataV01.RESPONSE_MEMBER, kotlinx.serialization.json.Json.parseToJsonElement(
                "[" + slot("""["org.example.doc","psc"]""", other) + "," + slot("""["org.example.doc","ssc"]""", seed) + "]",
            )))
        }
        assertArrayEquals(seed, source(md).secretSeed(1L))
        // No ssc slot, or two: no seed.
        val none = buildJsonArray { add(entry(org.siros.sdk.credentials.AuxiliaryDataV01.RESPONSE_MEMBER, kotlinx.serialization.json.Json.parseToJsonElement("[" + slot("""["psc"]""", other) + "]"))) }
        assertNull(source(none).secretSeed(1L))
        val two = buildJsonArray {
            add(entry(org.siros.sdk.credentials.AuxiliaryDataV01.RESPONSE_MEMBER, kotlinx.serialization.json.Json.parseToJsonElement(
                "[" + slot("""["a","ssc"]""", seed) + "," + slot("""["b","ssc"]""", other) + "]",
            )))
        }
        assertNull(source(two).secretSeed(1L))
    }

    @Test
    fun anAuxiliaryDataMemberOfOnlyIgnoredExtensionsHasNoSeed() = runTest {
        val ext = kotlinx.serialization.json.Json.parseToJsonElement("""[{"type":"future_kind","alg":"sha-256","path":["x"],"opening":"ignored"}]""")
        assertNull(source(buildJsonArray { add(entry(org.siros.sdk.credentials.AuxiliaryDataV01.RESPONSE_MEMBER, ext)) }).secretSeed(1L))
        // A superseded entry beside it is not a fallback.
        val md = buildJsonArray {
            add(entry(org.siros.sdk.credentials.AuxiliaryDataV01.RESPONSE_MEMBER, ext))
            add(entry(legacyType, buildJsonObject { put("org.siros.nym_auth", JsonPrimitive(hex)) }))
        }
        assertNull(source(md).secretSeed(1L))
    }
}
