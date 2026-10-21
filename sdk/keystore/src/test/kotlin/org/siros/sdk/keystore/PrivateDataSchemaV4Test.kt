package org.siros.sdk.keystore

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.AESDecrypter
import com.nimbusds.jose.crypto.AESEncrypter
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.credentials.UnsupportedSchemaVersionException
import org.siros.sdk.credentials.UnsupportedSchemaVersionException.Kind
import java.security.MessageDigest

/**
 * privatedata-spec 2.8 (S.schemaVersion 4), section 6: version stamping, migration, and the
 * refusal to rewrite what this SDK does not implement. The vectors have no cases for these
 * rules, so they are constructed here. Also pins the vendored vector files to the digests in
 * `vectors.PROVENANCE.txt`.
 */
class PrivateDataSchemaV4Test {

    private val json = Json { ignoreUnknownKeys = true }
    private val prf = ByteArray(32) { it.toByte() }
    private val salt = ByteArray(32) { (it + 0x10).toByte() }
    private val info = "eDiplomas PRF".toByteArray(Charsets.UTF_8)

    private fun resource(name: String): ByteArray =
        javaClass.classLoader!!.getResourceAsStream("privatedata-spec/$name")!!.readBytes()

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun vector(id: String, realEvents: Boolean = true): JsonObject =
        resource("vectors.jsonl").toString(Charsets.UTF_8).lineSequence().filter { it.isNotBlank() }
            .map { json.parseToJsonElement(it).jsonObject.let { v -> if (realEvents) v.withRealEvents() else v } }
            .first { it["id"]!!.jsonPrimitive.content == id }

    private fun plaintextOf(id: String): JsonObject = vector(id)["inputs"]!!.jsonObject["plaintextState"]!!.jsonObject

    private fun buildContainer(plaintext: JsonObject): ByteArray {
        val (mainKey, mainKeyInfo) = EncryptedContainer.generateMainKey()
        val prfKey = EncryptedContainer.derivePrfKey(prf, salt, info)
        val enc = EncryptedContainer.wrapMainKey(prfKey, mainKey, mainKeyInfo)
        val jwe = JWEObject(JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256GCM), Payload(plaintext.toString()))
        jwe.encrypt(AESEncrypter(mainKey))
        return EncryptedContainer.serialize(
            ContainerData(
                jwe = jwe.serialize(),
                mainKey = mainKeyInfo,
                prfKeys = listOf(
                    PrfKeyInfo(
                        credentialId = ByteArray(8) { 1 }, transports = null, prfSalt = ByteArray(32),
                        hkdfSalt = salt, hkdfInfo = info, algorithm = AesGcmKeyAlgorithm("AES-GCM", 256),
                        keypair = enc.keypair, unwrapKey = enc.unwrapKey,
                    ),
                ),
            ),
        )
    }

    private fun decrypt(container: ByteArray): JsonObject {
        val c = EncryptedContainer.parse(container)
        val e = c.prfKeys.first { it.hkdfSalt.contentEquals(salt) }
        val mainKey = EncryptedContainer.unwrapMainKey(EncryptedContainer.derivePrfKey(prf, e.hkdfSalt, e.hkdfInfo), e, c.mainKey!!)
        val jwe = JWEObject.parse(c.jwe)
        jwe.decrypt(AESDecrypter(mainKey))
        return json.parseToJsonElement(jwe.payload.toString()).jsonObject
    }

    private suspend fun unlocked(plaintext: JsonObject) = JweKeystore().also { it.unlock(prf, buildContainer(plaintext), salt, info) }

    private fun state(p: JsonObject) = p["S"]!!.jsonObject

    /** A plaintext with S at [version], the given [events], and optional extra S members. */
    private fun plaintext(
        version: JsonElement? = JsonPrimitive(4),
        events: List<JsonObject> = emptyList(),
        extraS: Map<String, JsonElement> = emptyMap(),
        credentials: JsonArray = JsonArray(emptyList()),
    ) = buildJsonObject {
        put("lastEventHash", JsonPrimitive("sha256:x"))
        put("events", JsonArray(events))
        put(
            "S",
            JsonObject(
                buildMap {
                    if (version != null) put("schemaVersion", version)
                    put("credentials", credentials)
                    put("keypairs", JsonArray(emptyList()))
                    put("presentations", JsonArray(emptyList()))
                    put("credentialIssuanceSessions", JsonArray(emptyList()))
                    put("settings", buildJsonObject { put("openidRefreshTokenMaxAgeInSeconds", JsonPrimitive("0")) })
                    putAll(extraS)
                },
            ),
        )
    }

    private fun event(type: String, version: JsonElement? = JsonPrimitive(4)) = JsonObject(
        buildMap {
            put("type", JsonPrimitive(type))
            if (version != null) put("schemaVersion", version)
            put("eventId", JsonPrimitive(1))
            put("parentHash", JsonPrimitive(""))
            put("timestampSeconds", JsonPrimitive(100))
        },
    )

    private fun cred(id: Long, extra: Map<String, JsonElement> = emptyMap()) = JsonObject(
        buildMap {
            put("credentialId", JsonPrimitive(id))
            put("format", JsonPrimitive("dc+sd-jwt"))
            put("data", JsonPrimitive("data-$id"))
            put("kid", JsonPrimitive("k1"))
            put("instanceId", JsonPrimitive(0))
            put("batchId", JsonPrimitive(1))
            put("credentialIssuerIdentifier", JsonPrimitive("https://issuer.example.com"))
            put("credentialConfigurationId", JsonPrimitive("cfg"))
            putAll(extra)
        },
    )

    private suspend fun assertRefused(p: JsonObject, kind: Kind, version: Int?, eventType: String? = null) {
        val k = unlocked(p)
        // Reading is unaffected.
        assertTrue(k.isUnlocked)
        val e = try {
            k.exportEncryptedContainer()
            fail("rewrote a container it does not implement"); return
        } catch (e: UnsupportedSchemaVersionException) { e }
        assertEquals(kind, e.kind)
        assertEquals(version, e.schemaVersion)
        assertEquals(eventType, e.eventType)
        assertEquals("unsupported_schema_version", e.errorCode)
        // Still refused on a second attempt: nothing was "half" written.
        try {
            k.exportEncryptedContainer()
            fail("second export succeeded")
        } catch (_: UnsupportedSchemaVersionException) {
        }
    }

    // ── vendored vectors ───────────────────────────────────────────────

    @Test
    fun vendoredFilesMatchTheDigestsInTheProvenanceFile() {
        val provenance = resource("vectors.PROVENANCE.txt").toString(Charsets.UTF_8)
        assertTrue(provenance.contains("901a9a132c27471e8b89467667c3221fa3e91d28"))
        val files = listOf(
            "vectors.jsonl", "fixtures/legacy-v1-symmetric.json", "fixtures/metadata-preservation.json",
            "fixtures/multi-passkey-v3.json", "fixtures/single-credential-v3.json",
            "edge-cases/empty-presentations.json", "edge-cases/max-size-container.json",
            "edge-cases/unicode-credentials.json", "edge-cases/unknown-credential-members.json",
        )
        for (f in files) {
            assertTrue("$f digest is not recorded in the provenance file", provenance.contains(sha256(resource(f))))
        }
    }

    // ── version stamping and migration ────────────────────────────────

    @Test
    fun newStateIsWrittenAtVersion4() = runTest {
        val k = JweKeystore().also { it.unlock(prf, ByteArray(0), salt, info) }
        assertEquals(JsonPrimitive(4), state(decrypt(k.exportEncryptedContainer()))["schemaVersion"])
    }

    @Test
    fun migratingVersion3ToVersion4OnlyChangesSchemaVersion() = runTest {
        // single-credential-v3-001 is a version 3 container as wallet-frontend writes it.
        val v3 = plaintextOf("single-credential-v3-001")
        assertEquals(JsonPrimitive(3), state(v3)["schemaVersion"])
        val out = decrypt(unlocked(v3).exportEncryptedContainer())
        // The vector's keypairs are placeholders without key material, which this SDK cannot read and
        // does not write back (pre-existing, unrelated to versions); everything else is identical.
        fun comparable(p: JsonObject) = JsonObject(p + ("S" to JsonObject(state(p) - "keypairs")))
        val expected = JsonObject(v3 + ("S" to JsonObject(state(v3) + ("schemaVersion" to JsonPrimitive(4)))))
        assertEquals(comparable(expected), comparable(out))
    }

    @Test
    fun aVersion3ContainerWithoutMetadataOrExtensionsGetsNeitherOnRewrite() = runTest {
        val v3 = plaintext(version = JsonPrimitive(3), credentials = JsonArray(listOf(cred(1))))
        val out = decrypt(unlocked(v3).exportEncryptedContainer())
        assertEquals(JsonPrimitive(4), state(out)["schemaVersion"])
        assertFalse("metadata" in state(out)["credentials"]!!.jsonArray[0].jsonObject)
        assertFalse("extensions" in state(out))
    }

    @Test
    fun aVersion3ContainerThatAlreadyCarriesMetadataAndExtensionsIsReadAsVersion4() = runTest {
        val md = buildJsonArray { add(buildJsonObject { put("type", JsonPrimitive("org.siros.secret_seed")); put("value", JsonPrimitive("00")) }) }
        val ext = buildJsonObject { put("org.siros.bbs", buildJsonObject { put("k", JsonPrimitive("v")) }) }
        val v3 = plaintext(
            version = JsonPrimitive(3),
            events = listOf(event("set_extension", JsonPrimitive(3))),
            extraS = mapOf("extensions" to ext),
            credentials = JsonArray(listOf(cred(1, mapOf("metadata" to md)))),
        )
        val k = unlocked(v3)
        assertEquals(md, k.getCredentialMetadata(1L))
        assertEquals("v", k.extensionEntries("org.siros.bbs")["k"])
        val out = decrypt(k.exportEncryptedContainer())
        assertEquals(JsonPrimitive(4), state(out)["schemaVersion"])
        assertEquals(md, state(out)["credentials"]!!.jsonArray[0].jsonObject["metadata"])
        assertEquals(ext, state(out)["extensions"])
        assertEquals(v3["events"], out["events"])
    }

    @Test
    fun metadataAndExtensionsAreOnlyEverWrittenIntoAVersion4Container() = runTest {
        // The SDK always rewrites at version 4, so a rewrite of ANY container that holds
        // metadata or extensions must carry schemaVersion 4 with them.
        val k = JweKeystore().also { it.unlock(prf, ByteArray(0), salt, info) }
        k.saveCredential(7L, """{"id":7,"format":"dc+sd-jwt","raw":"h.p.s","kid":"k1","batch_id":9,"instance_id":0}""")
        k.setCredentialMetadata(7L, buildJsonArray { add(buildJsonObject { put("type", JsonPrimitive("t")); put("value", JsonPrimitive(1)) }) })
        k.setExtensionEntry("org.siros.bbs", "k", "v")
        val s = state(decrypt(k.exportEncryptedContainer()))
        assertNotNull(s["credentials"]!!.jsonArray[0].jsonObject["metadata"])
        assertNotNull(s["extensions"])
        assertEquals(JsonPrimitive(4), s["schemaVersion"])
    }

    @Test
    fun vectorPlaceholderEventsAreRefused() = runTest {
        // The spec's own round-trip vectors carry events no schema version defines and no schemaVersion
        // (see SpecVectorEvents.kt); section 6 says refuse, so the verbatim vector is refused.
        val verbatim = vector("credential-metadata-001", realEvents = false)["inputs"]!!.jsonObject["plaintextState"]!!.jsonObject
        assertRefused(verbatim, Kind.EVENT_VERSION, null, "credential-added")
    }

    // ── refusal ───────────────────────────────────────────────────────

    @Test
    fun refusesToRewriteStateVersion5ButStillReadsIt() = runTest {
        val p = plaintext(version = JsonPrimitive(5), credentials = JsonArray(listOf(cred(1))))
        assertRefused(p, Kind.STATE_VERSION, 5)
        assertEquals("data-1", unlocked(p).getAllCredentials().getValue(1L).let { json.parseToJsonElement(it).jsonObject["raw"]!!.jsonPrimitive.content })
    }

    @Test
    fun refusesStateVersionsItDoesNotImplement() = runTest {
        assertRefused(plaintext(version = JsonPrimitive(2)), Kind.STATE_VERSION, 2)
        assertRefused(plaintext(version = JsonPrimitive(1)), Kind.STATE_VERSION, 1)
        assertRefused(plaintext(version = null), Kind.STATE_VERSION, null) // absent means 1 to wallet-frontend
        assertRefused(plaintext(version = JsonPrimitive("4")), Kind.STATE_VERSION, null)
        assertRefused(plaintext(version = JsonPrimitive(4.5)), Kind.STATE_VERSION, null)
    }

    @Test
    fun refusesAnEventWithSchemaVersion5() = runTest {
        assertRefused(
            plaintext(events = listOf(event("alter_settings", JsonPrimitive(4)), event("alter_settings", JsonPrimitive(5)))),
            Kind.EVENT_VERSION, 5, "alter_settings",
        )
        assertRefused(plaintext(events = listOf(event("alter_settings", null))), Kind.EVENT_VERSION, null, "alter_settings")
    }

    @Test
    fun refusesAnUnknownEventType() = runTest {
        // The event of extensions-unknown-event-001's history A.
        val unknown = vector("extensions-unknown-event-001")["inputs"]!!.jsonObject["historyA"]!!.jsonArray[0].jsonObject
        assertRefused(plaintext(events = listOf(unknown)), Kind.EVENT_TYPE, 4, "a_type_this_reader_does_not_know")
        // A version 4 event type spelled like a v3 one is not a way round it, nor is a missing type.
        assertRefused(plaintext(events = listOf(JsonObject(event("x") - "type"))), Kind.EVENT_TYPE, 4, null)
    }

    @Test
    fun refusalLeavesTheStoredContainerAndTheKeystoreUntouched() = runTest {
        val container = buildContainer(plaintext(version = JsonPrimitive(5), credentials = JsonArray(listOf(cred(1)))))
        val k = JweKeystore().also { it.unlock(prf, container, salt, info) }
        k.saveCredential(2L, """{"id":2,"format":"dc+sd-jwt","raw":"h.p.s","kid":"k1","batch_id":9,"instance_id":0}""")
        try {
            k.exportEncryptedContainer()
            fail("rewrote")
        } catch (_: UnsupportedSchemaVersionException) {
        }
        // The caller still holds the original bytes; a fresh keystore reads exactly what was there.
        val k2 = JweKeystore().also { it.unlock(prf, container, salt, info) }
        assertEquals(setOf(1L), k2.getAllCredentials().keys)
    }

    @Test
    fun acceptsEveryEventTypeAndVersionTheSpecDefines() = runTest {
        val types = listOf(
            "new_credential", "delete_credential", "new_keypair", "delete_keypair", "new_presentation",
            "delete_presentation", "alter_settings", "save_credential_issuance_session",
            "delete_credential_issuance_session",
        )
        val events = types.flatMap { t -> (1..4).map { v -> event(t, JsonPrimitive(v)) } } + event("set_extension", JsonPrimitive(4))
        val p = plaintext(events = events)
        val out = decrypt(unlocked(p).exportEncryptedContainer())
        assertEquals(p["events"], out["events"])
        assertEquals(p["lastEventHash"], out["lastEventHash"])
    }

    // ── preservation ──────────────────────────────────────────────────

    @Test
    fun unknownMembersAreRewrittenWithIdenticalValues() = runTest {
        val unknownS = buildJsonObject {
            put("a", buildJsonArray { add(JsonPrimitive(1)); add(JsonPrimitive("two")); add(buildJsonObject { put("n", JsonPrimitive(3.5)) }) })
            put("b", JsonPrimitive(null as String?))
        }
        val metadata = buildJsonArray {
            add(buildJsonObject {
                put("type", JsonPrimitive("t")); put("value", buildJsonObject { put("z", JsonPrimitive(1)) })
                put("x-unknown-entry-member", buildJsonArray { add(JsonPrimitive(true)) })
            })
        }
        val c = cred(1, mapOf("metadata" to metadata, "x-unknown-credential-member" to unknownS))
        val p = plaintext(version = JsonPrimitive(3), extraS = mapOf("x-unknown-top-level" to unknownS), credentials = JsonArray(listOf(c)))
        val k = unlocked(p)
        k.saveCredential(9L, """{"id":9,"format":"dc+sd-jwt","raw":"h.p.s","kid":"k1","batch_id":9,"instance_id":0}""")
        val out = state(decrypt(k.exportEncryptedContainer()))
        assertEquals(unknownS, out["x-unknown-top-level"])
        val entry = out["credentials"]!!.jsonArray.first { it.jsonObject["credentialId"]!!.jsonPrimitive.content == "1" }.jsonObject
        assertEquals(unknownS, entry["x-unknown-credential-member"])
        assertEquals(metadata, entry["metadata"])
        assertNull(out["credentials"]!!.jsonArray.map { it.jsonObject }.firstOrNull { it["credentialId"]!!.jsonPrimitive.content == "9" }?.get("metadata"))
    }
}
