package org.siros.sdk.keystore

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.AESDecrypter
import com.nimbusds.jose.crypto.AESEncrypter
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
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
import org.siros.sdk.credentials.CredentialMetadata
import org.siros.sdk.credentials.KeystoreException
import org.siros.sdk.credentials.StoredCredential
import java.security.MessageDigest

/**
 * Per-credential `metadata` (privatedata-spec §6, §5A) and the preservation of
 * every member this SDK does not own: consumes the vectors of
 * privatedata-spec 3.0 (f393ccb) (see `vectors.PROVENANCE.txt`).
 *
 * The vectors' credential entries use string `id`s and no `credentialId`, so
 * this SDK cannot read them as credentials. They are tested twice: verbatim
 * (every entry must be carried through untouched) and in an "adapted" form,
 * where each entry additionally gets a numeric `credentialId`/`data` so it IS
 * loaded and rebuilt, which is where unknown members and `metadata` are at risk.
 */
class CredentialMetadataKeystoreTest {

    private val json = Json { ignoreUnknownKeys = true }
    private val prf = ByteArray(32) { it.toByte() }
    private val salt = ByteArray(32) { (it + 0x10).toByte() }
    private val info = "eDiplomas PRF".toByteArray(Charsets.UTF_8)
    private val seedType = "org.siros.secret_seed"
    private val seedHex = "00112233445566778899aabbccddeeff"

    private fun seedEntry(hex: String = seedHex) = buildJsonObject {
        put("type", JsonPrimitive(seedType))
        put("value", buildJsonObject { put("org.siros.nym_auth", JsonPrimitive(hex)) })
    }

    private fun resourceBytes(name: String): ByteArray =
        javaClass.classLoader!!.getResourceAsStream("privatedata-spec/$name")!!.readBytes()

    private fun loadVectors(): Map<String, JsonObject> {
        val bytes = resourceBytes("vectors.jsonl")
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals(
            "vectors file no longer matches the hash in its PROVENANCE file",
            "a06ec5a21c0b74aaae16595a685c38aa538fa65b46ece7dfe50f9286d839c0ba",
            sha,
        )
        return bytes.toString(Charsets.UTF_8).lineSequence().filter { it.isNotBlank() }
            .map { json.parseToJsonElement(it).jsonObject }
            .associateBy { it["id"]!!.jsonPrimitive.content }
    }

    private fun encrypt(mainKey: javax.crypto.SecretKey, state: JsonObject): String {
        val jwe = JWEObject(JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256GCM), Payload(state.toString()))
        jwe.encrypt(AESEncrypter(mainKey))
        return jwe.serialize()
    }

    private fun buildContainer(plaintext: JsonObject): ByteArray {
        val (mainKey, mainKeyInfo) = EncryptedContainer.generateMainKey()
        val prfKey = EncryptedContainer.derivePrfKey(prf, salt, info)
        val enc = EncryptedContainer.wrapMainKey(prfKey, mainKey, mainKeyInfo)
        val container = ContainerData(
            jwe = encrypt(mainKey, plaintext),
            mainKey = mainKeyInfo,
            prfKeys = listOf(
                PrfKeyInfo(
                    credentialId = ByteArray(8) { 1 },
                    transports = null,
                    prfSalt = ByteArray(32),
                    hkdfSalt = salt,
                    hkdfInfo = info,
                    algorithm = AesGcmKeyAlgorithm("AES-GCM", 256),
                    keypair = enc.keypair,
                    unwrapKey = enc.unwrapKey,
                ),
            ),
        )
        return EncryptedContainer.serialize(container)
    }

    private fun decrypt(container: ByteArray): JsonObject {
        val c = EncryptedContainer.parse(container)
        val prfEntry = c.prfKeys.first { it.hkdfSalt.contentEquals(salt) }
        val prfKey = EncryptedContainer.derivePrfKey(prf, prfEntry.hkdfSalt, prfEntry.hkdfInfo)
        val mainKey = EncryptedContainer.unwrapMainKey(prfKey, prfEntry, c.mainKey!!)
        val jwe = JWEObject.parse(c.jwe)
        jwe.decrypt(AESDecrypter(mainKey))
        return json.parseToJsonElement(jwe.payload.toString()).jsonObject
    }

    private suspend fun unlocked(plaintext: JsonObject): JweKeystore =
        JweKeystore().also { it.unlock(prf, buildContainer(plaintext), salt, info) }

    private fun state(plaintext: JsonObject) = plaintext["S"]!!.jsonObject
    private fun creds(plaintext: JsonObject) = state(plaintext)["credentials"]!!.jsonArray

    /** Give every entry a readable numeric identity, keeping every other member (incl. `id`). */
    private fun adapt(plaintext: JsonObject): JsonObject {
        fun adaptEntry(i: Int, e: JsonElement): JsonElement {
            val o = e.jsonObject
            return JsonObject(
                buildMap {
                    put("credentialId", JsonPrimitive(i + 1L))
                    put("data", JsonPrimitive("data-$i"))
                    put("instanceId", JsonPrimitive(0))
                    put("batchId", JsonPrimitive(1))
                    putAll(o.filterKeys { it != "instanceId" && it != "batchId" })
                },
            )
        }
        val s = state(plaintext)
        val newS = JsonObject(s + ("credentials" to JsonArray(creds(plaintext).mapIndexed(::adaptEntry))))
        return JsonObject(plaintext + ("S" to newS))
    }

    private fun roundTripVectorIds() = listOf(
        "credential-metadata-001",
        "credential-metadata-absent-001",
        "credential-metadata-empty-array-001",
        "credential-unknown-member-001",
        "container-unknown-top-level-member-001",
    )

    // ── the six vectors ─────────────────────────────────────────────────

    @Test
    fun vectors_verbatim_roundTripToTheExpectedState() = runTest {
        val vectors = loadVectors()
        for (id in roundTripVectorIds()) {
            val v = vectors.getValue(id)
            val keystore = unlocked(v["inputs"]!!.jsonObject["plaintextState"]!!.jsonObject)
            val out = decrypt(keystore.exportEncryptedContainer())
            assertEquals("vector $id", v["expected"]!!.jsonObject["roundTripState"], out)
        }
    }

    @Test
    fun vectors_adapted_roundTripToTheExpectedStateAndExposeMetadata() = runTest {
        val vectors = loadVectors()
        for (id in roundTripVectorIds()) {
            val v = vectors.getValue(id)
            val keystore = unlocked(adapt(v["inputs"]!!.jsonObject["plaintextState"]!!.jsonObject))
            val out = decrypt(keystore.exportEncryptedContainer())
            assertEquals(
                "vector $id",
                adapt(v["expected"]!!.jsonObject["roundTripState"]!!.jsonObject),
                out,
            )
        }
        // The metadata is readable through the API, exactly as delivered.
        val withMetadata = vectors.getValue("credential-metadata-001")["inputs"]!!.jsonObject["plaintextState"]!!.jsonObject
        val keystore = unlocked(adapt(withMetadata))
        assertEquals(creds(withMetadata)[0].jsonObject["metadata"], keystore.getCredentialMetadata(1L))
        // [] and absent both read as "none".
        for (id in listOf("credential-metadata-absent-001", "credential-metadata-empty-array-001")) {
            val k = unlocked(adapt(vectors.getValue(id)["inputs"]!!.jsonObject["plaintextState"]!!.jsonObject))
            assertNull(id, k.getCredentialMetadata(1L))
        }
    }

    @Test
    fun vector_deliveredSecretCommitment() {
        val v = loadVectors().getValue("delivered-secret-commitment-001")["inputs"]!!.jsonObject
        val seed = v["secret_seed_hex"]!!.jsonPrimitive.content.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(seed).joinToString("") { "%02x".format(it) }
        for (c in v["cases"]!!.jsonArray) {
            val case = c.jsonObject
            val matches = digest == case["ssc_hex"]!!.jsonPrimitive.content
            assertEquals(case["name"]!!.jsonPrimitive.content == "match", matches)
        }
    }

    // ── API and storage ─────────────────────────────────────────────────

    private suspend fun fresh(): JweKeystore =
        JweKeystore().also { it.unlock(prf, ByteArray(0), salt, info) }

    private val storedJson = """{"id":7,"format":"dc+sd-jwt","raw":"h.p.s","kid":"k1","batch_id":9,"instance_id":0}"""

    @Test
    fun setGetAndExportImportRoundTrip() = runTest {
        val k = fresh()
        k.saveCredential(7L, storedJson)
        assertNull(k.getCredentialMetadata(7L))
        val md = buildJsonArray { add(seedEntry()); add(buildJsonObject { put("type", JsonPrimitive("x")); put("value", buildJsonObject { put("a", JsonNull) }) }) }
        k.setCredentialMetadata(7L, md)
        assertEquals(md, k.getCredentialMetadata(7L))

        val exported = k.exportEncryptedContainer()
        val entry = creds(decrypt(exported)).single().jsonObject
        assertEquals(md, entry["metadata"])

        k.lock()
        assertFalse(k.isUnlocked)
        k.unlock(prf, exported, salt, info)
        assertEquals(md, k.getCredentialMetadata(7L))
        // The stored JSON never carries it.
        assertFalse(k.getCredential(7L)!!.contains(seedHex))
    }

    @Test
    fun exportTwiceIsIdenticalAndEmptyMetadataIsNeverEmitted() = runTest {
        val k = fresh()
        k.saveCredential(7L, storedJson)
        k.setCredentialMetadata(7L, buildJsonArray { add(seedEntry()) })
        val first = decrypt(k.exportEncryptedContainer())
        val k2 = unlocked(first)
        val second = decrypt(k2.exportEncryptedContainer())
        assertEquals(first.toString(), second.toString())

        k2.setCredentialMetadata(7L, JsonArray(emptyList()))
        val cleared = creds(decrypt(k2.exportEncryptedContainer())).single().jsonObject
        assertFalse("metadata" in cleared)
        k2.saveCredential(8L, storedJson.replace("\"id\":7", "\"id\":8"))
        assertFalse("metadata" in creds(decrypt(k2.exportEncryptedContainer()))[1].jsonObject)
    }

    private fun withUnknowns(): JsonObject = adapt(
        loadVectors().getValue("credential-metadata-001")["inputs"]!!.jsonObject["plaintextState"]!!.jsonObject,
    )

    @Test
    fun unknownMembersSurviveAddingDeletingAndOtherChanges() = runTest {
        val original = withUnknowns()
        val originalEntry = creds(original)[0].jsonObject
        val unknownTop = state(original)["x-unknown-top-level"]
        val k = unlocked(original)

        suspend fun assertSurvives(label: String) {
            val out = decrypt(k.exportEncryptedContainer())
            val entry = creds(out).first { it.jsonObject["credentialId"]!!.jsonPrimitive.content == "1" }.jsonObject
            assertEquals(label, originalEntry["x-unknown-credential-member"], entry["x-unknown-credential-member"])
            assertEquals(label, originalEntry["metadata"], entry["metadata"])
            assertEquals(label, unknownTop, state(out)["x-unknown-top-level"])
        }

        k.saveCredential(50L, storedJson.replace("\"id\":7", "\"id\":50"))
        assertSurvives("after adding another credential")
        k.deleteCredential(50L)
        assertSurvives("after deleting another credential")
        k.savePresentationRecord(
            3L,
            """{"id":3,"flow_id":"","credential_ids":[1],"timestamp":1000,"verifier_name":"v"}""",
        )
        assertSurvives("after a presentation record")
        k.setCredentialRefreshToken(1L, CredentialRefreshTokenEntry(refreshToken = "r", credentialIssuerIdentifier = "i", credentialConfigurationId = "c"))
        assertSurvives("after a refresh token change")
    }

    @Test
    fun unknownSettingsMembersSurvive() = runTest {
        val original = withUnknowns()
        val s = state(original)
        val settings = JsonObject(
            s["settings"]!!.jsonObject + ("x-unknown-setting" to buildJsonObject { put("k", JsonPrimitive(1)) }),
        )
        val k = unlocked(JsonObject(original + ("S" to JsonObject(s + ("settings" to settings)))))
        val out = state(decrypt(k.exportEncryptedContainer()))["settings"]!!.jsonObject
        assertEquals(settings, out)
    }

    @Test
    fun unknownContainerLevelMembersSurvive() = runTest {
        val original = withUnknowns()
        val withWrapper = JsonObject(original + ("x-unknown-wrapper" to buildJsonObject { put("w", JsonPrimitive(true)) }))
        val k = unlocked(withWrapper)
        assertEquals(withWrapper["x-unknown-wrapper"], decrypt(k.exportEncryptedContainer())["x-unknown-wrapper"])
    }

    @Test
    fun deletedCredentialsMetadataIsGoneAndNotResurrected() = runTest {
        val k = unlocked(withUnknowns())
        k.deleteCredential(1L)
        assertNull(k.getCredentialMetadata(1L))
        val out = decrypt(k.exportEncryptedContainer())
        assertEquals(0, creds(out).size)
        assertFalse(out.toString().contains(seedHex))
        // Re-saving the same id does not bring the old members back.
        k.saveCredential(1L, storedJson.replace("\"id\":7", "\"id\":1"))
        val again = creds(decrypt(k.exportEncryptedContainer())).single().jsonObject
        assertFalse("metadata" in again)
        assertFalse("x-unknown-credential-member" in again)
        assertNull(k.getCredentialMetadata(1L))

        val base = withUnknowns()
        val opaque = buildJsonObject {
            put("id", JsonPrimitive("unreadable"))
            put("metadata", buildJsonArray { add(seedEntry()) })
        }
        val plaintext = JsonObject(base + ("S" to JsonObject(state(base) + ("credentials" to JsonArray(creds(base) + opaque)))))
        val k2 = unlocked(plaintext)
        k2.clearCredentials()
        val cleared = decrypt(k2.exportEncryptedContainer())
        assertEquals(0, creds(cleared).size)
        assertFalse(cleared.toString().contains(seedHex))
        k2.saveCredential(1L, storedJson.replace("\"id\":7", "\"id\":1"))
        assertFalse("x-unknown-credential-member" in creds(decrypt(k2.exportEncryptedContainer())).single().jsonObject)
    }

    @Test
    fun lockClearsMetadataAndItDoesNotLeakIntoANextUnlock() = runTest {
        val k = unlocked(withUnknowns())
        assertNotNull(k.getCredentialMetadata(1L))
        k.lock()
        k.unlock(prf, ByteArray(0), salt, info)
        k.saveCredential(1L, storedJson.replace("\"id\":7", "\"id\":1"))
        assertNull(k.getCredentialMetadata(1L))
        assertFalse(decrypt(k.exportEncryptedContainer()).toString().contains(seedHex))
    }

    @Test
    fun credentialWithDisplayMetadataAndContainerMetadataStaysVisible() = runTest {
        // StoredCredential.metadata is DISPLAY metadata (an object). The container
        // `metadata` is an array. They must never meet: an array in the stored JSON
        // would fail to decode and the credential would silently vanish.
        val k = fresh()
        val display = StoredCredential(
            id = 7L, format = "dc+sd-jwt", raw = "h.p.s", kid = "k1", batchId = 9L, instanceId = 0,
            metadata = CredentialMetadata(name = "Display name", vct = "urn:vct"),
        )
        k.saveCredential(7L, Json.encodeToString(StoredCredential.serializer(), display))
        k.setCredentialMetadata(7L, buildJsonArray { add(seedEntry()) })
        val exported = k.exportEncryptedContainer()

        k.lock()
        k.unlock(prf, exported, salt, info)
        val restored = Json { ignoreUnknownKeys = true }
            .decodeFromString(StoredCredential.serializer(), k.getCredential(7L)!!)
        assertEquals(7L, restored.id)
        assertNull("display metadata is not persisted in the container", restored.metadata)
        assertEquals(seedType, k.getCredentialMetadata(7L)!![0].jsonObject["type"]!!.jsonPrimitive.content)
    }

    @Test
    fun malformedMetadataIsPreservedVerbatimAndHiddenFromTheApi() = runTest {
        val base = adapt(
            loadVectors().getValue("credential-metadata-absent-001")["inputs"]!!.jsonObject["plaintextState"]!!.jsonObject,
        )
        for (bad in listOf<JsonElement>(JsonPrimitive("garbage"), JsonPrimitive(5), buildJsonObject { put("a", JsonPrimitive(1)) })) {
            val entry = JsonObject(creds(base)[0].jsonObject + ("metadata" to bad))
            val plaintext = JsonObject(base + ("S" to JsonObject(state(base) + ("credentials" to JsonArray(listOf(entry))))))
            val k = unlocked(plaintext)
            assertNull(k.getCredentialMetadata(1L))
            assertNotNull("credential stays visible", k.getCredential(1L))
            val out = creds(decrypt(k.exportEncryptedContainer())).single().jsonObject
            assertEquals(bad, out["metadata"])
        }
        // null is "no metadata" and is never written back.
        val nullEntry = JsonObject(creds(base)[0].jsonObject + ("metadata" to JsonNull))
        val k = unlocked(JsonObject(base + ("S" to JsonObject(state(base) + ("credentials" to JsonArray(listOf(nullEntry)))))))
        assertFalse("metadata" in creds(decrypt(k.exportEncryptedContainer())).single().jsonObject)
    }

    @Test
    fun setterFailsClosed() = runTest {
        val k = fresh()
        k.saveCredential(7L, storedJson)
        val bad = listOf(
            buildJsonArray { add(JsonPrimitive("x")) },
            buildJsonArray { add(buildJsonObject { put("value", JsonPrimitive("v")) }) },
            buildJsonArray { add(buildJsonObject { put("type", JsonPrimitive("")); put("value", JsonPrimitive("v")) }) },
            buildJsonArray { add(buildJsonObject { put("type", JsonPrimitive(5)); put("value", JsonPrimitive("v")) }) },
            buildJsonArray { add(buildJsonObject { put("type", JsonPrimitive("t")) }) },
        )
        for (b in bad) {
            try {
                k.setCredentialMetadata(7L, b)
                fail("accepted $b")
            } catch (_: KeystoreException) {
            }
        }
        try {
            k.setCredentialMetadata(99L, buildJsonArray { add(seedEntry()) })
            fail("accepted an unknown credential")
        } catch (_: KeystoreException) {
        }
        assertNull(k.getCredentialMetadata(7L))
        k.lock()
        try {
            k.setCredentialMetadata(7L, buildJsonArray { add(seedEntry()) })
            fail("accepted while locked")
        } catch (_: KeystoreException) {
        }
    }

    @Test
    fun adapterForwardsMetadataToItsCredentialsKeystore() = runTest {
        val adapter = WscdKeystoreAdapter(mockk<Signer>(relaxed = true))
        adapter.unlock(prf, ByteArray(0), salt, info)
        adapter.saveCredential(7L, storedJson)
        val md = buildJsonArray { add(seedEntry()) }
        adapter.setCredentialMetadata(7L, md)
        assertEquals(md, adapter.getCredentialMetadata(7L))
        adapter.deleteCredential(7L)
        assertNull(adapter.getCredentialMetadata(7L))
    }

    @Test
    fun opaqueEntriesKeepTheirPositionAmongOwnedOnes() = runTest {
        val base = adapt(
            loadVectors().getValue("credential-unknown-member-001")["inputs"]!!.jsonObject["plaintextState"]!!.jsonObject,
        )
        val opaque = buildJsonObject { put("id", JsonPrimitive("cred-x")); put("x", JsonPrimitive(1)) }
        val entries = listOf(creds(base)[0], opaque, creds(base)[1])
        val plaintext = JsonObject(base + ("S" to JsonObject(state(base) + ("credentials" to JsonArray(entries)))))
        val k = unlocked(plaintext)
        val out = creds(decrypt(k.exportEncryptedContainer()))
        assertEquals(entries, out.toList())
    }
}
