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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Base64
import javax.crypto.SecretKey

/**
 * Conformance tests driven by privatedata-spec's shared cross-client test
 * vectors (`test-vectors/vectors.jsonl`, bundled here as a test resource -
 * see [loadVectors]). These vectors are the normative fixtures shared with
 * wallet-frontend and siros-sdk-swift (privatedata-spec/test-vectors/README.md).
 *
 * KNOWN LIMITATION: the vectors currently checked into privatedata-spec do
 * NOT include an `expected` block (containerJsonBytes/containerHash/jweCompact),
 * even though the README's documented schema has one. That means the
 * README's normative requirements #1-3 (encryption determinism, decrypting
 * the golden container, byte-identical round-trip against a golden
 * container) aren't checkable from this file alone - there's no golden
 * ciphertext to decrypt or compare against, and true cross-client
 * byte-for-byte compatibility can only be verified by actually running
 * wallet-frontend against the same vector. What IS checkable, and what
 * these tests check, is requirements #4-6: metadata preservation, event
 * preservation, and field completeness - by hand-building a container
 * carrying each vector's `plaintextState` (using this SDK's own
 * `EncryptedContainer` primitives) and confirming this SDK decrypts it
 * back losslessly, including across a save-a-new-credential-and-re-export
 * cycle.
 */
class PrivateDataSpecConformanceTest {

    private val json = Json { ignoreUnknownKeys = true }
    private val b64Url: Base64.Decoder = Base64.getUrlDecoder()

    private fun loadVectors(): List<JsonObject> {
        val stream = javaClass.classLoader!!.getResourceAsStream("privatedata-spec/vectors.jsonl")
            ?: throw IllegalStateException("privatedata-spec/vectors.jsonl not found on test classpath")
        return stream.bufferedReader(Charsets.UTF_8).readText()
            .lineSequence()
            .filter { it.isNotBlank() }
            .map { json.parseToJsonElement(it).jsonObject }
            .toList()
    }

    private fun vector(id: String): JsonObject =
        loadVectors().first { it["id"]!!.jsonPrimitive.content == id }

    /**
     * Vector binary fields are documented as base64url (test-vectors/README.md),
     * but the multi-passkey vector's `credentialIds` are literal human-readable
     * strings instead - decode as base64url where possible, else fall back to
     * raw UTF-8 bytes. Either way the bytes only need to be distinct per entry;
     * JweKeystore selects PRF entries by hkdfSalt, not credentialId (see
     * JweKeystore.unlock()), so this ambiguity doesn't affect what's tested.
     */
    private fun decodeVectorBytes(value: String): ByteArray = try {
        b64Url.decode(value)
    } catch (_: IllegalArgumentException) {
        value.toByteArray(Charsets.UTF_8)
    }

    /** Encrypt [plaintextState] as a JWE using [mainKey], matching JweKeystore.exportEncryptedContainer(). */
    private fun encryptJwe(mainKey: SecretKey, plaintextState: JsonObject): String {
        val header = JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256GCM)
        val jweObject = JWEObject(header, Payload(plaintextState.toString()))
        jweObject.encrypt(AESEncrypter(mainKey))
        return jweObject.serialize()
    }

    private data class PrfEntryInput(val credentialId: ByteArray, val prfOutput: ByteArray, val hkdfSalt: ByteArray)

    /**
     * Hand-build a container carrying [plaintextState], with one prfKeys[]
     * entry per [entries], all wrapping the SAME mainKey - matching the
     * wallet-frontend's multi-passkey container shape (one wallet, several
     * registered authenticators, each independently able to unlock it).
     */
    private fun buildContainer(
        entries: List<PrfEntryInput>,
        hkdfInfo: ByteArray,
        plaintextState: JsonObject,
    ): ByteArray {
        val (mainKey, mainKeyInfo) = EncryptedContainer.generateMainKey()
        val prfKeys = entries.map { entry ->
            val prfKey = EncryptedContainer.derivePrfKey(entry.prfOutput, entry.hkdfSalt, hkdfInfo)
            val encapsulation = EncryptedContainer.wrapMainKey(prfKey, mainKey, mainKeyInfo)
            PrfKeyInfo(
                credentialId = entry.credentialId,
                transports = null,
                prfSalt = ByteArray(32),
                hkdfSalt = entry.hkdfSalt,
                hkdfInfo = hkdfInfo,
                algorithm = AesGcmKeyAlgorithm("AES-GCM", 256),
                keypair = encapsulation.keypair,
                unwrapKey = encapsulation.unwrapKey,
            )
        }
        val container = ContainerData(
            jwe = encryptJwe(mainKey, plaintextState),
            mainKey = mainKeyInfo,
            prfKeys = prfKeys,
        )
        return EncryptedContainer.serialize(container)
    }

    /** Independently decrypt an exported container without going through JweKeystore, using known PRF material. */
    private fun independentlyDecrypt(containerBytes: ByteArray, prfOutput: ByteArray, hkdfSalt: ByteArray, hkdfInfo: ByteArray): JsonObject {
        val container = EncryptedContainer.parse(containerBytes)
        val mainKeyInfo = container.mainKey!!
        val prfKeyInfo = container.prfKeys.first { it.hkdfSalt.contentEquals(hkdfSalt) }
        val prfKey = EncryptedContainer.derivePrfKey(prfOutput, prfKeyInfo.hkdfSalt, prfKeyInfo.hkdfInfo)
        val mainKey = EncryptedContainer.unwrapMainKey(prfKey, prfKeyInfo, mainKeyInfo)
        val jweObject = JWEObject.parse(container.jwe)
        jweObject.decrypt(AESDecrypter(mainKey))
        return json.parseToJsonElement(jweObject.payload.toString()).jsonObject
    }

    // ── single-credential-v3-001 ─────────────────────────────────────

    @Test
    fun singleCredentialVector_decryptFidelityAndRoundTrip() = runTest {
        val v = vector("single-credential-v3-001")
        val inputs = v["inputs"]!!.jsonObject
        val credentialId = decodeVectorBytes(inputs["credentialId"]!!.jsonPrimitive.content)
        val prfOutput = decodeVectorBytes(inputs["prfOutput"]!!.jsonPrimitive.content)
        val hkdfSalt = decodeVectorBytes(inputs["hkdfSalt"]!!.jsonPrimitive.content)
        val hkdfInfo = inputs["hkdfInfo"]!!.jsonPrimitive.content.toByteArray(Charsets.UTF_8)
        val plaintextState = inputs["plaintextState"]!!.jsonObject

        val containerBytes = buildContainer(
            listOf(PrfEntryInput(credentialId, prfOutput, hkdfSalt)),
            hkdfInfo,
            plaintextState,
        )

        // decryptMatch: decrypting the hand-built container reproduces plaintextState exactly.
        val keystore = JweKeystore()
        keystore.unlock(prfOutput, containerBytes, hkdfSalt, hkdfInfo)
        assertTrue(keystore.isUnlocked)

        // metadata: per-credential fields survive into the publicly-queryable credential store.
        val credentialsArray = plaintextState["S"]!!.jsonObject["credentials"]!!
        val expectedCredObj = (credentialsArray as JsonArray)[0].jsonObject
        val restoredCredJson = keystore.getCredential(1L)
        assertTrue("expected credential 1 to survive decrypt", restoredCredJson != null)
        val restoredCred = json.parseToJsonElement(restoredCredJson!!).jsonObject
        assertEquals(expectedCredObj["format"]!!.jsonPrimitive.content, restoredCred["format"]!!.jsonPrimitive.content)
        assertEquals(expectedCredObj["kid"]!!.jsonPrimitive.content, restoredCred["kid"]!!.jsonPrimitive.content)
        assertEquals(
            expectedCredObj["credentialIssuerIdentifier"]!!.jsonPrimitive.content,
            restoredCred["credential_issuer_identifier"]!!.jsonPrimitive.content,
        )
        assertEquals(
            expectedCredObj["credentialConfigurationId"]!!.jsonPrimitive.content,
            restoredCred["credential_configuration_id"]!!.jsonPrimitive.content,
        )

        // roundTrip: export -> independently decrypt -> compare to the original plaintextState.
        // NOTE: `keypairs[]` is intentionally excluded from this comparison. The
        // vector's keypairs entries are flat metadata stubs ({id, did, algorithm})
        // with no actual EC private key JWK material, unlike the real nested
        // {kid, keypair: {kid, did, alg, publicKey, privateKey}} shape JweKeystore
        // (and wallet-frontend) actually produce - so JweKeystore.loadFromWalletStateV3
        // can't load them into a signable key, and re-export can't reproduce them
        // (there's nothing real to reproduce). This is a limitation of the vector
        // fixture, not of the SDK: every OTHER section (events/lastEventHash/
        // credentials/presentations/settings/credentialIssuanceSessions) round-trips
        // losslessly and is checked explicitly below.
        val exported = keystore.exportEncryptedContainer()
        val redecrypted = independentlyDecrypt(exported, prfOutput, hkdfSalt, hkdfInfo)
        assertEquals(plaintextState["lastEventHash"], redecrypted["lastEventHash"])
        assertEquals(plaintextState["events"], redecrypted["events"])
        assertEquals(plaintextState["S"]!!.jsonObject["credentials"], redecrypted["S"]!!.jsonObject["credentials"])
        assertEquals(plaintextState["S"]!!.jsonObject["presentations"], redecrypted["S"]!!.jsonObject["presentations"])
        assertEquals(plaintextState["S"]!!.jsonObject["settings"], redecrypted["S"]!!.jsonObject["settings"])
        assertEquals(
            plaintextState["S"]!!.jsonObject["credentialIssuanceSessions"],
            redecrypted["S"]!!.jsonObject["credentialIssuanceSessions"],
        )
    }

    @Test
    fun singleCredentialVector_addingCredentialAfterUnlockPreservesOriginalStateAndAddsNew() = runTest {
        // Regression test for a real bug found while writing this suite:
        // buildWalletStateV3() used to return preservedWalletState verbatim
        // whenever it was non-null (i.e. whenever unlock() loaded an EXISTING
        // container), completely ignoring anything saved via saveCredential()/
        // generateKey() during that session - meaning a second credential
        // added by a returning user would silently vanish on export, and
        // lastEventHash/events were reset to empty in the fallback path.
        val v = vector("single-credential-v3-001")
        val inputs = v["inputs"]!!.jsonObject
        val credentialId = decodeVectorBytes(inputs["credentialId"]!!.jsonPrimitive.content)
        val prfOutput = decodeVectorBytes(inputs["prfOutput"]!!.jsonPrimitive.content)
        val hkdfSalt = decodeVectorBytes(inputs["hkdfSalt"]!!.jsonPrimitive.content)
        val hkdfInfo = inputs["hkdfInfo"]!!.jsonPrimitive.content.toByteArray(Charsets.UTF_8)
        val plaintextState = inputs["plaintextState"]!!.jsonObject

        val containerBytes = buildContainer(
            listOf(PrfEntryInput(credentialId, prfOutput, hkdfSalt)),
            hkdfInfo,
            plaintextState,
        )

        val keystore = JweKeystore()
        keystore.unlock(prfOutput, containerBytes, hkdfSalt, hkdfInfo)

        val newCredentialJson = """{"id":999,"format":"vc+sd-jwt","raw":"header.payload.sig","kid":"key-999","credential_issuer_identifier":"https://issuer2.example.com","credential_configuration_id":"other-diploma"}"""
        keystore.saveCredential(999L, newCredentialJson)

        val exported = keystore.exportEncryptedContainer()
        val redecrypted = independentlyDecrypt(exported, prfOutput, hkdfSalt, hkdfInfo)

        // Event history and top-level hash must not be wiped by the mutation.
        assertEquals(plaintextState["lastEventHash"], redecrypted["lastEventHash"])
        assertEquals(plaintextState["events"], redecrypted["events"])

        val redecryptedCreds = redecrypted["S"]!!.jsonObject["credentials"] as JsonArray
        val credIds = redecryptedCreds.map { it.jsonObject["credentialId"]!!.jsonPrimitive.content.toLong() }
        assertTrue("original credential 1 must survive", 1L in credIds)
        assertTrue("newly added credential 999 must be present", 999L in credIds)

        val newCredEntry = redecryptedCreds.first { it.jsonObject["credentialId"]!!.jsonPrimitive.content.toLong() == 999L }.jsonObject
        assertEquals("vc+sd-jwt", newCredEntry["format"]!!.jsonPrimitive.content)
        assertEquals("https://issuer2.example.com", newCredEntry["credentialIssuerIdentifier"]!!.jsonPrimitive.content)
        assertEquals("other-diploma", newCredEntry["credentialConfigurationId"]!!.jsonPrimitive.content)

        // Field completeness: presentations/settings/credentialIssuanceSessions preserved unchanged.
        assertEquals(
            plaintextState["S"]!!.jsonObject["presentations"],
            redecrypted["S"]!!.jsonObject["presentations"],
        )
        assertEquals(
            plaintextState["S"]!!.jsonObject["settings"],
            redecrypted["S"]!!.jsonObject["settings"],
        )
        assertEquals(
            plaintextState["S"]!!.jsonObject["credentialIssuanceSessions"],
            redecrypted["S"]!!.jsonObject["credentialIssuanceSessions"],
        )
    }

    // ── multi-passkey-v3-001 ──────────────────────────────────────────

    @Test
    fun multiPasskeyVector_anyRegisteredPasskeyUnlocksTheSameSharedState() = runTest {
        val v = vector("multi-passkey-v3-001")
        val inputs = v["inputs"]!!.jsonObject
        val credentialIds = (inputs["credentialIds"] as JsonArray).map { it.jsonPrimitive.content }
        val prfOutputs = (inputs["prfOutputs"] as JsonArray).map { it.jsonPrimitive.content }
        val hkdfSalts = (inputs["hkdfSalts"] as JsonArray).map { it.jsonPrimitive.content }
        val hkdfInfo = inputs["hkdfInfo"]!!.jsonPrimitive.content.toByteArray(Charsets.UTF_8)
        val plaintextState = inputs["plaintextState"]!!.jsonObject

        assertEquals(3, credentialIds.size)
        assertEquals(credentialIds.size, prfOutputs.size)
        assertEquals(credentialIds.size, hkdfSalts.size)

        val entries = credentialIds.indices.map { i ->
            PrfEntryInput(
                credentialId = decodeVectorBytes(credentialIds[i]),
                prfOutput = decodeVectorBytes(prfOutputs[i]),
                hkdfSalt = decodeVectorBytes(hkdfSalts[i]),
            )
        }
        val containerBytes = buildContainer(entries, hkdfInfo, plaintextState)

        // prfSelection: unlocking with ANY of the 3 passkeys' own PRF material
        // must resolve to the SAME shared wallet state (all 3 wrap one mainKey).
        for (entry in entries) {
            val keystore = JweKeystore()
            keystore.unlock(entry.prfOutput, containerBytes, entry.hkdfSalt, hkdfInfo)
            assertTrue(keystore.isUnlocked)

            val creds = keystore.getAllCredentials()
            assertEquals(3, creds.size)
            for (id in listOf(1L, 2L, 3L)) {
                assertTrue("credential $id must be visible via passkey ${entries.indexOf(entry)}", creds.containsKey(id))
            }
        }
    }

    @Test
    fun multiPasskeyVector_wrongPrfOutputForAGivenHkdfSaltFailsToUnlock() = runTest {
        val v = vector("multi-passkey-v3-001")
        val inputs = v["inputs"]!!.jsonObject
        val credentialIds = (inputs["credentialIds"] as JsonArray).map { it.jsonPrimitive.content }
        val prfOutputs = (inputs["prfOutputs"] as JsonArray).map { it.jsonPrimitive.content }
        val hkdfSalts = (inputs["hkdfSalts"] as JsonArray).map { it.jsonPrimitive.content }
        val hkdfInfo = inputs["hkdfInfo"]!!.jsonPrimitive.content.toByteArray(Charsets.UTF_8)
        val plaintextState = inputs["plaintextState"]!!.jsonObject

        val entries = credentialIds.indices.map { i ->
            PrfEntryInput(
                credentialId = decodeVectorBytes(credentialIds[i]),
                prfOutput = decodeVectorBytes(prfOutputs[i]),
                hkdfSalt = decodeVectorBytes(hkdfSalts[i]),
            )
        }
        val containerBytes = buildContainer(entries, hkdfInfo, plaintextState)

        // Use passkey #0's hkdfSalt but passkey #1's prfOutput - must fail, not
        // silently unlock into someone else's key material.
        val keystore = JweKeystore()
        try {
            keystore.unlock(entries[1].prfOutput, containerBytes, entries[0].hkdfSalt, hkdfInfo)
            fail("Expected unlock to fail with mismatched prfOutput/hkdfSalt pairing")
        } catch (_: Exception) {
            // expected
        }
    }
}
