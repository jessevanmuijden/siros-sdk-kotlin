package org.siros.sdk.keystore

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.AESDecrypter
import com.nimbusds.jose.crypto.AESEncrypter
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.BbsHolderState
import org.siros.sdk.credentials.KeystoreException

/**
 * `S.extensions` in the container — privatedata-spec §6.1.
 *
 * The property under test throughout is the one the whole extension design
 * rests on: a client must be able to carry a namespace it does not
 * implement. Everything else here is bookkeeping; that one is the reason
 * the mechanism exists.
 */
class ExtensionStoreTest {

    private val fakePrfOutput = ByteArray(32) { it.toByte() }
    private val hkdfSalt = ByteArray(32) { (it + 0x10).toByte() }
    private val hkdfInfo = "SIROS Wallet PRF".toByteArray(Charsets.UTF_8)

    private suspend fun freshKeystore(): JweKeystore =
        JweKeystore().also { it.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo) }

    private suspend fun reopen(container: ByteArray): JweKeystore =
        JweKeystore().also { it.unlock(fakePrfOutput, container, hkdfSalt, hkdfInfo) }

    // -----------------------------------------------------------------------

    @Test
    fun entriesSurviveExportAndReopen() = runTest {
        val keystore = freshKeystore()
        keystore.setExtensionEntry("org.siros.bbs", "cred-1", "state-one")
        keystore.setExtensionEntry("org.siros.bbs", "cred-2", "state-two")
        keystore.setExtensionEntry("org.siros.wscd", "kid-a1b2", "key-metadata")

        val reopened = reopen(keystore.exportEncryptedContainer())

        assertEquals(
            mapOf("cred-1" to "state-one", "cred-2" to "state-two"),
            reopened.extensionEntries("org.siros.bbs"),
        )
        assertEquals(
            mapOf("kid-a1b2" to "key-metadata"),
            reopened.extensionEntries("org.siros.wscd"),
        )
    }

    /**
     * A namespace this build has never heard of must round-trip untouched.
     *
     * This is the invariant. A client that drops what it does not recognise
     * does not degrade a credential, it destroys one — the state a blind BBS
     * credential needs cannot be reconstructed after the fact. And the
     * failure lands on whichever client is *last*, not the one that caused
     * it.
     */
    @Test
    fun anUnknownNamespaceIsCarriedVerbatim() = runTest {
        val keystore = freshKeystore()
        keystore.setExtensionEntry("com.example.not.implemented.here", "entity-7", "opaque-payload")
        keystore.setExtensionEntry("org.siros.bbs", "cred-1", "state-one")

        // Two round trips, so a client that reads and rewrites twice is
        // covered rather than only the first hop.
        val once = reopen(keystore.exportEncryptedContainer())
        val twice = reopen(once.exportEncryptedContainer())

        assertEquals(
            mapOf("entity-7" to "opaque-payload"),
            twice.extensionEntries("com.example.not.implemented.here"),
        )
        assertEquals(mapOf("cred-1" to "state-one"), twice.extensionEntries("org.siros.bbs"))
    }

    @Test
    fun anAbsentNamespaceIsEmptyRatherThanAnError() = runTest {
        val keystore = freshKeystore()
        assertEquals(emptyMap<String, String>(), keystore.extensionEntries("org.siros.bbs"))
    }

    /**
     * Deleting the entity an entry names must delete the entry
     * (privatedata-spec §6.1.2). An entry left behind is a long-lived secret
     * belonging to a credential that no longer exists.
     */
    @Test
    fun removingAnEntryDropsItAndEmptiesTheNamespace() = runTest {
        val keystore = freshKeystore()
        keystore.setExtensionEntry("org.siros.bbs", "cred-1", "state-one")
        keystore.setExtensionEntry("org.siros.bbs", "cred-2", "state-two")

        keystore.removeExtensionEntry("org.siros.bbs", "cred-1")
        assertEquals(mapOf("cred-2" to "state-two"), keystore.extensionEntries("org.siros.bbs"))

        keystore.removeExtensionEntry("org.siros.bbs", "cred-2")
        val reopened = reopen(keystore.exportEncryptedContainer())
        assertEquals(emptyMap<String, String>(), reopened.extensionEntries("org.siros.bbs"))

        // And the namespace leaves no empty object behind in the container.
        assertNull(extensionsOf(reopened.exportEncryptedContainer())?.get("org.siros.bbs"))
    }

    /**
     * The wire shape is what privatedata-spec §6.1 specifies: namespace ->
     * entry key -> opaque string. Checked against the container rather than
     * the accessors, since another client reads the container.
     */
    @Test
    fun theWireShapeMatchesTheSpecification() = runTest {
        val keystore = freshKeystore()
        keystore.setExtensionEntry("org.siros.bbs", "cred-1", "state-one")

        val extensions = extensionsOf(keystore.exportEncryptedContainer())
        assertTrue("S.extensions must be present", extensions != null)
        val ns = extensions!!["org.siros.bbs"]!!.jsonObject
        assertEquals("state-one", ns["cred-1"]!!.jsonPrimitive.content)
    }

    /** Later writes to one key replace earlier ones — last-write-wins. */
    @Test
    fun writingTheSameKeyTwiceKeepsTheLaterValue() = runTest {
        val keystore = freshKeystore()
        keystore.setExtensionEntry("org.siros.bbs", "cred-1", "first")
        keystore.setExtensionEntry("org.siros.bbs", "cred-1", "second")
        assertEquals(mapOf("cred-1" to "second"), keystore.extensionEntries("org.siros.bbs"))
    }

    // --- BbsHolderStateVault ------------------------------------------------

    @Test
    fun holderStateRoundTripsThroughTheContainer() = runTest {
        val keystore = freshKeystore()
        val vault = BbsHolderStateVault(keystore)
        val state = BbsHolderState(
            issuerPublicKey = byteArrayOf(1, 2, 3),
            secretProverBlind = ByteArray(32) { it.toByte() },
            committedMessages = listOf(byteArrayOf(9), byteArrayOf(8, 7)),
            keybindPublicKeys = listOf(byteArrayOf(4, 5)),
        )

        vault.put("cred-1", state)
        val restored = BbsHolderStateVault(reopen(keystore.exportEncryptedContainer())).get("cred-1")

        assertEquals(state, restored)
    }

    /**
     * Two credentials' state must not overwrite each other.
     *
     * This is why the entry key names a credential rather than the
     * subsystem: an aggregate `"bbs"` entry would make the second write
     * discard the first, and resolution is last-write-wins per entry.
     */
    @Test
    fun eachCredentialGetsItsOwnEntry() = runTest {
        val keystore = freshKeystore()
        val vault = BbsHolderStateVault(keystore)
        val a = BbsHolderState(byteArrayOf(1), ByteArray(32), listOf(byteArrayOf(0xA)), emptyList())
        val b = BbsHolderState(byteArrayOf(2), ByteArray(32) { 1 }, listOf(byteArrayOf(0xB)), emptyList())

        vault.put("cred-a", a)
        vault.put("cred-b", b)

        assertEquals(a, vault.get("cred-a"))
        assertEquals(b, vault.get("cred-b"))
        assertEquals(setOf("cred-a", "cred-b"), vault.credentialIds())
    }

    /**
     * Missing state means "cannot present", and the caller must be able to
     * tell that apart from a successful lookup — never presented unbound.
     */
    @Test
    fun absentHolderStateIsNull() = runTest {
        val vault = BbsHolderStateVault(freshKeystore())
        assertNull(vault.get("never-stored"))
    }

    @Test
    fun removingHolderStateDeletesTheEntry() = runTest {
        val keystore = freshKeystore()
        val vault = BbsHolderStateVault(keystore)
        vault.put("cred-1", BbsHolderState(byteArrayOf(1), ByteArray(32), emptyList(), emptyList()))
        vault.remove("cred-1")
        assertNull(vault.get("cred-1"))
        assertEquals(emptySet<String>(), vault.credentialIds())
    }

    /**
     * A corrupt entry reads as absent rather than throwing.
     *
     * The caller's contract is already "null means this cannot be
     * presented"; surfacing a decode failure as an exception from a lookup
     * would give it a second way to fail with the same meaning.
     */
    @Test
    fun anUndecodableEntryReadsAsAbsent() = runTest {
        val keystore = freshKeystore()
        keystore.setExtensionEntry(BbsHolderStateVault.NAMESPACE, "cred-1", "not json at all")
        assertNull(BbsHolderStateVault(keystore).get("cred-1"))
    }

    // --- what a non-conforming or second container does ----------------------

    /**
     * §6.1 makes an entry value a string. A peer that stored a number or a
     * boolean must not have it read in as one (no entry is reported for it)
     * nor handed back re-typed; and since spec 3.0 a rewriter must preserve
     * what it does not understand, so it is written back UNCHANGED and in place.
     */
    @Test
    fun aNonStringEntryValueIsNotReadButWrittenBackUnchanged() = runTest {
        val keystore = freshKeystore()
        keystore.setExtensionEntry("org.siros.bbs", "cred-1", "state-one")

        val tampered = rewriteExtensions(keystore.exportEncryptedContainer()) {
            put(
                "com.example.peer",
                buildJsonObject {
                    put("number", JsonPrimitive(42))
                    put("boolean", JsonPrimitive(true))
                    put("object", buildJsonObject { put("nested", JsonPrimitive("x")) })
                    put("text", JsonPrimitive("carried"))
                },
            )
        }

        val reopened = reopen(tampered)
        assertEquals(
            mapOf("text" to "carried"),
            reopened.extensionEntries("com.example.peer"),
        )
        // And nothing re-typed reaches the container on the way back out: every value is as authored.
        val peer = extensionsOf(reopened.exportEncryptedContainer())!!["com.example.peer"]!!.jsonObject
        assertEquals(listOf("number", "boolean", "object", "text"), peer.keys.toList())
        assertEquals(JsonPrimitive(42), peer["number"])
        assertEquals(JsonPrimitive(true), peer["boolean"])
        assertEquals(buildJsonObject { put("nested", JsonPrimitive("x")) }, peer["object"])
        assertEquals(mapOf("cred-1" to "state-one"), reopened.extensionEntries("org.siros.bbs"))
    }

    /**
     * Unlocking is a load, not a merge.
     *
     * The same instance can be unlocked against a second container — another
     * account on a shared device, or a re-unlock after entries were dropped
     * elsewhere. Carrying the first container's entries into the second and
     * writing them back on export would put one account's state, including
     * long-lived BBS secrets, into another's container.
     */
    @Test
    fun unlockingASecondContainerReplacesRatherThanMergesEntries() = runTest {
        val first = freshKeystore()
        first.setExtensionEntry("org.siros.bbs", "cred-1", "state-one")

        val second = freshKeystore()
        second.setExtensionEntry("org.siros.bbs", "cred-2", "state-two")

        val keystore = reopen(first.exportEncryptedContainer())
        assertEquals(mapOf("cred-1" to "state-one"), keystore.extensionEntries("org.siros.bbs"))

        keystore.unlock(fakePrfOutput, second.exportEncryptedContainer(), hkdfSalt, hkdfInfo)

        assertEquals(mapOf("cred-2" to "state-two"), keystore.extensionEntries("org.siros.bbs"))
        assertEquals(
            "the first container's entry must not be written back into the second",
            mapOf("cred-2" to "state-two"),
            reopen(keystore.exportEncryptedContainer()).extensionEntries("org.siros.bbs"),
        )
    }

    /**
     * A write to a locked keystore has nowhere to go: [JweKeystore.lock] has
     * already dropped the in-memory map and the next unlock loads rather
     * than merges. Silently accepting it would tell a caller its state was
     * stored when it was not — and for BBS that state cannot be recomputed.
     */
    @Test
    fun mutatingWhileLockedFailsRatherThanBeingDiscarded() = runTest {
        val keystore = freshKeystore()
        keystore.setExtensionEntry("org.siros.bbs", "cred-1", "state-one")
        keystore.lock()

        assertThrows(KeystoreException::class.java) {
            runBlocking { keystore.setExtensionEntry("org.siros.bbs", "cred-1", "state-one") }
        }
        assertThrows(KeystoreException::class.java) {
            runBlocking { keystore.removeExtensionEntry("org.siros.bbs", "cred-1") }
        }

        // Reading, though, stays a plain "nothing available" — the answer a
        // presentation-time lookup already has to handle.
        assertEquals(emptyMap<String, String>(), keystore.extensionEntries("org.siros.bbs"))
    }

    // --- the other container owner -------------------------------------------

    /**
     * `WscdKeystoreAdapter` must write extension state into the same
     * container its credentials live in.
     *
     * Two classes own a container, and which one a wallet has depends on
     * whether its signing keys are WSCD-backed — a deployment detail that
     * has nothing to do with extension state. If this adapter kept its own
     * copy, or dropped writes, a WSCD-backed wallet would issue BBS
     * credentials whose holder state never reached the account's other
     * devices. Same failure as not storing it at all, only harder to see.
     */
    @Test
    fun theWscdAdapterWritesIntoTheContainerItExports() = runTest {
        val adapter = WscdKeystoreAdapter(mockk<Signer>(relaxed = true))
        adapter.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)

        BbsHolderStateVault(adapter).put(
            "cred-1",
            BbsHolderState(byteArrayOf(1), ByteArray(32) { 2 }, listOf(byteArrayOf(3)), emptyList()),
        )

        val extensions = extensionsOf(adapter.exportEncryptedContainer())
        assertEquals(
            "the entry must be in the exported container, not only in the adapter",
            1,
            extensions?.get(BbsHolderStateVault.NAMESPACE)?.jsonObject?.size,
        )
    }

    /**
     * And a container written by one owner must be readable by the other —
     * they are the same format by design, so a user moving between a
     * WSCD-backed build and a software one keeps their credentials usable.
     */
    @Test
    fun eitherOwnerCanReadWhatTheOtherWrote() = runTest {
        val state = BbsHolderState(byteArrayOf(9), ByteArray(32) { 4 }, listOf(byteArrayOf(5)), emptyList())

        val adapter = WscdKeystoreAdapter(mockk<Signer>(relaxed = true))
        adapter.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        BbsHolderStateVault(adapter).put("cred-1", state)

        val plain = reopen(adapter.exportEncryptedContainer())
        assertEquals(state, BbsHolderStateVault(plain).get("cred-1"))

        // ...and back the other way.
        BbsHolderStateVault(plain).put("cred-2", state)
        val adapter2 = WscdKeystoreAdapter(mockk<Signer>(relaxed = true))
        adapter2.unlock(fakePrfOutput, plain.exportEncryptedContainer(), hkdfSalt, hkdfInfo)
        assertEquals(state, BbsHolderStateVault(adapter2).get("cred-2"))
    }

    // --- helpers ------------------------------------------------------------

    /**
     * Reads `S.extensions` straight out of the container's plaintext, the
     * way a peer client would — decrypting here rather than adding a
     * test-only accessor to production code.
     */
    private fun extensionsOf(container: ByteArray): JsonObject? {
        val parsed = EncryptedContainer.parse(container)
        val prfKeyInfo = parsed.prfKeys.first()
        val prfKey = EncryptedContainer.derivePrfKey(fakePrfOutput, prfKeyInfo.hkdfSalt, prfKeyInfo.hkdfInfo)
        val mainKey = EncryptedContainer.unwrapMainKey(prfKey, prfKeyInfo, parsed.mainKey!!)
        val jwe = JWEObject.parse(parsed.jwe)
        jwe.decrypt(AESDecrypter(mainKey))
        return Json.parseToJsonElement(jwe.payload.toString())
            .jsonObject["S"]?.jsonObject?.get("extensions")?.jsonObject
    }

    /**
     * Rewrites `S.extensions` inside a container and re-encrypts it, so a
     * test can present the keystore with a shape only a *peer* client would
     * have written. [transform] receives the existing entries and returns
     * the replacement.
     */
    private fun rewriteExtensions(
        container: ByteArray,
        transform: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit,
    ): ByteArray {
        val parsed = EncryptedContainer.parse(container)
        val prfKeyInfo = parsed.prfKeys.first()
        val prfKey = EncryptedContainer.derivePrfKey(fakePrfOutput, prfKeyInfo.hkdfSalt, prfKeyInfo.hkdfInfo)
        val mainKey = EncryptedContainer.unwrapMainKey(prfKey, prfKeyInfo, parsed.mainKey!!)
        val jwe = JWEObject.parse(parsed.jwe)
        jwe.decrypt(AESDecrypter(mainKey))
        val plaintext = Json.parseToJsonElement(jwe.payload.toString()).jsonObject
        val state = plaintext["S"]!!.jsonObject

        val rewritten = buildJsonObject {
            plaintext.forEach { (key, value) -> if (key != "S") put(key, value) }
            put(
                "S",
                buildJsonObject {
                    state.forEach { (key, value) -> if (key != "extensions") put(key, value) }
                    put(
                        "extensions",
                        buildJsonObject {
                            state["extensions"]?.jsonObject?.forEach { (ns, value) -> put(ns, value) }
                            transform()
                        },
                    )
                },
            )
        }

        val reencrypted = JWEObject(
            JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256GCM),
            Payload(rewritten.toString()),
        ).also { it.encrypt(AESEncrypter(mainKey)) }
        return EncryptedContainer.serialize(parsed.copy(jwe = reencrypted.serialize()))
    }
}
