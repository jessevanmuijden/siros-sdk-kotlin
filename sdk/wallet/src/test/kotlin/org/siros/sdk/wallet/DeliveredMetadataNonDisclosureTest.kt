// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import java.io.File
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.CredentialDisclosureGuard
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.keystore.JweKeystore

/**
 * The issuer-delivered container `metadata` (a secret_seed, say) is read in exactly one place and never
 * reaches display, history, presentations, logs or the stored credential.
 */
class DeliveredMetadataNonDisclosureTest {
    private val roots = listOf(
        File("src/main/kotlin"),
        File("../keystore/src/main/kotlin"),
        File("../credentials/src/main/kotlin"),
        File("../../sample-app/src/main/kotlin"),
    )

    private fun sources(): List<File> = roots.filter { it.exists() }.flatMap { r -> r.walkTopDown().filter { it.extension == "kt" }.toList() }

    @Test
    fun theContainerMetadataIsReadOnlyByTheKeystoresAndTheSeedSource() {
        val allowed = setOf("JweKeystore.kt", "WscdKeystoreAdapter.kt", "SirosWallet.kt")
        val reader = Regex("""\b(getCredentialMetadata|storedCredentialMetadata)\b""")
        val files = sources()
        assertTrue("no sources found", files.isNotEmpty())
        val offending = files.filter { it.name !in allowed && reader.containsMatchIn(it.readText()) }.map { it.path }
        assertTrue("container metadata read outside the allowed files: $offending", offending.isEmpty())
        // Inside SirosWallet only the seed source's lookup reads it.
        val uses = File("src/main/kotlin/org/siros/sdk/wallet/SirosWallet.kt").readLines()
            .filter { reader.containsMatchIn(it) && !it.trimStart().startsWith("*") && !it.trimStart().startsWith("//") }
        assertEquals(uses.toString(), 4, uses.size) // seed source lambda, its definition, and the two keystore calls
    }

    @Test
    fun theResponseLevelCredentialMetadataIsReadOnlyByTheReceiptCheck() {
        // Strip before merge: the object that can hold the seed is interpreted in exactly one place, which never
        // hands any display, history or logging code the member; everything else only passes the DTO along.
        val reader = Regex("""ResponseCredentialMetadata|credentialMetadata\??\.members|\.members\[|DeliveredResponseMetadata""")
        val allowed = setOf(
            "DeliveredCredentialMetadata.kt", "CredentialResponseMetadata.kt", "EngineTypes.kt", "OpenID4xProfile.kt",
            "SirosWallet.kt", "BlindIssuance.kt",
        )
        val offending = sources().filter { it.name !in allowed && reader.containsMatchIn(it.readText()) }.map { it.path }
        assertTrue("response credential_metadata referenced outside the receipt path: $offending", offending.isEmpty())
        val walletUses = File("src/main/kotlin/org/siros/sdk/wallet/SirosWallet.kt").readLines()
            .filter { Regex("""\.members\b""").containsMatchIn(it) && !it.trimStart().startsWith("*") && !it.trimStart().startsWith("//") }
        assertTrue("SirosWallet reads the members of the response object: $walletUses", walletUses.isEmpty())
    }

    @Test
    fun noLogCallMentionsDeliveredMetadataOrASeed() {
        val sensitive = Regex("""(credentialMetadata|deliveredByIndex|secretSeed|seedHex|storedCredentialMetadata|getCredentialMetadata)""")
        val offending = sources().filter { it.path.contains("/wallet/") || it.path.contains("/keystore/") || it.path.contains("sample-app") }
            .flatMap { f ->
                f.readLines().withIndex().filter { (_, l) ->
                    l.contains("Timber.") && !l.trimStart().startsWith("//") && sensitive.containsMatchIn(l)
                }.map { "${f.name}:${it.index + 1}" }
            }
        assertTrue("delivered metadata or seed named in a log call: $offending", offending.isEmpty())
    }

    @Test
    fun theKeystoreHoldsItApartFromEverythingTheStoreAndTheViewsSee() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(ByteArray(32) { it.toByte() }, ByteArray(0), ByteArray(32) { 5 }, "info".toByteArray())
        val cred = StoredCredential(
            id = 5L, format = "dc+sd-jwt", raw = NymTestCredentials.sdJwt(), batchId = 1L, instanceId = 0,
            metadata = org.siros.sdk.credentials.CredentialMetadata(name = "Nym", vct = "urn:nym"),
        )
        keystore.saveCredential(5L, Json.encodeToString(StoredCredential.serializer(), cred))
        keystore.setCredentialMetadata(
            5L,
            buildJsonArray {
                add(buildJsonObject { put("type", JsonPrimitive("org.siros.secret_seed")); put("value", buildJsonObject { put("org.siros.nym_auth", JsonPrimitive(NymTestCredentials.seedHex)) }) })
            },
        )
        // Not in the credential the store hands out, nor in any raw view of it.
        assertFalse(keystore.getCredential(5L)!!.contains(NymTestCredentials.seedHex))
        assertFalse(keystore.getAllCredentials().toString().contains(NymTestCredentials.seedHex))
        val view = CredentialDisclosureGuard.rawViewOf(cred)
        assertFalse(view.toString().contains(NymTestCredentials.seedHex))
        assertFalse(cred.toString().contains(NymTestCredentials.seedHex))
        // And the wallet's accessor is what the seed source reads, per credential.
        val wallet = allocate(keystore)
        assertEquals(1, wallet.storedCredentialMetadata(5L)!!.size)
        assertNull(wallet.storedCredentialMetadata(6L))
    }

    private fun allocate(keystore: JweKeystore): SirosWallet {
        val unsafeClass = Class.forName("sun.misc.Unsafe")
        val unsafeField = unsafeClass.getDeclaredField("theUnsafe").also { it.isAccessible = true }
        val wallet = unsafeClass.getMethod("allocateInstance", Class::class.java)
            .invoke(unsafeField.get(null), SirosWallet::class.java) as SirosWallet
        val f = SirosWallet::class.java.getDeclaredField("keystore").also { it.isAccessible = true }
        f.set(wallet, keystore)
        return wallet
    }
}
