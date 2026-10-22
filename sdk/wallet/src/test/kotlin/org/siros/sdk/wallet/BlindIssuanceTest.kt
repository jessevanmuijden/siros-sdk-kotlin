// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.ECKey
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.transport.CredentialResponseEncryptionRequest

/** The per-flow response key and opened-response state of an engine-blind issuance. */
class BlindIssuanceTest {

    private val request = CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", required = false)

    private fun issuer(jwk: JsonObject, body: JsonObject, alg: String = "ECDH-ES", enc: String = "A256GCM"): String {
        val obj = JWEObject(
            JWEHeader.Builder(JWEAlgorithm.parse(alg), EncryptionMethod.parse(enc)).build(),
            Payload(body.toString()),
        )
        obj.encrypt(ECDHEncrypter(ECKey.parse(jwk.toString())))
        return obj.serialize()
    }

    private fun response(vararg credentials: String, extra: () -> Map<String, kotlinx.serialization.json.JsonElement> = { emptyMap() }) =
        buildJsonObject {
            put("credentials", JsonArray(credentials.map { buildJsonObject { put("credential", JsonPrimitive(it)) } }))
            extra().forEach { (k, v) -> put(k, v) }
        }

    @Test
    fun noEncryptionRequestDeclinesAndHoldsNoKey() {
        val b = BlindIssuance()
        assertNull(b.offer("f", null))
        assertFalse(b.holdsKey("f"))
    }

    @Test
    fun anOfferedKeyIsHeldPerFlowAndItsPublicJwkIsReturned() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        assertTrue(b.holdsKey("f"))
        assertFalse(b.holdsKey("other"))
        assertEquals("enc", (jwk["use"] as JsonPrimitive).content)
        assertFalse(jwk.containsKey("d"))
    }

    @Test
    fun everyOfferGeneratesAFreshKeyAndTheOldOneNoLongerOpensAnything() {
        val b = BlindIssuance()
        val first = b.offer("f", request)!!
        val second = b.offer("f", request)!!
        assertNotEquals(first, second)
        // The issuer answered the first request, but the engine has moved on to a retry: the first key is gone.
        val stale = issuer(first, response("c1"))
        assertThrows(BlindIssuanceException::class.java) { b.open("f", stale, deferred = false) }
        b.open("f", issuer(second, response("c1")), deferred = false)
    }

    @Test
    fun aRequiredEncryptionTheWalletCannotProvideFailsTheIssuanceAndAnOptionalOneDeclines() {
        val b = BlindIssuance()
        val unsupported = CredentialResponseEncryptionRequest("RSA-OAEP", "A128GCM", required = true)
        val e = assertThrows(BlindIssuanceException::class.java) { b.offer("f", unsupported) }
        assertTrue(e.message!!, e.message!!.contains("requires"))
        assertFalse(b.holdsKey("f"))
        assertNull(b.offer("f", unsupported.copy(required = false)))
        assertFalse(b.holdsKey("f"))
    }

    @Test
    fun aDeclinedRetryDropsTheKeyOfTheEarlierRequest() {
        val b = BlindIssuance()
        b.offer("f", request)
        assertNull(b.offer("f", null))
        assertFalse(b.holdsKey("f"))
    }

    @Test
    fun openingReturnsOnlyTheControlFieldsAndKeepsTheRest() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        val control = b.open(
            "f",
            issuer(jwk, response("cred-1", "cred-2") { mapOf("notification_id" to JsonPrimitive("n-1")) }),
            deferred = false,
        )
        assertEquals(2, control.credentialCount)
        assertNull(control.transactionId)
        assertNull(control.interval)
        val taken = b.take("f")!!
        assertEquals(listOf("cred-1", "cred-2"), taken.credentials)
        assertEquals("n-1", taken.notificationId)
        assertTrue(taken.credentialMetadataEncryptedResponse)
        assertFalse(taken.deferredResponse)
    }

    @Test
    fun aDeferredIssuanceReturnsItsTransactionIdAndLaterDeliversTheCredentials() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        val pending = b.open(
            "f",
            issuer(jwk, buildJsonObject { put("transaction_id", JsonPrimitive("tx-9")); put("interval", JsonPrimitive(5)) }),
            deferred = false,
        )
        assertEquals("tx-9", pending.transactionId)
        assertEquals(5, pending.interval)
        val metadata = buildJsonObject { put("display", JsonArray(listOf(buildJsonObject { put("name", JsonPrimitive("N")) }))) }
        b.open(
            "f",
            issuer(jwk, response("late") { mapOf("notification_id" to JsonPrimitive("n-2"), "credential_metadata" to metadata) }),
            deferred = true,
        )
        val taken = b.take("f")!!
        assertEquals(listOf("late"), taken.credentials)
        assertEquals("n-2", taken.notificationId)
        assertEquals(metadata, taken.credentialMetadata!!.members)
        assertTrue("credentials that came from a Deferred Credential Response say so", taken.deferredResponse)
    }

    @Test
    fun metadataIsNeverCarriedBetweenResponses_aPendingResponsesMetadataIsNotAttachedToTheDeferredCredentials() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        // The initial pending response carries display metadata (a seed would be refused, below).
        b.open("f", issuer(jwk, buildJsonObject { put("transaction_id", JsonPrimitive("tx")); put("credential_metadata", buildJsonObject { put("display", JsonArray(listOf(buildJsonObject { put("name", JsonPrimitive("from-pending")) }))) }) }), deferred = false)
        // The deferred response that delivers the credentials carries none.
        b.open("f", issuer(jwk, response("late") { mapOf("notification_id" to JsonPrimitive("n")) }), deferred = true)
        val taken = b.take("f")!!
        assertEquals(listOf("late"), taken.credentials)
        assertNull("nothing of the pending response is attached", taken.credentialMetadata)
    }

    @Test
    fun aDeferredCredentialResponseCarryingASeedIsRefusedAtDecryption_withItsNotificationIdAndNothingRetained() {
        val seed = buildJsonObject { put("org.siros.secret_seed", buildJsonObject { put("org.siros.nym_auth", JsonPrimitive("00112233445566778899aabbccddeeff")) }) }
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        // First a pending response, then the deferred response WITH the credentials and a seed (deferred = true).
        b.open("f", issuer(jwk, buildJsonObject { put("transaction_id", JsonPrimitive("tx")) }), deferred = false)
        val e = assertThrows(BlindIssuanceException::class.java) {
            b.open("f", issuer(jwk, response("late") { mapOf("notification_id" to JsonPrimitive("n-seed"), "credential_metadata" to seed) }), deferred = true)
        }
        assertEquals("n-seed", e.notificationId)
        assertFalse(e.message!!.contains("00112233"))
        assertNull("nothing is retained", b.take("f"))
        // A first (non-deferred) response with credentials may still carry a seed: that is the normal delivery.
        val b2 = BlindIssuance()
        val jwk2 = b2.offer("g", request)!!
        b2.open("g", issuer(jwk2, response("c") { mapOf("notification_id" to JsonPrimitive("n"), "credential_metadata" to seed) }), deferred = false)
        assertNotNull(b2.take("g")!!.credentialMetadata)
    }

    @Test
    fun everyCredentialsEntryMustBeAnObjectWithAStringCredential_theInnerValueIsStored() {
        // Accepted: wrapped entries (the inner string is stored), and the one pre-1.0 draft shape, a top-level string `credential`.
        val ok = BlindIssuance()
        val jwk = ok.offer("f", request)!!
        ok.open(
            "f",
            issuer(
                jwk,
                buildJsonObject {
                    put("credential", JsonPrimitive("legacy"))
                    put("credentials", JsonArray(listOf(buildJsonObject { put("credential", JsonPrimitive("wrapped")) })))
                },
            ),
            deferred = false,
        )
        assertEquals(listOf("legacy", "wrapped"), ok.take("f")!!.credentials)
        // Refused, each keeping the decrypted notification_id and retaining nothing.
        fun refused(entries: JsonArray?, topLevel: kotlinx.serialization.json.JsonElement? = null) {
            val b = BlindIssuance()
            val k = b.offer("f", request)!!
            val body = buildJsonObject {
                put("notification_id", JsonPrimitive("n-bad"))
                topLevel?.let { put("credential", it) }
                entries?.let { put("credentials", it) }
            }
            val e = assertThrows(BlindIssuanceException::class.java) { b.open("f", issuer(k, body), deferred = false) }
            assertEquals("n-bad", e.notificationId)
            assertNull(b.take("f"))
        }
        refused(JsonArray(listOf(JsonPrimitive("bare string"))))
        refused(JsonArray(listOf(buildJsonObject { put("credential", buildJsonObject { put("@context", JsonPrimitive("x")) }) })))
        refused(JsonArray(listOf(buildJsonObject { put("credential", JsonPrimitive(7)) })))
        refused(JsonArray(listOf(buildJsonObject { put("credential", JsonPrimitive("")) })))
        refused(JsonArray(listOf(buildJsonObject { put("x", JsonPrimitive(1)) })))
        refused(JsonArray(listOf(JsonPrimitive("ok-ish"), buildJsonObject { put("credential", JsonPrimitive("fine")) })))
        refused(null, topLevel = buildJsonObject { put("credential", JsonPrimitive("nested")) })
        refused(null, topLevel = JsonPrimitive(5))
    }

    @Test
    fun aResponseLevelMetadataThatIsNotAnObjectIsKeptAsMalformedForTheReceiptToRefuse() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        b.open("f", issuer(jwk, response("c") { mapOf("credential_metadata" to JsonPrimitive("text")) }), deferred = false)
        assertTrue(b.take("f")!!.credentialMetadata!!.malformed)
    }

    @Test
    fun takeForgetsTheFlowSoTheKeyIsGoneAfterCompletion() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        b.open("f", issuer(jwk, response("c")), deferred = false)
        assertNotNull(b.take("f"))
        assertFalse(b.holdsKey("f"))
        assertNull(b.take("f"))
        assertThrows(BlindIssuanceException::class.java) { b.open("f", issuer(jwk, response("c")), deferred = false) }
    }

    @Test
    fun dropAndClearForgetKeysAndOpenedResponses() {
        val b = BlindIssuance()
        val jwkA = b.offer("a", request)!!
        b.offer("b", request)
        b.open("a", issuer(jwkA, response("c")), deferred = false)
        b.drop("a")
        assertFalse(b.holdsKey("a"))
        assertNull(b.take("a"))
        assertTrue(b.holdsKey("b"))
        b.clear()
        assertFalse(b.holdsKey("b"))
    }

    @Test
    fun openingFailsWithoutAKeyOnAnUndecryptableJweOrANonObjectPlaintext() {
        val b = BlindIssuance()
        assertThrows(BlindIssuanceException::class.java) { b.open("none", "a.b.c.d.e", deferred = false) }
        val jwk = b.offer("f", request)!!
        val e = assertThrows(BlindIssuanceException::class.java) { b.open("f", "not-a-jwe", deferred = false) }
        assertFalse(e.message!!.contains("not-a-jwe"))
        // A JWE that opens but holds an array, not a Credential Response.
        val obj = JWEObject(
            JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM).build(),
            Payload("[1,2]"),
        )
        obj.encrypt(ECDHEncrypter(ECKey.parse(jwk.toString())))
        assertThrows(BlindIssuanceException::class.java) { b.open("f", obj.serialize(), deferred = false) }
        assertNull("nothing was opened", b.take("f"))
    }

    @Test
    fun nothingPrintsACredentialOrASeed() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        b.open("f", issuer(jwk, response("secret-credential") { mapOf("notification_id" to JsonPrimitive("n")) }), deferred = false)
        val taken = b.take("f")!!
        assertFalse(taken.toString().contains("secret-credential"))
    }

    @Test
    fun aDeferredAnswerIsATransactionIdWithNoCountAndAnIssuedOneACountWithNoTransactionId() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        val pending = b.open("f", issuer(jwk, buildJsonObject { put("transaction_id", JsonPrimitive("tx")); put("interval", JsonPrimitive(7)) }), deferred = false)
        assertNull(pending.credentialCount)
        assertEquals("tx", pending.transactionId)
        assertEquals(7, pending.interval)
        // A deferred answer that again reports a transaction_id is answered the same way.
        val again = b.open("f", issuer(jwk, buildJsonObject { put("transaction_id", JsonPrimitive("tx2")) }), deferred = true)
        assertEquals("tx2", again.transactionId)
        assertNull(again.interval)
        val issued = b.open("f", issuer(jwk, response("a", "b", "c")), deferred = true)
        assertEquals(3, issued.credentialCount)
        assertNull(issued.transactionId)
        assertNull(issued.interval)
    }

    @Test
    fun aResponseWithBothOrNeitherIsRefusedKeepsNothingAndCarriesItsNotificationIdForTheReport() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        val both = response("c") { mapOf("transaction_id" to JsonPrimitive("tx"), "notification_id" to JsonPrimitive("n-both")) }
        val e1 = assertThrows(BlindIssuanceException::class.java) { b.open("f", issuer(jwk, both), deferred = false) }
        assertEquals("n-both", e1.notificationId)
        val neither = buildJsonObject { put("notification_id", JsonPrimitive("n-none")) }
        val e2 = assertThrows(BlindIssuanceException::class.java) { b.open("f", issuer(jwk, neither), deferred = false) }
        assertEquals("n-none", e2.notificationId)
        assertNull("a refused response is not kept", b.take("f"))
    }

    @Test
    fun theCountIsCappedAt256AndTheCapItselfIsAccepted() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        val atCap = b.open("f", issuer(jwk, response(*Array(256) { "c$it" })), deferred = false)
        assertEquals(256, atCap.credentialCount)
        b.drop("f")
        val jwk2 = b.offer("f", request)!!
        val e = assertThrows(BlindIssuanceException::class.java) { b.open("f", issuer(jwk2, response(*Array(257) { "c$it" })), deferred = false) }
        assertNull("no notification_id was in the response", e.notificationId)
        assertNull(b.take("f"))
    }

    @Test
    fun aJweThatDoesNotOpenCarriesNoNotificationId() {
        val b = BlindIssuance()
        b.offer("f", request)
        val e = assertThrows(BlindIssuanceException::class.java) { b.open("f", "a.b.c.d.e", deferred = false) }
        assertNull(e.notificationId)
    }

    // ---- the shape limits the engine used to enforce on credential_metadata (go-wallet-backend#463) ----

    private fun issuerRaw(jwk: JsonObject, text: String): String {
        val obj = JWEObject(JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM).build(), Payload(text))
        obj.encrypt(ECDHEncrypter(ECKey.parse(jwk.toString())))
        return obj.serialize()
    }

    /** A Credential Response whose `credential_metadata` is the raw JSON [metadata], with a notification_id. */
    private fun withMetadata(metadata: String) =
        """{"credentials":[{"credential":"c"}],"notification_id":"n-m","credential_metadata":$metadata}"""

    private fun accepted(metadata: String): Boolean {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        return try {
            b.open("f", issuerRaw(jwk, withMetadata(metadata)), deferred = false)
            true
        } catch (e: BlindIssuanceException) {
            false
        }
    }

    private fun refusedKeepingNotificationId(metadata: String) {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        val e = assertThrows(metadata.take(60), BlindIssuanceException::class.java) { b.open("f", issuerRaw(jwk, withMetadata(metadata)), deferred = false) }
        assertEquals("the decrypted notification_id is kept so the issuer can be told", "n-m", e.notificationId)
        assertNull("nothing of a refused response is retained", b.take("f"))
        assertFalse("the message names no value", e.message!!.contains("ppp"))
    }

    private fun nestedObjects(depth: Int) = "{\"a\":".repeat(depth) + "1" + "}".repeat(depth)
    private fun nestedArrays(containers: Int) = """{"a":""" + "[".repeat(containers - 1) + "]".repeat(containers - 1) + "}"
    private fun members(n: Int) = (0 until n).joinToString(",") { "\"k$it\":1" }

    @Test
    fun metadataExactlyAtEveryLimitIsAccepted() {
        // Depth counts the metadata object as 1: 16 nested objects, and an object holding 15 nested arrays, are the deepest.
        assertTrue(accepted(nestedObjects(16)))
        assertTrue(accepted(nestedArrays(16)))
        assertTrue(accepted("{" + members(256) + "}"))
        assertTrue(accepted("""{"x":{""" + members(256) + "}}"))
        assertTrue(accepted("""{"${"k".repeat(256)}":1}"""))
        // 128 two-byte characters are 256 bytes.
        assertTrue(accepted("""{"${"\u00e9".repeat(128)}":1}"""))
        assertTrue(accepted("""{"${"é".repeat(128)}":1}"""))
        // Exactly 1 MiB encoded: {"x":"<n>"} is 8 bytes of structure.
        assertTrue(accepted("""{"x":"${"p".repeat(CredentialMetadataShape.MAX_BYTES - 8)}"}"""))
        // Duplicate names are only refused at the top level and inside the seed object.
        assertTrue(accepted("""{"display":[{"name":"a","name":"b"}],"x":{"y":1,"y":2}}"""))
        assertTrue(accepted("{}"))
    }

    @Test
    fun metadataOverAnyLimitIsRefusedKeepsNothingAndKeepsTheNotificationId() {
        refusedKeepingNotificationId(nestedObjects(17))
        refusedKeepingNotificationId(nestedArrays(17))
        refusedKeepingNotificationId("{" + members(257) + "}")
        refusedKeepingNotificationId("""{"x":{""" + members(257) + "}}")
        refusedKeepingNotificationId("""{"${"k".repeat(257)}":1}""")
        refusedKeepingNotificationId("""{"x":{"${"k".repeat(257)}":1}}""")
        refusedKeepingNotificationId("""{"${"\u00e9".repeat(129)}":1}""")
        refusedKeepingNotificationId("""{"${"é".repeat(129)}":1}""")
        refusedKeepingNotificationId("""{"x":"${"p".repeat(CredentialMetadataShape.MAX_BYTES - 7)}"}""")
        refusedKeepingNotificationId("""{"x":1,"x":2}""")
        refusedKeepingNotificationId("""{"org.siros.secret_seed":{"n":"00","n":"11"}}""")
        refusedKeepingNotificationId("""{"org.siros.secret_seed":{"n":"00"},"org.siros.secret_seed":{"n":"11"}}""")
        // A duplicate hidden behind an escape is still the same name.
        refusedKeepingNotificationId("""{"a":1,"\u0061":2}""")
    }

    @Test
    fun theLimitsApplyToAnyMetadataValueNotOnlyObjects() {
        // A deeply nested array as the whole value, and a 1 MiB string, are refused as well.
        refusedKeepingNotificationId("[".repeat(17) + "]".repeat(17))
        refusedKeepingNotificationId("\"" + "p".repeat(CredentialMetadataShape.MAX_BYTES) + "\"")
    }

    @Test
    fun aBodyWithoutMetadataOrWithOtherMembersIsUnaffected() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        b.open("f", issuerRaw(jwk, """{"credentials":[{"credential":"c"}],"x":${nestedObjects(40)}}"""), deferred = false)
        assertEquals(listOf("c"), b.take("f")!!.credentials)
    }

    // ---- lifecycle races and retention (review round 3) ----

    private fun pausedHolder(): Triple<BlindIssuance, java.util.concurrent.CountDownLatch, java.util.concurrent.CountDownLatch> {
        val started = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val holder = BlindIssuance(keyFactory = { alg, enc ->
            started.countDown()
            release.await()
            CredentialResponseKey.generate(alg, enc)
        })
        return Triple(holder, started, release)
    }

    private fun offerInBackground(holder: BlindIssuance, flowId: String): java.util.concurrent.Future<Result<JsonObject?>> =
        java.util.concurrent.Executors.newSingleThreadExecutor().submit<Result<JsonObject?>> { runCatching { holder.offer(flowId, request) } }

    @Test
    fun aClearThatFinishesWhileTheKeyIsBeingGenerated_isNotUndoneByTheLateInsertion() {
        val (holder, started, release) = pausedHolder()
        val result = offerInBackground(holder, "f")
        assertTrue(started.await(5, java.util.concurrent.TimeUnit.SECONDS))
        holder.clear()
        release.countDown()
        assertTrue("the offer fails instead of returning a key nobody holds", result.get(5, java.util.concurrent.TimeUnit.SECONDS).isFailure)
        assertFalse("the cleared flow is not resurrected", holder.holdsKey("f"))
        assertNull(holder.take("f"))
    }

    @Test
    fun aDropOfThatFlowDuringGeneration_isNotUndoneEither_butADropOfAnotherFlowIsNoReason() {
        val (holder, started, release) = pausedHolder()
        val result = offerInBackground(holder, "f")
        assertTrue(started.await(5, java.util.concurrent.TimeUnit.SECONDS))
        holder.drop("f")
        release.countDown()
        assertTrue(result.get(5, java.util.concurrent.TimeUnit.SECONDS).isFailure)
        assertFalse(holder.holdsKey("f"))

        val (holder2, started2, release2) = pausedHolder()
        val other = offerInBackground(holder2, "f")
        assertTrue(started2.await(5, java.util.concurrent.TimeUnit.SECONDS))
        holder2.drop("some-other-flow")
        release2.countDown()
        assertTrue("an unrelated drop does not invalidate this offer", other.get(5, java.util.concurrent.TimeUnit.SECONDS).isSuccess)
        assertTrue(holder2.holdsKey("f"))
    }

    @Test
    fun repeatedPendingResponsesRetainNothing_onlyAResponseWithCredentialsIsKept() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        val bigMetadata = """{"display":[{"name":"${"p".repeat(200_000)}"}]}"""
        repeat(25) { n ->
            val control = b.open(
                "f",
                issuerRaw(jwk, """{"transaction_id":"tx-$n","interval":5,"credential_metadata":$bigMetadata}"""),
                deferred = n > 0,
            )
            assertEquals("tx-$n", control.transactionId)
        }
        // Nothing of the 25 pending answers is held: not even an empty entry.
        assertNull(b.take("f"))
        val jwk2 = b.offer("f", request)!!
        repeat(3) { n -> b.open("f", issuerRaw(jwk2, """{"transaction_id":"tx","credential_metadata":$bigMetadata}"""), deferred = n > 0) }
        b.open("f", issuerRaw(jwk2, """{"credentials":[{"credential":"done"}],"notification_id":"n","credential_metadata":{"display":[]}}"""), deferred = true)
        val taken = b.take("f")!!
        assertEquals(listOf("done"), taken.credentials)
        assertEquals("n", taken.notificationId)
    }

    @Test
    fun aFlowOnAnOlderSocketLosesItsKeyButKeepsWhatItOpenedUntilPurged_andAnUntaggedFlowIsUntouched() {
        val b = BlindIssuance()
        val older = b.offer("old", request, generation = 1)!!
        b.open("old", issuer(older, response("kept")), deferred = false)
        b.offer("same", request, generation = 2)
        b.offer("untagged", request)
        b.markStaleBefore(2, now = 1_000)
        assertFalse(b.holdsKey("old"))
        assertTrue("a flow of the current socket is kept", b.holdsKey("same"))
        assertTrue("a flow with no generation is kept", b.holdsKey("untagged"))
        assertThrows(BlindIssuanceException::class.java) { b.open("old", issuer(older, response("x")), deferred = false) }
        b.purgeStale(graceMs = 30_000, now = 20_000)
        assertEquals("still within the grace", listOf("kept"), b.take("old")!!.credentials)
        // And after the grace it is gone.
        val jwk = b.offer("old2", request, generation = 1)!!
        b.open("old2", issuer(jwk, response("kept")), deferred = false)
        b.markStaleBefore(2, now = 1_000)
        b.purgeStale(graceMs = 30_000, now = 31_001)
        assertNull(b.take("old2"))
    }

    // ---- the liveness check and the claim are one step against teardown; pending responses never carry a seed (round 7) ----

    @Test
    fun aTeardownBetweenTheCallersCheckAndTheClaim_isNoticedAndNothingIsRetained() {
        val paused = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val holder = BlindIssuance(beforeClaim = { paused.countDown(); release.await() })
        val epoch = holder.epoch // captured BEFORE the caller's own liveness check
        val result = java.util.concurrent.Executors.newSingleThreadExecutor().submit<Result<JsonObject?>> {
            runCatching { holder.offer("f", request, epoch = epoch) }
        }
        assertTrue(paused.await(5, java.util.concurrent.TimeUnit.SECONDS))
        holder.clear() // the teardown runs while the caller is between its check and its claim
        release.countDown()
        assertTrue("the offer fails", result.get(5, java.util.concurrent.TimeUnit.SECONDS).isFailure)
        assertFalse("no key is retained after the teardown", holder.holdsKey("f"))
        assertNull(holder.take("f"))
        // A caller whose epoch was read AFTER the teardown is served.
        val fresh = BlindIssuance()
        fresh.clear()
        assertNotNull(fresh.offer("g", request, epoch = fresh.epoch))
    }

    @Test
    fun aPendingResponseCarryingASeedIsRefusedWithItsNotificationId_onFirstAndOnDeferredAnswers() {
        val seed = """{"org.siros.secret_seed":{"org.siros.nym_auth":"00112233445566778899aabbccddeeff"}}"""
        for (deferred in listOf(false, true)) {
            val b = BlindIssuance()
            val jwk = b.offer("f", request)!!
            val e = assertThrows(BlindIssuanceException::class.java) {
                b.open("f", issuerRaw(jwk, """{"transaction_id":"tx","interval":5,"notification_id":"n-seed","credential_metadata":$seed}"""), deferred = deferred)
            }
            assertEquals("the issuer can be told", "n-seed", e.notificationId)
            assertFalse("the message names no value", e.message!!.contains("00112233"))
            assertNull("nothing is retained", b.take("f"))
        }
    }

    @Test
    fun aNormalPendingResponseIsStillAnswered_evenWithOtherMetadata() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        val control = b.open("f", issuerRaw(jwk, """{"transaction_id":"tx","interval":5,"credential_metadata":{"display":[{"name":"x"}]}}"""), deferred = true)
        assertEquals("tx", control.transactionId)
        assertEquals(5, control.interval)
        assertEquals("tx2", b.open("f", issuerRaw(jwk, """{"transaction_id":"tx2"}"""), deferred = true).transactionId)
    }

    // ---- "a key was offered" outlives the key (review of #293) ----

    @Test
    fun theOfferedMarkerSurvivesASocketReplacementAndItsGrace_andEndsOnlyWithTheFlow() {
        val b = BlindIssuance()
        assertFalse(b.wasOffered("f"))
        b.offer("f", request, generation = 1)
        assertTrue(b.wasOffered("f"))
        b.markStaleBefore(2, now = 1_000)
        assertFalse("the key is gone", b.holdsKey("f"))
        assertTrue("the fact that one was offered is not", b.wasOffered("f"))
        b.purgeStale(graceMs = 30_000, now = 99_000)
        assertTrue("not even after the grace: the flow has not ended", b.wasOffered("f"))
        b.drop("f")
        assertFalse("a dropped flow is no longer offered", b.wasOffered("f"))
    }

    @Test
    fun theOfferedMarkerEndsOnEveryTerminalPath_andIsBounded() {
        // take (an encrypted completion), drop (error, cancel, sign failure, a plain completion), clear (logout, destroy, a new connection)
        val b = BlindIssuance()
        val jwk = b.offer("taken", request)!!
        b.open("taken", issuer(jwk, response("c")), deferred = false)
        b.offer("dropped", request)
        b.offer("cleared", request)
        assertTrue(b.wasOffered("taken") && b.wasOffered("dropped") && b.wasOffered("cleared"))
        b.take("taken")
        b.drop("dropped")
        assertFalse(b.wasOffered("taken"))
        assertFalse(b.wasOffered("dropped"))
        assertTrue(b.wasOffered("cleared"))
        b.clear()
        assertFalse(b.wasOffered("cleared"))
        // A declined offer (no encryption) never marks the flow, and neither does one that could not be served.
        assertNull(b.offer("declined", null))
        assertFalse(b.wasOffered("declined"))
        assertNull(b.offer("unsupported", CredentialResponseEncryptionRequest("RSA-OAEP", "A128GCM", required = false)))
        assertFalse(b.wasOffered("unsupported"))
        // Bounded FAIL-CLOSED: at capacity a NEW offer is refused and nothing existing is evicted.
        val many = BlindIssuance()
        repeat(BlindIssuance.MAX_OFFERED_MARKERS) { many.offer("flow-$it", request) }
        val refused = assertThrows(BlindIssuanceException::class.java) { many.offer("one-too-many", request) }
        assertTrue(refused.message!!, refused.message!!.contains("Too many"))
        assertFalse("the refused offer left no marker, state or key", many.wasOffered("one-too-many") || many.holdsKey("one-too-many"))
        assertTrue("the oldest keeps its marker and its key", many.wasOffered("flow-0") && many.holdsKey("flow-0"))
        assertTrue(many.wasOffered("flow-${BlindIssuance.MAX_OFFERED_MARKERS - 1}"))
        // A re-offer for a flow that already has a marker (a c_nonce retry) is not "new" and is served.
        assertNotNull(many.offer("flow-0", request))
        // Freeing one makes room again.
        many.drop("flow-5")
        assertNotNull(many.offer("one-too-many", request))
        assertTrue(many.wasOffered("one-too-many"))
    }
}

