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
        val metadata = buildJsonObject { put("org.siros.secret_seed", buildJsonObject { put("ns", JsonPrimitive("00")) }) }
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
    fun theLegacySingleCredentialMemberAndOddCredentialShapesAreNormalised() {
        val b = BlindIssuance()
        val jwk = b.offer("f", request)!!
        b.open(
            "f",
            issuer(
                jwk,
                buildJsonObject {
                    put("credential", JsonPrimitive("legacy"))
                    put(
                        "credentials",
                        JsonArray(listOf(JsonPrimitive("plain"), buildJsonObject { put("credential", JsonPrimitive("wrapped")) }, buildJsonObject { put("x", JsonPrimitive(1)) })),
                    )
                },
            ),
            deferred = false,
        )
        assertEquals(listOf("legacy", "plain", "wrapped", """{"x":1}"""), b.take("f")!!.credentials)
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
}
