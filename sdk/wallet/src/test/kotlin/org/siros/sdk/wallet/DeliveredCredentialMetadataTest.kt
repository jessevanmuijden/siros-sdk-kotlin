package org.siros.sdk.wallet

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.SecretSeedDelivery
import org.siros.sdk.transport.DeliveredResponseMetadata
import org.siros.sdk.transport.ResponseCredentialMetadata
import org.siros.sdk.wallet.NymTestCredentials as N

/** The receipt of the response-level `credential_metadata`, by hand-made cases and by the privatedata-spec 2.4 vectors. */
class DeliveredCredentialMetadataTest {

    private val ns = SecretSeedDelivery.DEFAULT_NAMESPACE
    private val member = SecretSeedDelivery.MEMBER

    private class Response(
        override val credentialMetadata: ResponseCredentialMetadata?,
        override val credentialMetadataEncryptedResponse: Boolean,
        override val deferredResponse: Boolean = false,
    ) : DeliveredResponseMetadata

    private fun seedObject(hex: String = N.seedHex, namespace: String = ns) = buildJsonObject { put(namespace, JsonPrimitive(hex)) }

    private fun response(
        members: Map<String, JsonElement>? = mapOf(member to seedObject()),
        encrypted: Boolean = true,
        malformed: Boolean = false,
    ) = Response(
        when {
            malformed -> ResponseCredentialMetadata(malformed = true)
            members == null -> null
            else -> ResponseCredentialMetadata(JsonObject(members))
        },
        encrypted,
    )

    private fun cred(credential: String = N.sdJwt(), format: String = "dc+sd-jwt", notificationId: String? = "n1") =
        DeliveredCredential(format, credential, notificationId)

    private fun check(
        response: Response = response(),
        credentials: List<DeliveredCredential> = listOf(cred()),
        canStore: Boolean = true,
        advertised: Boolean = false,
        namespace: String = ns,
    ) = DeliveredCredentialMetadata.check(response, credentials, namespace, canStore, advertised)

    private fun assertRefused(reason: DeliveredMetadataRefusal, v: DeliveredMetadataVerdict) {
        assertTrue("expected $reason but was $v", v is DeliveredMetadataVerdict.Refuse)
        assertEquals(reason, (v as DeliveredMetadataVerdict.Refuse).reason)
    }

    private fun entries(v: DeliveredMetadataVerdict): JsonArray {
        assertTrue("expected an accept but was $v", v is DeliveredMetadataVerdict.Accept)
        return (v as DeliveredMetadataVerdict.Accept).entries
    }

    @Test
    fun noMetadataIsNone() {
        assertSame(DeliveredMetadataVerdict.None, check(response(members = null)))
        assertSame(DeliveredMetadataVerdict.None, check(response(members = emptyMap())))
    }

    @Test
    fun aMatchingSeedIsAcceptedForSdJwtAndMdoc_andStoredAsOneEntryPerMember() {
        val other = buildJsonObject { put("k", JsonNull) }
        for ((format, c) in listOf("dc+sd-jwt" to N.sdJwt(), "mso_mdoc" to N.mdoc())) {
            val e = entries(check(response(mapOf("example.other" to other, member to seedObject())), listOf(cred(c, format))))
            assertEquals(2, e.size)
            assertEquals(JsonPrimitive("example.other"), e[0].jsonObject["type"])
            assertEquals(other, e[0].jsonObject["value"])
            assertEquals(JsonPrimitive(member), e[1].jsonObject["type"])
            assertEquals(seedObject(), e[1].jsonObject["value"])
        }
    }

    @Test
    fun theSeedMustOpenTheSscOfEveryCredentialOfTheResponse() {
        val wrong = N.sdJwt(sscValues = listOf(N.hex(N.wrongSsc)))
        assertRefused(DeliveredMetadataRefusal.MISMATCH, check(credentials = listOf(cred(), cred(wrong))))
        assertRefused(DeliveredMetadataRefusal.MISMATCH, check(credentials = listOf(cred(wrong), cred())))
        assertTrue(check(credentials = listOf(cred(), cred(), cred())) is DeliveredMetadataVerdict.Accept)
    }

    @Test
    fun aSeedOfAnotherNamespaceDoesNotOpenIt_andOthersAreStoredUnverified() {
        assertRefused(DeliveredMetadataRefusal.NAMESPACE_ABSENT, check(response(mapOf(member to seedObject(namespace = "org.siros.other")))))
        val both = buildJsonObject {
            put("org.siros.other", JsonPrimitive("ffeeddccbbaa99887766554433221100"))
            put(ns, JsonPrimitive(N.seedHex))
        }
        assertEquals(both, entries(check(response(mapOf(member to both))))[0].jsonObject["value"])
        assertRefused(DeliveredMetadataRefusal.NAMESPACE_ABSENT, check(namespace = "org.example.designated"))
    }

    @Test
    fun aSeedNeedsAnEncryptedResponseAndANotificationId() {
        assertRefused(DeliveredMetadataRefusal.NOT_ENCRYPTED, check(response(encrypted = false)))
        assertRefused(DeliveredMetadataRefusal.NO_NOTIFICATION_ID, check(credentials = listOf(cred(notificationId = null))))
        assertRefused(DeliveredMetadataRefusal.NO_NOTIFICATION_ID, check(credentials = listOf(cred(notificationId = ""))))
        // The response-level id may sit on any one credential.
        assertTrue(check(credentials = listOf(cred(notificationId = null), cred(notificationId = "n"))) is DeliveredMetadataVerdict.Accept)
    }

    @Test
    fun otherMembersAreStoredUninterpreted_overPlainJsonToo() {
        val v = check(response(mapOf("example.other" to JsonPrimitive("v")), encrypted = false), credentials = listOf(cred(notificationId = null)))
        assertEquals(1, entries(v).size)
    }

    @Test
    fun anAdvertisedConfigurationRefusesAnUnencryptedResponse_evenWithoutAnyMetadata() {
        assertRefused(DeliveredMetadataRefusal.NOT_ENCRYPTED, check(response(members = null, encrypted = false), advertised = true))
        assertRefused(DeliveredMetadataRefusal.NOT_ENCRYPTED, check(response(mapOf("example.other" to JsonPrimitive(1)), encrypted = false), advertised = true))
        // Encrypted but without the seed an advertised configuration delivers: unavailable, never invented.
        assertRefused(DeliveredMetadataRefusal.SEED_UNAVAILABLE, check(response(members = null, encrypted = true), advertised = true))
        assertRefused(DeliveredMetadataRefusal.SEED_UNAVAILABLE, check(response(mapOf("example.other" to JsonPrimitive(1)), encrypted = true), advertised = true))
        assertTrue(check(response(), advertised = true) is DeliveredMetadataVerdict.Accept)
        assertSame(DeliveredMetadataVerdict.None, check(response(members = null, encrypted = false), advertised = false))
    }

    @Test
    fun malformedMetadataAndMalformedSeedMembersAreRefused() {
        assertRefused(DeliveredMetadataRefusal.MALFORMED, check(response(malformed = true)))
        for (bad in listOf<JsonElement>(
            JsonPrimitive(N.seedHex),
            JsonArray(listOf(JsonPrimitive(N.seedHex))),
            JsonObject(emptyMap()),
            seedObject(N.seedHex.uppercase()),
            seedObject(N.seedHex.dropLast(1)),
            seedObject(N.seedHex + "0"),
            buildJsonObject { put(ns, JsonArray(List(16) { JsonPrimitive(0) })) },
            buildJsonObject { put("", JsonPrimitive(N.seedHex)); put(ns, JsonPrimitive(N.seedHex)) },
            buildJsonObject { put("namespaces", JsonArray(listOf(JsonPrimitive(ns)))) },
        )) {
            assertRefused(DeliveredMetadataRefusal.MALFORMED, check(response(mapOf(member to bad))))
        }
    }

    @Test
    fun aDeferredResponseCarryingASeedIsRefused_evenWhenEncrypted_butOtherMetadataIsNot() {
        assertRefused(DeliveredMetadataRefusal.DEFERRED_SEED, check(Response(ResponseCredentialMetadata(JsonObject(mapOf(member to seedObject()))), true, true)))
        assertTrue(check(Response(ResponseCredentialMetadata(JsonObject(mapOf("example.other" to JsonPrimitive(1)))), true, true)) is DeliveredMetadataVerdict.Accept)
    }

    @Test
    fun aMalformedSeedOfAnyNamespaceIsMalformed_notOnlyTheDesignatedOne() {
        for (bad in listOf(N.seedHex.uppercase(), N.seedHex.dropLast(2), "zz".repeat(16))) {
            val both = buildJsonObject {
                put("org.siros.other", JsonPrimitive(bad))
                put(ns, JsonPrimitive(N.seedHex))
            }
            assertRefused(DeliveredMetadataRefusal.MALFORMED, check(response(mapOf(member to both))))
        }
    }

    @Test
    fun aKeystoreThatCannotHoldItAndACredentialWithoutACommitmentFailClosed() {
        assertRefused(DeliveredMetadataRefusal.NO_STORAGE, check(canStore = false))
        assertRefused(DeliveredMetadataRefusal.NO_COMMITMENT, check(credentials = listOf(cred("x", "dc+sd-jwt"))))
        assertRefused(DeliveredMetadataRefusal.NO_COMMITMENT, check(credentials = listOf(cred(N.sdJwt(), "jwt_vc_json"))))
    }

    @Test
    fun theVerdictAndTheCredentialShowNoSeed() {
        val v = check()
        assertFalse(v.toString().contains(N.seedHex))
        assertFalse(cred().toString().contains(N.sdJwt()))
        assertFalse(response().credentialMetadata.toString().contains(N.seedHex))
    }

    // ---- privatedata-spec 2.4 vectors (vendored with provenance under the keystore module's test resources) ----

    private val vectors: Map<String, JsonObject> by lazy {
        val f = File("../keystore/src/test/resources/privatedata-spec/vectors.jsonl")
        require(f.isFile) { "vector file not found at ${f.absolutePath}" }
        f.readLines().filter { it.isNotBlank() }.map { Json.parseToJsonElement(it).jsonObject }.associateBy { it["id"]!!.jsonPrimitive.content }
    }

    private fun cases(id: String): List<JsonObject> = vectors.getValue(id)["inputs"]!!.jsonObject["cases"]!!.jsonArray.map { it.jsonObject }

    private fun runWireCase(c: JsonObject): DeliveredMetadataVerdict {
        val wire = c["response"]!!.jsonObject
        val md = wire["credential_metadata"]
        val deferred = c["responseType"]?.jsonPrimitive?.content == "deferred"
        val response = Response(
            when (md) {
                null -> null
                is JsonObject -> ResponseCredentialMetadata(md)
                else -> ResponseCredentialMetadata(malformed = true)
            },
            c["jweEncrypted"]!!.jsonPrimitive.content.toBoolean(),
            deferred,
        )
        val ssc = c["sscHex"]!!.jsonPrimitive.content
        val notification = wire["notification_id"]?.jsonPrimitive?.content
        val credentials = wire["credentials"]!!.jsonArray.map { DeliveredCredential("dc+sd-jwt", N.sdJwt(sscValues = listOf(ssc)), notification) }
        return DeliveredCredentialMetadata.check(response, credentials, c["commitmentNamespace"]!!.jsonPrimitive.content, canStoreSecret = true)
    }

    @Test
    fun vector_acceptCases_storeOneEntryPerMemberInEveryCredential() {
        val all = cases("delivered-secret-wire-001")
        assertTrue(all.size >= 4)
        for (c in all) {
            val name = c["name"]!!.jsonPrimitive.content
            val v = runWireCase(c)
            assertTrue("$name: $v", v is DeliveredMetadataVerdict.Accept)
            assertEquals(name, c["expected"]!!.jsonObject["storedMetadataPerCredential"], (v as DeliveredMetadataVerdict.Accept).entries)
        }
    }

    @Test
    fun vector_malformedAndRefusalCases_areRefusedAndNothingIsAccepted() {
        val all = cases("delivered-secret-malformed-001") + cases("delivered-secret-refusal-001")
        assertTrue(all.size >= 20)
        for (c in all) {
            val name = c["name"]!!.jsonPrimitive.content
            assertEquals(name, "refuse", c["expected"]!!.jsonObject["outcome"]!!.jsonPrimitive.content)
            val v = runWireCase(c)
            assertTrue("$name: $v", v is DeliveredMetadataVerdict.Refuse)
        }
    }

    @Test
    fun vector_theSeedIsStrippedBeforeTheMerge_andNeverInTheMergedDisplayMetadata() {
        for (c in cases("delivered-secret-strip-001")) {
            val name = c["name"]!!.jsonPrimitive.content
            val issuer = c["issuerCredentialMetadata"]!!.jsonObject
            val response = c["responseCredentialMetadata"]!!.jsonObject
            val expected = c["expected"]!!.jsonObject
            assertEquals(name, expected["strippedResponse"], SecretSeedDelivery.stripped(response))
            val merged = SecretSeedDelivery.mergeDisplay(issuer, response)
            assertEquals(name, expected["mergedDisplayMetadata"], merged)
            assertFalse(name, merged.toString().contains("00112233445566778899aabbccddeeff"))
            // The secret store gets the seed entry, exactly as received.
            val stored = expected["storedMetadata"]!!.jsonArray
            val v = runWireCase(
                buildJsonObject {
                    put("jweEncrypted", JsonPrimitive(true))
                    put("commitmentNamespace", JsonPrimitive("org.siros.nym_auth"))
                    put("sscHex", JsonPrimitive("a8faed6abbf35c12a4b26e40f6feb19d736d90045c83b9f9a31f638d323e6811"))
                    put(
                        "response",
                        buildJsonObject {
                            put("credentials", JsonArray(listOf(buildJsonObject { put("credential", JsonPrimitive("x")) })))
                            put("notification_id", JsonPrimitive("n"))
                            put("credential_metadata", response)
                        },
                    )
                },
            )
            for (entry in stored) assertTrue(name, entry in (v as DeliveredMetadataVerdict.Accept).entries)
        }
    }

    @Test
    fun vector_advertisementsAreClassified() {
        for (c in cases("delivered-secret-advertise-001")) {
            val name = c["name"]!!.jsonPrimitive.content
            val member = c["issuerCredentialMetadata"]!!.jsonObject[SecretSeedDelivery.MEMBER]
            val outcome = c["expected"]!!.jsonObject["outcome"]!!.jsonPrimitive.content
            val got = SecretSeedDelivery.classifyAdvertisement(member)
            when (outcome) {
                "valid-advertisement" -> assertTrue(name, got is SecretSeedDelivery.Advertisement.Valid)
                "no-advertisement" -> assertSame(name, SecretSeedDelivery.Advertisement.None, got)
                "malformed" -> assertSame(name, SecretSeedDelivery.Advertisement.Malformed, got)
                else -> error("unknown outcome $outcome")
            }
            if (outcome == "valid-advertisement") {
                assertEquals(name, true, c["expected"]!!.jsonObject["walletMustRequestCredentialResponseEncryption"]!!.jsonPrimitive.content.toBoolean())
            }
        }
        assertNotNull(cases("delivered-secret-advertise-001"))
    }
}
