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

    // ---- Credential Auxiliary Data v0.1 (the spec vector) through the receipt check ----

    private val v01Opening = "8f3b2c9e41d07a65b1e2f4c3d9a08176".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val v01OpeningB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(v01Opening)
    private val v01Commitment = "JhQM6yeuK84BoGVVSxbLL9HjjeiBERnWHEZSIIMqwd0"
    private val v01Advertisement = org.siros.sdk.credentials.AuxiliaryAdvertisement(
        toWallet = listOf(org.siros.sdk.credentials.AuxiliaryAdvertisement.Slot(listOf("ssc"), "sha-256")),
        toIssuer = emptyList(),
    )

    private fun v01Cred(commitment: String = v01Commitment): DeliveredCredential {
        val b64 = { t: String -> java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(t.toByteArray()) }
        val disclosure = b64("""["salt","ssc","$commitment"]""")
        val digest = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(disclosure.toByteArray(Charsets.US_ASCII)))
        val jwt = b64("""{"alg":"none"}""") + "." + b64("""{"_sd_alg":"sha-256","_sd":["$digest"]}""") + ".sig~$disclosure~"
        return DeliveredCredential("dc+sd-jwt", jwt, "n1")
    }

    private fun v01CredWithClaim(name: String, value: String): DeliveredCredential {
        val b64 = { t: String -> java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(t.toByteArray()) }
        val ssc = b64("""["salt","ssc","$v01Commitment"]""")
        val extra = b64("""["salt2","$name","$value"]""")
        fun d(x: String) = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(x.toByteArray(Charsets.US_ASCII)))
        val jwt = b64("""{"alg":"none"}""") + "." + b64("""{"_sd_alg":"sha-256","_sd":["${d(ssc)}","${d(extra)}"]}""") + ".sig~$ssc~$extra~"
        return DeliveredCredential("dc+sd-jwt", jwt, "n1")
    }

    @Test
    fun v01_anOptionalCommitmentThatIsPresentButWrongOrMalformedIsRefused_onlyAnAbsentOneIsSkipped() {
        val good = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 5 })
        val sentPsc = sent(path = listOf("psc"), required = false, value = ByteArray(32) { 5 })
        assertTrue(checkV01(credentials = listOf(v01CredWithClaim("psc", good)), holderCommitments = listOf(sentPsc)) is DeliveredMetadataVerdict.Accept)
        // Present but not exactly the wallet's value, or not a 32-byte value at all: refused although optional.
        // A value that is readable but not the wallet's: the commitment is missing. One that is not readable at all: unreadable.
        assertRefused(
            DeliveredMetadataRefusal.HOLDER_COMMITMENT_MISSING,
            checkV01(credentials = listOf(v01CredWithClaim("psc", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 6 }))), holderCommitments = listOf(sentPsc)),
        )
        for (bad in listOf("AAAA", "not*base64")) {
            assertRefused(
                DeliveredMetadataRefusal.COMMITMENT_UNREADABLE,
                checkV01(credentials = listOf(v01CredWithClaim("psc", bad)), holderCommitments = listOf(sentPsc)),
            )
        }
        // Genuinely absent and optional: skipped.
        assertTrue(checkV01(holderCommitments = listOf(sentPsc)) is DeliveredMetadataVerdict.Accept)
    }

    @Test
    fun v01_anOptionalPscDisclosedUnderSha512IsRefused_notSkippedAsAbsent() {
        val b64 = { x: String -> java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(x.toByteArray()) }
        val other = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 9 })
        val disclosure = b64("""["salt","psc","$other"]""")
        val jwt = b64("""{"alg":"none"}""") + "." + b64("""{"_sd_alg":"sha-512","_sd":["digest-under-sha512"]}""") + ".sig~$disclosure~"
        val sentPsc = sent(path = listOf("psc"), required = false, value = ByteArray(32) { 5 })
        assertRefused(
            DeliveredMetadataRefusal.COMMITMENT_UNREADABLE,
            checkV01(credentials = listOf(DeliveredCredential("dc+sd-jwt", jwt, "n1")), holderCommitments = listOf(sentPsc)),
        )
    }

    // ---- truth table: what an advertisement (or none) allows a response to carry ----

    private fun configOf(advert: String?, legacy: Boolean = false) = Json { ignoreUnknownKeys = true }.decodeFromString(
        org.siros.sdk.credentials.CredentialConfiguration.serializer(),
        buildString {
            append("""{"format":"dc+sd-jwt"""")
            if (legacy) append(""","credential_metadata":{"org.siros.secret_seed":{"namespaces":["org.siros.nym_auth"]}}""")
            if (advert != null) append(""","auxiliary_data_supported":$advert""")
            append("}")
        },
    )

    private val extEntry = """{"type":"future_kind","alg":"sha-256","path":["x"],"opening":"ignored"}"""

    private fun members(vararg pairs: Pair<String, String>) =
        response(pairs.associate { (k, v) -> k to Json.parseToJsonElement(v) })

    /** The verdict of a receipt for [response] under the adapter and advertisement [config] selects (none selected: legacy, nothing advertised). */
    private fun receipt(config: org.siros.sdk.credentials.CredentialConfiguration, response: Response, credentials: List<DeliveredCredential> = listOf(v01Cred()), canStore: Boolean = true): DeliveredMetadataVerdict {
        val sel = org.siros.sdk.credentials.AuxiliaryDataShapes.select(config)
        val selected = sel as? org.siros.sdk.credentials.AuxiliarySelection.Selected
        return DeliveredCredentialMetadata.check(
            response, credentials, ns, canStore,
            advertised = selected?.advertisement?.toWallet?.isNotEmpty() == true,
            shape = selected?.shape ?: org.siros.sdk.credentials.LegacyOrgSirosShape,
            advertisement = selected?.advertisement,
        )
    }

    @Test
    fun truthTable_anAdvertisementOfOnlyUnrecognisedEntries_keepsTheShape_andNeitherHidesItNorAcceptsAForeignOrUnadvertisedSecret() {
        val onlyExt = configOf("""{"to_wallet":[{"type":"future_kind","alg":"sha-256","path":["x"]}]}""")
        val aux = "auxiliary_data"
        val recognised = """{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"opening":"$v01OpeningB64"}"""
        // 1. only extensions delivered: ignored, accepted.
        assertTrue(receipt(onlyExt, members(aux to "[$extEntry]")) is DeliveredMetadataVerdict.Accept)
        // ...and without a notification id or a place to keep a secret, since there is no secret.
        assertTrue(
            receipt(onlyExt, members(aux to "[$extEntry]"), listOf(DeliveredCredential("dc+sd-jwt", v01Cred().credential, null)), canStore = false) is DeliveredMetadataVerdict.Accept,
        )
        // 2. a recognised secret nobody advertised: refused (not accepted, not stored).
        assertTrue(receipt(onlyExt, members(aux to "[$extEntry,$recognised]")) is DeliveredMetadataVerdict.Refuse)
        // 2b. an entry with no alg is MALFORMED, not an ignorable extension: its unchecked opening must not be stored.
        assertRefused(
            DeliveredMetadataRefusal.MALFORMED,
            receipt(onlyExt, members(aux to """[{"type":"hash_commitment","path":["ssc"],"opening":"$v01OpeningB64"}]""")),
        )
        assertRefused(DeliveredMetadataRefusal.MALFORMED, receipt(onlyExt, members(aux to """[{"path":["ssc"],"opening":"$v01OpeningB64"}]""")))
        // 3. nothing delivered under that advertisement: nothing to refuse.
        assertTrue(receipt(onlyExt, response(members = mapOf("display" to JsonArray(emptyList())))) is DeliveredMetadataVerdict.Accept)
        // 4. a legacy-shape secret under a v0.1 advertisement: foreign, refused.
        assertRefused(DeliveredMetadataRefusal.MALFORMED, receipt(onlyExt, members(SecretSeedDelivery.MEMBER to """{"$ns":"${N.seedHex}"}""")))
        // 5. nothing advertised at all: a v0.1 secret is a foreign shape, refused.
        assertRefused(DeliveredMetadataRefusal.MALFORMED, receipt(configOf(null), members(aux to "[$recognised]")))
        // 6. a recognised slot advertised but only extensions delivered: the slot did not arrive.
        val withSlot = configOf("""{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"encoding":"base64url"}]}""")
        assertTrue(receipt(withSlot, members(aux to "[$extEntry]")) is DeliveredMetadataVerdict.Refuse)
        // 7. the same slot delivered: accepted.
        assertTrue(receipt(withSlot, members(aux to "[$recognised]")) is DeliveredMetadataVerdict.Accept)
        // 8. an empty advertisement object is not an advertisement at all: the configuration is malformed.
        assertTrue(org.siros.sdk.credentials.AuxiliaryDataShapes.select(configOf("{}")) is org.siros.sdk.credentials.AuxiliarySelection.Malformed)
    }

    @Test
    fun mergeDisplay_neverCarriesAnyShapesSecretIntoDisplayMetadata() {
        val issuerPublic = Json.parseToJsonElement("""{"display":[{"name":"PID"}]}""").jsonObject
        val v01 = Json.parseToJsonElement("""{"auxiliary_data":[{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"opening":"$v01OpeningB64"}],"claims":[1]}""").jsonObject
        val merged = SecretSeedDelivery.mergeDisplay(issuerPublic, v01)
        assertFalse("auxiliary_data reached display metadata", "auxiliary_data" in merged)
        assertEquals(setOf("display", "claims"), merged.keys)
        val both = Json.parseToJsonElement("""{"${SecretSeedDelivery.MEMBER}":{"$ns":"${N.seedHex}"},"auxiliary_data":[],"claims":[1]}""").jsonObject
        assertEquals(setOf("display", "claims"), SecretSeedDelivery.mergeDisplay(issuerPublic, both).keys)
        assertEquals(setOf("claims"), SecretSeedDelivery.stripped(both).keys)
    }

    // ---- read-time check of the commitment claim's REPRESENTATION (nothing is read from any `encoding` member: there is none on the wire) ----

    private fun goodB64() = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(N.goodSsc)

    private fun sscSent(path: List<String>) = listOf(org.siros.sdk.credentials.HolderCommitment(path, "sha-256", true, N.goodSsc.copyOf()))

    private fun verdictFor(format: String, credential: String, path: List<String>) =
        checkV01(credentials = listOf(DeliveredCredential(format, credential, "n1")), holderCommitments = sscSent(path), response = response(members = mapOf("display" to JsonArray(emptyList()))), advertised = false)

    private fun assertUnreadable(v: DeliveredMetadataVerdict, vararg mustContain: String) {
        assertRefused(DeliveredMetadataRefusal.COMMITMENT_UNREADABLE, v)
        val detail = (v as DeliveredMetadataVerdict.Refuse).detail!!
        mustContain.forEach { assertTrue("$detail should mention '$it'", detail.contains(it)) }
        assertFalse("the value is never in the detail", detail.contains(goodB64()) || detail.contains(N.hex(N.goodSsc)))
    }

    @Test
    fun theCommitmentClaimMustBeInTheRepresentationItsFormatDefines_otherwiseTheCredentialIsRefusedWithAShortTypedDetail() {
        val sdPath = listOf("ssc")
        val mdocPath = listOf(N.DOCTYPE, "ssc")
        // SD-JWT: unpadded base64url is accepted ...
        assertTrue(verdictFor("dc+sd-jwt", N.sdJwt(sscValues = listOf(goodB64())), sdPath) is DeliveredMetadataVerdict.Accept)
        // ... padded base64, hex and the standard alphabet are refused, naming the path and the shape (never the value).
        val padded = java.util.Base64.getEncoder().encodeToString(N.goodSsc)
        assertUnreadable(verdictFor("dc+sd-jwt", N.sdJwt(sscValues = listOf(padded)), sdPath), "[ssc]", "padding")
        assertUnreadable(verdictFor("dc+sd-jwt", N.sdJwt(sscValues = listOf(N.hex(N.goodSsc))), sdPath), "[ssc]", "hex")
        val std = java.util.Base64.getEncoder().withoutPadding().encodeToString(ByteArray(32) { 0xFB.toByte() })
        assertUnreadable(verdictFor("dc+sd-jwt", N.sdJwt(sscValues = listOf(std)), sdPath), "standard base64")
        // mdoc: a byte string of 32 bytes is accepted, a text string (whatever it holds) and a short byte string are refused.
        assertTrue(verdictFor("mso_mdoc", N.mdoc(listOf(N.bstr(N.goodSsc))), mdocPath) is DeliveredMetadataVerdict.Accept)
        assertUnreadable(verdictFor("mso_mdoc", N.mdoc(listOf(N.text(goodB64()))), mdocPath), "text string", "byte string is required")
        assertUnreadable(verdictFor("mso_mdoc", N.mdoc(listOf(N.bstr(ByteArray(16)))), mdocPath), "16 bytes")
    }

    // ---- the commitment claim is read per the ADVERTISED encoding (vc pull 850 publishes `encoding` in auxiliary_data_supported) ----

    private val specCommitment = java.util.Base64.getUrlDecoder().decode(v01Commitment)

    private fun written(encoding: String?) = when (encoding) {
        "base64" -> java.util.Base64.getEncoder().encodeToString(specCommitment)
        "hex" -> specCommitment.joinToString("") { "%02x".format(it) }
        else -> java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(specCommitment)
    }

    /** A delivery of the spec vector whose claim at [path] is [credential], advertised with [encoding]. */
    private fun deliveryVerdict(format: String, credential: String, path: List<String>, encoding: String?): DeliveredMetadataVerdict {
        val adv = org.siros.sdk.credentials.AuxiliaryAdvertisement(
            listOf(org.siros.sdk.credentials.AuxiliaryAdvertisement.Slot(path, "sha-256", false, encoding)), emptyList(),
        )
        val body = response(
            mapOf("auxiliary_data" to Json.parseToJsonElement("""[{"type":"hash_commitment","alg":"sha-256","path":${JsonArray(path.map { JsonPrimitive(it) })},"opening":"$v01OpeningB64"}]""")),
            encrypted = true,
        )
        return DeliveredCredentialMetadata.check(
            body, listOf(DeliveredCredential(format, credential, "n1")), ns, true, advertised = true,
            shape = org.siros.sdk.credentials.AuxiliaryDataV01, advertisement = adv,
        )
    }

    @Test
    fun everyAdvertisedEncodingIsReadInBothFormats_andAMismatchBetweenAdvertisedAndFoundIsRefusedWithAShortTypedDetail() {
        val mdocPath = listOf(N.DOCTYPE, "ssc")
        for (enc in listOf(null, "base64url", "base64", "hex")) {
            // SD-JWT: the claim is text in the advertised encoding (absent: unpadded base64url).
            assertTrue("sd-jwt $enc", deliveryVerdict("dc+sd-jwt", N.sdJwt(sscValues = listOf(written(enc))), listOf("ssc"), enc) is DeliveredMetadataVerdict.Accept)
            // mdoc: absent = a byte string; set = a text string in that encoding.
            val mdocClaim = if (enc == null) N.bstr(specCommitment) else N.text(written(enc))
            assertTrue("mdoc $enc", deliveryVerdict("mso_mdoc", N.mdoc(listOf(mdocClaim)), mdocPath, enc) is DeliveredMetadataVerdict.Accept)
        }
        fun unreadable(v: DeliveredMetadataVerdict, vararg words: String) {
            assertRefused(DeliveredMetadataRefusal.COMMITMENT_UNREADABLE, v)
            val detail = (v as DeliveredMetadataVerdict.Refuse).detail!!
            words.forEach { assertTrue("$detail should mention '$it'", detail.contains(it)) }
            assertFalse("never the value", detail.contains(written(null)) || detail.contains(written("hex")) || detail.contains(written("base64")))
        }
        // Advertised hex, found base64url (and the other way round, and padded vs unpadded).
        unreadable(deliveryVerdict("dc+sd-jwt", N.sdJwt(sscValues = listOf(written("base64url"))), listOf("ssc"), "hex"), "hex")
        unreadable(deliveryVerdict("dc+sd-jwt", N.sdJwt(sscValues = listOf(written("hex"))), listOf("ssc"), "base64url"), "looks like hex", "base64url")
        unreadable(deliveryVerdict("dc+sd-jwt", N.sdJwt(sscValues = listOf(written("base64url"))), listOf("ssc"), "base64"), "base64")
        unreadable(deliveryVerdict("dc+sd-jwt", N.sdJwt(sscValues = listOf(written("hex").uppercase())), listOf("ssc"), "hex"), "hex")
        // mdoc: a byte string where text was advertised, and text where nothing was advertised.
        unreadable(deliveryVerdict("mso_mdoc", N.mdoc(listOf(N.bstr(specCommitment))), mdocPath, "base64"), "byte string", "base64")
        unreadable(deliveryVerdict("mso_mdoc", N.mdoc(listOf(N.text(written("base64url")))), mdocPath, null), "text string", "byte string is required")
        unreadable(deliveryVerdict("mso_mdoc", N.mdoc(listOf(N.text(written("hex")))), mdocPath, "base64url"), "looks like hex")
    }

    @Test
    fun aHolderCommitmentIsCheckedAgainstTheAdvertisedEncodingOfItsSlotToo() {
        val value = N.goodSsc
        fun sentWith(enc: String?) = listOf(org.siros.sdk.credentials.HolderCommitment(listOf("ssc"), "sha-256", true, value.copyOf(), enc))
        fun text(enc: String?) = when (enc) {
            "hex" -> N.hex(value)
            "base64" -> java.util.Base64.getEncoder().encodeToString(value)
            else -> java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value)
        }
        for (enc in listOf(null, "base64url", "base64", "hex")) {
            assertTrue(enc, checkV01(credentials = listOf(DeliveredCredential("dc+sd-jwt", N.sdJwt(sscValues = listOf(text(enc))), "n1")), holderCommitments = sentWith(enc), response = response(members = mapOf("display" to JsonArray(emptyList()))), advertised = false) is DeliveredMetadataVerdict.Accept)
        }
        assertRefused(
            DeliveredMetadataRefusal.COMMITMENT_UNREADABLE,
            checkV01(credentials = listOf(DeliveredCredential("dc+sd-jwt", N.sdJwt(sscValues = listOf(text(null))), "n1")), holderCommitments = sentWith("hex"), response = response(members = mapOf("display" to JsonArray(emptyList()))), advertised = false),
        )
    }

    private fun v01Response(opening: String = v01OpeningB64, encrypted: Boolean = true) = response(
        mapOf("auxiliary_data" to Json.parseToJsonElement("""[{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"opening":"$opening"}]""")),
        encrypted,
    )

    private fun checkV01(
        response: Response = v01Response(),
        credentials: List<DeliveredCredential> = listOf(v01Cred()),
        advertised: Boolean = true,
        holderCommitments: List<org.siros.sdk.credentials.HolderCommitment> = emptyList(),
    ) = DeliveredCredentialMetadata.check(
        response, credentials, ns, true, advertised,
        shape = org.siros.sdk.credentials.AuxiliaryDataV01,
        advertisement = v01Advertisement,
        holderCommitments = holderCommitments,
    )

    private fun sent(path: List<String> = listOf("ssc"), required: Boolean = true, value: ByteArray = java.util.Base64.getUrlDecoder().decode(v01Commitment)) =
        org.siros.sdk.credentials.HolderCommitment(path, "sha-256", required, value)

    @Test
    fun v01_theCredentialMustHoldTheCommitmentTheWalletSent_afterIssuance() {
        // The claim at the to_issuer path holds exactly what was sent: accepted.
        assertTrue(checkV01(holderCommitments = listOf(sent())) is DeliveredMetadataVerdict.Accept)
        // A different value, or an absent REQUIRED claim: refused.
        assertRefused(DeliveredMetadataRefusal.HOLDER_COMMITMENT_MISSING, checkV01(holderCommitments = listOf(sent(value = ByteArray(32)))))
        assertRefused(DeliveredMetadataRefusal.HOLDER_COMMITMENT_MISSING, checkV01(holderCommitments = listOf(sent(path = listOf("psc")))))
        // An optional claim the issuer left out is allowed; a present-but-different optional one is not.
        assertTrue(checkV01(holderCommitments = listOf(sent(path = listOf("psc"), required = false))) is DeliveredMetadataVerdict.Accept)
        assertRefused(DeliveredMetadataRefusal.HOLDER_COMMITMENT_MISSING, checkV01(holderCommitments = listOf(sent(required = false, value = ByteArray(32)))))
        // Every credential of a batch.
        assertRefused(
            DeliveredMetadataRefusal.HOLDER_COMMITMENT_MISSING,
            checkV01(credentials = listOf(v01Cred(), v01Cred(commitment = "A".repeat(43))), holderCommitments = listOf(sent())),
        )
    }

    @Test
    fun v01_aV01SecretIsRefusedEvenWhenTheLegacyShapeWasTheAdvertisedOne() {
        // Advertised = true with the legacy adapter in force: the v0.1 member is a foreign shape and must not be stored uninterpreted.
        val v = DeliveredCredentialMetadata.check(v01Response(), listOf(v01Cred()), ns, true, advertised = true)
        assertRefused(DeliveredMetadataRefusal.MALFORMED, v)
    }

    @Test
    fun v01_theOpeningOfTheCommitmentInTheCredentialIsAccepted() {
        assertTrue(checkV01() is DeliveredMetadataVerdict.Accept)
    }

    @Test
    fun v01_aWrongOpeningOrAWrongCommitmentIsRefused_andAPlainResponseNeverCarriesASecret() {
        val wrong = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16))
        assertRefused(DeliveredMetadataRefusal.MISMATCH, checkV01(response = v01Response(opening = wrong)))
        assertRefused(DeliveredMetadataRefusal.MISMATCH, checkV01(credentials = listOf(v01Cred(commitment = "A".repeat(43)))))
        assertRefused(DeliveredMetadataRefusal.NOT_ENCRYPTED, checkV01(response = v01Response(encrypted = false)))
        assertRefused(DeliveredMetadataRefusal.MALFORMED, checkV01(response = v01Response(opening = "AAAA")))
    }

    @Test
    fun v01_everyCredentialOfTheBatchMustOpen() {
        assertRefused(DeliveredMetadataRefusal.MISMATCH, checkV01(credentials = listOf(v01Cred(), v01Cred(commitment = "A".repeat(43)))))
    }

    @Test
    fun v01_aSecretInAShapeTheIssuerDidNotAdvertiseIsNeverStoredUninterpreted() {
        // Not advertised: the default (legacy) adapter is in force and the v0.1 member is refused, not stored and not guessed at.
        val v = DeliveredCredentialMetadata.check(v01Response(), listOf(v01Cred()), ns, true, advertised = false)
        assertRefused(DeliveredMetadataRefusal.MALFORMED, v)
    }

    @Test
    fun v01_anAdvertisedSecretThatDidNotArriveIsUnavailable() {
        assertRefused(DeliveredMetadataRefusal.SEED_UNAVAILABLE, checkV01(response = response(members = mapOf("display" to JsonArray(emptyList())))))
    }
}
