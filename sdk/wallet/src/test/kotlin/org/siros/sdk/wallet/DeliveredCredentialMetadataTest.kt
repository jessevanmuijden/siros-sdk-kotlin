package org.siros.sdk.wallet

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.transport.DeliveredResponseMetadata
import org.siros.sdk.transport.ResponseCredentialMetadata
import org.siros.sdk.wallet.NymTestCredentials as N

/** The receipt of the response-level `credential_metadata` (Credential Auxiliary Data v0.1 only; superseded shapes are refused). */
class DeliveredCredentialMetadataTest {

    private val ns = "org.siros.nym_auth"
    private val legacyMembers = listOf("org.siros.secret_seed", "org.siros.holder_commitments", "org.siros.psc", "holder_commitments", "secret_members")

    private class Response(
        override val credentialMetadata: ResponseCredentialMetadata?,
        override val credentialMetadataEncryptedResponse: Boolean,
        override val deferredResponse: Boolean = false,
    ) : DeliveredResponseMetadata

    private fun response(
        members: Map<String, JsonElement>? = emptyMap(),
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
    ) = DeliveredCredentialMetadata.check(response, credentials, canStore, advertised)

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
    fun otherMembersAreStoredUninterpreted_overPlainJsonToo() {
        val v = check(response(mapOf("example.other" to JsonPrimitive("v")), encrypted = false), credentials = listOf(cred(notificationId = null)))
        assertEquals(1, entries(v).size)
    }

    @Test
    fun anAdvertisedConfigurationRefusesAnUnencryptedResponse_evenWithoutAnyMetadata() {
        assertRefused(DeliveredMetadataRefusal.NOT_ENCRYPTED, check(response(members = null, encrypted = false), advertised = true))
        assertRefused(DeliveredMetadataRefusal.NOT_ENCRYPTED, check(response(mapOf("example.other" to JsonPrimitive(1)), encrypted = false), advertised = true))
        // Encrypted but without the secret an advertised configuration delivers: unavailable, never invented.
        assertRefused(DeliveredMetadataRefusal.SEED_UNAVAILABLE, check(response(members = null, encrypted = true), advertised = true))
        assertRefused(DeliveredMetadataRefusal.SEED_UNAVAILABLE, check(response(mapOf("example.other" to JsonPrimitive(1)), encrypted = true), advertised = true))
        assertSame(DeliveredMetadataVerdict.None, check(response(members = null, encrypted = false), advertised = false))
    }

    @Test
    fun malformedMetadataIsRefused() {
        assertRefused(DeliveredMetadataRefusal.MALFORMED, check(response(malformed = true)))
    }

    @Test
    fun aSecretInASupersededShapeIsRefusedWheneverAndHoweverItArrives_andNothingIsStored() {
        val seeds = buildJsonObject { put(ns, JsonPrimitive(N.seedHex)) }
        for (m in legacyMembers) {
            for (encrypted in listOf(true, false)) {
                for (advertised in listOf(true, false)) {
                    assertRefused(
                        DeliveredMetadataRefusal.LEGACY_SECRET_MEMBER,
                        check(response(mapOf(m to seeds), encrypted = encrypted), advertised = advertised),
                    )
                }
            }
        }
        // Beside other members, beside a v0.1 member, in a deferred response, and without a notification id: still refused.
        assertRefused(DeliveredMetadataRefusal.LEGACY_SECRET_MEMBER, check(response(mapOf("example.other" to JsonPrimitive(1), "org.siros.secret_seed" to seeds))))
        assertRefused(DeliveredMetadataRefusal.LEGACY_SECRET_MEMBER, check(Response(ResponseCredentialMetadata(JsonObject(mapOf("org.siros.secret_seed" to seeds))), true, true)))
        assertRefused(DeliveredMetadataRefusal.LEGACY_SECRET_MEMBER, check(response(mapOf("org.siros.secret_seed" to seeds)), credentials = listOf(cred(notificationId = null))))
        assertFalse(check(response(mapOf("org.siros.secret_seed" to seeds))) is DeliveredMetadataVerdict.Accept)
    }

    @Test
    fun aSupersededMemberIsReportedFirst_evenWhenAHolderCommitmentIsMissingOrMismatched() {
        val sentMissing = listOf(org.siros.sdk.credentials.HolderCommitment(listOf("psc"), "sha-256", true, ByteArray(32) { 5 }))
        val sentWrong = listOf(org.siros.sdk.credentials.HolderCommitment(listOf("ssc"), "sha-256", true, ByteArray(32)))
        for (name in legacyMembers) {
            val md = mapOf(name to buildJsonObject { put("k", JsonPrimitive("v")) })
            for (sent in listOf(sentMissing, sentWrong)) {
                // Plain completion (relayed marker) and decrypted response (the member itself), each with a commitment the credential lacks
                // (sentMissing: a required psc the v01Cred() fixture never carries) or does not open (sentWrong: the wrong ssc value,
                // readable but mismatched - v01Cred() carries ssc as base64url, matching HolderCommitment's default encoding).
                val marker = Response(ResponseCredentialMetadata(JsonObject(emptyMap()), legacyMemberPresent = true), false)
                assertRefused(DeliveredMetadataRefusal.LEGACY_SECRET_MEMBER, DeliveredCredentialMetadata.check(marker, listOf(v01Cred()), true, false, holderCommitments = sent))
                assertRefused(DeliveredMetadataRefusal.LEGACY_SECRET_MEMBER, DeliveredCredentialMetadata.check(response(md), listOf(v01Cred()), true, false, holderCommitments = sent))
            }
        }
    }

    @Test
    fun theVerdictAndTheCredentialShowNoSeed() {
        val v = check(response(mapOf("org.siros.secret_seed" to buildJsonObject { put(ns, JsonPrimitive(N.seedHex)) })))
        assertFalse(v.toString().contains(N.seedHex))
        assertFalse(((v as DeliveredMetadataVerdict.Refuse).detail ?: "").contains(N.seedHex))
        assertFalse(cred().toString().contains(N.sdJwt()))
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

    /** The verdict of a receipt for [response] under the adapter and advertisement [config] selects (none selected: nothing advertised). */
    private fun receipt(config: org.siros.sdk.credentials.CredentialConfiguration, response: Response, credentials: List<DeliveredCredential> = listOf(v01Cred()), canStore: Boolean = true): DeliveredMetadataVerdict {
        val sel = org.siros.sdk.credentials.AuxiliaryDataShapes.select(config)
        val selected = sel as? org.siros.sdk.credentials.AuxiliarySelection.Selected
        return DeliveredCredentialMetadata.check(
            response, credentials, canStore,
            advertised = selected?.advertisement?.toWallet?.isNotEmpty() == true,
            shape = selected?.shape ?: org.siros.sdk.credentials.AuxiliaryDataV01,
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
        // 4. a legacy-shape secret under a v0.1 advertisement: superseded, refused, never stored.
        assertRefused(DeliveredMetadataRefusal.LEGACY_SECRET_MEMBER, receipt(onlyExt, members("org.siros.secret_seed" to """{"$ns":"${N.seedHex}"}""")))
        // 5. nothing advertised at all: a v0.1 secret nobody advertised is not accepted.
        assertRefused(DeliveredMetadataRefusal.NAMESPACE_ABSENT, receipt(configOf(null), members(aux to "[$recognised]")))
        // 6. a recognised slot advertised but only extensions delivered: the slot did not arrive.
        val withSlot = configOf("""{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"encoding":"base64url"}]}""")
        assertTrue(receipt(withSlot, members(aux to "[$extEntry]")) is DeliveredMetadataVerdict.Refuse)
        // 7. the same slot delivered: accepted.
        assertTrue(receipt(withSlot, members(aux to "[$recognised]")) is DeliveredMetadataVerdict.Accept)
        // 8. an empty advertisement object is not an advertisement at all: the configuration is malformed.
        assertTrue(org.siros.sdk.credentials.AuxiliaryDataShapes.select(configOf("{}")) is org.siros.sdk.credentials.AuxiliarySelection.Malformed)
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
            body, listOf(DeliveredCredential(format, credential, "n1")), true, advertised = true,
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
        response, credentials, true, advertised,
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
    fun v01_anAdvertisedSecretThatDidNotArriveIsUnavailable() {
        assertRefused(DeliveredMetadataRefusal.SEED_UNAVAILABLE, checkV01(response = response(members = mapOf("display" to JsonArray(emptyList())))))
    }
}
