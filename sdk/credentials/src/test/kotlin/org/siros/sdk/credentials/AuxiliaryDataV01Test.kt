// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class AuxiliaryDataV01Test {
    // The spec vector (verified): SHA-256(opening) = commitment.
    private val openingHex = "8f3b2c9e41d07a65b1e2f4c3d9a08176"
    private val commitmentB64 = "JhQM6yeuK84BoGVVSxbLL9HjjeiBERnWHEZSIIMqwd0"
    private val opening = openingHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val openingB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(opening)

    private fun config(aux: String?, legacy: String? = null) = Json { ignoreUnknownKeys = true }.decodeFromString(
        CredentialConfiguration.serializer(),
        buildString {
            append("""{"format":"dc+sd-jwt"""")
            if (legacy != null) append(""","credential_metadata":{"org.siros.secret_seed":$legacy}""")
            if (aux != null) append(""","auxiliary_data_supported":$aux""")
            append("}")
        },
    )

    private val goodAdvert = """{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["ssc"]}],"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["psc"],"required":true}]}"""

    @Test
    fun specVector_sha256OfTheOpeningIsTheCommitment() {
        val digest = MessageDigest.getInstance("SHA-256").digest(opening)
        assertEquals(commitmentB64, Base64.getUrlEncoder().withoutPadding().encodeToString(digest))
        assertTrue(SecretSeedCommitment.opens(opening, Base64.getUrlDecoder().decode(commitmentB64)))
        assertEquals(22, openingB64.length)
    }

    @Test
    fun advertisementSelectsV01_andIsNormalisedIncludingRequired() {
        val sel = AuxiliaryDataShapes.select(config(goodAdvert)) as AuxiliarySelection.Selected
        assertEquals(AuxiliaryDataV01.id, sel.shape.id)
        assertEquals(listOf(listOf("ssc")), sel.advertisement.toWallet.map { it.path })
        assertEquals(listOf(listOf("psc")), sel.advertisement.toIssuer.map { it.path })
        assertTrue(sel.advertisement.toIssuer.single().required)
    }

    @Test
    fun badAdvertisementsAreMalformed_neverGuessed() {
        val bad = listOf(
            """{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":[]}]}""",
            """{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["a"]},{"type":"hash_commitment","alg":"sha-256","path":["a"]}]}""",
            """{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["a"],"opening":"AAAA"}]}""",
            """{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["a"],"required":true}]}""",
            """{"to_wallet":[],"to_issuer":[]}""",
            "{}",
            """{"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["psc"],"required":"true"}]}""",
            """{"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["psc"],"required":"false"}]}""",
            """{"to_wallet":[],"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["psc"]}]}""",
            """{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["ssc"]}],"to_issuer":[]}""",
            """{"surprise":[]}""",
            "[]",
        )
        for (a in bad) assertTrue(a, AuxiliaryDataShapes.select(config(a)) is AuxiliarySelection.Malformed)
        assertTrue(AuxiliaryDataShapes.select(config(null)) is AuxiliarySelection.None)
    }

    @Test
    fun twoShapesAdvertisedAtOnceIsMalformed() {
        val both = config(goodAdvert, legacy = """{"namespaces":["org.siros.nym_auth"]}""")
        assertTrue(AuxiliaryDataShapes.select(both) is AuxiliarySelection.Malformed)
    }

    private fun response(vararg entries: String) = Json.parseToJsonElement("""{"auxiliary_data":[${entries.joinToString(",")}],"display":[]}""").jsonObject
    private fun entry(path: String = """["ssc"]""", opening: String = openingB64, alg: String = "sha-256", type: String = "hash_commitment") =
        """{"type":"$type","alg":"$alg","path":$path,"opening":"$opening"}"""

    @Test
    fun deliveryParsesTheOpeningAsSixteenBytes_andMalformedFailsClosed() {
        val md = response(entry())
        assertTrue(AuxiliaryDataV01.carriesSecret(md))
        val d = (AuxiliaryDataV01.parseDeliveries(md) as AuxiliaryParse.Parsed).deliveries.single()
        assertEquals(listOf("ssc"), d.path)
        assertArrayEquals(opening, d.bytes)
        assertFalse(d.toString().contains(openingHex))
        val bad = listOf(
            response(entry(opening = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(15)))),
            response(entry(opening = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(17)))),
            response(entry(opening = openingB64 + "==")),
            response(entry(opening = openingB64.replace('-', '+').replace('_', '/') + "!")),
            response(entry(), entry()),
            Json.parseToJsonElement("""{"auxiliary_data":[]}""").jsonObject,
            Json.parseToJsonElement("""{"auxiliary_data":{"path":["ssc"]}}""").jsonObject,
        )
        for (b in bad) assertTrue(b.toString(), AuxiliaryDataV01.parseDeliveries(b) is AuxiliaryParse.Malformed)
        assertEquals(emptyList<SecretDelivery>(), (AuxiliaryDataV01.parseDeliveries(Json.parseToJsonElement("""{"display":[]}""").jsonObject) as AuxiliaryParse.Parsed).deliveries)
    }

    @Test
    fun theDeliveryMustMatchTheAdvertisementExactly() {
        val adv = (AuxiliaryDataShapes.select(config(goodAdvert)) as AuxiliarySelection.Selected).advertisement
        val d = SecretDelivery(listOf("ssc"), "sha-256", opening)
        val extra = SecretDelivery(listOf("other"), "sha-256", opening)
        assertEquals(listOf(d), AuxiliaryDataV01.deliveriesToVerify(listOf(d), "ignored", adv))
        assertNull("an unadvertised secret", AuxiliaryDataV01.deliveriesToVerify(listOf(d, extra), "ignored", adv))
        assertNull("an advertised secret that did not arrive", AuxiliaryDataV01.deliveriesToVerify(listOf(extra), "ignored", adv))
        assertNull("no advertisement known: nothing is accepted", AuxiliaryDataV01.deliveriesToVerify(listOf(d), "ignored", null))
    }

    private fun sdJwt(claimName: String, valueB64: String, disclosed: Boolean, inClearAlso: Boolean = false): String {
        val b64 = { s: String -> Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray()) }
        val disclosure = b64("""["salt","$claimName","$valueB64"]""")
        val digest = CredentialDisclosureGuard.digestOf(disclosure)
        val payload = if (disclosed) """{"_sd_alg":"sha-256","_sd":["$digest"]${if (inClearAlso) ""","$claimName":"$valueB64"""" else ""}}"""
        else """{"$claimName":"$valueB64"}"""
        return b64("""{"alg":"none"}""") + "." + b64(payload) + ".sig" + (if (disclosed) "~$disclosure~" else "~")
    }

    @Test
    fun commitmentIsTheSdJwtClaimAtPath_disclosedOrInClear_andAmbiguityFailsClosed() {
        val d = SecretDelivery(listOf("ssc"), "sha-256", opening)
        for (disclosed in listOf(true, false)) {
            val c = AuxiliaryDataV01.commitmentOf("dc+sd-jwt", sdJwt("ssc", commitmentB64, disclosed), d)!!
            assertEquals(commitmentB64, Base64.getUrlEncoder().withoutPadding().encodeToString(c))
            assertTrue(SecretSeedCommitment.opens(opening, c))
        }
        assertNull(AuxiliaryDataV01.commitmentOf("dc+sd-jwt", sdJwt("ssc", commitmentB64, disclosed = true, inClearAlso = true), d))
        assertNull("another claim is never read", AuxiliaryDataV01.commitmentOf("dc+sd-jwt", sdJwt("other", commitmentB64, true), d))
        assertNull("not 32 bytes", AuxiliaryDataV01.commitmentOf("dc+sd-jwt", sdJwt("ssc", openingB64, true), d))
        assertNull("a nested path is not read", AuxiliaryDataV01.commitmentOf("dc+sd-jwt", sdJwt("ssc", commitmentB64, true), SecretDelivery(listOf("a", "ssc"), "sha-256", opening)))
        assertNull("unknown format", AuxiliaryDataV01.commitmentOf("ldp_vc", "x", d))
    }

    @Test
    fun placeInProof_isAnAuxiliaryDataClaimIdenticalForEveryProof() {
        val commitment = Base64.getUrlDecoder().decode(commitmentB64)
        val hc = listOf(HolderCommitment(listOf("psc"), "sha-256", true, commitment))
        val claim = AuxiliaryDataV01.placeInProof(hc)
        assertEquals(setOf("auxiliary_data"), claim.keys)
        val e = (claim.getValue("auxiliary_data") as JsonArray).single().jsonObject
        assertEquals("hash_commitment", (e["type"] as JsonPrimitive).content)
        assertEquals("sha-256", (e["alg"] as JsonPrimitive).content)
        assertEquals(listOf("psc"), e["path"]!!.jsonArray.map { (it as JsonPrimitive).content })
        assertEquals(commitmentB64, (e["commitment"] as JsonPrimitive).content)
        assertEquals("the same value for every proof of a request", claim, AuxiliaryDataV01.placeInProof(hc))
        assertTrue(AuxiliaryDataV01.placeInProof(emptyList()).isEmpty())
        for (bad in listOf(
            HolderCommitment(listOf("psc"), "sha-512", true, commitment),
            HolderCommitment(listOf("psc"), "sha-256", true, ByteArray(31)),
            HolderCommitment(emptyList(), "sha-256", true, commitment),
        )) {
            try {
                AuxiliaryDataV01.placeInProof(listOf(bad))
                fail("placed an invalid commitment")
            } catch (_: WalletException) {
            }
        }
    }

    @Test
    fun stripRemovesTheSecretMemberBeforeDisplay() {
        val md = response(entry())
        assertEquals(setOf("display"), AuxiliaryDataV01.stripFromMetadata(md).keys)
        assertEquals(JsonObject(emptyMap()), AuxiliaryDataV01.stripFromMetadata(Json.parseToJsonElement("""{"auxiliary_data":[]}""").jsonObject))
    }

    @Test
    fun theForbiddenAuxiliaryDataMemberInPublicMetadataMakesTheConfigurationMalformed_evenWithoutAnAdvertisement() {
        val withMember = Json { ignoreUnknownKeys = true }.decodeFromString(
            CredentialConfiguration.serializer(),
            """{"format":"dc+sd-jwt","credential_metadata":{"auxiliary_data":[{"type":"hash_commitment"}]}}""",
        )
        assertTrue(AuxiliaryDataShapes.select(withMember) is AuxiliarySelection.Malformed)
        val withBoth = Json { ignoreUnknownKeys = true }.decodeFromString(
            CredentialConfiguration.serializer(),
            """{"format":"dc+sd-jwt","credential_metadata":{"auxiliary_data":[]},"auxiliary_data_supported":$goodAdvert}""",
        )
        assertTrue(AuxiliaryDataShapes.select(withBoth) is AuxiliarySelection.Malformed)
        assertTrue(AuxiliaryDataShapes.select(config(null)) is AuxiliarySelection.None)
    }

    @Test
    fun unrecognisedEntriesAreIgnored_exceptARequiredToIssuerOneWhichMakesTheConfigurationUnusable() {
        val ext = """{"type":"future_kind","alg":"sha-256","path":["x"]}"""
        val badAlg = """{"type":"hash_commitment","alg":"sha-512","path":["y"]}"""
        val ok = """{"to_wallet":[$ext,{"type":"hash_commitment","alg":"sha-256","path":["ssc"]},$badAlg],"to_issuer":[$ext,{"type":"hash_commitment","alg":"sha-256","path":["psc"],"required":true},$badAlg]}"""
        val sel = AuxiliaryDataShapes.select(config(ok)) as AuxiliarySelection.Selected
        assertEquals(listOf(listOf("ssc")), sel.advertisement.toWallet.map { it.path })
        assertEquals(listOf(listOf("psc")), sel.advertisement.toIssuer.map { it.path })
        // An unrecognised OPTIONAL to_issuer entry alone: ignored; the advertised shape is kept with no recognised slots.
        val onlyExt = AuxiliaryDataShapes.select(config("""{"to_issuer":[$ext]}""")) as AuxiliarySelection.Selected
        assertTrue(onlyExt.advertisement.toWallet.isEmpty() && onlyExt.advertisement.toIssuer.isEmpty())
        // An unrecognised REQUIRED one cannot be satisfied.
        val required = """{"type":"future_kind","alg":"sha-256","path":["x"],"required":true}"""
        assertTrue(AuxiliaryDataShapes.select(config("""{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["ssc"]}],"to_issuer":[$required]}""")) is AuxiliarySelection.Malformed)
        // A recognised entry is still strict.
        assertTrue(AuxiliaryDataShapes.select(config("""{"to_wallet":[$ext,{"type":"hash_commitment","alg":"sha-256","path":[]}]}""")) is AuxiliarySelection.Malformed)
    }

    @Test
    fun aDeliveryWithAnExtensionEntryIsNormalisedToTheRecognisedSlotsOnly() {
        val ext = """{"type":"future_kind","alg":"sha-256","path":["x"],"opening":"not-checked"}"""
        val md = response(ext, entry(), """{"type":"hash_commitment","alg":"sha-512","path":["z"],"opening":"zz"}""")
        val parsed = (AuxiliaryDataV01.parseDeliveries(md) as AuxiliaryParse.Parsed).deliveries
        assertEquals(listOf(listOf("ssc")), parsed.map { it.path })
        val adv = (AuxiliaryDataShapes.select(config(goodAdvert)) as AuxiliarySelection.Selected).advertisement
        assertEquals(parsed, AuxiliaryDataV01.deliveriesToVerify(parsed, "x", adv))
        // Only extensions delivered: nothing recognised, so the advertised slot did not arrive.
        val onlyExt = (AuxiliaryDataV01.parseDeliveries(response(ext)) as AuxiliaryParse.Parsed).deliveries
        assertTrue(onlyExt.isEmpty())
        assertNull(AuxiliaryDataV01.deliveriesToVerify(onlyExt, "x", adv))
    }

    @Test
    fun anUnsupportedSdAlgIsAnInvalidClaimNotAnAbsentOne() {
        val b64 = { x: String -> Base64.getUrlEncoder().withoutPadding().encodeToString(x.toByteArray()) }
        val disclosure = b64("""["salt","psc","$commitmentB64"]""")
        for (alg in listOf("sha-512", "SHA-256", "")) {
            val jwt = b64("""{"alg":"none"}""") + "." + b64("""{"_sd_alg":"$alg","_sd":["x"]}""") + ".sig~$disclosure~"
            assertEquals(alg, AuxiliaryDataV01.Claim.Invalid, AuxiliaryDataV01.claimStatus("dc+sd-jwt", jwt, listOf("psc")))
        }
        val nonString = b64("""{"alg":"none"}""") + "." + b64("""{"_sd_alg":5,"_sd":[]}""") + ".sig~"
        assertEquals(AuxiliaryDataV01.Claim.Invalid, AuxiliaryDataV01.claimStatus("dc+sd-jwt", nonString, listOf("psc")))
        // No _sd_alg at all (the SHA-256 default) and nothing disclosed: genuinely absent.
        val none = b64("""{"alg":"none"}""") + "." + b64("""{"_sd":[]}""") + ".sig~"
        assertEquals(AuxiliaryDataV01.Claim.Absent, AuxiliaryDataV01.claimStatus("dc+sd-jwt", none, listOf("psc")))
    }
}
