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

    private fun config(aux: String?, legacy: String? = null, format: String = "dc+sd-jwt") = Json { ignoreUnknownKeys = true }.decodeFromString(
        CredentialConfiguration.serializer(),
        buildString {
            append("""{"format":"$format"""")
            if (legacy != null) append(""","credential_metadata":{"org.siros.secret_seed":$legacy}""")
            if (aux != null) append(""","auxiliary_data_supported":$aux""")
            append("}")
        },
    )

    private val goodAdvert = """{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"encoding":"base64url"}],"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["psc"],"required":true,"encoding":"base64url"}]}"""

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
            """{"to_wallet":[{"type":"hash_commitment","alg":"sha-512","path":["y"],"opening":"AAAA"}]}""",
            """{"to_issuer":[{"type":"hash_commitment","alg":"sha-512","path":["y"],"commitment":"AAAA"}]}""",
            """{"to_wallet":[{"type":"hash_commitment","alg":"sha-512","path":["y"],"commitment":"AAAA"}]}""",
            """{"to_wallet":[{"path":["ssc"]}]}""",
            """{"to_wallet":[{"type":5,"alg":"sha-256","path":["ssc"]}]}""",
            """{"to_wallet":[{"type":"hash_commitment","path":["ssc"]}]}""",
            """{"to_wallet":[{"type":"hash_commitment","alg":7,"path":["ssc"]}]}""",
            """{"to_wallet":[{"type":"hash_commitment","alg":"sha-512"}]}""",
            """{"to_wallet":[{"type":"hash_commitment","alg":"sha-512","path":[]}]}""",
            """{"to_issuer":[{"alg":"sha-256","path":["psc"]}]}""",
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

    private fun ext0() = """{"type":"future_kind","alg":"sha-256","path":["x"]}"""

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
            response("""{"alg":"sha-256","path":["ssc"],"opening":"$openingB64"}"""),
            response("""{"type":3,"alg":"sha-256","path":["ssc"],"opening":"$openingB64"}"""),
            response("""{"type":"hash_commitment","path":["ssc"],"opening":"$openingB64"}"""),
            response("""{"type":"hash_commitment","alg":9,"path":["ssc"],"opening":"$openingB64"}"""),
            response("""{"type":"hash_commitment","alg":"sha-512","opening":"$openingB64"}"""),
            response(ext0(), """{"type":"hash_commitment","path":["ssc"],"opening":"$openingB64"}"""),
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
        assertEquals(listOf(d), AuxiliaryDataV01.deliveriesToVerify(listOf(d), adv))
        assertNull("an unadvertised secret", AuxiliaryDataV01.deliveriesToVerify(listOf(d, extra), adv))
        assertNull("an advertised secret that did not arrive", AuxiliaryDataV01.deliveriesToVerify(listOf(extra), adv))
        assertNull("no advertisement known: nothing is accepted", AuxiliaryDataV01.deliveriesToVerify(listOf(d), null))
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
        val ok = """{"to_wallet":[$ext,{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"encoding":"base64url"},$badAlg],"to_issuer":[$ext,{"type":"hash_commitment","alg":"sha-256","path":["psc"],"required":true,"encoding":"base64url"},$badAlg]}"""
        val sel = AuxiliaryDataShapes.select(config(ok)) as AuxiliarySelection.Selected
        assertEquals(listOf(listOf("ssc")), sel.advertisement.toWallet.map { it.path })
        assertEquals(listOf(listOf("psc")), sel.advertisement.toIssuer.map { it.path })
        // An unrecognised OPTIONAL to_issuer entry alone: ignored; the advertised shape is kept with no recognised slots.
        val onlyExt = AuxiliaryDataShapes.select(config("""{"to_issuer":[$ext]}""")) as AuxiliarySelection.Selected
        assertTrue(onlyExt.advertisement.toWallet.isEmpty() && onlyExt.advertisement.toIssuer.isEmpty())
        // An unrecognised REQUIRED one cannot be satisfied.
        val required = """{"type":"future_kind","alg":"sha-256","path":["x"],"required":true}"""
        assertTrue(AuxiliaryDataShapes.select(config("""{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"encoding":"base64url"}],"to_issuer":[$required]}""")) is AuxiliarySelection.Malformed)
        // A recognised entry is still strict.
        assertTrue(AuxiliaryDataShapes.select(config("""{"to_wallet":[$ext,{"type":"hash_commitment","alg":"sha-256","path":[],"encoding":"base64url"}]}""")) is AuxiliarySelection.Malformed)
    }

    @Test
    fun aDeliveryWithAnExtensionEntryIsNormalisedToTheRecognisedSlotsOnly() {
        val ext = """{"type":"future_kind","alg":"sha-256","path":["x"],"opening":"not-checked"}"""
        val md = response(ext, entry(), """{"type":"hash_commitment","alg":"sha-512","path":["z"],"opening":"zz"}""")
        val parsed = (AuxiliaryDataV01.parseDeliveries(md) as AuxiliaryParse.Parsed).deliveries
        assertEquals(listOf(listOf("ssc")), parsed.map { it.path })
        val adv = (AuxiliaryDataShapes.select(config(goodAdvert)) as AuxiliarySelection.Selected).advertisement
        assertEquals(parsed, AuxiliaryDataV01.deliveriesToVerify(parsed, adv))
        // Only extensions delivered: nothing recognised, so the advertised slot did not arrive.
        val onlyExt = (AuxiliaryDataV01.parseDeliveries(response(ext)) as AuxiliaryParse.Parsed).deliveries
        assertTrue(onlyExt.isEmpty())
        assertNull(AuxiliaryDataV01.deliveriesToVerify(onlyExt, adv))
    }

    @Test
    fun anUnsupportedSdAlgIsAnInvalidClaimNotAnAbsentOne() {
        val b64 = { x: String -> Base64.getUrlEncoder().withoutPadding().encodeToString(x.toByteArray()) }
        val disclosure = b64("""["salt","psc","$commitmentB64"]""")
        for (alg in listOf("sha-512", "SHA-256", "")) {
            val jwt = b64("""{"alg":"none"}""") + "." + b64("""{"_sd_alg":"$alg","_sd":["x"]}""") + ".sig~$disclosure~"
            assertTrue(alg, AuxiliaryDataV01.claimStatus("dc+sd-jwt", jwt, listOf("psc")) is AuxiliaryDataV01.Claim.Invalid)
        }
        val nonString = b64("""{"alg":"none"}""") + "." + b64("""{"_sd_alg":5,"_sd":[]}""") + ".sig~"
        assertTrue(AuxiliaryDataV01.claimStatus("dc+sd-jwt", nonString, listOf("psc")) is AuxiliaryDataV01.Claim.Invalid)
        // No _sd_alg at all (the SHA-256 default) and nothing disclosed: genuinely absent.
        val none = b64("""{"alg":"none"}""") + "." + b64("""{"_sd":[]}""") + ".sig~"
        assertEquals(AuxiliaryDataV01.Claim.Absent, AuxiliaryDataV01.claimStatus("dc+sd-jwt", none, listOf("psc")))
    }

    @Test
    fun theAdvertisedEncodingIsKeptPerSlot_forBothFormats_andAnUnreadableOneMeansTheConfigurationIsNotOffered() {
        for (format in listOf("dc+sd-jwt", "mso_mdoc")) {
            // The path the receipt reader handles in this format.
            val path = if (format == "mso_mdoc") """["ns","ssc"]""" else """["ssc"]"""
            fun slot(enc: String?) = """{"type":"hash_commitment","alg":"sha-256","path":$path${enc?.let { ""","encoding":$it""" } ?: ""}}"""
            for (enc in listOf("base64url", "base64", "hex")) {
                val sel = AuxiliaryDataShapes.select(config("""{"to_wallet":[${slot("\"$enc\"")}]}""", format = format)) as AuxiliarySelection.Selected
                assertEquals("$format $enc", enc, sel.advertisement.toWallet.single().encoding)
            }
            // Absent: the claim is BYTES, which only an mdoc can hold; an SD-JWT configuration without an encoding is not offered.
            val none = AuxiliaryDataShapes.select(config("""{"to_wallet":[${slot(null)}]}""", format = format))
            if (format == "mso_mdoc") assertNull((none as AuxiliarySelection.Selected).advertisement.toWallet.single().encoding)
            else assertTrue("sd-jwt without an encoding", none is AuxiliarySelection.Malformed)
            // Unknown value, wrong case, non-string, empty: not offered.
            for (bad in listOf("\"rot13\"", "\"Hex\"", "5", "\"\"", "null", "true")) {
                assertTrue("$format $bad", AuxiliaryDataShapes.select(config("""{"to_wallet":[${slot(bad)}]}""", format = format)) is AuxiliarySelection.Malformed)
            }
        }
        // An encoding that makes no sense for the format (a commitment this wallet cannot read there at all).
        fun sdSlot(enc: String) = """{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"encoding":"$enc"}"""
        assertTrue(AuxiliaryDataShapes.select(config("""{"to_wallet":[${sdSlot("hex")}]}""", format = "jwt_vc_json")) is AuxiliarySelection.Malformed)
        // On the to_issuer side too, and an unknown encoding on an UNRECOGNISED entry is just an ignored extension.
        // (An OPTIONAL to_issuer entry with an unknown encoding is skipped, spec 4.1: see the dedicated test.)
        val ext = AuxiliaryDataShapes.select(config("""{"to_wallet":[{"type":"future_kind","alg":"sha-256","path":["x"],"encoding":"rot13"},${sdSlot("hex")}]}"""))
        assertTrue(ext is AuxiliarySelection.Selected)
    }

    @Test
    fun `mdoc entry without encoding is accepted`() {
        // The shape gdc issues for nym_auth: an mdoc ssc entry with NO encoding member (the claim is a byte string).
        val sel = AuxiliaryDataShapes.select(
            config("""{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["eu.europa.ec.eudi.nym_auth.1","ssc"]}],"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["eu.europa.ec.eudi.nym_auth.1","psc"],"required":true}]}""", format = "mso_mdoc"),
        ) as AuxiliarySelection.Selected
        assertNull(sel.advertisement.toWallet.single().encoding)
        assertNull(sel.advertisement.toIssuer.single().encoding)
        assertTrue(sel.advertisement.toIssuer.single().required)
    }

    @Test
    fun theProofEntryCarriesExactlyTypeAlgPathAndCommitment_neverEncodingRequiredOrOpening() {
        // The slot advertised an encoding and required: neither is echoed back (the issuer refuses an entry that carries them).
        val hc = listOf(HolderCommitment(listOf("psc"), "sha-256", true, ByteArray(32) { 1 }, "hex"))
        val entry = (AuxiliaryDataV01.placeInProof(hc).getValue("auxiliary_data") as JsonArray).single().jsonObject
        assertEquals(setOf("type", "alg", "path", "commitment"), entry.keys)
    }

    @Test
    fun anOptionalToIssuerEntryTheWalletCannotHonourIsSkipped_everythingItMustReadOrSendMakesTheConfigurationUnusable() {
        fun toIssuer(extra: String, required: Boolean) = """{"type":"hash_commitment","alg":"sha-256","path":["psc"],"encoding":"base64url"$extra${if (required) ""","required":true""" else ""}}"""
        val good = """{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"encoding":"base64url"}"""
        // Optional + unknown encoding string: omitted; the supported entries still select.
        val optionalBad = """{"type":"hash_commitment","alg":"sha-256","path":["other"],"encoding":"rot13"}"""
        val sel = AuxiliaryDataShapes.select(config("""{"to_wallet":[$good],"to_issuer":[$optionalBad,${toIssuer("", false)}]}""")) as AuxiliarySelection.Selected
        assertEquals(listOf(listOf("psc")), sel.advertisement.toIssuer.map { it.path })
        // Alone, it leaves nothing recognised but the shape is still selected.
        val alone = AuxiliaryDataShapes.select(config("""{"to_issuer":[$optionalBad]}""")) as AuxiliarySelection.Selected
        assertTrue(alone.advertisement.toIssuer.isEmpty())
        // REQUIRED, or in to_wallet: unusable.
        assertTrue(AuxiliaryDataShapes.select(config("""{"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["other"],"encoding":"rot13","required":true}]}""")) is AuxiliarySelection.Malformed)
        assertTrue(AuxiliaryDataShapes.select(config("""{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["other"],"encoding":"rot13"}]}""")) is AuxiliarySelection.Malformed)
        // A non-string encoding is malformed even when optional.
        assertTrue(AuxiliaryDataShapes.select(config("""{"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["other"],"encoding":5}]}""")) is AuxiliarySelection.Malformed)
    }

    @Test
    fun aRecognisedSlotWhosePathTheReceiptReaderCannotHandleIsRefusedAtSelection() {
        fun slot(path: String, enc: String? = "base64url") = """{"type":"hash_commitment","alg":"sha-256","path":$path${enc?.let { ""","encoding":"$it"""" } ?: ""}}"""
        // SD-JWT reads a top-level claim only; mdoc exactly [namespace, element].
        assertTrue(AuxiliaryDataShapes.select(config("""{"to_wallet":[${slot("""["person","ssc"]""")}]}""")) is AuxiliarySelection.Malformed)
        assertTrue(AuxiliaryDataShapes.select(config("""{"to_wallet":[${slot("""["ssc"]""")}]}""")) is AuxiliarySelection.Selected)
        for (path in listOf("""["ssc"]""", """["a","b","c"]""")) {
            assertTrue(path, AuxiliaryDataShapes.select(config("""{"to_wallet":[${slot(path, null)}]}""", format = "mso_mdoc")) is AuxiliarySelection.Malformed)
        }
        assertTrue(AuxiliaryDataShapes.select(config("""{"to_wallet":[${slot("""["ns","ssc"]""", null)}]}""", format = "mso_mdoc")) is AuxiliarySelection.Selected)
        // An optional to_issuer entry at an unreadable path is skipped, not fatal.
        val sel = AuxiliaryDataShapes.select(config("""{"to_wallet":[${slot("""["ssc"]""")}],"to_issuer":[${slot("""["person","psc"]""")}]}""")) as AuxiliarySelection.Selected
        assertTrue(sel.advertisement.toIssuer.isEmpty())
    }

    @Test
    fun aRecognisedResponseEntryCarryingEncodingOrCommitmentIsMalformed_beforeTheOpeningIsDecoded() {
        for (member in listOf(""","encoding":"hex"""", ""","commitment":"AAAA"""")) {
            val md = response("""{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"opening":"$openingB64"$member}""")
            assertTrue(member, AuxiliaryDataV01.parseDeliveries(md) is AuxiliaryParse.Malformed)
        }
    }
}
