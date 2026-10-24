// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AuxiliaryDataShapeTest {
    private fun config(credentialMetadata: String? = null, extra: String = "") = Json { ignoreUnknownKeys = true }.decodeFromString(
        CredentialConfiguration.serializer(),
        """{"format":"dc+sd-jwt"${credentialMetadata?.let { ""","credential_metadata":$it""" } ?: ""}$extra}""",
    )

    private val hex = "8f3b2c9e41d07a65b1e2f4c3d9a08176"

    @Test
    fun legacySelectedByItsAdvertisementAndNormalised() {
        val sel = AuxiliaryDataShapes.select(config("""{"org.siros.secret_seed":{"namespaces":["org.siros.nym_auth"]}}"""))
        sel as AuxiliarySelection.Selected
        assertEquals(LegacyOrgSirosShape.id, sel.shape.id)
        assertEquals(listOf(listOf("org.siros.nym_auth")), sel.advertisement.toWallet.map { it.path })
        assertTrue(sel.advertisement.toIssuer.isEmpty())
    }

    @Test
    fun noAdvertisementIsNone_andASeedValueInPublicMetadataIsMalformed() {
        assertTrue(AuxiliaryDataShapes.select(config()) is AuxiliarySelection.None)
        assertTrue(AuxiliaryDataShapes.select(config("""{"org.siros.secret_seed":{"org.siros.nym_auth":"$hex"}}""")) is AuxiliarySelection.Malformed)
    }

    @Test
    fun legacyDeliveryIsNormalisedToPathAlgBytes_andMalformedFailsClosed() {
        val md = Json.parseToJsonElement("""{"org.siros.secret_seed":{"org.siros.nym_auth":"$hex"},"display":[]}""").jsonObject
        assertTrue(LegacyOrgSirosShape.carriesSecret(md))
        val parsed = LegacyOrgSirosShape.parseDeliveries(md) as AuxiliaryParse.Parsed
        val d = parsed.deliveries.single()
        assertEquals(listOf("org.siros.nym_auth"), d.path)
        assertEquals("sha-256", d.alg)
        assertEquals(16, d.bytes.size)
        assertEquals(0x8f, d.bytes[0].toInt() and 0xff)
        val bad = Json.parseToJsonElement("""{"org.siros.secret_seed":{"org.siros.nym_auth":"NOTHEX"}}""").jsonObject
        assertTrue(LegacyOrgSirosShape.parseDeliveries(bad) is AuxiliaryParse.Malformed)
        assertFalse("secret never in toString", d.toString().contains("8f3b"))
    }

    @Test
    fun legacyStripRemovesTheSecretMemberOnly() {
        val md = Json.parseToJsonElement("""{"org.siros.secret_seed":{"a":"$hex"},"display":[1]}""").jsonObject
        val stripped = LegacyOrgSirosShape.stripFromMetadata(md)
        assertEquals(setOf("display"), stripped.keys)
    }

    @Test
    fun legacyPlacesThePscAsTheOrgSirosPscClaimAndRefusesAnythingElse() {
        val psc = ByteArray(32) { it.toByte() }
        val placed = LegacyOrgSirosShape.placeInProof(listOf(HolderCommitment(listOf("psc"), "sha-256", true, psc)))
        assertEquals(setOf("org.siros.psc"), placed.keys)
        assertEquals(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(psc), (placed.getValue("org.siros.psc") as JsonPrimitive).content)
        assertTrue(LegacyOrgSirosShape.placeInProof(emptyList()).isEmpty())
        try {
            LegacyOrgSirosShape.placeInProof(listOf(HolderCommitment(listOf("other"), "sha-256", true, psc)))
            org.junit.Assert.fail("placed an unknown commitment")
        } catch (e: WalletException) {
            assertEquals("holder_commitment_unsupported", e.errorCode)
        }
    }

    @Test
    fun legacyVerifiesTheNamespaceDeliveryOnlyAndReportsAnAbsentOne() {
        val a = SecretDelivery(listOf("org.siros.nym_auth"), "sha-256", ByteArray(16))
        val b = SecretDelivery(listOf("other"), "sha-256", ByteArray(16))
        assertEquals(listOf(a), LegacyOrgSirosShape.deliveriesToVerify(listOf(a, b), "org.siros.nym_auth", null))
        assertNull(LegacyOrgSirosShape.deliveriesToVerify(listOf(b), "org.siros.nym_auth", null))
    }
}
