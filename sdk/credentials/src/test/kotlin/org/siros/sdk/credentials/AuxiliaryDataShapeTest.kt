// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AuxiliaryDataShapeTest {
    private fun config(credentialMetadata: String? = null, extra: String = "") = Json { ignoreUnknownKeys = true }.decodeFromString(
        CredentialConfiguration.serializer(),
        """{"format":"dc+sd-jwt"${credentialMetadata?.let { ""","credential_metadata":$it""" } ?: ""}$extra}""",
    )

    private val hex = "8f3b2c9e41d07a65b1e2f4c3d9a08176"

    @Test
    fun theOnlyShapeIsV01() {
        assertEquals(listOf(AuxiliaryDataV01.id), AuxiliaryDataShapes.all.map { it.id })
    }

    @Test
    fun noAdvertisementIsNone() {
        assertTrue(AuxiliaryDataShapes.select(config()) is AuxiliarySelection.None)
    }

    @Test
    fun aSupersededSecretSeedAdvertisementIsNeverOffered() {
        // Neither the namespaces advertisement nor a seed value in public metadata selects anything: not offered.
        assertTrue(AuxiliaryDataShapes.select(config("""{"org.siros.secret_seed":{"namespaces":["org.siros.nym_auth"]}}""")) is AuxiliarySelection.Malformed)
        assertTrue(AuxiliaryDataShapes.select(config("""{"org.siros.secret_seed":{"org.siros.nym_auth":"$hex"}}""")) is AuxiliarySelection.Malformed)
    }

    @Test
    fun aSupersededMemberIsNotASecretOfTheV01Shape() {
        val md = Json.parseToJsonElement("""{"org.siros.secret_seed":{"org.siros.nym_auth":"$hex"},"display":[]}""").jsonObject
        assertFalse(AuxiliaryDataV01.carriesSecret(md))
        assertTrue(LegacySecretMembers.carriedBy(md))
        for (m in listOf("org.siros.holder_commitments", "org.siros.psc", "holder_commitments", "secret_members")) {
            assertTrue(m, LegacySecretMembers.carriedBy(Json.parseToJsonElement("""{"$m":{}}""").jsonObject))
        }
        assertFalse(LegacySecretMembers.carriedBy(Json.parseToJsonElement("""{"auxiliary_data":{},"display":[]}""").jsonObject))
    }
}
