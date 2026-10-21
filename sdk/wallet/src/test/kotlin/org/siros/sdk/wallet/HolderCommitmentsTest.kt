// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import java.security.MessageDigest
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.credentials.WalletException

class HolderCommitmentsTest {

    /** A psc that depends on (type, issuer) as exact strings, so a spelling difference shows. */
    private val source: (String, String) -> ByteArray = { credentialType, issuer ->
        MessageDigest.getInstance("SHA-256").digest("$credentialType|$issuer".toByteArray(Charsets.UTF_8))
    }

    private fun claims(
        requested: List<String>? = listOf("psc"),
        type: String? = "urn:eudi:pid:1",
        issuer: String? = "https://issuer.example",
        src: ((String, String) -> ByteArray)? = source,
    ) = HolderCommitments.proofClaims(requested, type, issuer, src)

    private fun refused(block: () -> Unit): WalletException {
        try {
            block()
        } catch (e: WalletException) {
            return e
        }
        fail("expected a WalletException")
        throw AssertionError()
    }

    @Test
    fun `the claim is unpadded base64url of the 32 byte commitment`() {
        val value = claims().getValue("org.siros.psc")
        assertEquals(43, value.length)
        assertFalse(value.contains("="))
        assertFalse(value.contains("+") || value.contains("/"))
        assertEquals(
            listOf(*source("urn:eudi:pid:1", "https://issuer.example").toTypedArray()),
            Base64.getUrlDecoder().decode(value).toList(),
        )
    }

    @Test
    fun `nothing requested adds nothing`() {
        assertEquals(emptyMap<String, String>(), claims(requested = null))
        assertEquals(emptyMap<String, String>(), claims(requested = emptyList()))
    }

    @Test
    fun `the issuer string is used verbatim so a trailing slash is a different commitment`() {
        val a = claims(issuer = "https://issuer.example")
        val b = claims(issuer = "https://issuer.example/")
        assertNotEquals(a, b)
    }

    @Test
    fun `the credential type is part of the derivation input`() {
        assertNotEquals(claims(type = "t1"), claims(type = "t2"))
    }

    @Test
    fun `an unknown commitment name refuses`() {
        assertEquals("holder_commitment_unsupported", refused { claims(requested = listOf("psc", "other")) }.errorCode)
    }

    @Test
    fun `a missing credential type or issuer refuses`() {
        refused { claims(type = null) }
        refused { claims(type = "") }
        refused { claims(issuer = null) }
        refused { claims(issuer = "") }
    }

    @Test
    fun `no commitment source refuses instead of omitting the claim`() {
        assertEquals("holder_commitment_unavailable", refused { claims(src = null) }.errorCode)
    }

    @Test
    fun `a commitment that is not 32 bytes refuses`() {
        refused { claims(src = { _, _ -> ByteArray(31) }) }
        refused { claims(src = { _, _ -> ByteArray(33) }) }
    }

    @Test
    fun `the commitment is wiped after use and appears in no refusal message`() {
        val handedOut = ByteArray(31) { 7 }
        val e = refused { claims(src = { _, _ -> handedOut }) }
        assertTrue(handedOut.all { it == 0.toByte() })
        assertFalse(e.message.orEmpty().contains(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(31) { 7 })))
    }

    @Test
    fun `the conflict exception carries the issuer text and the user string`() {
        val e = PseudonymCommitmentConflictException("org.siros.psc_conflict: different")
        assertEquals("org.siros.psc_conflict: different", e.issuerMessage)
        assertEquals("psc_conflict", e.errorCode)
        assertTrue(e.userMessageRes != 0)
    }
}
