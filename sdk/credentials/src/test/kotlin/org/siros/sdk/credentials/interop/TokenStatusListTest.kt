package org.siros.sdk.credentials.interop

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.Deflater

class TokenStatusListTest {

    // ── bit packing ─────────────────────────────────────────────────
    //
    // The draft's own example: entries are packed least-significant-bits
    // first within each byte.

    @Test
    fun `one-bit entries are read least significant bit first`() {
        // 0b1010_0101 -> indices 0..7 = 1,0,1,0,0,1,0,1
        val list = byteArrayOf(0xA5.toByte())
        val read = (0..7).map { TokenStatusList.readStatusAtIndex(list, 1, it) }
        assertEquals(listOf(1, 0, 1, 0, 0, 1, 0, 1), read)
    }

    @Test
    fun `two-bit entries pack four to a byte`() {
        // 0b11_10_01_00 -> indices 0..3 = 0,1,2,3
        val list = byteArrayOf(0xE4.toByte())
        assertEquals(listOf(0, 1, 2, 3), (0..3).map { TokenStatusList.readStatusAtIndex(list, 2, it) })
    }

    @Test
    fun `four-bit entries pack two to a byte`() {
        // 0b1100_0011 -> index 0 = 3, index 1 = 12
        val list = byteArrayOf(0xC3.toByte())
        assertEquals(3, TokenStatusList.readStatusAtIndex(list, 4, 0))
        assertEquals(12, TokenStatusList.readStatusAtIndex(list, 4, 1))
    }

    @Test
    fun `eight-bit entries are one per byte`() {
        val list = byteArrayOf(0x00, 0x01, 0x02, 0xFF.toByte())
        assertEquals(listOf(0, 1, 2, 255), (0..3).map { TokenStatusList.readStatusAtIndex(list, 8, it) })
    }

    @Test
    fun `an index past the end of the list reads as unknown, not as valid`() {
        // Reporting 0 (VALID) for an out-of-range index would silently treat
        // a revoked credential as good.
        assertNull(TokenStatusList.readStatusAtIndex(byteArrayOf(0x00), 1, 8))
        assertNull(TokenStatusList.readStatusAtIndex(byteArrayOf(0x00), 8, 1))
        assertNull(TokenStatusList.readStatusAtIndex(byteArrayOf(0x00), 1, -1))
    }

    @Test
    fun `an illegal entry width is reported as such, not as a missing index`() = kotlinx.coroutines.runBlocking {
        // "Index 1 is outside the status list" would send whoever is debugging
        // the issuer looking in entirely the wrong place.
        val client = TokenStatusListClient(
            httpGet = { _, _ -> statusListToken(bits = 3) },
            resolveIssuerKey = { _, _ -> issuerKey.toPublicJWK() },
        )
        val resolution = client.resolve(TokenStatusList.Reference(1, "https://x.example"))
        val reason = (resolution as TokenStatusList.Resolution.Unavailable).reason
        assertTrue(reason, reason.contains("entry width of 3 bits"))
    }

    @Test
    fun `an entry width the draft does not define is refused`() {
        assertNull(TokenStatusList.readStatusAtIndex(byteArrayOf(0x00), 3, 0))
        assertNull(TokenStatusList.readStatusAtIndex(byteArrayOf(0x00), 0, 0))
    }

    @Test
    fun `an index in a later byte is found`() {
        val list = ByteArray(4)
        list[2] = 0x04 // 0b0000_0100 -> bit 2 of byte 2 -> index 18
        assertEquals(1, TokenStatusList.readStatusAtIndex(list, 1, 18))
        assertEquals(0, TokenStatusList.readStatusAtIndex(list, 1, 17))
    }

    // ── decompression ───────────────────────────────────────────────

    @Test
    fun `a zlib-wrapped list inflates`() {
        val original = ByteArray(64) { (it % 7).toByte() }
        assertTrue(TokenStatusList.inflate(deflate(original, nowrap = false))!!.contentEquals(original))
    }

    @Test
    fun `a raw deflate list inflates too`() {
        // Some issuers emit raw DEFLATE; a corrupt-list error would be wrong.
        val original = ByteArray(64) { (it % 5).toByte() }
        assertTrue(TokenStatusList.inflate(deflate(original, nowrap = true))!!.contentEquals(original))
    }

    @Test
    fun `data that is not compressed at all is reported as undecompressable`() {
        assertNull(TokenStatusList.inflate(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)))
    }

    // ── the credential's reference ──────────────────────────────────

    @Test
    fun `a status list reference is read from a credential's claims`() {
        val reference = TokenStatusList.extractReference(
            claims("""{"status":{"status_list":{"idx":42,"uri":"https://issuer.example/statuslists/1"}}}"""),
        )
        assertNotNull(reference)
        assertEquals(42, reference!!.idx)
        assertEquals("https://issuer.example/statuslists/1", reference.uri)
    }

    @Test
    fun `a credential without a status reference has none`() {
        assertNull(TokenStatusList.extractReference(claims("""{"iss":"https://issuer.example"}""")))
        assertNull(TokenStatusList.extractReference(claims("""{"status":{}}""")))
        // A reference missing either half is not a reference.
        assertNull(TokenStatusList.extractReference(claims("""{"status":{"status_list":{"idx":1}}}""")))
        assertNull(
            TokenStatusList.extractReference(
                claims("""{"status":{"status_list":{"uri":"https://x.example"}}}"""),
            ),
        )
    }

    private fun claims(json: String) = Json.parseToJsonElement(json) as JsonObject

    /** The issuer key these tests sign their Status List Tokens with. */
    private val issuerKey: com.nimbusds.jose.jwk.ECKey by lazy {
        com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate()
    }

    /**
     * A properly signed Status List Token declaring [bits] as its entry width.
     *
     * Really signed, because the reader verifies the signature before it looks
     * at the list - an unsigned shell never reaches the width check.
     */
    private fun statusListToken(bits: Int): String {
        val claims = com.nimbusds.jwt.JWTClaimsSet.Builder()
            .issuer("https://issuer.example")
            .claim("status_list", mapOf("bits" to bits, "lst" to "eJw="))
            .build()
        val header = com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
            .type(com.nimbusds.jose.JOSEObjectType("statuslist+jwt"))
            .build()
        return com.nimbusds.jwt.SignedJWT(header, claims)
            .also { it.sign(com.nimbusds.jose.crypto.ECDSASigner(issuerKey)) }
            .serialize()
    }

    private fun deflate(data: ByteArray, nowrap: Boolean): ByteArray {
        val deflater = Deflater(Deflater.DEFAULT_COMPRESSION, nowrap)
        deflater.setInput(data)
        deflater.finish()
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        while (!deflater.finished()) {
            out.write(buffer, 0, deflater.deflate(buffer))
        }
        deflater.end()
        return out.toByteArray()
    }
    @Test
    fun `an entry width is read exactly or not at all`() {
        // `bits` decides how the list is carved up, and it comes from the
        // Status List Token - not this wallet's to trust before verification.
        // Truncating 1.5 to 1 is worse than rejecting it: it passes the
        // legal-width check and then reads the wrong credential's status.
        val client = TokenStatusListClient(httpGet = { _, _ -> null })
        assertEquals(1, client.exactEntryWidth(1))
        assertEquals(8, client.exactEntryWidth(8L))
        assertEquals(2, client.exactEntryWidth(2.0))
        assertEquals(4, client.exactEntryWidth(java.math.BigInteger.valueOf(4)))

        assertNull(client.exactEntryWidth(1.5))
        assertNull(client.exactEntryWidth(Double.NaN))
        assertNull(client.exactEntryWidth(Double.POSITIVE_INFINITY))
        assertNull(client.exactEntryWidth("8"))
        assertNull(client.exactEntryWidth(null))
        assertNull(client.exactEntryWidth(Long.MAX_VALUE))
    }
}
