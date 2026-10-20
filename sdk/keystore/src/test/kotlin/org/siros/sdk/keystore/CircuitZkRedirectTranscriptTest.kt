package org.siros.sdk.keystore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** The redirect (OpenID4VP QR) handover of a `circuit_zk` presentation. */
class CircuitZkRedirectTranscriptTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    // The OpenID4VP 1.0 B.2.6.1 non-normative example, as pinned by the shared nymauth challenge vectors
    // (zk-cred-vega test-vectors/nymauth/challenge-vectors.json, derive_redirect[0]).
    private val clientId = "x509_san_dns:example.com"
    private val nonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"
    private val responseUri = "https://example.com/response"
    private val thumbprint = java.util.Base64.getUrlEncoder().withoutPadding()
        .encodeToString(unhex("4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"))
    private val expected = "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"

    @Test
    fun theSpecExampleTranscriptIsReproduced() {
        assertEquals(expected, hex(MdocDeviceResponseBuilder.buildCircuitZkRedirectSessionTranscript(clientId, nonce, responseUri, thumbprint)))
    }

    @Test
    fun theThumbprintIsRequiredAndThirtyTwoBytes() {
        val short = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(31))
        val long = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(33))
        for (bad in listOf("", short, long, "$thumbprint=", thumbprint.replace('-', '+').replace('_', '/') + "+", "not base64!")) {
            assertThrows(bad, IllegalArgumentException::class.java) {
                MdocDeviceResponseBuilder.buildCircuitZkRedirectSessionTranscript(clientId, nonce, responseUri, bad)
            }
        }
    }

    @Test
    fun aRedirectTranscriptIsNotTheDcApiOne() {
        val dcapi = MdocDeviceResponseBuilder.buildDCAPISessionTranscript("https://example.com", nonce, thumbprint)
        assertEquals(false, hex(dcapi) == expected)
    }
}
