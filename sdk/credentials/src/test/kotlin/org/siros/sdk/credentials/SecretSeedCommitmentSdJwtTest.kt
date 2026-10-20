package org.siros.sdk.credentials

import java.security.MessageDigest
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The SD-JWT reader of `ssc`: only the top-level, sha-256-bound disclosure counts. */
class SecretSeedCommitmentSdJwtTest {
    private val ssc = "ab".repeat(32)
    private val other = "cd".repeat(32)

    private fun b64(s: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray(Charsets.UTF_8))
    private fun digest(d: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(d.toByteArray(Charsets.UTF_8)))

    /** A compact SD-JWT whose payload is `{"_sd":[topDigests],<extra>}` and which carries [disclosures]. */
    private fun jwt(topReferenced: List<String>, disclosures: List<String>, extra: String = ""): String {
        val sd = topReferenced.joinToString(",") { "\"${digest(it)}\"" }
        val payload = """{"vct":"urn:nym","_sd":[$sd]$extra}"""
        return b64("""{"alg":"none"}""") + "." + b64(payload) + ".sig~" + disclosures.joinToString("~") + "~"
    }

    private val top = b64("""["s0","ssc","$ssc"]""")
    private val nested = b64("""["s1","ssc","$other"]""")

    @Test
    fun theTopLevelDisclosureIsRead() {
        assertArrayEquals(ByteArray(32) { 0xab.toByte() }, SecretSeedCommitment.sscOfSdJwt(jwt(listOf(top), listOf(top))))
    }

    @Test
    fun aNestedSameNamedDisclosureIsIgnored() {
        // `nested` is referenced from a nested object's _sd (not the top-level one) and sits beside the real one.
        val credential = jwt(listOf(top), listOf(nested, top), extra = ""","address":{"_sd":["${digest(nested)}"]}""")
        assertArrayEquals(ByteArray(32) { 0xab.toByte() }, SecretSeedCommitment.sscOfSdJwt(credential))
    }

    @Test
    fun aNestedSscDisclosureAloneIsNotTheTopLevelClaim() {
        val credential = jwt(emptyList(), listOf(nested), extra = ""","address":{"_sd":["${digest(nested)}"]}""")
        assertNull(SecretSeedCommitment.sscOfSdJwt(credential))
    }

    @Test
    fun twoReferencedTopLevelDisclosuresAreRefused() {
        assertNull(SecretSeedCommitment.sscOfSdJwt(jwt(listOf(top, nested), listOf(top, nested))))
    }

    @Test
    fun aNonSha256SdAlgFailsClosed() {
        assertNull(SecretSeedCommitment.sscOfSdJwt(jwt(listOf(top), listOf(top), extra = ""","_sd_alg":"sha-512"""")))
        assertNull(SecretSeedCommitment.sscOfSdJwt(jwt(listOf(top), listOf(top), extra = ""","_sd_alg":"SHA-256"""")))
        assertNull(SecretSeedCommitment.sscOfSdJwt(jwt(listOf(top), listOf(top), extra = ""","_sd_alg":256""")))
    }

    @Test
    fun sha256SdAlgIsAccepted() {
        assertArrayEquals(ByteArray(32) { 0xab.toByte() }, SecretSeedCommitment.sscOfSdJwt(jwt(listOf(top), listOf(top), extra = ""","_sd_alg":"sha-256"""")))
    }
}
