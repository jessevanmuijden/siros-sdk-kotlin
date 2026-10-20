package org.siros.sdk.wallet

import com.upokecenter.cbor.CBORObject
import java.security.MessageDigest
import java.util.Base64

/** Builders for nym_auth-shaped credentials carrying an `ssc`, for tests of delivered-seed receipt. */
internal object NymTestCredentials {
    const val DOCTYPE = "eu.europa.ec.eudi.nym_auth.1"
    val seed = ByteArray(16) { (it * 17).toByte() }
    val seedHex = seed.joinToString("") { "%02x".format(it) }
    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
    val goodSsc = sha256(seed)
    val wrongSsc = sha256(ByteArray(16) { 1 })
    fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun b64(b: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    private fun b64(s: String) = b64(s.toByteArray(Charsets.UTF_8))

    /** A compact SD-JWT VC; [sscValues] are the `ssc` disclosures to carry (each a claim value). */
    fun sdJwt(
        sscValues: List<String> = listOf(hex(goodSsc)),
        referenceInSd: Boolean = true,
        sscInClear: String? = null,
        exp: Long = 9999999999L,
    ): String {
        val disclosures = sscValues.mapIndexed { i, v -> b64("""["salt$i","ssc","$v"]""") }
        val digests = disclosures.map { b64(sha256(it.toByteArray(Charsets.UTF_8))) }
        val sd = if (referenceInSd) digests.joinToString(",") { "\"$it\"" } else ""
        val clear = if (sscInClear != null) ""","ssc":"$sscInClear"""" else ""
        val payload = """{"vct":"urn:nym","iat":1700000000,"exp":$exp,"_sd":[$sd]$clear}"""
        return b64("""{"alg":"none"}""") + "." + b64(payload) + ".sig~" + disclosures.joinToString("~") + (if (disclosures.isEmpty()) "" else "~")
    }

    private fun cbor(o: Any) = CBORObject.FromObject(o)

    private fun item(id: Int, name: String, value: CBORObject): CBORObject {
        val m = CBORObject.NewMap()
        m[cbor("digestID")] = cbor(id.toLong())
        m[cbor("random")] = cbor(ByteArray(16))
        m[cbor("elementIdentifier")] = cbor(name)
        m[cbor("elementValue")] = value
        return CBORObject.FromObjectAndTag(m.EncodeToBytes(), 24)
    }

    /** A stored mdoc credential, base64url CBOR, with `ssc` elements [sscValues] in [namespace]. */
    fun mdoc(sscValues: List<CBORObject> = listOf(cbor(goodSsc)), namespace: String = DOCTYPE): String {
        val items = CBORObject.NewArray()
        items.Add(item(0, "birth_date", CBORObject.FromObjectAndTag("2000-06-15", 1004)))
        sscValues.forEachIndexed { i, v -> items.Add(item(10 + i, "ssc", v)) }
        val ns = CBORObject.NewMap()
        ns[cbor(namespace)] = items
        val mso = CBORObject.NewMap()
        mso[cbor("docType")] = cbor(DOCTYPE)
        val auth = CBORObject.NewArray()
        auth.Add(cbor(ByteArray(0)))
        auth.Add(CBORObject.NewMap())
        auth.Add(cbor(CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()))
        auth.Add(cbor(ByteArray(64)))
        val signed = CBORObject.NewMap()
        signed[cbor("nameSpaces")] = ns
        signed[cbor("issuerAuth")] = auth
        return b64(signed.EncodeToBytes())
    }

    fun bstr(b: ByteArray): CBORObject = cbor(b)
    fun text(s: String): CBORObject = cbor(s)
}
