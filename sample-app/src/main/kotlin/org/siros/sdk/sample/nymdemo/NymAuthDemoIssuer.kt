// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.nymdemo

import com.upokecenter.cbor.CBORObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

/**
 * A throw-away demo issuer for the `eu.europa.ec.eudi.nym_auth.1` mdoc, so the
 * demo screen has a credential to present without a real issuer.
 *
 * NOT AN ISSUER: the signing key below is public, committed, and exists only
 * so the fixture is a well-formed mdoc. Nothing may trust it.
 *
 * The output follows the rulebook's compact profile: only the data elements
 * the credential carries, 16-byte random values, digestIDs sequential from 0,
 * a MSO with no optional members, tdate values of the form
 * YYYY-MM-DDTHH:MM:SSZ, a P-256 device key and a P-256 Document Signer key.
 * The result is a bare IssuerSigned structure, which the SDK's stored
 * credential parser accepts.
 */
object NymAuthDemoIssuer {
    const val DOC_TYPE = "eu.europa.ec.eudi.nym_auth.1"

    /** The demo issuer's Credential Issuer Identifier: the holder's private seed (and psc) is per issuer. */
    const val ISSUER = "https://nym-demo-issuer.example"
    private const val SECRET_SEED_BYTES = 16

    // PKCS#8 P-256 private key and self-signed certificate of the demo
    // "issuer". Public by design - see the class comment.
    private const val DEMO_KEY_PKCS8 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/BD3hi8XFHKZOfrzJt1pEKUK8PObZ2hMptGeMHdOsRWhRANCAATSo8ReXz5Vgs5AJP+PDhhPx+WKtc+8Dk4TtrgwfqbjhQqkx361f617J9Ae6v+nzG15s96opIkDoi4rxD3HvOAd"
    private const val DEMO_CERT_DER = "MIIByTCCAW+gAwIBAgIUa8LLf/PY/DM76o0ksvITEUxd7I4wCgYIKoZIzj0EAwIwOjE4MDYGA1UEAwwvU0lST1MgbnltX2F1dGggZGVtbyBpc3N1ZXIgKE5PVCBGT1IgUFJPRFVDVElPTikwHhcNMjYxMDEzMjIyMzEzWhcNMzYxMDEwMjIyMzEzWjA6MTgwNgYDVQQDDC9TSVJPUyBueW1fYXV0aCBkZW1vIGlzc3VlciAoTk9UIEZPUiBQUk9EVUNUSU9OKTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNKjxF5fPlWCzkAk/48OGE/H5Yq1z7wOThO2uDB+puOFCqTHfrV/rXsn0B7q/6fMbXmz3qikiQOiLivEPce84B2jUzBRMB0GA1UdDgQWBBSTR50pC2S3SkRC8J2NFGH5yWDEyjAfBgNVHSMEGDAWgBSTR50pC2S3SkRC8J2NFGH5yWDEyjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCb5k9k5eScHBSdBZgei5/ia5O5gIYMzbTsKxVBjPCs7gIgMrvxOiTK63I5uF7jJaypxXiubng7e2VNjSnbU1/anMg="

    private val random = SecureRandom()
    private val tdate = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC)

    /** The demo Document Signer certificate, DER. */
    val certificateDer: ByteArray by lazy { Base64.getDecoder().decode(DEMO_CERT_DER) }

    private val signingKey: PrivateKey by lazy {
        KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(DEMO_KEY_PKCS8)))
    }

    /** A fresh software P-256 device key pair; the demo has no secure element. */
    fun newDeviceKey(): java.security.KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    /** A fresh random 16-byte `secret_seed`, as the rulebook's issuer would generate and deliver it. */
    fun newSecretSeed(): ByteArray = ByteArray(SECRET_SEED_BYTES).also(random::nextBytes)

    /** The `ssc` that commits to [secretSeed]: `SHA256(secret_seed)`. */
    fun commitmentTo(secretSeed: ByteArray): ByteArray {
        require(secretSeed.size == SECRET_SEED_BYTES) { "secret_seed must be $SECRET_SEED_BYTES bytes" }
        return MessageDigest.getInstance("SHA-256").digest(secretSeed)
    }

    /**
     * @param birthDate ISO full-date, e.g. `2000-01-31`
     * @param ssc 32-byte issuer seed commitment, `SHA256(secret_seed)` (see [commitmentTo]); the demo
     *   delivers the seed to the wallet out of band, through the presenter request
     * @param psc 32-byte holder seed commitment, or null to leave it out
     */
    fun issue(birthDate: String, ssc: ByteArray, psc: ByteArray?, deviceKey: ECPublicKey, now: Instant = Instant.now()): ByteArray {
        require(ssc.size == 32) { "ssc must be 32 bytes" }
        require(psc == null || psc.size == 32) { "psc must be 32 bytes" }

        val elements = buildList {
            add("birth_date" to CBORObject.FromObjectAndTag(birthDate, 1004))
            add("ssc" to CBORObject.FromObject(ssc))
            if (psc != null) add("psc" to CBORObject.FromObject(psc))
        }

        val items = CBORObject.NewArray()
        val digests = CBORObject.NewMap()
        elements.forEachIndexed { index, (name, value) ->
            val item = CBORObject.NewMap()
                .Add("digestID", index)
                .Add("random", ByteArray(16).also(random::nextBytes))
                .Add("elementIdentifier", name)
                .Add("elementValue", value)
            // IssuerSignedItemBytes: tag 24 over the encoded item. The digest is over the
            // encoding of that tagged value, not over the bare item.
            val tagged = CBORObject.FromObjectAndTag(item.EncodeToBytes(), 24)
            items.Add(tagged)
            digests.Add(index, MessageDigest.getInstance("SHA-256").digest(tagged.EncodeToBytes()))
        }

        val x = unsigned32(deviceKey.w.affineX)
        val y = unsigned32(deviceKey.w.affineY)
        val coseKey = CBORObject.NewMap().Add(1, 2).Add(-1, 1).Add(-2, x).Add(-3, y)

        val mso = CBORObject.NewMap()
            .Add("version", "1.0")
            .Add("digestAlgorithm", "SHA-256")
            .Add("valueDigests", CBORObject.NewMap().Add(DOC_TYPE, digests))
            .Add("deviceKeyInfo", CBORObject.NewMap().Add("deviceKey", coseKey))
            .Add("docType", DOC_TYPE)
            .Add(
                "validityInfo",
                CBORObject.NewMap()
                    .Add("signed", CBORObject.FromObjectAndTag(tdate.format(now), 0))
                    .Add("validFrom", CBORObject.FromObjectAndTag(tdate.format(now), 0))
                    .Add("validUntil", CBORObject.FromObjectAndTag(tdate.format(now.plusSeconds(365L * 24 * 3600)), 0)),
            )
        val payload = CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()

        // COSE_Sign1 with the exact protected header {1: -7} and x5chain (33) unprotected.
        val protectedHeader = CBORObject.NewMap().Add(1, -7).EncodeToBytes()
        val sigStructure = CBORObject.NewArray()
            .Add("Signature1")
            .Add(protectedHeader)
            .Add(ByteArray(0))
            .Add(payload)
            .EncodeToBytes()
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(signingKey)
            update(sigStructure)
            derToRaw(sign())
        }
        val issuerAuth = CBORObject.NewArray()
            .Add(protectedHeader)
            .Add(CBORObject.NewMap().Add(33, certificateDer))
            .Add(payload)
            .Add(signature)

        val issuerSigned = CBORObject.NewMap()
            .Add("nameSpaces", CBORObject.NewMap().Add(DOC_TYPE, items))
            .Add("issuerAuth", issuerAuth)
        return issuerSigned.EncodeToBytes()
    }

    private fun unsigned32(v: java.math.BigInteger): ByteArray {
        val raw = v.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32 -> raw.copyOfRange(raw.size - 32, raw.size)
            else -> ByteArray(32 - raw.size) + raw
        }
    }

    /** ASN.1 DER ECDSA signature to the raw r||s form COSE uses. */
    private fun derToRaw(der: ByteArray): ByteArray {
        var i = 2
        if (der[1].toInt() and 0x80 != 0) i = 2 + (der[1].toInt() and 0x7f)
        require(der[i].toInt() == 0x02) { "malformed ECDSA signature" }
        val rLen = der[i + 1].toInt() and 0xff
        val r = der.copyOfRange(i + 2, i + 2 + rLen)
        val sOff = i + 2 + rLen
        require(der[sOff].toInt() == 0x02) { "malformed ECDSA signature" }
        val sLen = der[sOff + 1].toInt() and 0xff
        val s = der.copyOfRange(sOff + 2, sOff + 2 + sLen)
        return unsigned32(java.math.BigInteger(1, r)) + unsigned32(java.math.BigInteger(1, s))
    }
}
