// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORObject
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.siros.sdk.credentials.interop.TokenStatusList
import java.util.Base64

/**
 * An mdoc's validity window and Token Status List reference come out of the
 * MSO, which is credential content: attacker-supplied until it has been
 * verified, and read here before that.
 */
class MdocValidityClaimsTest {

    /**
     * A bare `IssuerSigned` whose MSO carries `validityInfo` and the given
     * `status.status_list`. Not signed - nothing on this path verifies the
     * signature, which is the point: these bytes are read first.
     */
    private fun credential(statusListIdx: CBORObject): StoredCredential {
        val statusList = CBORObject.NewMap()
        statusList[CBORObject.FromObject("idx")] = statusListIdx
        statusList[CBORObject.FromObject("uri")] =
            CBORObject.FromObject("https://issuer.example/statuslists/1")
        val status = CBORObject.NewMap()
        status[CBORObject.FromObject("status_list")] = statusList

        val validity = CBORObject.NewMap()
        validity[CBORObject.FromObject("validFrom")] =
            CBORObject.FromObjectAndTag("2026-01-01T00:00:00Z", 0)
        validity[CBORObject.FromObject("validUntil")] =
            CBORObject.FromObjectAndTag("2027-01-01T00:00:00Z", 0)

        val mso = CBORObject.NewMap()
        mso[CBORObject.FromObject("docType")] = CBORObject.FromObject("org.iso.18013.5.1.mDL")
        mso[CBORObject.FromObject("validityInfo")] = validity
        mso[CBORObject.FromObject("status")] = status

        val issuerAuth = CBORObject.NewArray()
        issuerAuth.Add(CBORObject.FromObject(ByteArray(0)))
        issuerAuth.Add(CBORObject.NewMap())
        issuerAuth.Add(CBORObject.FromObject(CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()))
        issuerAuth.Add(CBORObject.FromObject(ByteArray(64)))

        val issuerSigned = CBORObject.NewMap()
        issuerSigned[CBORObject.FromObject("nameSpaces")] = CBORObject.NewMap()
        issuerSigned[CBORObject.FromObject("issuerAuth")] = issuerAuth

        return StoredCredential(
            id = 1,
            format = "mso_mdoc",
            raw = Base64.getUrlEncoder().withoutPadding().encodeToString(issuerSigned.EncodeToBytes()),
            batchId = 1,
            instanceId = 0,
        )
    }

    private fun statusList(claims: JsonObject) =
        claims["status"]?.jsonObject?.get("status_list")?.jsonObject

    @Test
    fun `a status list reference is read from the MSO`() {
        val claims = CredentialUtils.validityClaims(credential(CBORObject.FromObject(7)))
        assertNotNull(claims)
        assertEquals("2026-01-01T00:00:00Z", claims!!["validFrom"]?.jsonPrimitive?.content)
        val reference = statusList(claims)
        assertNotNull(reference)
        assertEquals(7, reference!!["idx"]?.jsonPrimitive?.content?.toInt())
        assertEquals("https://issuer.example/statuslists/1", reference["uri"]?.jsonPrimitive?.content)
    }

    @Test
    fun `an index past Int MAX_VALUE is not read rather than discarding everything`() {
        // AsInt32 throws on this, which would otherwise take the whole
        // credential's validity claims with it - including the validity
        // window, which has nothing to do with the bad index. A status list
        // with that many entries does not exist; the index is simply not
        // read, which leaves the reference incomplete and the status
        // unavailable.
        val claims = CredentialUtils.validityClaims(credential(CBORObject.FromObject(Long.MAX_VALUE)))
        assertNotNull(claims)
        assertEquals("2026-01-01T00:00:00Z", claims!!["validFrom"]?.jsonPrimitive?.content)
        assertNull(statusList(claims)!!["idx"])
        assertNull(TokenStatusList.extractReference(claims))
    }
}
