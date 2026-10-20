package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORObject
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The policy table and the claim-level enforcement points in `credentials`: matching, display, blob claims. */
class NonDisclosureTest {
    private val nym = NonDisclosurePolicy.NYM_AUTH_DOCTYPE
    private val json = Json { ignoreUnknownKeys = true }

    @After
    fun resetPolicy() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy.DEFAULT
    }

    private fun item(id: Long, name: String, value: CBORObject): CBORObject {
        val m = CBORObject.NewMap()
        m[CBORObject.FromObject("digestID")] = CBORObject.FromObject(id)
        m[CBORObject.FromObject("random")] = CBORObject.FromObject(ByteArray(16))
        m[CBORObject.FromObject("elementIdentifier")] = CBORObject.FromObject(name)
        m[CBORObject.FromObject("elementValue")] = value
        return CBORObject.FromObjectAndTag(m.EncodeToBytes(), 24)
    }

    private fun mdocRaw(docType: String): String {
        val items = CBORObject.NewArray()
        items.Add(item(0, "birth_date", CBORObject.FromObjectAndTag("2000-06-15", 1004)))
        items.Add(item(1, "ssc", CBORObject.FromObject(ByteArray(32) { 1 })))
        items.Add(item(2, "psc", CBORObject.FromObject(ByteArray(32) { 2 })))
        items.Add(item(3, "given_name", CBORObject.FromObject("Jane")))
        val ns = CBORObject.NewMap()
        ns[CBORObject.FromObject(docType)] = items
        val mso = CBORObject.NewMap()
        mso[CBORObject.FromObject("docType")] = CBORObject.FromObject(docType)
        val auth = CBORObject.NewArray()
        auth.Add(CBORObject.FromObject(ByteArray(0)))
        auth.Add(CBORObject.NewMap())
        auth.Add(CBORObject.FromObject(CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()))
        auth.Add(CBORObject.FromObject(ByteArray(64)))
        val signed = CBORObject.NewMap()
        signed[CBORObject.FromObject("nameSpaces")] = ns
        signed[CBORObject.FromObject("issuerAuth")] = auth
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signed.EncodeToBytes())
    }

    private fun mdoc(docType: String, id: Long = 1) =
        StoredCredential(id = id, format = "mso_mdoc", raw = mdocRaw(docType), batchId = id, instanceId = 0)

    private fun sdJwt(vct: String, vararg claims: Pair<String, String>): StoredCredential {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val disclosures = claims.mapIndexed { i, (n, v) -> enc.encodeToString("""["salt$i","$n","$v"]""".toByteArray()) }
        val digests = disclosures.joinToString(",") { "\"" + enc.encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(it.toByteArray())) + "\"" }
        val payload = enc.encodeToString("""{"vct":"$vct","_sd":[$digests],"_sd_alg":"sha-256"}""".toByteArray())
        val raw = "${enc.encodeToString("""{"alg":"ES256"}""".toByteArray())}.$payload.c2ln~" + disclosures.joinToString("~") + "~"
        return StoredCredential(id = 5, format = "dc+sd-jwt", raw = raw, batchId = 5, instanceId = 0)
    }

    private fun query(format: String, doctypeOrVct: String, vararg paths: String): JsonObject {
        val meta = if (format == "mso_mdoc") """"doctype_value":"$doctypeOrVct"""" else """"vct_values":["$doctypeOrVct"]"""
        val claims = paths.joinToString(",") { p ->
            val segs = if (format == "mso_mdoc") listOf(doctypeOrVct, p) else listOf(p)
            """{"path":[${segs.joinToString(",") { "\"$it\"" }}]}"""
        }
        return json.parseToJsonElement(
            """{"credentials":[{"id":"q","format":"$format","meta":{$meta}${if (paths.isEmpty()) "" else ""","claims":[$claims]"""}}]}"""
        ).jsonObject
    }

    // ---- the policy table ----

    @Test
    fun `the default data protects ssc, psc, secret_seed and birth_date of a nym_auth attestation and nothing else`() {
        val p = NonDisclosurePolicy.DEFAULT
        val bbs = NonDisclosurePolicy.NYM_AUTH_BBS_TYPE
        assertEquals(setOf(nym, bbs), p.types)
        for (type in listOf(nym, bbs)) {
            for (element in listOf("ssc", "psc", "secret_seed", "birth_date")) assertTrue("$type $element", p.isProtected(type, listOf(type, element)))
        }
        // birth_date of any OTHER credential is an ordinary claim.
        assertFalse(p.isProtected("eu.europa.ec.eudi.pid.1", listOf("eu.europa.ec.eudi.pid.1", "birth_date")))
        assertFalse(p.isProtected(nym, listOf(nym, "given_name")))
        assertFalse(p.isProtected("other.doctype", listOf("other.doctype", "ssc")))
        assertFalse(p.isProtected(null, listOf(nym, "ssc")))
        assertFalse(NonDisclosurePolicy.NONE.isProtected(nym, listOf(nym, "ssc")))
    }

    @Test
    fun `a protected path covers what is below it, and a request for an ancestor reaches it`() {
        val p = NonDisclosurePolicy(mapOf("t" to setOf(listOf("a", "b"))))
        assertTrue(p.isProtected("t", listOf("a", "b")))
        assertTrue(p.isProtected("t", listOf("a", "b", "c")))
        assertFalse(p.isProtected("t", listOf("a")))
        assertFalse(p.isProtected("t", listOf("a", "x")))
        assertTrue(p.requestsProtected("t", listOf(listOf("a", "b"))))
        assertTrue(p.requestsProtected("t", listOf(listOf("a", "b", "c"))))
        assertTrue(p.requestsProtected("t", listOf(listOf("a"))))
        assertTrue(p.requestsProtected("t", listOf(emptyList())))
        assertFalse(p.requestsProtected("t", listOf(listOf("a", "x"), listOf("z"))))
        assertFalse(p.requestsProtected("other", listOf(listOf("a", "b"))))
    }

    @Test
    fun `the table is data, so another type is another entry`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("secret"))))
        assertTrue(CredentialDisclosureGuard.isProtected("my.vct", listOf("secret")))
        assertFalse(CredentialDisclosureGuard.isProtected(nym, listOf(nym, "ssc")))
    }

    @Test
    fun `a wallet registering a looser policy cannot weaken one that registered a stricter policy`() {
        val strict = Any()
        val loose = Any()
        CredentialDisclosureGuard.register(strict, NonDisclosurePolicy.DEFAULT)
        CredentialDisclosureGuard.register(loose, NonDisclosurePolicy.NONE)
        assertTrue(CredentialDisclosureGuard.isProtected(nym, listOf(nym, "ssc")))
        assertTrue(CredentialDisclosureGuard.isProtected(nym, listOf(nym, "psc")))
        // Order does not matter, and the union covers both tables.
        val other = Any()
        CredentialDisclosureGuard.register(other, NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("secret")))))
        assertTrue(CredentialDisclosureGuard.isProtected("my.vct", listOf("secret")))
        assertTrue(CredentialDisclosureGuard.isProtected(nym, listOf(nym, "ssc")))
        // Dropping the strict wallet lifts only what it alone asked for.
        CredentialDisclosureGuard.unregister(strict)
        assertFalse(CredentialDisclosureGuard.isProtected(nym, listOf(nym, "ssc")))
        assertTrue(CredentialDisclosureGuard.isProtected("my.vct", listOf("secret")))
    }

    @Test
    fun `a single registration is in force as itself, and assigning policy replaces every registration`() {
        val owner = Any()
        CredentialDisclosureGuard.register(owner, NonDisclosurePolicy.NONE)
        assertSame(NonDisclosurePolicy.NONE, CredentialDisclosureGuard.policy)
        CredentialDisclosureGuard.policy = NonDisclosurePolicy.DEFAULT
        assertSame(NonDisclosurePolicy.DEFAULT, CredentialDisclosureGuard.policy)
        // The earlier registration no longer takes part.
        CredentialDisclosureGuard.register(Any(), NonDisclosurePolicy.DEFAULT)
        assertTrue(CredentialDisclosureGuard.isProtected(nym, listOf(nym, "ssc")))
    }

    // ---- enforcement point 1: matching ----

    @Test
    fun `a query for ssc, psc or birth_date matches nothing, a query for another claim matches`() {
        val cred = mdoc(nym)
        assertTrue(CredentialMatcher.match(query("mso_mdoc", nym, "ssc"), listOf(cred)).single().candidates.isEmpty())
        assertTrue(CredentialMatcher.match(query("mso_mdoc", nym, "psc"), listOf(cred)).single().candidates.isEmpty())
        assertTrue(CredentialMatcher.match(query("mso_mdoc", nym, "birth_date", "ssc"), listOf(cred)).single().candidates.isEmpty())
        assertTrue(CredentialMatcher.match(query("mso_mdoc", nym, "birth_date"), listOf(cred)).single().candidates.isEmpty())
        assertEquals(1, CredentialMatcher.match(query("mso_mdoc", nym, "given_name"), listOf(cred)).single().candidates.size)
        // A claimless query asks for the whole attestation, which includes protected claims: no match.
        assertTrue(CredentialMatcher.match(query("mso_mdoc", nym), listOf(cred)).single().candidates.isEmpty())
    }

    @Test
    fun `a legacy zk query for a protected claim matches nothing either`() {
        val q = json.parseToJsonElement(
            """{"credentials":[{"id":"q","format":"mso_mdoc_zk","meta":{"source_format":"mso_mdoc","doctype_value":"$nym"},"claims":[{"path":["$nym","ssc"]}]}]}"""
        ).jsonObject
        assertTrue(CredentialMatcher.match(q, listOf(mdoc(nym))).single().candidates.isEmpty())
    }

    @Test
    fun `a type without a policy entry is unaffected`() {
        val other = mdoc("other.doctype")
        assertEquals(1, CredentialMatcher.match(query("mso_mdoc", "other.doctype", "ssc"), listOf(other)).single().candidates.size)
        assertEquals(4, CredentialUtils.extractClaims(other).size)
        assertEquals(4, SharedDcqlMatcher.buildFfiClaims(other).size)
    }

    @Test
    fun `an sd-jwt vct with a policy entry is protected the same way`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("secret"))))
        val c = sdJwt("my.vct", "secret" to "s", "name" to "Jane")
        assertTrue(CredentialMatcher.match(query("dc+sd-jwt", "my.vct", "secret"), listOf(c)).single().candidates.isEmpty())
        assertEquals(1, CredentialMatcher.match(query("dc+sd-jwt", "my.vct", "name"), listOf(c)).single().candidates.size)
        val shown = CredentialUtils.extractClaims(c).map { it.key }
        assertFalse("secret" in shown)
        assertTrue("name" in shown)
        assertFalse(CredentialUtils.flattenClaimPaths(c).any { it.first == listOf("secret") })
        assertTrue(CredentialUtils.flattenClaimPaths(c).any { it.first == listOf("name") })
        assertTrue(SharedDcqlMatcher.buildFfiClaims(c).none { it.path == listOf("secret") })
        assertTrue(SharedDcqlMatcher.buildFfiClaims(c).any { it.path == listOf("name") })
        // Another vct is unaffected.
        val d = sdJwt("another.vct", "secret" to "s")
        assertEquals(1, CredentialMatcher.match(query("dc+sd-jwt", "another.vct", "secret"), listOf(d)).single().candidates.size)
    }

    // ---- enforcement points 2 and 4: the blob's claims, display ----

    @Test
    fun `no protected claim is registered, listed or displayed`() {
        val cred = mdoc(nym)
        val displayed = CredentialUtils.extractClaims(cred)
        assertEquals(setOf("$nym.given_name"), displayed.map { it.key }.toSet())
        for (c in displayed) {
            assertFalse(c.value.contains("0101") && c.key.endsWith("ssc"))
        }
        assertEquals(displayed.map { it.key }, CredentialUtils.extractMdocClaims(cred).map { it.key })
        val ffi = SharedDcqlMatcher.buildFfiClaims(cred)
        assertEquals(setOf(listOf(nym, "given_name")), ffi.map { it.path }.toSet())
        assertTrue(ffi.none { f -> f.path.last() == "ssc" || f.path.last() == "psc" || f.path.last() == "birth_date" })
    }

    // ---- the guard's own failure ----

    @Test
    fun `a presentation of a protected element is refused, and the refusal names no claim`() {
        val e = assertThrows(DisclosureRefusedException::class.java) {
            CredentialDisclosureGuard.requireNoneProtected(nym, mapOf(nym to listOf("given_name", "ssc")))
        }
        assertFalse(e.message!!.contains("ssc"))
        assertThrows(DisclosureRefusedException::class.java) {
            CredentialDisclosureGuard.requireNoneProtected(nym, mapOf(nym to listOf("birth_date")))
        }
        CredentialDisclosureGuard.requireNoneProtected(nym, mapOf(nym to listOf("given_name")))
        CredentialDisclosureGuard.requireNoneProtected("other.doctype", mapOf("other.doctype" to listOf("ssc")))
    }

    @Test
    fun `an sd-jwt presentation with a protected disclosure is refused`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("secret"))))
        val c = sdJwt("my.vct", "secret" to "s", "name" to "Jane")
        val parts = c.raw.split("~").filter { it.isNotEmpty() }
        val disclosures = parts.drop(1)
        assertThrows(DisclosureRefusedException::class.java) { CredentialDisclosureGuard.requireNoneProtectedSdJwt(c.raw, disclosures) }
        CredentialDisclosureGuard.requireNoneProtectedSdJwt(c.raw, disclosures.drop(1))
        // An unreadable disclosure could be anything, so it is refused too.
        assertThrows(DisclosureRefusedException::class.java) { CredentialDisclosureGuard.requireNoneProtectedSdJwt(c.raw, listOf("!!")) }
        CredentialDisclosureGuard.requireNoneProtectedSdJwt(sdJwt("other.vct", "secret" to "s").raw, listOf(parts[1]))
    }

    // ---- ancestors of a protected nested path ----

    private fun b64(s: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray())
    private fun digest(d: String) =
        Base64.getUrlEncoder().withoutPadding().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(d.toByteArray()))

    /** vct + a selectively disclosable `address` object holding selectively disclosable `secret` and `street`, and a top-level `secret`. */
    private class Nested(val raw: String, val address: String, val secret: String, val street: String, val topSecret: String)

    private fun nestedSdJwt(vct: String): Nested {
        val secret = b64("""["s1","secret","hush"]""")
        val street = b64("""["s2","street","Main St"]""")
        val address = b64("""["s3","address",{"_sd":["${digest(secret)}","${digest(street)}"]}]""")
        val topSecret = b64("""["s4","secret","top"]""")
        val payload = b64("""{"vct":"$vct","_sd":["${digest(address)}","${digest(topSecret)}"],"_sd_alg":"sha-256"}""")
        val raw = "${b64("""{"alg":"ES256"}""")}.$payload.c2ln~$address~$secret~$street~$topSecret~"
        return Nested(raw, address, secret, street, topSecret)
    }

    @Test
    fun `a protected path whose segment contains a dot is neither displayed nor registered`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("a.b", "secret"))))
        val payload = b64("""{"vct":"my.vct","a.b":{"secret":"hush","ok":"fine"}}""")
        val raw = "${b64("""{"alg":"ES256"}""")}.$payload.c2ln~"
        val c = StoredCredential(
            id = 8, format = "dc+sd-jwt", raw = raw, batchId = 8, instanceId = 0,
            metadata = CredentialMetadata(
                vct = "my.vct",
                claims = listOf(ClaimMeta(path = listOf("a.b", "secret")), ClaimMeta(path = listOf("a.b", "ok"))),
            ),
        )
        val shown = CredentialUtils.extractClaims(c)
        assertFalse(shown.any { it.value == "hush" })
        assertTrue(shown.any { it.value == "fine" })
        assertTrue(SharedDcqlMatcher.buildFfiClaims(c).none { it.value == "hush" })
        assertTrue(SharedDcqlMatcher.buildFfiClaims(c).any { it.value == "fine" })
    }

    @Test
    fun `an object holding a protected nested sd-jwt claim is not displayed or matched`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("address", "secret"))))
        val n = nestedSdJwt("my.vct")
        val c = StoredCredential(id = 7, format = "dc+sd-jwt", raw = n.raw, batchId = 7, instanceId = 0)
        assertFalse(CredentialUtils.extractClaims(c).any { it.key == "address" })
        assertTrue(CredentialUtils.extractClaims(c).any { it.key == "secret" })
        val paths = CredentialUtils.flattenClaimPaths(c).map { it.first }
        assertFalse(paths.contains(listOf("address")))
        assertFalse(paths.contains(listOf("address", "secret")))
        assertTrue(paths.contains(listOf("address", "street")))
        assertTrue(paths.contains(listOf("secret")))
    }

    @Test
    fun `an sd-jwt presentation refuses a disclosure that is a protected path or an ancestor of one`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("address", "secret"))))
        val n = nestedSdJwt("my.vct")
        // The ancestor: the address object would carry the digest of address.secret.
        assertThrows(DisclosureRefusedException::class.java) { CredentialDisclosureGuard.requireNoneProtectedSdJwt(n.raw, listOf(n.address)) }
        // The protected path itself, named only "secret" inside address.
        assertThrows(DisclosureRefusedException::class.java) { CredentialDisclosureGuard.requireNoneProtectedSdJwt(n.raw, listOf(n.secret)) }
        // Not protected: a sibling, and a top-level claim that merely shares the name.
        CredentialDisclosureGuard.requireNoneProtectedSdJwt(n.raw, listOf(n.street, n.topSecret))
    }

    /** A compact SD-JWT whose issuer payload is [payloadJson] verbatim, with no disclosures. */
    private fun cleartextSdJwt(payloadJson: String): StoredCredential {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val raw = "${enc.encodeToString("""{"alg":"ES256"}""".toByteArray())}.${enc.encodeToString(payloadJson.toByteArray())}.c2ln~"
        return StoredCredential(id = 9, format = "dc+sd-jwt", raw = raw, batchId = 9, instanceId = 0)
    }

    @Test
    fun `a protected claim in the issuer payload is refused even with no disclosure selected`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("secret"), listOf("address", "pin"))))
        // Top-level, nested, and an ancestor holding a protected path as a non-object value.
        for (payload in listOf(
            """{"vct":"my.vct","secret":"s"}""",
            """{"vct":"my.vct","address":{"pin":"1"}}""",
            """{"vct":"my.vct","secret":{"deeper":"s"}}""",
            """{"vct":"my.vct","address":[{"pin":"1"}]}""",
        )) {
            val c = cleartextSdJwt(payload)
            assertThrows(payload, DisclosureRefusedException::class.java) { CredentialDisclosureGuard.requireNoneProtectedSdJwt(c.raw, emptyList()) }
        }
        // Unprotected cleartext, a sibling of the protected nested path, a dotted key that is not the path, and another vct.
        for (payload in listOf(
            """{"vct":"my.vct","name":"Jane"}""",
            """{"vct":"my.vct","address":{"street":"x"}}""",
            """{"vct":"my.vct","address.pin":"1","secret.x":"2"}""",
            """{"vct":"other.vct","secret":"s"}""",
        )) {
            CredentialDisclosureGuard.requireNoneProtectedSdJwt(cleartextSdJwt(payload).raw, emptyList())
        }
    }

    @Test
    fun `a protected cleartext claim is neither displayed nor matched on`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("secret"), listOf("address", "pin"))))
        val c = cleartextSdJwt("""{"vct":"my.vct","secret":"s","name":"Jane","address":{"pin":"1","street":"x"}}""")
        val shown = CredentialUtils.extractClaims(c).map { it.key }
        assertFalse(shown.contains("secret"))
        assertFalse(shown.contains("address"))
        assertTrue(shown.contains("name"))
        val paths = CredentialUtils.flattenClaimPaths(c).map { it.first }
        assertFalse(paths.contains(listOf("secret")))
        assertFalse(paths.contains(listOf("address")))
        assertFalse(paths.contains(listOf("address", "pin")))
        assertTrue(paths.contains(listOf("address", "street")))
        assertTrue(CredentialDisclosureGuard.requestsProtected(c, listOf(listOf("secret"))))
    }

    private fun RawCredentialView.shown(): String =
        listOfNotNull(parts.header?.toString(), parts.payload?.toString(), rawText) .plus(parts.disclosures.map { it.toString() }).joinToString("\n")

    @Test
    fun `the raw view redacts protected cleartext claims and disclosures, nested ones included`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("secret"), listOf("address", "secret"), listOf("address", "pin"))))
        // Disclosures: address (ancestor), address.secret (protected), address.street, top-level secret.
        val n = nestedSdJwt("my.vct")
        val v = CredentialDisclosureGuard.rawViewOf(StoredCredential(id = 7, format = "dc+sd-jwt", raw = n.raw, batchId = 7, instanceId = 0))
        assertTrue(v.redacted)
        assertFalse(v.shown().contains("hush"))
        assertFalse(v.shown().contains("\"secret\""))
        assertTrue(v.shown().contains("Main St"))
        assertNull(v.rawText)
        // Cleartext payload claims, nested too.
        val c = cleartextSdJwt("""{"vct":"my.vct","secret":"S1","name":"Jane","address":{"pin":"P1","street":"x"},"other":[{"secret":"S2"}]}""")
        val cv = CredentialDisclosureGuard.rawViewOf(c)
        assertFalse(cv.shown().contains("S1"))
        assertFalse(cv.shown().contains("P1"))
        assertTrue(cv.shown().contains("Jane"))
        assertTrue(cv.shown().contains("\"street\""))
        // A protected array-valued ancestor is not searched, so it is dropped.
        val a = CredentialDisclosureGuard.rawViewOf(cleartextSdJwt("""{"vct":"my.vct","address":[{"pin":"P3"}]}"""))
        assertFalse(a.shown().contains("P3"))
    }

    @Test
    fun `the raw view of a protected mdoc or unparseable credential shows no raw text, an unprotected one is unchanged`() {
        val m = CredentialDisclosureGuard.rawViewOf(mdoc(nym))
        assertTrue(m.redacted)
        assertNull(m.rawText)
        assertTrue(m.parts.disclosures.isEmpty() && m.parts.payload == null)
        // Type not in the policy: shown as before, including the raw string when unparseable.
        val other = CredentialDisclosureGuard.rawViewOf(mdoc("other.doctype"))
        assertFalse(other.redacted)
        assertEquals(mdoc("other.doctype").raw, other.rawText)
        val plain = CredentialDisclosureGuard.rawViewOf(sdJwt("other.vct", "secret" to "s"))
        assertFalse(plain.redacted)
        assertTrue(plain.shown().contains("\"s\"") || plain.parts.disclosures.size == 1)
        assertEquals(1, plain.parts.disclosures.size)
    }

    @Test
    fun `an mdoc element holding a protected sub-path is hidden and refused`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf(nym to setOf(listOf(nym, "given_name", "inner"))))
        assertFalse(CredentialUtils.extractMdocClaims(mdoc(nym)).any { it.key == "$nym.given_name" })
        assertTrue(CredentialUtils.extractMdocClaims(mdoc(nym)).any { it.key == "$nym.birth_date" })
        assertThrows(DisclosureRefusedException::class.java) {
            CredentialDisclosureGuard.requireNoneProtected(nym, mapOf(nym to listOf("given_name")))
        }
        CredentialDisclosureGuard.requireNoneProtected(nym, mapOf(nym to listOf("birth_date")))
    }
}
