package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialUtilsTest {

    // A valid SD-JWT VC with header.payload.signature format
    // Header: {"alg":"ES256","typ":"vc+sd-jwt"}
    // Payload below
    private val sampleJwt: String by lazy {
        val header = b64url("""{"alg":"ES256","typ":"vc+sd-jwt"}""")
        val payload = b64url("""{
            "iss": "https://issuer.example.com",
            "sub": "user123",
            "iat": 1700000000,
            "exp": 1800000000,
            "vct": "urn:example:diploma",
            "given_name": "Alice",
            "family_name": "Smith",
            "degree": "MSc Computer Science",
            "cnf": {"jwk": {}},
            "_sd_alg": "sha-256"
        }""")
        "$header.$payload.fakesig"
    }

    private fun b64url(s: String): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray())

    @Test
    fun `parseJwtPayload extracts payload from JWT`() {
        val payload = CredentialUtils.parseJwtPayload(sampleJwt)
        assertNotNull(payload)
        assertEquals("https://issuer.example.com", payload!!["iss"]?.let {
            (it as kotlinx.serialization.json.JsonPrimitive).content
        })
        assertEquals("Alice", payload["given_name"]?.let {
            (it as kotlinx.serialization.json.JsonPrimitive).content
        })
    }

    @Test
    fun `parseJwtPayload handles SD-JWT with disclosures`() {
        val sdJwt = "$sampleJwt~disclosure1~disclosure2"
        val payload = CredentialUtils.parseJwtPayload(sdJwt)
        assertNotNull(payload)
        assertEquals("Alice", payload!!["given_name"]?.let {
            (it as kotlinx.serialization.json.JsonPrimitive).content
        })
    }

    @Test
    fun `parseJwtPayload returns null for invalid input`() {
        assertNull(CredentialUtils.parseJwtPayload("not-a-jwt"))
        assertNull(CredentialUtils.parseJwtPayload(""))
        assertNull(CredentialUtils.parseJwtPayload("only-one-part"))
    }

    @Test
    fun `parseJwtPayload returns null for malformed base64`() {
        assertNull(CredentialUtils.parseJwtPayload("aaa.!!!invalid!!!.bbb"))
    }

    @Test
    fun `extractClaims returns user-facing claims`() {
        val cred = StoredCredential(
            id = 1L,
            batchId = 1L,
            instanceId = 0,
            format = "vc+sd-jwt",
            raw = sampleJwt,
        )
        val claims = CredentialUtils.extractClaims(cred)
        // Should exclude JWT metadata keys (iss, sub, iat, exp, vct, cnf, _sd_alg)
        val keys = claims.map { it.key }
        assertTrue("given_name" in keys)
        assertTrue("family_name" in keys)
        assertTrue("degree" in keys)
        assertTrue("iss" !in keys)
        assertTrue("exp" !in keys)
        assertTrue("cnf" !in keys)
        assertTrue("_sd_alg" !in keys)
        assertTrue("vct" !in keys)
    }

    @Test
    fun `extractClaims uses VCTM labels when available`() {
        val cred = StoredCredential(
            id = 1L,
            batchId = 1L,
            instanceId = 0,
            format = "vc+sd-jwt",
            raw = sampleJwt,
            metadata = CredentialMetadata(
                claims = listOf(
                    ClaimMeta(path = listOf("given_name"), label = "First Name"),
                    ClaimMeta(path = listOf("family_name"), label = "Surname"),
                ),
            ),
        )
        val claims = CredentialUtils.extractClaims(cred)
        val givenName = claims.find { it.key == "given_name" }
        assertNotNull(givenName)
        assertEquals("First Name", givenName!!.label)

        val familyName = claims.find { it.key == "family_name" }
        assertNotNull(familyName)
        assertEquals("Surname", familyName!!.label)
    }

    @Test
    fun `extractClaims resolves deeply nested VCTM claim paths`() {
        // Reproduces the diploma/ELM-schema bug: claims nested several levels
        // under a single top-level key (not a flat pid/ehic-style schema).
        val nestedJwt: String by lazy {
            val header = b64url("""{"alg":"ES256","typ":"vc+sd-jwt"}""")
            val payload = b64url("""{
                "iss": "https://issuer.example.com",
                "iat": 1700000000,
                "exp": 1800000000,
                "vct": "urn:example:diploma",
                "credentialSubject": {
                    "givenName": {"und": "Alice"},
                    "hasClaim": {
                        "awardedBy": {
                            "awardingBody": {"legalName": {"nl": "ArtEZ"}}
                        }
                    }
                }
            }""")
            "$header.$payload.fakesig"
        }
        val cred = StoredCredential(
            id = 1L,
            batchId = 1L,
            instanceId = 0,
            format = "vc+sd-jwt",
            raw = nestedJwt,
            metadata = CredentialMetadata(
                claims = listOf(
                    ClaimMeta(
                        path = listOf("credentialSubject", "givenName", "und"),
                        label = "Given Name",
                    ),
                    ClaimMeta(
                        path = listOf("credentialSubject", "hasClaim", "awardedBy", "awardingBody", "legalName", "nl"),
                        label = "Institution",
                    ),
                ),
            ),
        )

        val claims = CredentialUtils.extractClaims(cred)

        val givenName = claims.find { it.label == "Given Name" }
        assertNotNull(givenName)
        assertEquals("Alice", givenName!!.value)

        val institution = claims.find { it.label == "Institution" }
        assertNotNull(institution)
        assertEquals("ArtEZ", institution!!.value)

        // The shared top-level ancestor ("credentialSubject") must not ALSO
        // appear as its own raw-dumped claim now that its nested values were
        // resolved individually - this exact collapse-into-one-blob was the bug.
        assertTrue("credentialSubject" !in claims.map { it.key })
    }

    private fun sdJwtDisclosure(salt: String, claimName: String, claimValueJson: String): String {
        val json = """["$salt","$claimName",$claimValueJson]"""
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
    }

    private fun sha256Base64Url(s: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(s.toByteArray())
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    @Test
    fun `extractClaims resolves a top-level claim disclosed via SD-JWT disclosure, not embedded in the payload`() {
        // Reproduces the real bug found via live testing: a properly-issued
        // SD-JWT VC (e.g. a PID) selectively discloses its actual claims -
        // they are NEVER present in the JWT payload itself, only a SHA-256
        // digest of each disclosure under `_sd`. An mdoc has no such
        // indirection (claims live directly in CBOR namespaces), which is
        // why only SD-JWT credentials showed labels with no values.
        val disclosure = sdJwtDisclosure("2GLC42sKQveCfGfryNRN9w", "given_name", "\"Alice\"")
        val digest = sha256Base64Url(disclosure)
        val header = b64url("""{"alg":"ES256","typ":"vc+sd-jwt"}""")
        val payload = b64url(
            """{
                "iss": "https://issuer.example.com",
                "vct": "urn:example:pid",
                "_sd": ["$digest"],
                "_sd_alg": "sha-256"
            }""",
        )
        val sdJwt = "$header.$payload.fakesig~$disclosure~"

        val cred = StoredCredential(id = 1L, batchId = 1L, instanceId = 0, format = "vc+sd-jwt", raw = sdJwt)
        val claims = CredentialUtils.extractClaims(cred)

        val givenName = claims.find { it.key == "given_name" }
        assertNotNull("a disclosed claim absent from the raw payload must still be resolved", givenName)
        assertEquals("Alice", givenName!!.value)
    }

    @Test
    fun `extractClaims resolves a nested claim disclosed inside a nested object's own _sd array`() {
        // SD-JWT allows `_sd` at any nesting level, not just the top - an
        // issuer that groups claims under e.g. "address" can selectively
        // disclose individual address fields too.
        val disclosure = sdJwtDisclosure("eluV5Og3gSNII8EYnsxA_A", "street_address", "\"Schulstr. 12\"")
        val digest = sha256Base64Url(disclosure)
        val header = b64url("""{"alg":"ES256","typ":"vc+sd-jwt"}""")
        val payload = b64url(
            """{
                "iss": "https://issuer.example.com",
                "vct": "urn:example:pid",
                "address": {"_sd": ["$digest"], "locality": "Berlin"},
                "_sd_alg": "sha-256"
            }""",
        )
        val sdJwt = "$header.$payload.fakesig~$disclosure~"

        val cred = StoredCredential(
            id = 1L,
            batchId = 1L,
            instanceId = 0,
            format = "vc+sd-jwt",
            raw = sdJwt,
            metadata = CredentialMetadata(
                claims = listOf(
                    ClaimMeta(path = listOf("address", "street_address"), label = "Street"),
                    ClaimMeta(path = listOf("address", "locality"), label = "City"),
                ),
            ),
        )
        val claims = CredentialUtils.extractClaims(cred)

        val street = claims.find { it.label == "Street" }
        assertNotNull("a claim disclosed inside a nested object's own _sd array must still resolve", street)
        assertEquals("Schulstr. 12", street!!.value)

        val city = claims.find { it.label == "City" }
        assertNotNull(city)
        assertEquals("Berlin", city!!.value)
    }

    @Test
    fun `flattenClaimPaths exposes a nested claim VCTM does not declare`() {
        // Reproduces a real user report: a verifier's DCQL query asked for
        // path ["registered_address", "full_address"] against a real
        // `eucc` credential that genuinely has it, and got "you do not
        // have any credentials that match this request" - because
        // extractClaims (a *display* function) never exposes a nested
        // claim unless VCTM explicitly declares that exact sub-path; this
        // credential's VCTM does not. flattenClaimPaths must expose it
        // regardless of VCTM coverage, since that's what DCQL matching
        // actually needs.
        val header = b64url("""{"alg":"ES256","typ":"vc+sd-jwt"}""")
        val payload = b64url(
            """{
                "iss": "https://issuer.example.com",
                "vct": "urn:eudi:eucc:1",
                "registered_address": {
                    "full_address": "1 Example Street, Anytown",
                    "country": "NL"
                },
                "_sd_alg": "sha-256"
            }""",
        )
        val jwt = "$header.$payload.fakesig"
        // No VCTM claims at all - this credential's type metadata simply
        // doesn't cover this nested path, which must not matter.
        val cred = StoredCredential(id = 1L, batchId = 1L, instanceId = 0, format = "dc+sd-jwt", raw = jwt)

        val paths = CredentialUtils.flattenClaimPaths(cred)

        val fullAddress = paths.find { it.first == listOf("registered_address", "full_address") }
        assertNotNull("a nested claim VCTM doesn't declare must still be exposed for matching", fullAddress)
        assertEquals("1 Example Street, Anytown", (fullAddress!!.second as JsonPrimitive).content)

        // The parent node itself must also be addressable, for a verifier
        // that asks for the whole object rather than one field inside it.
        val parent = paths.find { it.first == listOf("registered_address") }
        assertNotNull(parent)
    }

    @Test
    fun `flattenClaimPaths resolves a claim disclosed inside a nested object's own _sd array`() {
        // Mirrors extractClaims' equivalent test - the disclosure-merge step
        // is shared, but this confirms flattenClaimPaths sees the result too.
        val disclosure = sdJwtDisclosure("eluV5Og3gSNII8EYnsxA_A", "street_address", "\"Schulstr. 12\"")
        val digest = sha256Base64Url(disclosure)
        val header = b64url("""{"alg":"ES256","typ":"vc+sd-jwt"}""")
        val payload = b64url(
            """{
                "iss": "https://issuer.example.com",
                "vct": "urn:example:pid",
                "address": {"_sd": ["$digest"], "locality": "Berlin"},
                "_sd_alg": "sha-256"
            }""",
        )
        val sdJwt = "$header.$payload.fakesig~$disclosure~"
        val cred = StoredCredential(id = 1L, batchId = 1L, instanceId = 0, format = "dc+sd-jwt", raw = sdJwt)

        val paths = CredentialUtils.flattenClaimPaths(cred)

        val street = paths.find { it.first == listOf("address", "street_address") }
        assertNotNull(street)
        assertEquals("Schulstr. 12", (street!!.second as JsonPrimitive).content)
    }

    @Test
    fun `flattenClaimPaths excludes JWT metadata keys and returns empty for mdoc`() {
        val cred = StoredCredential(
            id = 1L,
            batchId = 1L,
            instanceId = 0,
            format = "vc+sd-jwt",
            raw = sampleJwt,
        )
        val paths = CredentialUtils.flattenClaimPaths(cred).map { it.first }
        assertTrue(listOf("given_name") in paths)
        assertTrue(listOf("iss") !in paths)
        assertTrue(listOf("vct") !in paths)

        val mdocCred = cred.copy(format = "mso_mdoc")
        assertTrue(CredentialUtils.flattenClaimPaths(mdocCred).isEmpty())
    }

    @Test
    fun `extractClaims formats keys when no VCTM`() {
        val cred = StoredCredential(
            id = 1L,
            batchId = 1L,
            instanceId = 0,
            format = "vc+sd-jwt",
            raw = sampleJwt,
        )
        val claims = CredentialUtils.extractClaims(cred)
        val givenName = claims.find { it.key == "given_name" }
        assertEquals("Given Name", givenName!!.label)
    }

    @Test
    fun `extractClaims returns empty for unparseable credential`() {
        val cred = StoredCredential(id = 2L, format = "vc+sd-jwt", raw = "not-a-jwt", batchId = 2L, instanceId = 0)
        assertTrue(CredentialUtils.extractClaims(cred).isEmpty())
    }

    @Test
    fun `formatClaimKey formats snake_case and kebab-case`() {
        assertEquals("Given Name", CredentialUtils.formatClaimKey("given_name"))
        assertEquals("Family Name", CredentialUtils.formatClaimKey("family-name"))
        assertEquals("Degree", CredentialUtils.formatClaimKey("degree"))
    }

    @Test
    fun `buildMetadata combines offer and VCTM`() {
        val offer = CredentialOffer(
            credentialConfigurationId = "diploma",
            credentialIssuerIdentifier = "https://issuer.example.com",
            credentialName = "Diploma (offer)",
            issuerName = "Test Issuer",
            backgroundColor = "#000000",
        )
        val vctm = Vctm(
            vct = "urn:example:diploma",
            display = listOf(
                VctmDisplay(
                    locale = "en",
                    name = "University Diploma",
                    description = "A diploma from VCTM",
                    rendering = VctmRendering(
                        simple = VctmSimpleRendering(
                            backgroundColor = "#003366",
                            textColor = "#ffffff",
                        ),
                    ),
                ),
            ),
            claims = listOf(
                VctmClaim(
                    path = listOf("given_name"),
                    display = listOf(VctmClaimDisplay(locale = "en", label = "Given Name")),
                    sd = "allowed",
                    mandatory = true,
                ),
            ),
        )

        val metadata = CredentialUtils.buildMetadata(
            offer = offer,
            vctm = vctm,
            rawCredential = sampleJwt,
        )

        // VCTM display should take precedence
        assertEquals("University Diploma", metadata.name)
        assertEquals("A diploma from VCTM", metadata.description)
        assertEquals("#003366", metadata.backgroundColor)
        assertEquals("#ffffff", metadata.textColor)
        assertEquals("urn:example:diploma", metadata.vct)
        assertEquals("Test Issuer", metadata.issuer?.name)
        assertEquals(1, metadata.claims?.size)
        assertEquals("Given Name", metadata.claims!![0].label)
        assertEquals(true, metadata.claims!![0].mandatory)
    }

    @Test
    fun `buildMetadata falls back to offer when no VCTM`() {
        val offer = CredentialOffer(
            credentialConfigurationId = "diploma",
            credentialIssuerIdentifier = "https://issuer.example.com",
            credentialName = "Diploma (offer)",
            issuerName = "Test Issuer",
            backgroundColor = "#000000",
        )
        val metadata = CredentialUtils.buildMetadata(offer = offer)
        assertEquals("Diploma (offer)", metadata.name)
        assertEquals("#000000", metadata.backgroundColor)
        assertNull(metadata.claims)
    }

    // ── mdoc (mso_mdoc) ───────────────────────────────────────────────

    private val mdocDocType = "org.iso.18013.5.1.mDL"
    private val mdocNamespace = "org.iso.18013.5.1"

    private fun buildTaggedItem(digestId: Long, elementIdentifier: String, elementValue: String): com.upokecenter.cbor.CBORObject {
        val item = com.upokecenter.cbor.CBORObject.NewMap()
        item[com.upokecenter.cbor.CBORObject.FromObject("digestID")] = com.upokecenter.cbor.CBORObject.FromObject(digestId)
        item[com.upokecenter.cbor.CBORObject.FromObject("random")] = com.upokecenter.cbor.CBORObject.FromObject(ByteArray(16))
        item[com.upokecenter.cbor.CBORObject.FromObject("elementIdentifier")] = com.upokecenter.cbor.CBORObject.FromObject(elementIdentifier)
        item[com.upokecenter.cbor.CBORObject.FromObject("elementValue")] = com.upokecenter.cbor.CBORObject.FromObject(elementValue)
        return com.upokecenter.cbor.CBORObject.FromObjectAndTag(item.EncodeToBytes(), 24)
    }

    /** Build a synthetic mdoc credential's raw (base64url) bytes: a DeviceResponse-shaped envelope. */
    private fun buildMdocRaw(): String {
        val items = com.upokecenter.cbor.CBORObject.NewArray()
        items.Add(buildTaggedItem(0, "family_name", "Doe"))
        items.Add(buildTaggedItem(1, "given_name", "Jane"))

        val nameSpaces = com.upokecenter.cbor.CBORObject.NewMap()
        nameSpaces[com.upokecenter.cbor.CBORObject.FromObject(mdocNamespace)] = items

        val issuerAuth = com.upokecenter.cbor.CBORObject.NewArray()
        repeat(4) { issuerAuth.Add(com.upokecenter.cbor.CBORObject.FromObject(ByteArray(0))) }

        val issuerSigned = com.upokecenter.cbor.CBORObject.NewMap()
        issuerSigned[com.upokecenter.cbor.CBORObject.FromObject("nameSpaces")] = nameSpaces
        issuerSigned[com.upokecenter.cbor.CBORObject.FromObject("issuerAuth")] = issuerAuth

        val document = com.upokecenter.cbor.CBORObject.NewMap()
        document[com.upokecenter.cbor.CBORObject.FromObject("docType")] = com.upokecenter.cbor.CBORObject.FromObject(mdocDocType)
        document[com.upokecenter.cbor.CBORObject.FromObject("issuerSigned")] = issuerSigned

        val documents = com.upokecenter.cbor.CBORObject.NewArray()
        documents.Add(document)

        val envelope = com.upokecenter.cbor.CBORObject.NewMap()
        envelope[com.upokecenter.cbor.CBORObject.FromObject("documents")] = documents
        envelope[com.upokecenter.cbor.CBORObject.FromObject("status")] = com.upokecenter.cbor.CBORObject.FromObject(0)

        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(envelope.EncodeToBytes())
    }

    @Test
    fun `extractClaims dispatches to mdoc parsing for mso_mdoc format`() {
        val cred = StoredCredential(
            id = 3L,
            batchId = 3L,
            instanceId = 0,
            format = "mso_mdoc",
            raw = buildMdocRaw(),
            metadata = CredentialMetadata(
                doctype = mdocDocType,
                claims = listOf(
                    ClaimMeta(path = listOf(mdocNamespace, "family_name"), label = "Family Name", mandatory = true),
                ),
            ),
        )

        val claims = CredentialUtils.extractClaims(cred)
        assertEquals(2, claims.size)
        val familyName = claims.first { it.key == "$mdocNamespace.family_name" }
        assertEquals("Family Name", familyName.label)
        assertEquals("Doe", familyName.value)
        assertTrue(familyName.mandatory)

        val givenName = claims.first { it.key == "$mdocNamespace.given_name" }
        // No ClaimMeta entry for given_name - falls back to formatted key.
        assertEquals("Given Name", givenName.label)
        assertEquals("Jane", givenName.value)
    }

    @Test
    fun `parseMdocDocument recovers the real docType with no metadata at all`() {
        // Mirrors a credential from a third-party issuer with no MDDL schema
        // endpoint at our internal /type-metadata/<scope> convention - the
        // metadata fetch fails, so `metadata` stays null, but the docType is
        // still authoritatively present in the credential's own MSO/CBOR.
        val cred = StoredCredential(
            id = 4L,
            batchId = 4L,
            instanceId = 0,
            format = "mso_mdoc",
            raw = buildMdocRaw(),
            metadata = null,
        )

        val document = CredentialUtils.parseMdocDocument(cred)
        assertEquals(mdocDocType, document?.docType)
    }

    @Test
    fun `buildMdocMetadata populates doctype and claims from MDDL schema`() {
        val offer = CredentialOffer(
            credentialConfigurationId = "mdl",
            credentialIssuerIdentifier = "https://issuer.example.com",
            credentialName = "Driving Licence (offer)",
            issuerName = "Test Issuer",
        )
        val schema = MddlSchema(
            format = "mso_mdoc",
            doctype = mdocDocType,
            display = listOf(MddlDisplay(locale = java.util.Locale.getDefault().toLanguageTag(), name = "Driving Licence")),
            claims = mapOf(
                mdocNamespace to mapOf(
                    "family_name" to MddlClaimMeta(
                        display = listOf(MddlClaimDisplay(locale = java.util.Locale.getDefault().toLanguageTag(), name = "Family Name")),
                        mandatory = true,
                        valueType = "tstr",
                    ),
                ),
            ),
        )

        val metadata = CredentialUtils.buildMdocMetadata(offer = offer, mddlSchema = schema)
        assertEquals("Driving Licence", metadata.name)
        assertEquals(mdocDocType, metadata.doctype)
        assertNull(metadata.vct)
        assertEquals(1, metadata.claims?.size)
        assertEquals(listOf(mdocNamespace, "family_name"), metadata.claims!![0].path)
        assertEquals("Family Name", metadata.claims!![0].label)
        assertTrue(metadata.claims!![0].mandatory)
    }

    @Test
    fun `buildMdocMetadata falls back to offer when no MDDL schema`() {
        val offer = CredentialOffer(
            credentialConfigurationId = "mdl",
            credentialIssuerIdentifier = "https://issuer.example.com",
            credentialName = "Driving Licence (offer)",
            issuerName = "Test Issuer",
        )
        val metadata = CredentialUtils.buildMdocMetadata(offer = offer)
        assertEquals("Driving Licence (offer)", metadata.name)
        assertNull(metadata.doctype)
        assertNull(metadata.claims)
    }
}
