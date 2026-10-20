package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORObject
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class CredentialMatcherTest {

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * A minimal but REAL CBOR-encoded bare `IssuerSigned` structure (no
     * enclosing `{documents: [...]}` envelope), base64url-encoded the same
     * way [StoredCredential.raw] is stored - see `MdocCborTest`'s matching
     * fixture builder for why the payload must be a real double-encoded
     * byte string, not an in-memory tagged object.
     */
    private fun mdocRaw(docType: String): String {
        val item = CBORObject.NewMap()
        item[CBORObject.FromObject("digestID")] = CBORObject.FromObject(0L)
        item[CBORObject.FromObject("random")] = CBORObject.FromObject(ByteArray(16))
        item[CBORObject.FromObject("elementIdentifier")] = CBORObject.FromObject("given_name")
        item[CBORObject.FromObject("elementValue")] = CBORObject.FromObject("Jane")
        val items = CBORObject.NewArray()
        items.Add(CBORObject.FromObjectAndTag(item.EncodeToBytes(), 24))
        val nameSpaces = CBORObject.NewMap()
        nameSpaces[CBORObject.FromObject("org.iso.18013.5.1")] = items

        val mso = CBORObject.NewMap()
        mso[CBORObject.FromObject("docType")] = CBORObject.FromObject(docType)
        val taggedMsoBytes = CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()
        val issuerAuth = CBORObject.NewArray()
        issuerAuth.Add(CBORObject.FromObject(ByteArray(0)))
        issuerAuth.Add(CBORObject.NewMap())
        issuerAuth.Add(CBORObject.FromObject(taggedMsoBytes))
        issuerAuth.Add(CBORObject.FromObject(ByteArray(64)))

        val bareIssuerSigned = CBORObject.NewMap()
        bareIssuerSigned[CBORObject.FromObject("nameSpaces")] = nameSpaces
        bareIssuerSigned[CBORObject.FromObject("issuerAuth")] = issuerAuth

        return Base64.getUrlEncoder().withoutPadding().encodeToString(bareIssuerSigned.EncodeToBytes())
    }

    /** An SD-JWT whose payload carries `vct`, in the `<jwt>~` shape stored. */
    private fun sdJwtRaw(vct: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"ES256"}""".toByteArray())
        val payload = enc.encodeToString("""{"vct":"$vct"}""".toByteArray())
        return "$header.$payload.c2ln~"
    }

    /**
     * A credential is matched on the vct it carries, not on whether the
     * wallet happens to have built display metadata for it yet.
     *
     * `metadata` is a rendering artefact - absent until the issuance flow has
     * an offer to build it from, repopulated later by hydration, which skips
     * credentials whose metadata is already real. Matching on it alone made a
     * freshly issued EBW-OID credential invisible to a query naming its exact
     * vct, on the gdc environment, while the PID beside it matched.
     */
    @Test
    fun match_uses_the_credentials_own_vct_when_metadata_has_none() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = sdJwtRaw("uri:eu.ebw.oid.1"),
                metadata = null,
                batchId = 1L,
                instanceId = 0,
            ),
        )
        val query = json.parseToJsonElement(
            """
            {"credentials":[{"id":"ebw_oid","format":"dc+sd-jwt",
              "meta":{"vct_values":["uri:eu.ebw.oid.1"]}}]}
            """.trimIndent(),
        ).jsonObject

        val results = CredentialMatcher.match(query, credentials)
        assertEquals(1, results.size)
        assertEquals(listOf(1L), results[0].candidates.map { it.id })
    }

    /** The payload's vct wins, and a query for the stale one no longer matches. */
    @Test
    fun match_prefers_the_payload_vct_over_a_stale_metadata_copy() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = sdJwtRaw("uri:eu.ebw.oid.1"),
                metadata = CredentialMetadata(vct = "urn:stale:1"),
                batchId = 1L,
                instanceId = 0,
            ),
        )
        fun queryFor(vct: String) = json.parseToJsonElement(
            """{"credentials":[{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["$vct"]}}]}""",
        ).jsonObject

        assertEquals(1, CredentialMatcher.match(queryFor("uri:eu.ebw.oid.1"), credentials)[0].candidates.size)
        assertTrue(CredentialMatcher.match(queryFor("urn:stale:1"), credentials)[0].candidates.isEmpty())
    }

    @Test
    fun match_filters_by_format_and_vct() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "raw-1",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
                batchId = 1L,
                instanceId = 0,
            ),
            StoredCredential(
                id = 2L,
                format = "mso_mdoc",
                raw = "raw-2",
                metadata = CredentialMetadata(doctype = "eu.europa.ec.eudi.pid.1"),
                batchId = 2L,
                instanceId = 0,
            ),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "q-pid",
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": ["urn:eu:pid:1"]
                  },
                  "claims": [
                    { "path": ["given_name"] }
                  ]
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val results = CredentialMatcher.match(query, credentials)

        assertEquals(1, results.size)
        assertEquals("q-pid", results.first().queryId)
        assertEquals(listOf(1L), results.first().candidates.map { it.id })
        assertEquals(listOf(listOf("given_name")), results.first().requestedClaims)
    }

    @Test
    fun match_filters_by_doctype_for_mdoc() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "mso_mdoc",
                raw = "raw-1",
                metadata = CredentialMetadata(doctype = "eu.europa.ec.eudi.pid.1"),
                batchId = 1L,
                instanceId = 0,
            ),
            StoredCredential(
                id = 2L,
                format = "mso_mdoc",
                raw = "raw-2",
                metadata = CredentialMetadata(doctype = "com.example.other"),
                batchId = 2L,
                instanceId = 0,
            ),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "q-doc",
                  "format": "mso_mdoc",
                  "meta": {
                    "doctype_value": "eu.europa.ec.eudi.pid.1"
                  }
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val matchedIds = CredentialMatcher.matchedCredentialIds(query, credentials)
        assertEquals(listOf(1L), matchedIds)
    }

    @Test
    fun match_filters_by_doctype_for_mdoc_with_no_metadata() {
        // Mirrors a credential from a third-party issuer with no MDDL schema
        // endpoint at our internal /type-metadata/<scope> convention - the
        // metadata fetch fails, so `metadata` stays null, but the docType is
        // still authoritatively present in the credential's own MSO/CBOR, so
        // it must still be matchable.
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "mso_mdoc",
                raw = buildMdocRaw("eu.europa.ec.eudi.pid.1"),
                metadata = null,
                batchId = 1L,
                instanceId = 0,
            ),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "q-doc",
                  "format": "mso_mdoc",
                  "meta": {
                    "doctype_value": "eu.europa.ec.eudi.pid.1"
                  }
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val matchedIds = CredentialMatcher.matchedCredentialIds(query, credentials)
        assertEquals(listOf(1L), matchedIds)
    }

    @Test
    fun mso_mdoc_zk_query_matches_credential_stored_as_plain_mso_mdoc() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "mso_mdoc",
                raw = mdocRaw("org.iso.18013.5.1.mDL"),
                batchId = 1L,
                instanceId = 0,
            ),
            StoredCredential(
                id = 2L,
                format = "dc+sd-jwt",
                raw = "raw-2",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
                batchId = 2L,
                instanceId = 0,
            ),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "q-zk",
                  "format": "mso_mdoc_zk",
                  "meta": {
                    "doctype_value": "org.iso.18013.5.1.mDL"
                  }
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val results = CredentialMatcher.match(query, credentials)

        assertEquals(1, results.size)
        assertEquals(listOf(1L), results.first().candidates.map { it.id })
    }

    @Test
    fun mso_mdoc_zk_query_parses_zk_system_type_and_ppid_context() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "mso_mdoc",
                raw = mdocRaw("org.iso.18013.5.1.mDL"),
                batchId = 1L,
                instanceId = 0,
            ),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "q-zk",
                  "format": "mso_mdoc_zk",
                  "meta": {
                    "doctype_value": "org.iso.18013.5.1.mDL",
                    "ppid_context": "https://verifier.example/",
                    "zk_system_type": [
                      { "system": "longfellow", "id": "longfellow-v8", "circuit_hash": "abc123", "num_attributes": 2 }
                    ]
                  }
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val result = CredentialMatcher.match(query, credentials).first()

        assertEquals("https://verifier.example/", result.ppidContext)
        assertEquals(1, result.zkSystemTypes?.size)
        val spec = result.zkSystemTypes!!.first()
        assertEquals("longfellow-v8", spec.id)
        assertEquals("longfellow", spec.system)
        // params are flat top-level keys on the wire entry (no nested
        // "params" object) - confirmed via multipaz's own OpenID4VP.kt parsing.
        assertEquals("abc123", spec.params["circuit_hash"])
        assertEquals("2", spec.params["num_attributes"])
    }

    @Test
    fun mso_mdoc_zk_query_does_not_match_sd_jwt_credential() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "raw-1",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
                batchId = 1L,
                instanceId = 0,
            ),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                { "id": "q-zk", "format": "mso_mdoc_zk" }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val matchedIds = CredentialMatcher.matchedCredentialIds(query, credentials)
        assertTrue(matchedIds.isEmpty())
    }

    /** Build a synthetic mdoc credential's raw (base64url) bytes: a bare IssuerSigned structure with the given docType embedded in a stub MSO. */
    private fun buildMdocRaw(docType: String): String {
        val mso = com.upokecenter.cbor.CBORObject.NewMap()
        mso[com.upokecenter.cbor.CBORObject.FromObject("docType")] = com.upokecenter.cbor.CBORObject.FromObject(docType)
        val msoTagged = com.upokecenter.cbor.CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24)
        val issuerAuth = com.upokecenter.cbor.CBORObject.NewArray()
        issuerAuth.Add(com.upokecenter.cbor.CBORObject.FromObject(ByteArray(0)))
        issuerAuth.Add(com.upokecenter.cbor.CBORObject.NewMap())
        issuerAuth.Add(com.upokecenter.cbor.CBORObject.FromObject(msoTagged.EncodeToBytes()))
        issuerAuth.Add(com.upokecenter.cbor.CBORObject.FromObject(ByteArray(0)))

        val issuerSigned = com.upokecenter.cbor.CBORObject.NewMap()
        issuerSigned[com.upokecenter.cbor.CBORObject.FromObject("nameSpaces")] = com.upokecenter.cbor.CBORObject.NewMap()
        issuerSigned[com.upokecenter.cbor.CBORObject.FromObject("issuerAuth")] = issuerAuth

        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(issuerSigned.EncodeToBytes())
    }

    @Test
    fun match_returns_all_when_query_has_no_credentials_array() {
        val credentials = listOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw-a", batchId = 1L, instanceId = 0),
            StoredCredential(id = 2L, format = "mso_mdoc", raw = "raw-b", batchId = 2L, instanceId = 0),
        )

        val query = json.parseToJsonElement("""{ "unexpected": true }""").jsonObject
        val results = CredentialMatcher.match(query, credentials)

        assertEquals(1, results.size)
        assertEquals("_default", results.first().queryId)
        assertTrue(results.first().candidates.map { it.id }.containsAll(listOf(1L, 2L)))
    }

    @Test
    fun matched_credential_ids_are_distinct_across_multiple_queries() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "raw-1",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
                batchId = 1L,
                instanceId = 0,
            )
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "q-1",
                  "format": "DC+SD-JWT",
                  "meta": { "vct_values": ["urn:eu:pid:1"] }
                },
                {
                  "id": "q-2",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] }
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val matchedIds = CredentialMatcher.matchedCredentialIds(query, credentials)

        assertEquals(listOf(1L), matchedIds)
    }

    @Test
    fun match_excludes_credentials_without_required_vct_or_doctype_metadata() {
        val credentials = listOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw-1", batchId = 1L, instanceId = 0),
            StoredCredential(id = 2L, format = "mso_mdoc", raw = "raw-2", batchId = 2L, instanceId = 0),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "q-vct",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] }
                },
                {
                  "id": "q-doc",
                  "format": "mso_mdoc",
                  "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" }
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val results = CredentialMatcher.match(query, credentials)

        assertEquals(emptyList<StoredCredential>(), results.first { it.queryId == "q-vct" }.candidates)
        assertEquals(emptyList<StoredCredential>(), results.first { it.queryId == "q-doc" }.candidates)
    }

    @Test
    fun match_skips_queries_without_ids_and_ignores_malformed_claim_entries() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "raw-1",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
                batchId = 1L,
                instanceId = 0,
            )
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] }
                },
                {
                  "id": "q-valid",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] },
                  "claims": [
                    { "path": ["given_name"] },
                    { "path": "not-an-array" },
                    true
                  ]
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val results = CredentialMatcher.match(query, credentials)

        assertEquals(1, results.size)
        assertEquals("q-valid", results.single().queryId)
        assertEquals(listOf(listOf("given_name")), results.single().requestedClaims)
    }

    // --- credential_sets tests (OID4VP §6.2) ---

    @Test
    fun parseCredentialSets_returns_null_when_absent() {
        val query = json.parseToJsonElement("""{ "credentials": [] }""").jsonObject
        val sets = CredentialMatcher.parseCredentialSets(query)
        assertEquals(null, sets)
    }

    @Test
    fun parseCredentialSets_parses_required_and_optional_sets() {
        val query = json.parseToJsonElement(
            """
            {
              "credentials": [],
              "credential_sets": [
                {
                  "options": [["pid"], ["other_pid"], ["cred_1", "cred_2"]]
                },
                {
                  "required": false,
                  "options": [["nice_to_have"]]
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val sets = CredentialMatcher.parseCredentialSets(query)!!
        assertEquals(2, sets.size)

        // First set: required (default), 3 options
        assertTrue(sets[0].required)
        assertEquals(3, sets[0].options.size)
        assertEquals(listOf("pid"), sets[0].options[0])
        assertEquals(listOf("other_pid"), sets[0].options[1])
        assertEquals(listOf("cred_1", "cred_2"), sets[0].options[2])

        // Second set: optional, 1 option
        assertEquals(false, sets[1].required)
        assertEquals(1, sets[1].options.size)
        assertEquals(listOf("nice_to_have"), sets[1].options[0])
    }

    @Test
    fun parseCredentialSets_skips_malformed_entries() {
        val query = json.parseToJsonElement(
            """
            {
              "credentials": [],
              "credential_sets": [
                { "options": [] },
                { "options": [["valid"]] }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val sets = CredentialMatcher.parseCredentialSets(query)!!
        assertEquals(1, sets.size)
        assertEquals(listOf(listOf("valid")), sets[0].options)
    }

    @Test
    fun findSatisfiableOptions_identifies_satisfiable_options() {
        val queryResults = listOf(
            CredentialMatcher.MatchResult("pid", "dc+sd-jwt",
                listOf(StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "r", batchId = 1L, instanceId = 0)),
                emptyList()),
            CredentialMatcher.MatchResult("other_pid", "dc+sd-jwt",
                emptyList(), // no matches
                emptyList()),
            CredentialMatcher.MatchResult("cred_1", "dc+sd-jwt",
                listOf(StoredCredential(id = 2L, format = "dc+sd-jwt", raw = "r", batchId = 2L, instanceId = 0)),
                emptyList()),
            CredentialMatcher.MatchResult("cred_2", "dc+sd-jwt",
                listOf(StoredCredential(id = 3L, format = "dc+sd-jwt", raw = "r", batchId = 3L, instanceId = 0)),
                emptyList()),
        )

        val credentialSets = listOf(
            CredentialMatcher.CredentialSetQuery(
                options = listOf(listOf("pid"), listOf("other_pid"), listOf("cred_1", "cred_2")),
                required = true,
            )
        )

        val satisfiable = CredentialMatcher.findSatisfiableOptions(credentialSets, queryResults)

        // "pid" option is satisfiable (has matches)
        // "other_pid" option is NOT satisfiable (no matches)
        // "cred_1" + "cred_2" option IS satisfiable (both have matches)
        assertEquals(2, satisfiable.size)
        assertEquals(0, satisfiable[0].credentialSetIndex)
        assertEquals(0, satisfiable[0].optionIndex) // "pid"
        assertEquals(listOf("pid"), satisfiable[0].queryIds)

        assertEquals(0, satisfiable[1].credentialSetIndex)
        assertEquals(2, satisfiable[1].optionIndex) // "cred_1", "cred_2"
        assertEquals(listOf("cred_1", "cred_2"), satisfiable[1].queryIds)
    }

    @Test
    fun matchDcql_returns_full_output_with_credential_sets() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "raw-1",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
                batchId = 1L,
                instanceId = 0,
            ),
            StoredCredential(
                id = 2L,
                format = "mso_mdoc",
                raw = "raw-2",
                metadata = CredentialMetadata(doctype = "org.iso.18013.5.1.mDL"),
                batchId = 2L,
                instanceId = 0,
            ),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "pid",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] },
                  "claims": [{ "path": ["given_name"] }]
                },
                {
                  "id": "mdl",
                  "format": "mso_mdoc",
                  "meta": { "doctype_value": "org.iso.18013.5.1.mDL" }
                }
              ],
              "credential_sets": [
                {
                  "options": [["pid"], ["mdl"]]
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val output = CredentialMatcher.matchDcql(query, credentials)

        // Both query results should have matches
        assertEquals(2, output.queryResults.size)
        assertEquals("pid", output.queryResults[0].queryId)
        assertEquals(1, output.queryResults[0].candidates.size)
        assertEquals("mdl", output.queryResults[1].queryId)
        assertEquals(1, output.queryResults[1].candidates.size)

        // credential_sets should be parsed
        val sets = output.credentialSets!!
        assertEquals(1, sets.size)
        assertTrue(sets[0].required)

        // Both options should be satisfiable
        assertEquals(2, output.satisfiableOptions.size)
    }

    @Test
    fun matchDcql_without_credential_sets_returns_null_sets() {
        val credentials = listOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "r",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"), batchId = 1L, instanceId = 0),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "pid",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] }
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val output = CredentialMatcher.matchDcql(query, credentials)
        assertEquals(null, output.credentialSets)
        assertTrue(output.satisfiableOptions.isEmpty())
        assertEquals(1, output.queryResults.size)
    }

    @Test
    fun match_still_returns_flat_list_for_backward_compatibility() {
        val credentials = listOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "r",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"), batchId = 1L, instanceId = 0),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "pid",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] }
                }
              ],
              "credential_sets": [
                { "options": [["pid"]] }
              ]
            }
            """.trimIndent()
        ).jsonObject

        // match() should still work as before, ignoring credential_sets
        val results = CredentialMatcher.match(query, credentials)
        assertEquals(1, results.size)
        assertEquals("pid", results[0].queryId)
    }

    @Test
    fun matchMdocDocType_filtersByRealDocTypeParsedFromCbor() {
        val credentials = listOf(
            StoredCredential(id = 1L, format = "mso_mdoc", raw = mdocRaw("org.iso.18013.5.1.mDL"), batchId = 1L, instanceId = 0),
            StoredCredential(id = 2L, format = "mso_mdoc", raw = mdocRaw("eu.europa.ec.eudi.pid.1"), batchId = 2L, instanceId = 0),
        )

        val matches = CredentialMatcher.matchMdocDocType(credentials, "org.iso.18013.5.1.mDL")

        assertEquals(listOf(1L), matches.map { it.id })
    }

    @Test
    fun matchMdocDocType_excludesNonMdocFormatsEvenWithMatchingDocType() {
        // A DCQL/SD-JWT credential should never be selectable by an
        // ISO 18013-5 proximity request's bare docType string, regardless
        // of what its (irrelevant) format-specific fields happen to contain.
        val credentials = listOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "not-cbor-at-all", batchId = 1L, instanceId = 0),
            StoredCredential(id = 2L, format = "mso_mdoc", raw = mdocRaw("org.iso.18013.5.1.mDL"), batchId = 2L, instanceId = 0),
        )

        val matches = CredentialMatcher.matchMdocDocType(credentials, "org.iso.18013.5.1.mDL")

        assertEquals(listOf(2L), matches.map { it.id })
    }

    @Test
    fun matchMdocDocType_returnsEmptyWhenNoDocTypeMatches() {
        val credentials = listOf(
            StoredCredential(id = 1L, format = "mso_mdoc", raw = mdocRaw("com.example.other"), batchId = 1L, instanceId = 0),
        )

        val matches = CredentialMatcher.matchMdocDocType(credentials, "org.iso.18013.5.1.mDL")

        assertTrue(matches.isEmpty())
    }

    // ── requestedCredentialTypes ─────────────────────────────────────

    @Test
    fun requestedCredentialTypes_namesVctAndDoctypeValues() {
        val query = json.parseToJsonElement(
            """{"credentials":[
                 {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eu.europa.ec.eudi:pid:1"]}},
                 {"id":"mdl","format":"mso_mdoc","meta":{"source_format":"mso_mdoc","doctype_value":"org.iso.18013.5.1.mDL"}}
               ]}"""
        ).jsonObject

        assertEquals(
            listOf("urn:eu.europa.ec.eudi:pid:1", "org.iso.18013.5.1.mDL"),
            CredentialMatcher.requestedCredentialTypes(query),
        )
    }

    @Test
    fun requestedCredentialTypes_dedupesAndReadsPluralDoctypeValues() {
        val query = json.parseToJsonElement(
            """{"credentials":[
                 {"id":"a","meta":{"vct_values":["urn:example:pid","urn:example:pid"]}},
                 {"id":"b","meta":{"doctype_values":["org.iso.18013.5.1.mDL"],"vct_values":["urn:example:pid"]}}
               ]}"""
        ).jsonObject

        assertEquals(
            listOf("urn:example:pid", "org.iso.18013.5.1.mDL"),
            CredentialMatcher.requestedCredentialTypes(query),
        )
    }

    @Test
    fun requestedCredentialTypes_fallsBackToTheQueryIdWhenNothingIsConstrained() {
        val query = json.parseToJsonElement(
            """{"credentials":[{"id":"any-credential","format":"dc+sd-jwt"}]}"""
        ).jsonObject

        assertEquals(listOf("any-credential"), CredentialMatcher.requestedCredentialTypes(query))
    }

    @Test
    fun requestedCredentialTypes_toleratesQueriesItCannotRead() {
        // JSON null where a string belongs, a non-object entry, and no
        // credentials array at all: a verifier's request must never crash
        // the wallet's attempt to explain what it is missing.
        assertTrue(
            CredentialMatcher.requestedCredentialTypes(
                json.parseToJsonElement("""{"credentials":["not-an-object",{"id":null,"meta":{"vct_values":[null]}}]}""").jsonObject
            ).isEmpty()
        )
        assertTrue(
            CredentialMatcher.requestedCredentialTypes(
                json.parseToJsonElement("""{"nonsense":true}""").jsonObject
            ).isEmpty()
        )
    }

    private fun pid() = listOf(
        StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw-1", metadata = CredentialMetadata(vct = "urn:eu:pid:1"), batchId = 1L, instanceId = 0),
    )

    private fun candidates(query: String) =
        CredentialMatcher.match(json.parseToJsonElement(query).jsonObject, pid()).flatMap { it.candidates }.map { it.id }

    /**
     * Matcher 0.7.0 rejects a request repeating a credential query id or a claim id. The engine's
     * rejection must not fall back to the built-in matcher, which answers it: a reference to the
     * repeated id would resolve to whichever came first.
     */
    @Test
    fun a_repeated_credential_query_id_offers_nothing() {
        val ok = """{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["urn:eu:pid:1"]}}]}"""
        assertEquals(listOf(1L), candidates(ok))
        val repeated = """{"credentials":[
            {"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["urn:eu:pid:1"]}},
            {"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["urn:eu:pid:1"]}}]}"""
        assertTrue(candidates(repeated).isEmpty())
    }

    @Test
    fun a_repeated_claim_id_offers_nothing() {
        val repeated = """{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["urn:eu:pid:1"]},
            "claims":[{"id":"c","path":["x"]},{"id":"c","path":["y"]}]}]}"""
        assertTrue(candidates(repeated).isEmpty())
        // Claim ids repeated across DIFFERENT queries are not a repeat.
        val acrossQueries = """{"credentials":[
            {"id":"a","claims":[{"id":"c","path":["x"]}]},
            {"id":"b","claims":[{"id":"c","path":["x"]}]}]}"""
        assertTrue(!CredentialMatcher.hasDuplicateDcqlIds(json.parseToJsonElement(acrossQueries).jsonObject["credentials"]!!.jsonArray))
    }
}
