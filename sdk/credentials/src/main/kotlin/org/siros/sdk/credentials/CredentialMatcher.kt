// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import timber.log.Timber

/**
 * Client-side credential matching against DCQL queries (OID4VP 1.0 §6).
 *
 * Since the wallet engine does not perform credential matching, the SDK
 * must parse DCQL (Digital Credential Query Language) queries and filter
 * stored credentials locally. The DCQL query comes from the verifier via
 * the engine's `match_request` message.
 *
 * DCQL query structure (OID4VP 1.0 §6):
 * ```json
 * {
 *   "credentials": [
 *     {
 *       "id": "query-id",
 *       "format": "dc+sd-jwt",
 *       "meta": { "vct_values": ["urn:eu.europa.ec.eudi:pid:1"] },
 *       "claims": [{ "path": ["given_name"] }]
 *     }
 *   ],
 *   "credential_sets": [
 *     {
 *       "options": [["query-id-a"], ["query-id-b", "query-id-c"]],
 *       "required": true
 *     }
 *   ]
 * }
 * ```
 *
 * Matching rules (§6.4.2):
 * 1. Each credential query has an optional `format` — must match [StoredCredential.format]
 * 2. `meta.vct_values` — credential's vct must be in the list
 * 3. `meta.doctype_value` — credential's doctype must match (mso_mdoc)
 * 4. If no format/vct/doctype constraints, any credential matches
 *
 * Credential sets selection (§6.4.2):
 * - If `credential_sets` is not provided → return presentations for ALL credentials
 * - Otherwise → satisfy all required credential set queries, optionally any others
 * - To satisfy a set → return presentations matching ONE of its `options`
 */
object CredentialMatcher {

    /**
     * Result of matching credentials against a single DCQL credential query.
     */
    data class MatchResult(
        /** DCQL credential query ID. */
        val queryId: String,
        /** Requested format, if specified. */
        val format: String?,
        /** Credentials that matched this query. */
        val candidates: List<StoredCredential>,
        /** Claim paths requested by the verifier. */
        val requestedClaims: List<List<String>>,
        /**
         * Parsed `meta.zk_system_type` (present only when [format] is
         * `"mso_mdoc_zk"`) - the verifier's own list of acceptable ZK proof
         * systems, in priority order, per multipaz's wire convention
         * (confirmed via `balfanz/multipaz`'s `ppid` branch `verifier.kt`).
         * Feed to [ZkProofSystem.matchingSpec]/[ZkProofSystemRegistry.resolve]
         * to pick which one (if any) this wallet can actually satisfy.
         */
        val zkSystemTypes: List<ZkSystemSpec>? = null,
        /**
         * Parsed `meta.ppid_context`, if the verifier supplied one - see
         * [VerifierIdentity.ppidContext]'s doc comment. `null` is a normal,
         * common case (most requests won't set this).
         */
        val ppidContext: String? = null,
        /** The plan a `circuit_zk` query was matched under; null for every other format. */
        val circuitZkPlan: CircuitZkPlan? = null,
        /**
         * Why a `zkp_req` query matched nothing, as a stable content-free code (`invalid-request`, `request-rejected`,
         * `no-circuit`, `source-format`, `no-credential`); null when it matched or for any other format.
         */
        val circuitZkRefusal: String? = null,
    )

    /**
     * A credential set query from DCQL `credential_sets` (OID4VP §6.2).
     *
     * Represents one grouping constraint: the wallet must satisfy
     * one of the [options] by providing matching credentials for
     * all credential query IDs in that option.
     */
    data class CredentialSetQuery(
        /** Each option is a list of credential query IDs that together satisfy this set. */
        val options: List<List<String>>,
        /** Whether this credential set is required (default true per spec). */
        val required: Boolean = true,
    )

    /**
     * An option within a credential set that can be satisfied by the wallet's credentials.
     */
    data class SatisfiableOption(
        /** Index of the credential set in the `credential_sets` array. */
        val credentialSetIndex: Int,
        /** Index of the option within the credential set's `options` array. */
        val optionIndex: Int,
        /** The credential query IDs in this option. */
        val queryIds: List<String>,
    )

    /**
     * Full DCQL match output including per-query results and credential set constraints.
     */
    data class DcqlMatchOutput(
        /** Per-credential-query match results. */
        val queryResults: List<MatchResult>,
        /** Parsed credential set constraints, or null if `credential_sets` was absent. */
        val credentialSets: List<CredentialSetQuery>?,
        /** Options that can be satisfied given the wallet's current credentials. */
        val satisfiableOptions: List<SatisfiableOption>,
        /**
         * Whether the ORIGINAL request has a `circuit_zk` credential query, however that query was
         * read: a query dropped from [queryResults] (no string `id`) still sets it. A caller that
         * does not answer `circuit_zk` through its own path must refuse the whole request when this
         * is set, never answer the ordinary queries alone.
         */
        val hasCircuitZkQuery: Boolean = false,
        /** How many credential queries of the original request produced no entry in [queryResults] (no string `id`). */
        val unparsedQueryCount: Int = 0,
    )

    /**
     * Match stored credentials against a DCQL query.
     *
     * @param dcqlQuery The DCQL query JSON from the verifier
     * @param credentials All stored credentials
     * @param zkSystemIds The wallet's registered ZK proof systems (see
     *   [org.siros.sdk.wallet.SirosWallet.zkSystemIds]) - required for the
     *   shared engine to recognize a ZK-format/`zk_system_type` request as
     *   satisfiable at all; see [SharedDcqlMatcher.evaluate]'s doc comment.
     * @return A list of [MatchResult] — one per credential query in the DCQL
     */
    fun match(
        dcqlQuery: JsonObject,
        credentials: List<StoredCredential>,
        zkSystemIds: List<String> = emptyList(),
    ): List<MatchResult> {
        return matchDcql(dcqlQuery, credentials, zkSystemIds).queryResults
    }

    /**
     * True if [dcqlQuery] asks for at least one `"mso_mdoc_zk"` credential -
     * i.e. satisfying it will require generating a zero-knowledge proof
     * rather than disclosing raw claims. Operates directly on the raw DCQL
     * query, before any credential matching happens, so callers that need to
     * know this early (e.g. a DC API loading screen that wants to show a
     * ZK-specific status message while [SirosWallet][org.siros.sdk.wallet]'s
     * full request handling - trust evaluation, matching, proof generation -
     * is still in flight) don't need the wallet's credential store to check.
     */
    fun isZkRequest(dcqlQuery: JsonObject): Boolean =
        dcqlQuery["credentials"]?.jsonArray?.any { entry ->
            entry.jsonObject["format"]?.jsonPrimitive?.contentOrNull
                ?.equals("mso_mdoc_zk", ignoreCase = true) == true
        } ?: false

    /**
     * Match stored credentials against a full DCQL query, including `credential_sets`.
     *
     * Returns per-query match results, parsed credential set constraints,
     * and which options are satisfiable given the wallet's credentials.
     *
     * @param dcqlQuery The DCQL query JSON from the verifier
     * @param credentials All stored credentials
     * @param zkSystemIds The wallet's registered ZK proof systems (see
     *   [org.siros.sdk.wallet.SirosWallet.zkSystemIds]) - required for the
     *   shared engine to recognize a ZK-format/`zk_system_type` request as
     *   satisfiable at all; see [SharedDcqlMatcher.evaluate]'s doc comment.
     * @param circuitZk Support for `circuit_zk` queries; `null` (the default) means the
     *   feature is off and such a query matches nothing, as before.
     * @param clientMetadata The request's `client_metadata`, handed to the planner.
     * @return A [DcqlMatchOutput] with full matching information
     */
    fun matchDcql(
        dcqlQuery: JsonObject,
        credentials: List<StoredCredential>,
        zkSystemIds: List<String> = emptyList(),
        circuitZk: CircuitZkSupport? = null,
        clientMetadata: JsonObject? = null,
    ): DcqlMatchOutput {
        val credentialQueries = dcqlQuery["credentials"]?.jsonArray ?: run {
            Timber.w("DCQL query has no 'credentials' array, returning all credentials")
            return DcqlMatchOutput(
                queryResults = listOf(MatchResult(
                    queryId = "_default",
                    format = null,
                    candidates = credentials,
                    requestedClaims = emptyList(),
                )),
                credentialSets = null,
                satisfiableOptions = emptyList(),
            )
        }

        val parsed = credentialQueries.mapNotNull { queryElement ->
            val query = queryElement.jsonObject
            if (circuitZk != null && CredentialUtils.isCircuitZkFormat(query["format"]?.jsonPrimitive?.contentOrNull)) {
                matchCircuitZkQuery(query, credentials, circuitZk, clientMetadata)
            } else {
                matchSingleQuery(query, credentials)
            }
        }
        // Request level, from the ORIGINAL queries: a circuit_zk query that matchCircuitZkQuery or
        // matchSingleQuery dropped (no string `id`) leaves no result to look at, and the request
        // still contains it.
        val circuitQueries = credentialQueries.filter { isCircuitZkQuery(it) }
        val hasCircuitZkQuery = circuitQueries.isNotEmpty()
        val unparsedQueryCount = credentialQueries.size - parsed.size

        // Which credentials qualify is decided by the shared engine - the same
        // one the OS credential picker runs, and the only implementation here
        // tested against the specification's own examples. This matcher still
        // parses everything else the wallet needs at presentation time
        // (requested claims, zk_system_type, ppid_context), because those are
        // read from the query rather than decided by it.
        //
        // The visible change is that a credential missing a claim the verifier
        // asked for is no longer offered. OID4VP 1.0 §6.4.1 requires that; the
        // parsing path above never checked it, so such a credential would be
        // offered, consented to, and then fail to satisfy the verifier.
        //
        // A request with a circuit_zk query is not given to the engine whole: the planner is what
        // decides those queries (fail closed, see [matchCircuitZkQuery]). The ordinary queries of
        // such a request are still validated by the engine, as a request of their own (the
        // circuit queries and `credential_sets` removed), so a credential missing a claim they ask
        // for is not offered just because a circuit_zk query sits beside them. Per-query candidates
        // are all that is taken from that answer. The engine not answering is a refusal for them
        // here, not the built-in fallback, which never checked claims.
        //
        // A request repeating a credential query `id` or a claim `id` (§6.1,
        // §6.3) is malformed, and the engine rejects it as such (matcher
        // 0.7.0). Rejecting is not an engine failure to fall back from: the
        // built-in matcher would answer it, resolving each reference to
        // whichever entry came first, which is how a request for two
        // credentials used to be quietly answered with one. Fail closed.
        val malformed = hasDuplicateDcqlIds(credentialQueries)
        // A circuit source that fails registers no claimless doctype (the claims are then registered, the stricter side).
        val claimless = try { circuitZk?.circuits?.docTypes().orEmpty() } catch (e: Exception) { emptySet() }
        val ordinaryQueries = credentialQueries.filterNot { isCircuitZkQuery(it) }
        val shared = if (malformed || hasCircuitZkQuery) null else engine(dcqlQuery, credentials, zkSystemIds, claimless)
        val ordinaryShared = if (!malformed && hasCircuitZkQuery && ordinaryQueries.isNotEmpty()) {
            engine(JsonObject(mapOf("credentials" to JsonArray(ordinaryQueries))), credentials, zkSystemIds, claimless)
        } else {
            null
        }
        val queryResults = when {
            malformed -> {
                Timber.w("DCQL query repeats a credential or claim id (OID4VP 1.0 §6.1/§6.3); offering nothing")
                parsed.map { it.copy(candidates = emptyList()) }
            }

            hasCircuitZkQuery -> parsed.map { result ->
                if (CredentialUtils.isCircuitZkFormat(result.format)) {
                    result
                } else if (ordinaryShared == null) {
                    // The engine could not validate them: not offered, never the unchecked built-in answer.
                    Timber.w("DCQL query '${result.queryId}': the engine could not validate it beside a circuit_zk query; offering nothing")
                    result.copy(candidates = emptyList())
                } else {
                    val qualifying = ordinaryShared.candidatesByQuery[result.queryId].orEmpty().toSet()
                    SharedDcqlMatcher.reportDifference(result.queryId, result.candidates.map { it.id }, qualifying.toList())
                    result.copy(candidates = result.candidates.filter { it.id in qualifying })
                }
            }

            shared == null -> {
                // No answer, not an empty answer. Falling back keeps
                // presentations working where the engine cannot decide, which
                // is worth more than consistency. SharedDcqlMatcher has
                // already logged why — with the exception, when there was one
                // — so repeating it here would only double the noise on every
                // call.
                parsed
            }

            !shared.satisfiable -> {
                // §6.4: "MUST NOT return any Credential(s)" — not even the
                // queries that were answerable on their own. A request can ask
                // for two credentials and get one; offering that one lets a
                // user consent to a presentation that cannot satisfy the
                // verifier.
                //
                // Reported once for the request rather than per query. The
                // per-query line explains a decline as a missing claim, which
                // is the usual cause and the wrong one here.
                SharedDcqlMatcher.reportUnsatisfiable(
                    // One credential can be a candidate for several queries;
                    // the log names credentials, not candidacies.
                    parsed.flatMap { r -> r.candidates.map { it.id } }.distinct(),
                )
                parsed.map { it.copy(candidates = emptyList()) }
            }

            else -> parsed.map { result ->
                val ids = shared.candidatesByQuery[result.queryId].orEmpty()
                SharedDcqlMatcher.reportDifference(
                    result.queryId,
                    result.candidates.map { it.id },
                    ids,
                )
                // Built once per query, not once per candidate.
                val qualifying = ids.toSet()
                result.copy(candidates = result.candidates.filter { it.id in qualifying })
            }
        }

        val credentialSets = parseCredentialSets(dcqlQuery)
        val satisfiableOptions = if (credentialSets != null) {
            findSatisfiableOptions(credentialSets, queryResults)
        } else {
            emptyList()
        }

        return DcqlMatchOutput(
            queryResults = queryResults,
            credentialSets = credentialSets,
            satisfiableOptions = satisfiableOptions,
            hasCircuitZkQuery = hasCircuitZkQuery,
            unparsedQueryCount = unparsedQueryCount,
        )
    }

    /** Whether [query], as read from the request, asks for the `circuit_zk` format (without throwing on a malformed one). */
    private fun isCircuitZkQuery(query: JsonElement): Boolean =
        CredentialUtils.isCircuitZkFormat(((query as? JsonObject)?.get("format") as? JsonPrimitive)?.contentOrNull)

    /**
     * The engine that validates ordinary queries; [SharedDcqlMatcher.evaluate] unless a test
     * replaces it (the native library is not available to unit tests).
     */
    internal var engine: (JsonObject, List<StoredCredential>, List<String>, Set<String>) -> SharedDcqlMatcher.Outcome? =
        { query, credentials, zkSystemIds, claimlessDoctypes -> SharedDcqlMatcher.evaluate(query, credentials, zkSystemIds, claimlessDoctypes) }

    /** Whether two credential queries share an `id`, or two claims of one query do (§6.1, §6.3). */
    internal fun hasDuplicateDcqlIds(credentialQueries: JsonArray): Boolean {
        fun repeats(ids: List<String>) = ids.size != ids.toSet().size
        val queries = credentialQueries.mapNotNull { it as? JsonObject }
        if (repeats(queries.mapNotNull { (it["id"] as? JsonPrimitive)?.contentOrNull })) return true
        return queries.any { query ->
            repeats(
                (query["claims"] as? JsonArray).orEmpty()
                    .mapNotNull { ((it as? JsonObject)?.get("id") as? JsonPrimitive)?.contentOrNull },
            )
        }
    }

    /**
     * Flatten match results into a single list of matching credential IDs.
     * Suitable for passing to the engine's match response.
     */
    fun matchedCredentialIds(dcqlQuery: JsonObject, credentials: List<StoredCredential>): List<Long> {
        return match(dcqlQuery, credentials)
            .flatMap { it.candidates }
            .distinctBy { it.id }
            .map { it.id }
    }

    /**
     * Match stored credentials against an ISO 18013-5 mdoc `docType`
     * requested during a proximity (BLE/NFC) presentation - the mdoc
     * proximity protocol has no DCQL query, just a bare docType string in
     * the `DeviceRequest`'s `ItemsRequest`.
     */
    fun matchMdocDocType(credentials: List<StoredCredential>, docType: String): List<StoredCredential> {
        return credentials.filter { it.format == "mso_mdoc" && CredentialUtils.parseMdocDocument(it)?.docType == docType }
    }

    /**
     * The credential types a DCQL query asks for, in query order and
     * de-duplicated: `meta.vct_values` for SD-JWT VCs, `meta.doctype_value`
     * (and the plural `doctype_values` some verifiers send) for mdocs, and
     * the credential query's own `id` for a query that constrains neither.
     *
     * Lets the wallet say what is missing when nothing matched, rather than
     * only that nothing did. Deliberately the same rule
     * go-wallet-backend's `requestedCredentialTypes` applies, so the
     * wallet's reason and the engine's error name the same things.
     * Best-effort: a query shape neither side understands yields no names,
     * and every read is type-checked rather than coerced - a verifier that
     * sends JSON `null` where a string belongs must not crash matching (see
     * [matchDcql]'s callers for the same lesson learned the hard way).
     */
    fun requestedCredentialTypes(dcqlQuery: JsonObject): List<String> {
        val queries = dcqlQuery["credentials"] as? JsonArray ?: return emptyList()
        val types = LinkedHashSet<String>()
        for (element in queries) {
            val query = element as? JsonObject ?: continue
            val meta = query["meta"] as? JsonObject
            val vctValues = (meta?.get("vct_values") as? JsonArray)
                ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
            val doctypeValues = listOfNotNull((meta?.get("doctype_value") as? JsonPrimitive)?.contentOrNull) +
                (meta?.get("doctype_values") as? JsonArray)
                    ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
            if (vctValues.isEmpty() && doctypeValues.isEmpty()) {
                (query["id"] as? JsonPrimitive)?.contentOrNull?.let { types.add(it) }
            } else {
                types.addAll(vctValues)
                types.addAll(doctypeValues)
            }
        }
        return types.toList()
    }

    /**
     * Parse the `credential_sets` array from a DCQL query (OID4VP §6.2).
     *
     * @return Parsed credential set queries, or null if `credential_sets` is absent
     */
    fun parseCredentialSets(dcqlQuery: JsonObject): List<CredentialSetQuery>? {
        val setsArray = dcqlQuery["credential_sets"] as? JsonArray ?: return null
        if (setsArray.isEmpty()) return null

        return setsArray.mapNotNull { element ->
            val obj = element as? JsonObject ?: return@mapNotNull null
            val options = (obj["options"] as? JsonArray)?.mapNotNull { optElement ->
                (optElement as? JsonArray)?.mapNotNull { it.jsonPrimitive.contentOrNull }
                    ?.takeIf { it.isNotEmpty() }
            } ?: return@mapNotNull null
            if (options.isEmpty()) return@mapNotNull null

            val required = obj["required"]?.jsonPrimitive?.booleanOrNull ?: true
            CredentialSetQuery(options = options, required = required)
        }.takeIf { it.isNotEmpty() }
    }

    /**
     * Find which credential set options are satisfiable given match results.
     *
     * An option is satisfiable if every credential query ID in it has at
     * least one matching credential in the query results.
     */
    fun findSatisfiableOptions(
        credentialSets: List<CredentialSetQuery>,
        queryResults: List<MatchResult>,
    ): List<SatisfiableOption> {
        val queryResultsById = queryResults.associateBy { it.queryId }

        return credentialSets.flatMapIndexed { setIndex, credentialSet ->
            credentialSet.options.mapIndexedNotNull { optionIndex, queryIds ->
                val allSatisfied = queryIds.all { queryId ->
                    val result = queryResultsById[queryId]
                    result != null && result.candidates.isNotEmpty()
                }
                if (allSatisfied) {
                    SatisfiableOption(
                        credentialSetIndex = setIndex,
                        optionIndex = optionIndex,
                        queryIds = queryIds,
                    )
                } else {
                    null
                }
            }
        }
    }

    /** One `circuit_zk` query, decided by the planner, validator and circuit table. Fails closed. */
    private fun matchCircuitZkQuery(
        query: JsonObject,
        credentials: List<StoredCredential>,
        support: CircuitZkSupport,
        clientMetadata: JsonObject?,
    ): MatchResult? {
        val queryId = query["id"]?.jsonPrimitive?.contentOrNull ?: return null
        val evaluation = CircuitZkMatching.evaluate(query, clientMetadata, credentials, support)
        return MatchResult(
            queryId = queryId,
            format = query["format"]?.jsonPrimitive?.contentOrNull,
            candidates = evaluation.matched,
            requestedClaims = emptyList(),
            circuitZkPlan = evaluation.plan,
            circuitZkRefusal = evaluation.refusal,
        )
    }

    private fun matchSingleQuery(
        query: JsonObject,
        credentials: List<StoredCredential>,
    ): MatchResult? {
        val queryId = query["id"]?.jsonPrimitive?.contentOrNull ?: return null
        val format = query["format"]?.jsonPrimitive?.contentOrNull
        val meta = query["meta"]?.jsonObject
        val claims = parseClaims(query["claims"])

        // Extract type constraints
        val vctValues = meta?.get("vct_values")?.jsonArray
            ?.mapNotNull { it.jsonPrimitive.contentOrNull }
            ?.toSet()

        val doctypeValue = meta?.get("doctype_value")?.jsonPrimitive?.contentOrNull
        val zkSystemTypes = meta?.get("zk_system_type")?.jsonArray?.mapNotNull { parseZkSystemSpec(it) }
            ?.takeIf { it.isNotEmpty() }
        val ppidContext = meta?.get("ppid_context")?.jsonPrimitive?.contentOrNull

        val matched = credentials.filter { cred ->
            matchesFormat(cred, format) &&
                matchesVct(cred, vctValues) &&
                matchesDoctype(cred, doctypeValue) &&
                // A query for a protected claim matches nothing (see CredentialDisclosureGuard). A query with no `claims` at
                // all asks for the WHOLE attestation, which includes them: the empty path is an ancestor of every claim.
                !CredentialDisclosureGuard.requestsProtected(cred, claims.ifEmpty { listOf(emptyList()) })
        }

        Timber.d("DCQL query '$queryId': format=$format vct=$vctValues doctype=$doctypeValue → ${matched.size} matches")

        return MatchResult(
            queryId = queryId,
            format = format,
            candidates = matched,
            requestedClaims = claims,
            zkSystemTypes = zkSystemTypes,
            ppidContext = ppidContext,
        )
    }

    /**
     * Parses one entry of a DCQL query's `meta.zk_system_type` array into a
     * [ZkSystemSpec] - `{id, system, ...params}`. Confirmed via multipaz's
     * own parsing of this exact wire shape (`OpenID4VP.kt`'s
     * `for (param in entry) { if (key == "system" || key == "id") continue;
     * item.addParam(param.key, param.value) }`): every OTHER top-level key
     * on the entry (e.g. `num_attributes`, `version`, `circuit_hash`,
     * `block_enc_hash`, `block_enc_sig`) IS a param - there is no nested
     * `"params"` object on the wire. An earlier version of this parser
     * looked for `obj["params"]`, which never exists on a real request -
     * `zkSystemTypes` parsed successfully (id/system were still read) but
     * every param (including `num_attributes`) silently came back empty,
     * masking a real circuit-selection bug until it started being checked.
     */
    private fun parseZkSystemSpec(element: JsonElement): ZkSystemSpec? {
        val obj = element as? JsonObject ?: return null
        val id = obj["id"]?.jsonPrimitive?.contentOrNull ?: return null
        val system = obj["system"]?.jsonPrimitive?.contentOrNull ?: return null
        val params = obj.entries
            .filterNot { (key, _) -> key == "id" || key == "system" }
            .associate { (key, value) -> key to (value.jsonPrimitive.contentOrNull ?: "") }
        return ZkSystemSpec(id = id, system = system, params = params)
    }

    private fun matchesFormat(credential: StoredCredential, format: String?): Boolean {
        if (format == null) return true
        // Without circuit_zk support (the feature is off) such a query matches nothing, as it always has.
        if (CredentialUtils.isCircuitZkFormat(format)) return false
        if (format.equals("mso_mdoc_zk", ignoreCase = true)) {
            // A verifier requesting a ZK-wrapped presentation ("mso_mdoc_zk")
            // still matches a credential stored in the ordinary "mso_mdoc"
            // shape - producing a ZK proof is a presentation-time transform
            // (see ZkProofSystem.generateProof), not a distinct storage
            // format. There is no separate on-device "ZK credential" to store.
            return credential.format.equals("mso_mdoc", ignoreCase = true)
        }
        return credential.format.equals(format, ignoreCase = true)
    }

    private fun matchesVct(credential: StoredCredential, vctValues: Set<String>?): Boolean {
        if (vctValues == null || vctValues.isEmpty()) return true
        // The vct the credential itself carries, and only then the copy in
        // its metadata - the same order, and for the same reason, as
        // matchesDoctype below. `metadata` is a rendering artefact: it is
        // absent until the issuance flow has an offer to build it from, and
        // is repopulated later by hydration, which skips any credential
        // whose metadata is already real. Matching on it alone means a
        // credential that is present, valid and presentable is invisible to
        // DCQL for reasons that have nothing to do with the credential.
        //
        // Seen on the gdc environment: an EBW-OID credential issued minutes
        // earlier, carrying `vct: uri:eu.ebw.oid.1`, against a query asking
        // for exactly that - 0 matches, while the PID next to it matched.
        val credVct = CredentialUtils.vctOf(credential) ?: return false
        return credVct in vctValues
    }

    private fun matchesDoctype(credential: StoredCredential, doctypeValue: String?): Boolean {
        if (doctypeValue == null) return true
        // The real docType, parsed from the credential's own MSO - NOT
        // credential.metadata?.doctype, which only gets populated if this
        // credential's issuer happens to expose an MDDL schema endpoint at
        // our internal /type-metadata/<scope> convention. A third-party
        // issuer (e.g. a real interop test event's mDL) has no reason to
        // implement that, so relying on it here silently made every such
        // credential unmatchable via DCQL, even though it's otherwise a
        // perfectly valid, presentable credential.
        val credDoctype = CredentialUtils.parseMdocDocument(credential)?.docType
            ?: credential.metadata?.doctype
            ?: return false
        return credDoctype == doctypeValue
    }

    private fun parseClaims(element: JsonElement?): List<List<String>> {
        if (element == null || element !is JsonArray) return emptyList()
        return element.mapNotNull { claimElement ->
            val obj = claimElement as? JsonObject ?: return@mapNotNull null
            val path = (obj["path"] as? JsonArray)
                ?.mapNotNull { it.jsonPrimitive.contentOrNull }
            path
        }
    }
}
