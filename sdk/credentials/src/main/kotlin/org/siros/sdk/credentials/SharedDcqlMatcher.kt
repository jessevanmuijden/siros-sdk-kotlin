// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonObject
import timber.log.Timber
import uniffi.siros_dc_matcher_ffi.FfiClaim
import uniffi.siros_dc_matcher_ffi.FfiCredential
import uniffi.siros_dc_matcher_ffi.SirosBlobBuilder
import uniffi.siros_dc_matcher_ffi.matchDcql as ffiMatchDcql

/**
 * DCQL matching by the shared Rust engine, the same one the OS credential
 * picker runs.
 *
 * [CredentialMatcher] implements a subset of DCQL: it filters on format and
 * type metadata, and does not check that a credential actually has the claims
 * a verifier asked for. OpenID4VP 1.0 §6.4.1 requires that check - a
 * credential missing a requested claim "MUST NOT" be returned - so today a
 * user can be offered a credential, consent, and have the presentation fail to
 * satisfy the verifier. `claim_sets` and `values` are missing too, and the
 * Swift SDK implements a slightly different subset again.
 *
 * This exists to retire all three implementations in favour of one that is
 * tested against the specification's own examples.
 *
 * ## Not yet trusted
 *
 * [CredentialMatcher] still decides the result. This runs alongside it and
 * reports where the two disagree, because the change it brings is not
 * cosmetic: enforcing §6.4.1 *narrows* what a wallet offers, correctly, and a
 * user whose credential stops appearing deserves that to be one deliberate
 * change rather than a side effect of another. Switching over is a separate
 * step, once the disagreements on real requests are understood.
 */
internal object SharedDcqlMatcher {

    /**
     * What the shared engine decided.
     *
     * [satisfiable] is not derivable from [candidatesByQuery]. A request can
     * ask for two credentials and get one: the answerable query has
     * candidates, and the request as a whole still must offer nothing
     * (§6.4). Carrying the flag rather than collapsing it into an empty map
     * keeps the two reasons for offering nothing distinguishable — which
     * matters, because they are explained to a user differently.
     */
    internal data class Outcome(
        /** Whether anything at all may be offered (§6.4). */
        val satisfiable: Boolean,
        /** Per-query candidates, complete and uncapped. */
        val candidatesByQuery: Map<String, List<Long>>,
    )

    /**
     * What the shared engine matched, or `null` if it could not run.
     *
     * `null` is not "nothing matched". The native library may be missing for
     * this ABI, or the engine may reject a request this SDK would have
     * accepted - both mean "no answer", and a caller must not read that as an
     * empty match.
     */
    fun evaluate(
        dcqlQuery: JsonObject,
        credentials: List<StoredCredential>,
    ): Outcome? {
        return try {
            // `use`: the builder holds a native handle, and matching runs on every
            // presentation.
            val blob = SirosBlobBuilder().use { builder ->
                credentials.forEach { builder.addCredential(toFfi(it)) }
                builder.build()
            }
            val outcome = ffiMatchDcql(blob, dcqlQuery.toString())
            // `matches`, not `combinations`. The engine bounds how many
            // combinations it returns, because the count is a product of the
            // per-query candidate counts — so reconstructing per-query
            // candidates from them would omit credentials that do qualify, and
            // this result is used to *filter*. An omission there is a
            // credential silently missing from what the user is offered, which
            // is the exact failure this component is prone to.
            //
            // `matches` is the engine's own per-query candidates, complete and
            // uncapped, so `dropped` does not bear on this answer at all.
            // It is also populated whether or not the request can be satisfied
            // as a whole, which is why `satisfiable` is carried alongside it
            // rather than inferred from it.
            Outcome(
                satisfiable = outcome.satisfiable,
                candidatesByQuery = outcome.matches.associate { queryMatch ->
                    queryMatch.queryId to queryMatch.credentials
                        .mapNotNull { it.credentialId.toLongOrNull() }
                        .distinct()
                },
            )
        } catch (e: Throwable) {
            // Deliberately broad. This is the first call into a native library
            // on the presentation path, and an UnsatisfiedLinkError from a
            // packaging mistake is an Error rather than an Exception -
            // catching only Exception would let it escape and take a
            // presentation down for a decision that has a fallback.
            Timber.w(e, "Shared DCQL engine unavailable; keeping the built-in matcher's answer")
            null
        }
    }

    /**
     * Report where the two implementations disagree, for one credential query.
     *
     * Logged rather than thrown. The shared engine decides now, so a
     * disagreement is not a fault - it is almost always the engine correctly
     * declining a credential that lacks a claim the verifier asked for, which
     * the built-in matcher never checked (OID4VP 1.0 §6.4.1). Recorded because
     * "my credential stopped appearing" is a support question, and this is the
     * line that answers it.
     */
    fun reportUnsatisfiable(builtIn: List<Long>) {
        Timber.i(
            "The shared engine declined the request as a whole (OID4VP 1.0 §6.4): some part of " +
                "it cannot be answered, so none of it may be offered. The built-in matcher would " +
                "have offered %s. This is not a per-credential decline - no credential here is " +
                "missing a requested claim",
            builtIn,
        )
    }

    fun reportDifference(queryId: String, builtIn: List<Long>, shared: List<Long>) {
        val onlyBuiltIn = builtIn - shared.toSet()
        val onlyShared = shared - builtIn.toSet()
        if (onlyBuiltIn.isEmpty() && onlyShared.isEmpty()) return

        Timber.i(
            "DCQL query '%s': the shared engine declined %s that the built-in matcher would " +
                "have offered (most likely a requested claim the credential lacks, " +
                "OID4VP 1.0 §6.4.1), and offered %s it would not",
            queryId,
            onlyBuiltIn,
            onlyShared,
        )
    }

    private fun toFfi(cred: StoredCredential) = FfiCredential(
        id = cred.id.toString(),
        format = cred.format,
        // The real docType, from the credential's own MSO - not issuer
        // metadata, which is only populated when the issuer happens to expose
        // a SIROS-internal schema endpoint.
        doctype = CredentialUtils.parseMdocDocument(cred)?.docType ?: cred.metadata?.doctype,
        // Likewise the vct the credential itself declares - the shared
        // engine matches on this, and the metadata copy is absent until
        // something has built it.
        vct = CredentialUtils.vctOf(cred),
        title = cred.metadata?.name ?: cred.format,
        subtitle = cred.metadata?.issuer?.name ?: "",
        iconId = null,
        claims = buildFfiClaims(cred),
    )

    /**
     * Builds the shared engine's claim list for one credential.
     *
     * mdoc keeps using [CredentialUtils.extractClaims] (a *display*
     * function) + [splitClaimKey]'s dotted-namespace split - correct there,
     * since an mdoc's own claims are always exactly `[namespace, element]`.
     *
     * JSON-based credentials (`dc+sd-jwt`, `jwt_vc_json`, ...) instead use
     * [CredentialUtils.flattenClaimPaths] directly, NOT `extractClaims` +
     * [splitClaimKey] the way mdoc does - two compounding bugs made that
     * combination wrong here (found via a real user report of a verifier's
     * nested claim path, e.g. `registered_address.full_address`, always
     * failing to match even though the wallet held a credential with
     * exactly that claim):
     *
     * 1. `extractClaims` only exposes a nested claim if VCTM explicitly
     *    declares that exact sub-path; anything VCTM doesn't cover is
     *    dumped as ONE un-recursed claim for the whole top-level value, so
     *    a verifier's request for a specific field inside it can never
     *    match. `flattenClaimPaths` walks every nested object regardless of
     *    VCTM coverage.
     * 2. Even when VCTM DOES declare the nested path, `extractClaims`
     *    collapses it into a single dotted string
     *    (`claim.path.joinToString(".")`, purely a display convenience),
     *    and `splitClaimKey` cannot tell that dot apart from a literal dot
     *    that belongs to a single non-mdoc claim name - it just returns the
     *    string whole either way, so the engine received a ONE-segment
     *    path (`["registered_address.full_address"]`) for what should have
     *    been two (`["registered_address", "full_address"]"`).
     *    `flattenClaimPaths` returns real path arrays throughout, with no
     *    join/resplit step to lose that boundary at all.
     */
    internal fun buildFfiClaims(cred: StoredCredential): List<FfiClaim> {
        if (cred.format.equals("mso_mdoc", ignoreCase = true)) {
            return CredentialUtils.extractClaims(cred).map { claim ->
                FfiClaim(
                    path = splitClaimKey(cred.format, claim.key),
                    value = claim.value,
                    display = claim.label,
                    displayValue = null,
                )
            }
        }
        val labelsByPath = cred.metadata?.claims.orEmpty().associate { it.path to it.label }
        return CredentialUtils.flattenClaimPaths(cred).map { (path, value) ->
            FfiClaim(
                path = path,
                value = CredentialUtils.formatClaimValue(value),
                display = labelsByPath[path] ?: CredentialUtils.formatClaimKey(path.last()),
                displayValue = null,
            )
        }
    }

    /**
     * Split a display-claim key into the path components DCQL matches
     * against - mdoc only; see [buildFfiClaims]'s doc comment for why
     * JSON-based credentials no longer go through this at all.
     *
     * mdoc element identifiers never contain dots while namespaces
     * routinely do, so the split is on the last one -
     * `org.iso.18013.5.1.family_name` is a namespace and an element, not
     * five path components.
     */
    internal fun splitClaimKey(format: String, key: String): List<String> =
        if (format.equals("mso_mdoc", ignoreCase = true) && key.contains('.')) {
            listOf(key.substringBeforeLast('.'), key.substringAfterLast('.'))
        } else {
            listOf(key)
        }
}
