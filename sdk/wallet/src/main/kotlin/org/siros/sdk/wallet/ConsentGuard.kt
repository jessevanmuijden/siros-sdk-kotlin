// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.SirosException
import org.siros.sdk.transport.engine.CredentialRef

/**
 * What the user consented to disclose for one (query, credential) pair - the SAME value this wallet reported in its own
 * `consent` flow action, the one thing an engine cannot have invented on its own.
 *
 * [claims] null means the WHOLE credential was consented with no claim-level restriction (a DCQL query with no `claims`
 * array, or a non-DCQL match) - distinct from an explicit, empty claim set. The distinction matters downstream: some
 * signers (mdoc) read an empty disclosed-claims list as "disclose nothing", others (SD-JWT) read it as "disclose
 * everything" - [ConsentGuard.verify] never collapses the two, so callers must pass [claims] through as recorded, not
 * normalize it to empty.
 */
internal data class ConsentedSelection(val queryId: String?, val credentialId: String, val claims: Set<String>?)

/**
 * The consent recorded for one flow, exactly as sent to the engine's `consent` flow action (see
 * [SirosWallet.handleCredentialSelection]). Immutable; built once, read (never mutated) by [ConsentGuard].
 */
internal class ConsentRecord private constructor(private val byKey: Map<Pair<String?, String>, Set<String>?>?) {
    constructor(selections: List<ConsentedSelection>) : this(selections.associate { (it.queryId to it.credentialId) to it.claims } as Map<Pair<String?, String>, Set<String>?>?)

    /** Whether [queryId]/[credentialId] was part of this consent at all. */
    fun contains(queryId: String?, credentialId: String): Boolean = byKey == null || byKey.containsKey(queryId to credentialId)

    /**
     * The consented claims for [queryId]/[credentialId]: null means the WHOLE credential was consented (no claim-level
     * restriction). Callers must check [contains] first - this returns null both for "not consented" and for "consented,
     * unrestricted", which [ConsentGuard.verify] tells apart via [contains].
     */
    operator fun get(queryId: String?, credentialId: String): Set<String>? = byKey?.get(queryId to credentialId)

    companion object {
        /**
         * TEST-ONLY: a record that answers EVERY (query, credential) pair as consented with no claim-level restriction, so
         * a test exercising something else entirely is not required to know about this defence-in-depth check. Production
         * code never constructs one.
         */
        fun unrestrictedForTests(): ConsentRecord = ConsentRecord(null)
    }
}

/** Why [ConsentGuard.verify] refused a batch. [detail] names no claim value - only ids, counts and indices. */
internal sealed class ConsentMismatchReason(val detail: String) {
    data object NoRecord : ConsentMismatchReason("no consent was recorded for this flow")
    data class MalformedEntry(val index: Int) : ConsentMismatchReason("entry $index names no credential")
    data class UnknownSelection(val index: Int) : ConsentMismatchReason("entry $index names a credential/query the user was not asked to consent to")
    data class ExtraClaims(val index: Int, val count: Int) : ConsentMismatchReason("entry $index asks to disclose $count claim(s) the user did not consent to")
}

/**
 * The engine's `sign_presentation`/`generate_proof` request round-trips `credentials_to_include` from what THIS wallet itself
 * reported in its own `consent` flow action - a buggy or compromised engine could instead ask to disclose more than that
 * (e.g. consent for one claim, `credentials_to_include` naming every claim of the credential). Never thrown by [SirosException]
 * logging only; never the user's claim values.
 */
internal class ConsentMismatchException(val reason: ConsentMismatchReason) :
    SirosException("The request to sign does not match what was consented to (${reason.detail})", errorCode = "consent_mismatch")

/**
 * Defence in depth against a buggy or compromised engine: [verify] checks every entry of [refs] against [record] - the exact
 * selections this wallet itself sent in its own `consent` flow action - and returns, PER (query, credential) pair, the claims
 * to actually disclose. Callers MUST use the returned map, never [refs]' own `disclosedClaims`: a null or empty value there is
 * not a trivially safe "nothing more than usual" input, since some signing paths read an empty/absent claim list as "disclose
 * everything" (full mdoc/SD-JWT disclosure). Order-independent (accepts reordering of [refs] relative to how they were
 * consented); an unknown query/credential pair, a malformed entry (no credential id), a missing record for the flow, or any
 * claim outside the consented set refuses the WHOLE batch - fail closed, before anything is signed. Pure; never logs.
 */
internal object ConsentGuard {
    /**
     * Returns, per (query, credential) pair, the claims to actually disclose: null means the WHOLE credential was
     * consented (no restriction) - callers must pass that null straight through to the signer, never default it to an
     * empty list (see [ConsentedSelection]'s doc comment for why that is not equivalent for every signer).
     */
    fun verify(record: ConsentRecord?, refs: List<CredentialRef>): Map<Pair<String?, String>, Set<String>?> {
        // Nothing to check against nothing to disclose: a caller that was going to refuse for an unrelated reason (SCA
        // disabled, no transaction_data) before it even looks at credentials_to_include must not be pre-empted by this.
        if (refs.isEmpty()) return emptyMap()
        if (record == null) throw ConsentMismatchException(ConsentMismatchReason.NoRecord)
        val out = LinkedHashMap<Pair<String?, String>, Set<String>?>()
        refs.forEachIndexed { i, ref ->
            val credId = ref.credentialId.takeIf { it.isNotEmpty() } ?: throw ConsentMismatchException(ConsentMismatchReason.MalformedEntry(i))
            val key = ref.credentialQueryId to credId
            if (!record.contains(key.first, key.second)) throw ConsentMismatchException(ConsentMismatchReason.UnknownSelection(i))
            val consented = record[key.first, key.second]
            // null consented = whole credential, no restriction: whatever specific claims the engine names here were
            // already shown to the user at consent time, so there is nothing to compare against.
            if (consented != null) {
                val asked = ref.disclosedClaims.orEmpty().toSet()
                if (!consented.containsAll(asked)) {
                    throw ConsentMismatchException(ConsentMismatchReason.ExtraClaims(i, (asked - consented).size))
                }
            }
            out[key] = consented
        }
        return out
    }
}
