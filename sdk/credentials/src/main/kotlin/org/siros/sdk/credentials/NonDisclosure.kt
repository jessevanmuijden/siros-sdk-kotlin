// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.Json

/**
 * Claims the wallet never discloses, matches on, registers or displays: a data
 * table keyed by credential type (an mdoc `docType` or an SD-JWT `vct`) to the
 * protected claim paths of that type. Nothing in the logic is tied to a
 * particular type; a type with no entry is unaffected.
 *
 * A path is the DCQL claim path: `[namespace, element]` for an mdoc, the claim
 * name path for an SD-JWT. A protected path covers itself and everything below
 * it.
 */
class NonDisclosurePolicy(protectedPaths: Map<String, Set<List<String>>>) {
    private val protectedByType: Map<String, Set<List<String>>> = protectedPaths.mapValues { it.value.toSet() }

    /** The types this policy has an entry for. */
    val types: Set<String> get() = protectedByType.keys

    /** The protected paths of [type] (empty for a type without an entry). */
    fun protectedPaths(type: String?): Set<List<String>> = type?.let { protectedByType[it] }.orEmpty()

    /** Whether the claim at [path] of a credential of [type] is protected. */
    fun isProtected(type: String?, path: List<String>): Boolean =
        protectedPaths(type).any { p -> path.size >= p.size && path.subList(0, p.size) == p }

    /**
     * Whether asking for any of [requested] would reach a protected claim:
     * a protected path or something below it, or an ancestor of one (a whole
     * namespace, say).
     */
    fun requestsProtected(type: String?, requested: List<List<String>>): Boolean {
        val protectedHere = protectedPaths(type)
        if (protectedHere.isEmpty()) return false
        return requested.any { r ->
            protectedHere.any { p ->
                (r.size >= p.size && r.subList(0, p.size) == p) || (r.size < p.size && p.subList(0, r.size) == r)
            }
        }
    }

    /**
     * The policy protecting everything either policy protects (per type, the
     * union of the protected paths). Returns [this] or [other] when one already
     * covers the other, so a single policy is never copied.
     */
    fun union(other: NonDisclosurePolicy): NonDisclosurePolicy {
        if (other === this || other.protectedByType.isEmpty()) return this
        if (protectedByType.isEmpty()) return other
        val merged = (protectedByType.keys + other.protectedByType.keys).associateWith { t ->
            protectedByType[t].orEmpty() + other.protectedByType[t].orEmpty()
        }
        return when (merged) {
            protectedByType -> this
            other.protectedByType -> other
            else -> NonDisclosurePolicy(merged)
        }
    }

    companion object {
        /** The nym_auth document type, whose `ssc` and `psc` are seed commitments. */
        const val NYM_AUTH_DOCTYPE = "eu.europa.ec.eudi.nym_auth.1"

        /** The nym_auth attestation of the `bbs_cd` source format (held). */
        const val NYM_AUTH_BBS_TYPE = "eu.europa.ec.eudi.nym_auth.bbs.1"

        /** The elements of a nym_auth attestation that are never disclosed (rulebook v0.4): the seeds and `birth_date`. */
        // A claim-name guard, not a wire shape: a claim called secret_seed must never be disclosable, even if some old credential carries one.
        private val NYM_AUTH_PROTECTED = listOf("ssc", "psc", "secret_seed", "birth_date")

        /**
         * The default data: `ssc`, `psc`, `secret_seed` and `birth_date` of a nym_auth attestation (both types). A request
         * through any format other than `zkp_req` that names one of them, uses a wildcard path or asks for the whole
         * attestation does not match it. `birth_date` of any OTHER credential is an ordinary claim: the entry is per type.
         * `age_check` reads `birth_date` locally to prove a bound; the value itself is never disclosed.
         */
        val DEFAULT = NonDisclosurePolicy(
            listOf(NYM_AUTH_DOCTYPE, NYM_AUTH_BBS_TYPE).associateWith { type -> NYM_AUTH_PROTECTED.map { listOf(type, it) }.toSet() },
        )

        /** No protected claims anywhere. */
        val NONE = NonDisclosurePolicy(emptyMap())
    }
}

/**
 * A presentation would have disclosed a protected claim. The wallet refuses
 * it outright: stripping the claim would hand the verifier a presentation
 * that looks complete and is not. The message names no claim.
 */
class DisclosureRefusedException : SirosException(
    "A presentation would disclose a protected claim; refused",
    errorCode = "protected_claim_refused",
)

/**
 * The one guard behind every enforcement point: matching, the OS picker blob,
 * presentation building, display. It consults the policy in force.
 *
 * The enforcement points are stateless utilities, so the guard is process-wide,
 * but no wallet can weaken another: each `SirosWallet` [register]s its own
 * policy and the policy in force is the union of every live registration (what
 * any wallet protects is protected). A wallet configured with
 * [NonDisclosurePolicy.NONE] therefore only lifts the protection while no
 * other wallet in the process asks for it. Registrations are weak, and
 * [unregister] drops one explicitly.
 */
object CredentialDisclosureGuard {
    private val lock = Any()
    private val registrations = java.util.WeakHashMap<Any, NonDisclosurePolicy>()

    @Volatile
    private var inForce: NonDisclosurePolicy = NonDisclosurePolicy.DEFAULT

    /**
     * The policy in force. Reading returns the union of the registered policies
     * (the default while none is registered). Assigning replaces everything
     * registered with [value]: for apps and tests that manage the policy
     * themselves, not for wallets.
     */
    var policy: NonDisclosurePolicy
        get() = inForce
        set(value) = synchronized(lock) {
            registrations.clear()
            inForce = value
        }

    /** Registers [policy] for [owner] (replacing its earlier one); the policy in force is recomputed. */
    fun register(owner: Any, policy: NonDisclosurePolicy) = synchronized(lock) {
        registrations[owner] = policy
        recompute()
    }

    /** Drops [owner]'s registration. */
    fun unregister(owner: Any) = synchronized(lock) {
        if (registrations.remove(owner) != null) recompute()
    }

    private fun recompute() {
        inForce = registrations.values.reduceOrNull { a, b -> a.union(b) } ?: NonDisclosurePolicy.DEFAULT
    }

    private val json = Json { ignoreUnknownKeys = true }

    /** The type the policy is keyed by for [credential]: its mdoc `docType` or its SD-JWT `vct`. */
    fun typeOf(credential: StoredCredential): String? =
        if (credential.format.equals("mso_mdoc", ignoreCase = true)) {
            CredentialUtils.parseMdocDocument(credential)?.docType ?: credential.metadata?.doctype
        } else {
            CredentialUtils.vctOf(credential)
        }

    /** Whether the claim at [path] of [type] is protected. */
    fun isProtected(type: String?, path: List<String>): Boolean = policy.isProtected(type, path)

    /** Whether asking for [requested] of [type] would reach a protected claim, as [NonDisclosurePolicy.requestsProtected]. */
    fun requestsProtected(type: String?, requested: List<List<String>>): Boolean = policy.requestsProtected(type, requested)

    /** Whether asking for [requested] of [credential] would reach a protected claim. */
    fun requestsProtected(credential: StoredCredential, requested: List<List<String>>): Boolean {
        if (policy.types.isEmpty()) return false
        return policy.requestsProtected(typeOf(credential), requested)
    }

    /**
     * Fail-closed check for an mdoc presentation about to disclose [disclosed]
     * (namespace to element identifiers).
     *
     * @throws DisclosureRefusedException if any of them is protected.
     */
    fun requireNoneProtected(docType: String, disclosed: Map<String, Collection<String>>) {
        for ((namespace, elements) in disclosed) {
            for (element in elements) {
                // Ancestor-aware: an element holding a protected sub-path is refused too.
                if (policy.requestsProtected(docType, listOf(listOf(namespace, element)))) throw DisclosureRefusedException()
            }
        }
    }

    /**
     * Fail-closed check for an SD-JWT presentation about to carry
     * [selectedDisclosures] of the compact [credential].
     *
     * It covers both halves of what a presentation reveals: the selected disclosures, and the
     * always-disclosed claims in the issuer JWT payload, which every presentation carries unchanged
     * (so a protected claim stored there is refused even with no disclosure selected at all).
     *
     * @throws DisclosureRefusedException if the presentation would carry a protected claim.
     */
    fun requireNoneProtectedSdJwt(credential: String, selectedDisclosures: List<String>) {
        if (policy.types.isEmpty()) return
        var payloadObj: JsonObject? = null
        val vct = try {
            val payload = credential.substringBefore('~').split('.').getOrNull(1) ?: return
            val obj = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(payload), Charsets.UTF_8)) as? JsonObject
            payloadObj = obj
            (obj?.get("vct") as? JsonPrimitive)?.contentOrNull
        } catch (e: Exception) {
            null
        } ?: return
        val protectedHere = policy.protectedPaths(vct)
        if (protectedHere.isEmpty()) return
        if (payloadObj != null && carriesProtectedCleartext(vct, payloadObj, emptyList(), 0)) throw DisclosureRefusedException()
        val pathsByDigest = disclosurePaths(credential)
        for (disclosure in selectedDisclosures) {
            val name = try {
                val array = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(disclosure), Charsets.UTF_8)) as? JsonArray
                (array?.getOrNull(1) as? JsonPrimitive)?.takeIf { it.isString }?.content
            } catch (e: Exception) {
                // Unreadable: it could be anything, so it is not sent.
                throw DisclosureRefusedException()
            }
            if (name == null) continue
            // A disclosure is refused when its claim path is protected, below a protected
            // path, or an ancestor of one (an `address` object holding a protected
            // `address.secret`). Its path comes from where its digest sits in the credential;
            // a disclosure not found there (a nested one whose parent is not carried, say)
            // cannot be placed, so any protected path that mentions its name refuses it.
            val path = pathsByDigest[digestOf(disclosure)]
            val refused = if (path != null) {
                policy.requestsProtected(vct, listOf(path))
            } else {
                policy.requestsProtected(vct, listOf(listOf(name))) || protectedHere.any { name in it }
            }
            if (refused) throw DisclosureRefusedException()
        }
    }

    /**
     * What a raw-credential debug view may show of [credential]: the whole of it when its type
     * protects nothing, otherwise a redacted view. Redaction is ancestor-aware and segment-based
     * (as the other enforcement points): cleartext payload claims that are protected, below a
     * protected path or hold one are dropped, and so are the disclosures whose placed path is
     * protected, below one or holds one. A disclosure that cannot be placed is dropped when a
     * protected path mentions its name, and an array-element disclosure (no claim name) is always
     * dropped for a protected type. A format that cannot be redacted structurally (an mdoc) shows
     * no raw text at all for a protected type.
     */
    fun rawViewOf(credential: StoredCredential): RawCredentialView {
        val raw = credential.raw
        val type = typeOf(credential)
        val protectedHere = policy.protectedPaths(type)
        if (protectedHere.isEmpty()) {
            val parts = CredentialUtils.parseSdJwtParts(raw)
            val unparseable = parts.header == null && parts.payload == null && parts.disclosures.isEmpty()
            return RawCredentialView(parts, rawText = if (unparseable) raw else null, redacted = false)
        }
        val none = SdJwtParts(null, null, emptyList())
        if (credential.format.equals("mso_mdoc", ignoreCase = true) || type == null) {
            return RawCredentialView(none, rawText = null, redacted = true)
        }
        val parts = CredentialUtils.parseSdJwtParts(raw)
        val payload = parts.payload?.let { redactObject(type, it, emptyList(), 0) }
        val pathsByDigest = disclosurePaths(raw)
        val kept = ArrayList<JsonElement>()
        for (segment in raw.split('~').drop(1).filter { it.isNotBlank() }) {
            val array = try {
                json.parseToJsonElement(String(Base64.getUrlDecoder().decode(segment), Charsets.UTF_8)) as? JsonArray
            } catch (e: Exception) {
                null
            } ?: continue
            val name = (array.getOrNull(1) as? JsonPrimitive)?.takeIf { it.isString }?.content
            if (array.size != 3 || name == null) continue
            val path = pathsByDigest[digestOf(segment)]
            val refused = if (path != null) {
                policy.requestsProtected(type, listOf(path))
            } else {
                policy.requestsProtected(type, listOf(listOf(name))) || protectedHere.any { name in it }
            }
            if (refused) continue
            // A kept object-valued disclosure may still hold a protected descendant.
            val value = array[2]
            val redactedValue = if (value is JsonObject && path != null) redactObject(type, value, path, 0) else value
            kept.add(JsonArray(listOf(array[0], array[1], redactedValue)))
        }
        return RawCredentialView(SdJwtParts(parts.header, payload, kept), rawText = null, redacted = true)
    }

    private fun redactObject(vct: String, obj: JsonObject, prefix: List<String>, depth: Int): JsonObject {
        if (depth > 32) return JsonObject(emptyMap())
        val out = LinkedHashMap<String, JsonElement>()
        for ((key, value) in obj) {
            val path = prefix + key
            if (key != "_sd" && policy.requestsProtected(vct, listOf(path)) && value !is JsonObject) continue
            if (key != "_sd" && policy.isProtected(vct, path)) continue
            out[key] = if (value is JsonObject && key != "_sd") redactObject(vct, value, path, depth + 1) else value
        }
        return JsonObject(out)
    }

    /**
     * Whether [obj], a cleartext (always-disclosed) object of the issuer payload at [prefix],
     * holds a protected claim. The path is built from the original segments, never a dotted key.
     * An object is searched below; a protected path or something under it is refused, and so is a
     * non-object value (an array, say) sitting at an ancestor of a protected path, which cannot be
     * searched by path. `_sd` digests are not cleartext claims: the disclosures they point to are
     * the other half of the guard.
     */
    private fun carriesProtectedCleartext(vct: String, obj: JsonObject, prefix: List<String>, depth: Int): Boolean {
        // Too deep to walk: it could hold anything, so it is not sent.
        if (depth > 32) return true
        for ((key, value) in obj) {
            if (prefix.isEmpty() && (key == "_sd" || key == "_sd_alg")) continue
            if (prefix.isNotEmpty() && key == "_sd") continue
            val path = prefix + key
            if (policy.isProtected(vct, path)) return true
            if (value is JsonObject) {
                if (carriesProtectedCleartext(vct, value, path, depth + 1)) return true
            } else if (policy.requestsProtected(vct, listOf(path))) {
                return true
            }
        }
        return false
    }

    internal fun digestOf(disclosure: String): String =
        Base64.getUrlEncoder().withoutPadding()
            .encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(disclosure.toByteArray(Charsets.UTF_8)))

    /**
     * The claim path of every object-property disclosure carried by [credential], keyed by the
     * disclosure's digest: found by walking the issuer payload and each disclosed object's `_sd`
     * lists from the root. A disclosure no walk reaches has no entry.
     */
    internal fun disclosurePaths(credential: String): Map<String, List<String>> {
        val parts = credential.split('~')
        val payload = try {
            val body = parts[0].split('.').getOrNull(1) ?: return emptyMap()
            json.parseToJsonElement(String(Base64.getUrlDecoder().decode(body), Charsets.UTF_8)) as? JsonObject ?: return emptyMap()
        } catch (e: Exception) {
            return emptyMap()
        }
        val byDigest = HashMap<String, Pair<String, kotlinx.serialization.json.JsonElement>>()
        for (segment in parts.drop(1).filter { it.isNotEmpty() }) {
            try {
                val array = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(segment), Charsets.UTF_8)) as? JsonArray ?: continue
                if (array.size != 3) continue
                val claimName = (array[1] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: continue
                byDigest[digestOf(segment)] = claimName to array[2]
            } catch (e: Exception) {
                continue
            }
        }
        val result = HashMap<String, List<String>>()
        fun walk(obj: JsonObject, prefix: List<String>, depth: Int) {
            if (depth > 32) return
            for ((key, value) in obj) {
                if (key == "_sd") {
                    for (d in (value as? JsonArray).orEmpty()) {
                        val digest = (d as? JsonPrimitive)?.contentOrNull ?: continue
                        val (claimName, claimValue) = byDigest[digest] ?: continue
                        val path = prefix + claimName
                        result[digest] = path
                        if (claimValue is JsonObject) walk(claimValue, path, depth + 1)
                    }
                } else if (value is JsonObject) {
                    walk(value, prefix + key, depth + 1)
                }
            }
        }
        walk(payload, emptyList(), 0)
        return result
    }
}

/**
 * What a raw-credential debug view may show: [parts] decoded (redacted when [redacted]), or
 * [rawText] when the credential is not an SD-JWT and nothing is protected. With [redacted] and no
 * parts there is nothing to show.
 */
data class RawCredentialView(
    val parts: SdJwtParts,
    val rawText: String?,
    val redacted: Boolean,
)
