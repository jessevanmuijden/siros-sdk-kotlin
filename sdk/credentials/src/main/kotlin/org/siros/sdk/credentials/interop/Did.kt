// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.interop

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import java.net.URLDecoder
import java.util.Base64

/** A DID method this SDK knows by name. */
enum class DidMethod(val methodName: String) {
    /** `did:jwk` - the key itself, base64url-encoded into the identifier. Resolves offline. */
    JWK("jwk"),

    /** `did:web` - the DID document served over HTTPS from a domain the DID names. */
    WEB("web"),

    /**
     * `did:webvh` - `did:web` plus a verifiable, append-only history of the
     * document. A DIIP Future Direction, not yet required by any release.
     * Resolved (or not) by go-trust like any other network method.
     */
    WEBVH("webvh"),

    /**
     * `did:key` - the key encoded as a multicodec. Predates DIIP in this SDK
     * and in wallet-frontend; a wallet holding credentials bound to one keeps
     * working, but no DIIP version requires it.
     */
    KEY("key"),
    ;

    companion object {
        /** The method of a DID string, or null if it is not a DID or the method is unknown. */
        fun of(did: String): DidMethod? {
            val name = methodName(did) ?: return null
            return entries.firstOrNull { it.methodName == name }
        }

        /**
         * The method name of any syntactically valid DID, named here or not.
         *
         * Which DID methods actually resolve is go-trust's answer, not this
         * SDK's. [of] only says whether this SDK knows a method by name -
         * which is what a profile's list of required methods is about - and
         * must not be used to decide what may be delegated.
         */
        fun methodName(did: String): String? {
            if (!did.startsWith("did:")) return null
            val rest = did.removePrefix("did:")
            val method = rest.substringBefore(':')
            // A DID is `did:<method>:<id>`; a method with no identifier after
            // it is not one.
            if (method.isEmpty() || method.length == rest.length) return null
            if (rest.substring(method.length + 1).isEmpty()) return null
            return method
        }
    }
}

/**
 * The subset of a DID document this SDK reads: the verification methods and
 * which relationships they take part in.
 *
 * DIIP names keys by relationship - an Issuer signs with a key from
 * `assertionMethod`, a Holder's `cnf.kid` points into `authentication` - so a
 * document is only useful here if it keeps that distinction.
 */
data class DidDocument(
    /** The DID this document describes. */
    val id: String,
    /** Verification methods by their full id (`<did>#<fragment>`). */
    val verificationMethods: Map<String, VerificationMethod>,
    /** Verification method ids in the `authentication` relationship. */
    val authentication: List<String> = emptyList(),
    /** Verification method ids in the `assertionMethod` relationship. */
    val assertionMethod: List<String> = emptyList(),
) {
    /**
     * The public JWK (as a JSON object) named by [kid] within [relationship].
     *
     * A null [kid] means "whichever key this relationship has", which is the
     * only thing a verifier can do when the credential or proof did not name
     * one - unambiguous for `did:jwk`, which has exactly one.
     */
    /**
     * @param relationship which verification relationship the key must be
     *   authorized for. A key absent from that relationship is not returned,
     *   even when the document has no other keys - see the body.
     */
    fun findPublicKey(kid: String?, relationship: DidRelationship): JsonObject? {
        val ids = when (relationship) {
            DidRelationship.AUTHENTICATION -> authentication
            DidRelationship.ASSERTION_METHOD -> assertionMethod
            DidRelationship.ANY -> verificationMethods.keys.toList()
        }
        // No fallback to "every verification method" for a NAMED relationship.
        // A key the controller did not place in `assertionMethod` is not
        // authorized to assert, and treating an empty relationship as "all
        // keys" would let an Issuer's DID document sign credentials with a key
        // it only published for, say, key agreement. Fail closed; [ANY] is the
        // one caller that legitimately means "whichever key this document has"
        // (resolving a did:jwk back to its own key).
        val candidates = ids
        val match = when {
            // With no `kid` to go on, only one key is unambiguous. Taking the
            // first would make verification depend on document order: a token
            // signed by another of the issuer's assertion keys would be
            // rejected, and an unsigned-for key could be accepted instead.
            // Same rule as selectIssuerKey applies to a published JWKS.
            kid == null -> candidates.singleOrNull()
            // A `kid` may be the absolute DID URL or just the fragment.
            else -> candidates.firstOrNull { it == kid || it.substringAfter('#', "") == kid.substringAfter('#', kid) }
        } ?: return null
        return verificationMethods[match]?.publicKeyJwk
    }
}

/** Which verification relationship a key is being looked up for. */
enum class DidRelationship { AUTHENTICATION, ASSERTION_METHOD, ANY }

/** One verification method of a [DidDocument]. */
data class VerificationMethod(
    val id: String,
    val type: String,
    val controller: String,
    /** The public key as a JWK. Only `JsonWebKey2020`-shaped methods carry one. */
    val publicKeyJwk: JsonObject?,
)

/** What a resolution attempt produced. */
sealed class DidResolution {
    data class Resolved(val document: DidDocument) : DidResolution()

    /**
     * Resolution did not produce a document. This is a failure, never a
     * silently-empty success: a caller that cannot tell the two apart would
     * treat an unreachable issuer as an unsigned credential.
     */
    data class Failed(val did: String, val reason: String) : DidResolution()

    /** The document if resolution succeeded, else null. */
    val documentOrNull: DidDocument? get() = (this as? Resolved)?.document
}

/**
 * How a DID that needs resolving is resolved.
 *
 * Deliberately an interface this SDK does not implement for the network
 * methods. DID method resolution is a trust decision - which document is
 * authoritative for an identifier - and in SIROS that lives in go-trust,
 * reached through go-wallet-backend's engine. A wallet that fetched
 * `did:web` documents itself would be making that decision locally, with its
 * own idea of which hosts to believe, and silently diverging from whatever
 * the deployment's trust registry says.
 *
 * `SirosWallet` supplies an implementation backed by the backend's
 * `/v1/resolve`; a host composing the lower-level modules supplies its own.
 *
 * @return the resolved DID document as JSON, or null if it could not be
 *   resolved. Null is a failure, never an empty success - see [DidResolution].
 */
fun interface DidResolutionDelegate {
    suspend fun resolve(did: String): JsonObject?
}

/**
 * Resolves the DIDs a wallet encounters.
 *
 * `did:jwk` is resolved here, locally and offline: the key *is* the
 * identifier, so there is no document to fetch, nobody to ask, and no trust
 * decision to delegate - the same reason wallet-frontend resolves it locally
 * too. Every other method is handed to [delegate], which routes it to
 * go-trust. This split is the whole design: the SDK answers only the question
 * that has an arithmetic answer, and never the one that needs a trust
 * registry.
 *
 * @param profile decides which methods a compliant wallet must be able to
 *   resolve, which is what [requiredMethods] reports. It does not restrict
 *   what gets resolved: a method outside it - or one this SDK does not know by
 *   name at all - is still delegated, since DIIP explicitly does not forbid
 *   identifiers it does not require, and which methods resolve is go-trust's
 *   answer rather than this SDK's.
 * @param delegate resolves everything except `did:jwk`. Null means a wallet
 *   with no resolution authority configured: `did:jwk` still works, and
 *   anything else fails rather than being fetched directly.
 */
class DidResolver(
    private val profile: DiipProfile = DiipProfile.LATEST,
    private val delegate: DidResolutionDelegate? = null,
) {
    /** Resolve any DID this wallet can. */
    suspend fun resolve(did: String): DidResolution {
        // Any syntactically valid DID is resolvable as far as this SDK is
        // concerned. Enumerating the methods here would make the SDK the
        // authority on which of them exist, and it is not: go-trust is, and a
        // method it learns about must not need an SDK release.
        val method = DidMethod.methodName(did)
            ?: return DidResolution.Failed(did, "Not a DID: $did")

        // did:jwk carries its own key. Sending it to a resolution service
        // would add a network round trip, a dependency, and a failure mode,
        // for an answer that is already in the identifier.
        if (method == DidMethod.JWK.methodName) return resolveDidJwk(did)

        val resolver = delegate
            ?: return DidResolution.Failed(
                did,
                "No DID resolution delegate configured; $method resolution is the backend's to perform",
            )
        val document = runCatching { resolver.resolve(did) }.getOrNull()
            ?: return DidResolution.Failed(did, "Could not resolve $did")
        val parsed = runCatching { parseDidDocument(document) }.getOrNull()
            ?: return DidResolution.Failed(did, "Resolution of $did did not return a DID document")
        if (parsed.id != did) {
            // A document naming a different subject is not this DID's
            // document, whoever returned it.
            return DidResolution.Failed(did, "Resolved document declares id '${parsed.id}'")
        }
        return DidResolution.Resolved(parsed)
    }

    /** The methods [profile] requires a compliant wallet to resolve. */
    val requiredMethods: Set<DidMethod> get() = profile.resolvableDidMethods
}

/**
 * Build a `did:jwk` from a public JWK.
 *
 * The method-specific identifier is the base64url encoding of the JWK, so the
 * same key must always serialize identically: WebCrypto bookkeeping (`ext`,
 * `key_ops`) and any private key material are stripped, and members are
 * emitted in a fixed order.
 *
 * @see <a href="https://github.com/quartzjer/did-jwk/blob/main/spec.md">did:jwk</a>
 */
fun createDidJwk(publicKeyJwk: JsonObject): String {
    val canonical = canonicalPublicJwk(publicKeyJwk)
    val encoded = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(canonical.toString().toByteArray(Charsets.UTF_8))
    return "did:jwk:$encoded"
}

/** [createDidJwk] over a JWK given as a JSON string. */
fun createDidJwk(publicKeyJwkJson: String): String =
    createDidJwk(Json.parseToJsonElement(publicKeyJwkJson).jsonObject)

/**
 * The verification method id of a `did:jwk`'s only key.
 *
 * A did:jwk document has exactly one verification method, `#0`, which is why
 * DIIP can say "a `kid` from the `authentication` relationship" and a wallet
 * can produce it without resolving anything.
 */
fun didJwkKeyId(did: String): String = "$did#0"

/**
 * Resolve a `did:jwk` - no network, and no failure mode other than a
 * malformed identifier, since the key is the identifier.
 */
fun resolveDidJwk(did: String): DidResolution {
    if (!did.startsWith("did:jwk:")) return DidResolution.Failed(did, "Not a did:jwk")
    val encoded = did.removePrefix("did:jwk:").substringBefore('#').substringBefore('?')
    val jwk = runCatching {
        val decoded = Base64.getUrlDecoder().decode(encoded).toString(Charsets.UTF_8)
        Json.parseToJsonElement(decoded).jsonObject
    }.getOrNull() ?: return DidResolution.Failed(did, "did:jwk identifier is not a base64url-encoded JWK")

    val vmId = didJwkKeyId(did)
    val vm = VerificationMethod(
        id = vmId,
        type = "JsonWebKey2020",
        controller = did,
        publicKeyJwk = jwk,
    )
    return DidResolution.Resolved(
        DidDocument(
            id = did,
            verificationMethods = mapOf(vmId to vm),
            authentication = listOf(vmId),
            assertionMethod = listOf(vmId),
        ),
    )
}

/** Parse a DID document JSON object into the subset this SDK reads. */
fun parseDidDocument(root: JsonObject): DidDocument {
    val id = (root["id"] as? JsonPrimitive)?.contentOrNull ?: error("DID document has no id")
    val methods = LinkedHashMap<String, VerificationMethod>()

    fun absolute(ref: String) = if (ref.startsWith("#")) "$id$ref" else ref

    fun register(element: kotlinx.serialization.json.JsonElement): String? = when (element) {
        // A relationship entry is either a reference to a verification method
        // declared elsewhere in the document, or the method inlined.
        is JsonPrimitive -> element.contentOrNull?.let(::absolute)
        is JsonObject -> {
            val vmId = (element["id"] as? JsonPrimitive)?.contentOrNull?.let(::absolute)
            if (vmId == null) {
                null
            } else {
                methods[vmId] = VerificationMethod(
                    id = vmId,
                    type = (element["type"] as? JsonPrimitive)?.contentOrNull ?: "",
                    controller = (element["controller"] as? JsonPrimitive)?.contentOrNull ?: id,
                    publicKeyJwk = element["publicKeyJwk"] as? JsonObject,
                )
                vmId
            }
        }
        else -> null
    }

    (root["verificationMethod"] as? JsonArray)?.forEach { register(it) }

    fun relationship(name: String): List<String> =
        (root[name] as? JsonArray)?.mapNotNull { register(it) } ?: emptyList()

    // Both relationships are resolved BEFORE the document is built: an
    // inlined verification method is registered as a side effect of reading
    // the relationship that carries it, so `methods` must not be read until
    // both have run.
    val authentication = relationship("authentication")
    val assertionMethod = relationship("assertionMethod")

    return DidDocument(
        id = id,
        verificationMethods = methods.toMap(),
        authentication = authentication,
        assertionMethod = assertionMethod,
    )
}

/**
 * Strip a JWK down to the members that identify the public key, in a fixed
 * order, so that the same key always yields the same `did:jwk`.
 *
 * The members kept are exactly RFC 7638's required ones for the key type -
 * the same set a JWK thumbprint is computed over. That is what makes the
 * mapping one-to-one: a key that also carries `alg`, `use`, `kid` or WebCrypto
 * bookkeeping (`ext`, `key_ops`) must not get a different DID from the same
 * key without them, or one wallet's `did:jwk` stops matching another's for the
 * same key pair. Private members never reach a DID at all.
 *
 * The order is lexicographic, which is not an arbitrary choice either: it is
 * both RFC 7638's canonicalization and what wallet-frontend ends up emitting
 * (it stringifies a WebCrypto `exportKey("jwk")` result, which comes back
 * alphabetically ordered, with `ext`/`key_ops` destructured away). The same
 * key has to produce the same DID on every client that reads the shared
 * `privatedata` container, so this has to match rather than merely be stable.
 */
internal fun canonicalPublicJwk(jwk: JsonObject): JsonObject {
    val required = when ((jwk["kty"] as? JsonPrimitive)?.contentOrNull) {
        "EC" -> listOf("crv", "kty", "x", "y")
        "OKP" -> listOf("crv", "kty", "x")
        "RSA" -> listOf("e", "kty", "n")
        "oct" -> listOf("k", "kty")
        // An unknown key type has no defined required set; keeping only what
        // is certainly part of every JWK is safer than guessing a wider one.
        else -> listOf("kty")
    }
    return buildJsonObject {
        for (member in required) {
            jwk[member]?.let { put(member, it) }
        }
    }
}

/**
 * The `kid` a credential's `cnf` claim binds it to.
 *
 * DIIP binds the Holder with a `cnf.kid` naming a verification method of
 * their DID document. Credentials predating that carry `cnf.jwk` and are
 * addressed by JWK thumbprint, which is what this SDK has always used as a
 * local key id. Returns null when the credential has no holder binding at all.
 */
fun resolveCnfKid(cnf: JsonObject?, thumbprintOf: (JsonObject) -> String): String? {
    cnf?.get("kid")?.let { it as? JsonPrimitive }?.contentOrNull?.let { return it }
    (cnf?.get("jwk") as? JsonObject)?.let { return thumbprintOf(it) }
    return null
}
