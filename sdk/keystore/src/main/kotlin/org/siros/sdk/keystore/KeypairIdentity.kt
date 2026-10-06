// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.siros.sdk.credentials.interop.InteropProfile
import org.siros.sdk.credentials.interop.createDidJwk
import org.siros.sdk.credentials.interop.DidRelationship
import org.siros.sdk.credentials.interop.resolveDidJwk
import org.siros.sdk.credentials.interop.didJwkKeyId
import timber.log.Timber

/**
 * How a holder key pair is turned into a DID and a local key id.
 *
 * The value is shared with wallet-frontend's `DID_KEY_VERSION` config, and it
 * has to be: both clients read the same encrypted `privatedata` container, so
 * a key written by one is looked up by the other under whatever id it was
 * stored with.
 */
enum class DidKeyVersion(val value: String) {
    /**
     * `did:jwk`, with the key id being the DID's only verification method,
     * `<did>#0`. What DIIP requires of a Holder, and the default.
     */
    JWK("jwk"),

    /**
     * `did:key` with the P-256 multicodec, key id being the JWK thumbprint.
     * Predates DIIP; kept so a wallet already holding credentials bound to
     * one keeps working.
     */
    P256_PUB("p256-pub"),

    /**
     * `did:key` with a JCS-canonicalized JWK, key id being the JWK
     * thumbprint. wallet-frontend's other legacy option.
     */
    JWK_JCS_PUB("jwk_jcs-pub"),
    ;

    /**
     * Whether keys of this version are named by a DID URL rather than by a
     * JWK thumbprint. This is the branch that matters at every call site:
     * a DID URL can be resolved by a relying party, a thumbprint cannot.
     */
    val namesKeysByDidUrl: Boolean get() = this == JWK

    companion object {
        /**
         * How a wallet speaking [profile] names its keys.
         *
         * DIIP identifies a Holder by `did:jwk`, so its keys are named by the
         * DID URL. HAIP identifies the Holder by the key itself, so there is
         * no DID to name one with and the JWK thumbprint - what this SDK has
         * always used - stands.
         */
        fun forProfile(profile: InteropProfile): DidKeyVersion = when (profile) {
            InteropProfile.DIIP -> JWK
            InteropProfile.HAIP -> P256_PUB
        }

        /**
         * Parse the value as written in configuration. Unknown or absent
         * values fall back to [JWK], the DIIP identifier, rather than
         * silently dropping to a legacy one - a caller that wants the HAIP
         * naming asks for it through [forProfile].
         */
        fun fromValue(value: String?): DidKeyVersion {
            val match = entries.firstOrNull { it.value.equals(value?.trim(), ignoreCase = true) }
            if (match == null && !value.isNullOrBlank()) {
                Timber.w("Unknown did_key_version '$value'; using ${JWK.value}")
            }
            return match ?: JWK
        }
    }
}

/** A key pair's DID and the local id it is addressed by. */
data class KeypairIdentity(val did: String, val kid: String)

/**
 * Derive a key pair's identity from its public key.
 *
 * For [DidKeyVersion.JWK] the key id is a DID URL - DIIP binds the Holder
 * with a `cnf.kid` naming a verification method of their DID document, and
 * `#0` is the only one a `did:jwk` document has. The legacy versions keep
 * the JWK thumbprint they have always used.
 *
 * The `did:key` computation for the legacy versions stays where it was, in
 * [JweKeystore], since it needs the EC point rather than the JWK; this
 * function takes the DID as an argument for those.
 */
fun deriveKeypairIdentity(
    publicJwk: JsonObject,
    version: DidKeyVersion,
    legacyDid: () -> String,
    thumbprint: () -> String,
): KeypairIdentity = when (version) {
    DidKeyVersion.JWK -> {
        val did = createDidJwk(publicJwk)
        KeypairIdentity(did = did, kid = didJwkKeyId(did))
    }
    DidKeyVersion.P256_PUB, DidKeyVersion.JWK_JCS_PUB ->
        KeypairIdentity(did = legacyDid(), kid = thumbprint())
}

/**
 * Whether a stored key pair is the one a credential means by [kid].
 *
 * A key pair's id depends on [DidKeyVersion]: a DID URL for `did:jwk`, a JWK
 * thumbprint for the `did:key` versions. Some credentials can only ever name
 * the holder key by value, and so can only produce a thumbprint - an mdoc's
 * `deviceKeyInfo.deviceKey`, and an SD-JWT `cnf.jwk`. Without the fallback, a
 * wallet configured for `did:jwk` could not present the mdoc credentials it
 * already holds, which is exactly the regression this guards.
 */
fun keypairMatchesKid(storedKid: String, publicJwkJson: String, kid: String): Boolean {
    if (storedKid == kid) return true
    val thumbprint = runCatching { JWK.parse(publicJwkJson).computeThumbprint().toString() }.getOrNull()
    return matchesThumbprint(thumbprint, kid)
}

/** [keypairMatchesKid] for a key already parsed into a Nimbus [JWK]. */
fun keypairMatchesKid(storedKid: String, publicKey: JWK, kid: String): Boolean {
    if (storedKid == kid) return true
    val thumbprint = runCatching { publicKey.toPublicJWK().computeThumbprint().toString() }.getOrNull()
    return matchesThumbprint(thumbprint, kid)
}

private fun matchesThumbprint(thumbprint: String?, kid: String): Boolean {
    if (thumbprint == null) return false
    if (thumbprint == kid) return true
    // A `did:jwk` embeds the key it names, so comparing the two is an exact
    // answer rather than a guess: a credential bound to `did:jwk:...#0` is
    // bound to this key pair exactly when the embedded key is this one. This
    // is what lets a wallet whose keys are named by thumbprint still present a
    // credential it was issued under DIIP.
    return thumbprintOfDidJwk(kid) == thumbprint
}

/**
 * The JWK thumbprint of the key a `did:jwk` embeds, or null when [kid] is not
 * one of its verification methods.
 *
 * A `did:jwk` document has exactly one verification method, `#0`, so the only
 * DID URLs that name a key here are the bare DID and `<did>#0`. Anything else
 * names nothing: accepting `did:jwk:<key>#anything` would let a malformed or
 * hostile `cnf.kid` bind a credential to a key it never named, which is the
 * DID URL binding this exists to enforce.
 */
fun thumbprintOfDidJwk(kid: String): String? {
    if (!kid.startsWith("did:jwk:")) return null
    val did = kid.substringBefore('#')
    if (kid != did && kid != didJwkKeyId(did)) return null
    // kid is now known to name `#0`, so look that method up by its own id
    // rather than by whatever spelling the credential used.
    val key = resolveDidJwk(did).documentOrNull
        ?.findPublicKey(kid = didJwkKeyId(did), relationship = DidRelationship.AUTHENTICATION)
        ?: return null
    return runCatching { JWK.parse(key.toString()).computeThumbprint().toString() }.getOrNull()
}

/**
 * The `kid` a credential's `cnf` claim binds it to.
 *
 * DIIP binds the Holder with `cnf.kid`, a DID URL into their `authentication`
 * relationship. Credentials issued before that carry `cnf.jwk` instead and
 * are addressed by JWK thumbprint - this SDK's own legacy key id. Returns
 * null when the credential has no holder binding at all.
 */
fun resolveCnfKid(cnf: JsonObject?): String? =
    org.siros.sdk.credentials.interop.resolveCnfKid(cnf) { jwk ->
        JWK.parse(jwk.toString()).computeThumbprint().toString()
    }

/** [resolveCnfKid] over a credential payload, which may or may not carry a `cnf`. */
fun resolveCnfKidFromPayload(payload: JsonObject?): String? =
    resolveCnfKid(payload?.get("cnf") as? JsonObject)

internal val keypairIdentityJson = Json { ignoreUnknownKeys = true }
