package org.siros.sdk.credentials.interop

/**
 * Which DIIP profile version a wallet targets.
 *
 * DIIP (Decentralized Identity Interop Profile) is not a specification but a
 * *profile*: it pins the versions of OID4VCI, OID4VP, SD-JWT VC and the Token
 * Status List that an implementation must support, and removes optionality
 * inside them. Because it pins versions, a new DIIP release moves wire
 * details a wallet has to get right - so the profile is a value the SDK
 * carries and branches on, not a set of hardcoded constants.
 *
 * The profile is released roughly twice a year. [LATEST] is what a wallet
 * gets by default; an older one stays selectable for an ecosystem that has
 * not moved yet, which is the whole point of naming versions.
 *
 * @see <a href="https://github.com/FIDEScommunity/DIIP">FIDEScommunity/DIIP</a>
 */
enum class DiipProfile(
    /** The profile version as it is written, e.g. `"v5"`. */
    val version: String,
) {
    /**
     * DIIP v4 - OID4VCI draft 15, OID4VP draft 28, SD-JWT VC draft 08,
     * Token Status List draft 10. No trust establishment mechanism.
     */
    V4("v4"),

    /**
     * DIIP v5, approved by the FIDES Community on 2026-01-15 - OID4VCI 1.0
     * Final, OID4VP 1.0 Final, SD-JWT VC draft 13, Token Status List draft
     * 15, and OpenID Federation DCP as an OPTIONAL trust establishment
     * mechanism.
     */
    V5("v5"),

    /**
     * DIIP v6 - a FIDES Community draft. Its release text is at present
     * identical to [V5]; what it adds here is the profile's own signposted
     * Future Directions, which are the changes a wallet can prepare for
     * without waiting for the text: `did:webvh` alongside `did:web`, the
     * Digital Credentials API, and OpenID Federation support in Wallets
     * (not only in Issuer and Verifier Agents).
     *
     * Everything v6 adds is additive - a v6 wallet is a superset of a v5
     * one - which is why it is safe to make it the default.
     */
    V6("v6"),
    ;

    // ── Identifiers ─────────────────────────────────────────────────

    /**
     * The DID method a Holder's own credential keys are identified by.
     *
     * Every DIIP version requires `did:jwk` for Holders. `did:key` is not a
     * DIIP identifier at all - it is what this SDK and wallet-frontend used
     * before DIIP, and a wallet still holding credentials bound to one keeps
     * working (see `KeypairIdentity`), but it is never what a new key gets.
     */
    val holderDidMethod: DidMethod get() = DidMethod.JWK

    /**
     * DID methods whose documents this profile requires a wallet to resolve -
     * to find an Issuer's signing key, or to check a Verifier's identity.
     */
    val resolvableDidMethods: Set<DidMethod>
        get() = when (this) {
            V4, V5 -> setOf(DidMethod.JWK, DidMethod.WEB)
            // Future Directions: "A near-future version of DIIP will probably
            // require support for did:webvh instead of did:web." Resolving
            // both is strictly more interoperable than resolving either.
            //
            // Whether a given method actually resolves is go-trust's answer,
            // not this SDK's - see [DidResolver]. This set says what the
            // profile requires of a compliant deployment, which is what an
            // interop report should cite.
            V6 -> setOf(DidMethod.JWK, DidMethod.WEB, DidMethod.WEBVH)
        }

    // ── Issuance (OID4VCI) ──────────────────────────────────────────

    /**
     * Whether the Authorization Request must be able to carry
     * `authorization_details` with a `credential_configuration_id`.
     *
     * Required of Wallets by every DIIP version; `scope` must be supported
     * too, so this is about being *able* to send it, not about choosing.
     */
    val supportsAuthorizationDetails: Boolean get() = true

    /**
     * The `.well-known` suffix an SD-JWT VC issuer publishes its signing keys
     * under. Renamed by SD-JWT VC between draft 08 and draft 13, so it moves
     * with the profile version rather than being a constant.
     */
    val sdJwtVcIssuerMetadataPath: String
        get() = when (this) {
            V4 -> "/.well-known/jwt-vc-issuer"
            V5, V6 -> "/.well-known/vc-issuer"
        }

    // ── Presentation (OID4VP) ───────────────────────────────────────

    /**
     * How a Verifier's `client_id` names its scheme.
     *
     * OID4VP draft 28 wrote a DID-identified Verifier as the bare DID
     * (`did:web:verifier.example`), with the scheme carried out of band in
     * `client_id_scheme`. OID4VP 1.0 Final replaced that with Client
     * Identifier Prefixes, where the prefix is part of the `client_id`
     * itself (`decentralized_identifier:did:web:verifier.example`). A wallet
     * has to read both to talk to both generations of Verifier - see
     * `ClientIdScheme.parse`, which does - but only one of them is what this
     * profile says a compliant Verifier sends.
     */
    val clientIdStyle: ClientIdStyle
        get() = when (this) {
            V4 -> ClientIdStyle.BARE_SCHEME
            V5, V6 -> ClientIdStyle.PREFIXED
        }

    /**
     * Whether the profile requires the W3C Digital Credentials API as a
     * presentation channel. v5 explicitly lists it as *not* required; it is
     * a v6 Future Direction.
     */
    val requiresDigitalCredentialsApi: Boolean get() = this >= V6

    // ── Validity and revocation ─────────────────────────────────────

    /**
     * The Token Status List draft a compliant Issuer publishes. The bit
     * packing and the `status_list` claim shape this SDK reads have not
     * changed across these drafts, so this is informational - it is what an
     * interop report should cite, not a branch in the reader.
     */
    val tokenStatusListDraft: Int
        get() = when (this) {
            V4 -> 10
            V5, V6 -> 15
        }

    // ── Trust establishment ─────────────────────────────────────────

    /**
     * Whether a *Wallet* is expected to take part in OpenID Federation.
     *
     * v5 requires Entity Configurations of Issuer and Verifier Agents only,
     * and makes the whole section OPTIONAL. Making Wallets participate is a
     * signposted Future Direction.
     */
    val requiresWalletFederation: Boolean get() = this >= V6

    companion object {
        /**
         * The newest profile this SDK implements, and the default for a
         * wallet that does not pick one. Each version is additive over the
         * one before, so defaulting forward does not drop support for an
         * ecosystem still on an older release.
         */
        @JvmField
        val LATEST: DiipProfile = V6

        /**
         * Parse a profile version as written in configuration - `"v5"`,
         * `"V5"` or `"5"` all work. Returns null for anything else, so a
         * caller can fall back to [LATEST] rather than crash on a typo.
         */
        fun fromVersion(value: String?): DiipProfile? {
            val normalized = value?.trim()?.lowercase()?.removePrefix("v") ?: return null
            return entries.firstOrNull { it.version.removePrefix("v") == normalized }
        }
    }
}

/** How a Verifier's `client_id` names the scheme it is identified under. */
enum class ClientIdStyle {
    /** OID4VP draft 28 and earlier: the bare identifier, e.g. `did:web:x`. */
    BARE_SCHEME,

    /** OID4VP 1.0 Final: `<prefix>:<identifier>`, e.g. `decentralized_identifier:did:web:x`. */
    PREFIXED,
}
