package org.siros.sdk.wallet

/**
 * Represents the result of a trust evaluation for a verifier or issuer.
 *
 * Provides rich metadata about the trust decision beyond a simple boolean,
 * enabling host apps to render informative consent UIs with verifier identity,
 * trust framework information, and visual indicators.
 */
data class TrustResult(
    /** Whether the entity is trusted. */
    val trusted: Boolean,

    /** Trust framework that evaluated the entity (e.g., "etsi-tl", "openid-federation", "lote"). */
    val framework: String? = null,

    /** Human-readable reason for the trust decision. */
    val reason: String? = null,

    /** Display name of the verifier/issuer (from trust metadata or client_metadata). */
    val entityName: String? = null,

    /** Logo URI for the verifier/issuer. */
    val entityLogo: String? = null,

    /** The client_id_scheme used on the wire (e.g., "x509_san_dns", "did", "verifier_attestation"). */
    val clientIdScheme: String? = null,

    /** Normalized identifier (hostname for x509, DID for did:web, entity_id for federation). */
    val identifier: String? = null,

    /** Domain extracted from the verifier identity. */
    val domain: String? = null,

    /**
     * The `context` object of the trust response, when it carried one; absent
     * otherwise. Read-only: the SDK does not interpret it, and consumers (the
     * verifier-id sources, for one) read what they need.
     */
    val context: kotlinx.serialization.json.JsonObject? = null,
) {
    /** Parsed client_id_scheme providing type-safe access to the verifier identity. */
    val parsedScheme: ClientIdScheme?
        get() = identifier?.let { ClientIdScheme.parse(it) }
}
