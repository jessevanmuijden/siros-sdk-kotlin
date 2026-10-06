package org.siros.sdk.wallet

/**
 * Represents a parsed OID4VP client_id_scheme with its normalized identifier.
 *
 * The client_id on the wire uses a prefix convention (e.g., "x509_san_dns:hostname")
 * to indicate how the verifier identifies itself. This sealed class provides
 * type-safe access to the parsed components.
 *
 * Two generations of that convention are in the field. OID4VP draft 28 wrote
 * a DID-identified Verifier as the bare DID, with the scheme carried
 * out of band in `client_id_scheme`. OID4VP 1.0 Final replaced that with
 * Client Identifier Prefixes, where the prefix is part of the `client_id`
 * itself - `decentralized_identifier:did:web:verifier.example`,
 * `redirect_uri:https://...`, `openid_federation:https://...`. DIIP requires
 * the `did` scheme, which is why the prefixed spelling has to parse, but a
 * wallet has to read both to talk to both generations of Verifier - see
 * [org.siros.sdk.credentials.interop.DiipProfile.clientIdStyle] for which one a
 * given profile version says a compliant Verifier sends.
 */
sealed class ClientIdScheme {
    /** The normalized identifier (hostname, DID, URL, etc.) */
    abstract val identifier: String

    /** X.509 SAN DNS — verifier identified by hostname in certificate SAN. */
    data class X509SanDns(override val identifier: String) : ClientIdScheme()

    /** X.509 SAN URI — verifier identified by URI in certificate SAN. */
    data class X509SanUri(override val identifier: String) : ClientIdScheme()

    /** DID-based — verifier identified by a Decentralized Identifier. */
    data class Did(override val identifier: String, val method: String) : ClientIdScheme()

    /** Verifier attestation — verifier authenticated via third-party attestation JWT. */
    data class VerifierAttestation(override val identifier: String) : ClientIdScheme()

    /** HTTPS URL — verifier identified by URL (redirect_uri scheme or unsigned). */
    data class Https(override val identifier: String) : ClientIdScheme()

    /**
     * OpenID Federation — verifier identified by an Entity Identifier whose
     * trust chain resolves to a trust anchor. DIIP's optional trust
     * establishment mechanism.
     */
    data class OpenIdFederation(override val identifier: String) : ClientIdScheme()

    /**
     * X.509 certificate hash — the verifier's certificate identified by the
     * base64url SHA-256 of its DER encoding, not by a name.
     */
    data class X509Hash(override val identifier: String) : ClientIdScheme()

    /** Pre-registered or unknown scheme — catch-all. */
    data class PreRegistered(override val identifier: String) : ClientIdScheme()

    /**
     * A user-facing identifier with the scheme prefix stripped - a raw
     * client_id like "x509_san_dns:verifier.multipaz.org" is meaningless to
     * a user; the hostname alone is what matters. Falls back to the
     * unmodified [identifier] when no hostname can be extracted (e.g. a
     * non-web DID, or an x509_hash whose value is a certificate hash, not a
     * name).
     */
    val displayName: String
        get() = when (this) {
            is X509SanDns -> identifier
            is X509SanUri -> hostFromUrl(identifier) ?: identifier
            is Https -> hostFromUrl(identifier) ?: identifier
            is Did -> if (method == "web") {
                // did:web:example.com[:path...] -> example.com - path segments
                // after the host are colon-separated per the did:web spec.
                identifier.removePrefix("did:web:").substringBefore(':')
            } else {
                identifier
            }
            is OpenIdFederation -> hostFromUrl(identifier) ?: identifier
            // An x509_hash value is a certificate digest; there is no name in
            // it to show, so the raw value stands.
            is X509Hash -> identifier
            is VerifierAttestation, is PreRegistered -> identifier
        }

    companion object {
        private fun hostFromUrl(value: String): String? =
            runCatching { java.net.URI(value).host }.getOrNull()?.takeIf { it.isNotBlank() }

        /**
         * Parse a raw client_id string into a typed [ClientIdScheme].
         *
         * Mirrors the parsing logic in wallet-frontend's `parseClientIdScheme`.
         */
        fun parse(clientId: String): ClientIdScheme = when {
            clientId.startsWith("x509_san_dns:") ->
                X509SanDns(clientId.removePrefix("x509_san_dns:"))
            clientId.startsWith("x509_san_uri:") ->
                X509SanUri(clientId.removePrefix("x509_san_uri:"))
            clientId.startsWith("x509_hash:") ->
                X509Hash(clientId.removePrefix("x509_hash:"))
            // OID4VP 1.0 Final's prefix for a DID-identified Verifier. Checked
            // before the bare "did:" form, since the prefixed spelling
            // contains it.
            clientId.startsWith("decentralized_identifier:") ->
                didOf(clientId.removePrefix("decentralized_identifier:"))
            clientId.startsWith("did:") ->
                didOf(clientId)
            clientId.startsWith("verifier_attestation:") ->
                VerifierAttestation(clientId.removePrefix("verifier_attestation:"))
            clientId.startsWith("openid_federation:") ->
                OpenIdFederation(clientId.removePrefix("openid_federation:"))
            clientId.startsWith("redirect_uri:") ->
                Https(clientId.removePrefix("redirect_uri:"))
            clientId.startsWith("https://") || clientId.startsWith("http://") ->
                Https(clientId)
            else ->
                PreRegistered(clientId)
        }

        private fun didOf(did: String): ClientIdScheme =
            Did(did, method = did.split(":").getOrElse(1) { "" })
    }
}
