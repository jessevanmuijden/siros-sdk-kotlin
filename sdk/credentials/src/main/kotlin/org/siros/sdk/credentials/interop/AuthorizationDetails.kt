// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.interop

import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VCI `authorization_details` construction.
 *
 * DIIP requires a Wallet to support both ways of asking an Issuer for a
 * specific credential type: `authorization_details` carrying a
 * `credential_configuration_id` (OID4VCI 1.0 §5.1.1), and the `scope`
 * parameter. `authorization_details` is the structured form and the one Issuer
 * Agents must support, so the wallet sends it whenever it knows which
 * configuration it wants.
 *
 * This lives apart from any transport on purpose. These SDKs never build the
 * Authorization Request - go-wallet-backend's engine does, for every transport
 * - so the *decision* stays here, where DIIP puts it, and the transport only
 * forwards the result. wallet-frontend makes the same split for the same
 * reason (`lib/openid-flow/authorizationDetails.ts`), and the two have to
 * agree: they talk to the same engine and the same issuers.
 */
object AuthorizationDetails {

    /**
     * Build the `authorization_details` for one credential configuration, or
     * null when the wallet should not send any.
     *
     * [advertisedTypes] is the Authorization Server's
     * `authorization_details_types_supported`, and is optional because the
     * wallet does not always hold it: on the engine-driven transports the
     * Authorization Server is discovered server-side. When it is absent the
     * details are built anyway and the engine, which does have the metadata,
     * decides whether to use them - sending intent the Issuer may ignore is
     * safe, whereas withholding it would fail the requirement outright. When
     * it is present, an Authorization Server that advertises its supported
     * types *without* `openid_credential` is taken at its word.
     */
    fun build(
        credentialConfigurationId: String?,
        advertisedTypes: Collection<String>? = null,
    ): List<AuthorizationDetail>? {
        if (credentialConfigurationId.isNullOrBlank()) return null
        if (advertisedTypes != null && OPENID_CREDENTIAL !in advertisedTypes) return null
        return listOf(
            AuthorizationDetail(
                type = OPENID_CREDENTIAL,
                credentialConfigurationId = credentialConfigurationId,
            ),
        )
    }

    /** The only `authorization_details` type OID4VCI defines for issuance. */
    const val OPENID_CREDENTIAL = "openid_credential"
}

/**
 * One `openid_credential` authorization detail.
 *
 * Only the `credential_configuration_id` form is produced: DIIP requires that
 * one, and it is what the `format`-based alternative was replaced by.
 */
@Serializable
data class AuthorizationDetail(
    /**
     * Always emitted, even though it has a default: kotlinx.serialization
     * omits defaults unless told otherwise, and an `authorization_details`
     * entry without its `type` is not something an Authorization Server can
     * act on. [EncodeDefault] pins that regardless of how the caller's [Json]
     * is configured.
     */
    @OptIn(ExperimentalSerializationApi::class)
    @EncodeDefault
    val type: String = AuthorizationDetails.OPENID_CREDENTIAL,
    @SerialName("credential_configuration_id") val credentialConfigurationId: String,
)
