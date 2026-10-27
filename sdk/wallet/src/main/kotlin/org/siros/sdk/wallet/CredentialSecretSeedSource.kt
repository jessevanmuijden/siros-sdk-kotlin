// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

/**
 * Where the wallet gets a credential's issuer-delivered `secret_seed` (16 bytes) for a `circuit_zk`
 * presentation whose pseudonym config derives from it (`known-offender-matching-ssc`,
 * `account-recovery-ssc`, `user-managed-pseudonym-xsite-ssc`).
 *
 * INTERNAL SEAM. The wallet's default source is [KeystoreSecretSeedSource]: the seed the issuer delivered
 * with the credential (the response-level `auxiliary_data` member, kept per credential in the privatedata container). [NONE]
 * holds nothing, so every ssc-based request is refused. The wallet hands the returned array to the
 * presenter, which verifies `SHA256(seed) == ssc` itself (before every use), and zeroes the array
 * afterwards; an implementation must therefore return a fresh copy on each call. A source must never log
 * the seed.
 */
internal fun interface CredentialSecretSeedSource {
    /** A fresh copy of the seed of the credential with id [credentialId], or null when none is held. */
    suspend fun secretSeed(credentialId: Long): ByteArray?

    companion object {
        /** No credential has a seed. */
        val NONE = CredentialSecretSeedSource { null }
    }
}

/**
 * The seed delivered with a stored credential, read from that credential's container `metadata` ([metadataOf]) as the
 * Credential Auxiliary Data v0.1 entry (`auxiliary_data`): the opening of its SSC slot is the seed. Fails closed: no
 * metadata, no such entry, more than one, no or more than one SSC slot all mean no seed. An entry of a superseded
 * shape (`org.siros.secret_seed`) is not interpreted: such a credential has no seed here and must be re-issued. The
 * returned array is a fresh copy for the caller to zero; nothing is cached, logged or put anywhere else.
 */
internal class KeystoreSecretSeedSource(
    private val metadataOf: suspend (Long) -> kotlinx.serialization.json.JsonArray?,
) : CredentialSecretSeedSource {
    override suspend fun secretSeed(credentialId: Long): ByteArray? {
        val entries = metadataOf(credentialId).orEmpty().mapNotNull { it as? kotlinx.serialization.json.JsonObject }
        val v01 = entries.filter { (it["type"] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { p -> p.isString }?.content == org.siros.sdk.credentials.AuxiliaryDataV01.RESPONSE_MEMBER }
        val member = v01.singleOrNull()?.get("value") ?: return null
        val parsed = org.siros.sdk.credentials.AuxiliaryDataV01.parseDeliveries(
            kotlinx.serialization.json.JsonObject(mapOf(org.siros.sdk.credentials.AuxiliaryDataV01.RESPONSE_MEMBER to member)),
        ) as? org.siros.sdk.credentials.AuxiliaryParse.Parsed ?: return null
        // The credential's seed is the opening of its SSC slot (the claim named "ssc", whatever its namespace); the others are
        // other secrets of the same response and are zeroed here. Not exactly one such slot: no seed.
        val slot = parsed.deliveries.filter { it.path.last() == SSC_CLAIM }.singleOrNull()
        parsed.deliveries.filter { it !== slot }.forEach { it.bytes.fill(0) }
        return slot?.bytes
    }
}

/** The claim name of the `nym_auth` seed commitment (privatedata-spec 5A): the path the v0.1 opening for the seed is delivered under. */
private const val SSC_CLAIM = "ssc"
