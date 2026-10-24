// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

/**
 * Where the wallet gets a credential's issuer-delivered `secret_seed` (16 bytes) for a `circuit_zk`
 * presentation whose pseudonym config derives from it (`known-offender-matching-ssc`,
 * `account-recovery-ssc`, `user-managed-pseudonym-xsite-ssc`).
 *
 * INTERNAL SEAM. The wallet's default source is [KeystoreSecretSeedSource]: the seed the issuer delivered
 * with the credential (the response-level `credential_metadata`, kept per credential in the privatedata container). [NONE]
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
 * The seed delivered with a stored credential, read from that credential's container `metadata` ([metadataOf]) as
 * the entry of type [org.siros.sdk.credentials.SecretSeedDelivery.MEMBER], whose value maps namespaces to seeds: the
 * one of [namespace]. Fails closed: no metadata, no such entry, more than one such entry, no seed for the namespace,
 * or a value that is not exactly 32 lowercase hex characters all mean no seed. The returned array is a fresh copy for
 * the caller to zero; nothing is cached, logged or put anywhere else.
 */
internal class KeystoreSecretSeedSource(
    private val namespace: String,
    private val metadataOf: suspend (Long) -> kotlinx.serialization.json.JsonArray?,
) : CredentialSecretSeedSource {
    override suspend fun secretSeed(credentialId: Long): ByteArray? {
        val entries = metadataOf(credentialId).orEmpty().mapNotNull { it as? kotlinx.serialization.json.JsonObject }
        // Credential Auxiliary Data v0.1: exactly one delivered opening is the credential's seed; more or fewer fail closed.
        val v01 = entries.filter { (it["type"] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { p -> p.isString }?.content == org.siros.sdk.credentials.AuxiliaryDataV01.RESPONSE_MEMBER }
        if (v01.isNotEmpty()) {
            val member = v01.singleOrNull()?.get("value") ?: return null
            val parsed = org.siros.sdk.credentials.AuxiliaryDataV01.parseDeliveries(
                kotlinx.serialization.json.JsonObject(mapOf(org.siros.sdk.credentials.AuxiliaryDataV01.RESPONSE_MEMBER to member)),
            ) as? org.siros.sdk.credentials.AuxiliaryParse.Parsed ?: return null
            val only = parsed.deliveries.singleOrNull() ?: run { parsed.deliveries.forEach { it.bytes.fill(0) }; return null }
            return only.bytes
        }
        val matching = metadataOf(credentialId).orEmpty().mapNotNull { it as? kotlinx.serialization.json.JsonObject }
            .filter { (it["type"] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { p -> p.isString }?.content == org.siros.sdk.credentials.SecretSeedDelivery.MEMBER }
        val seeds = matching.singleOrNull()?.get("value") as? kotlinx.serialization.json.JsonObject ?: return null
        val hex = (seeds[namespace] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        return org.siros.sdk.credentials.SecretSeedCommitment.seedFromHex(hex)
    }
}
