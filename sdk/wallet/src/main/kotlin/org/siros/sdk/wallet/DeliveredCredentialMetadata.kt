// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.SecretSeedCommitment
import org.siros.sdk.credentials.SecretSeedDelivery
import org.siros.sdk.transport.DeliveredResponseMetadata

/** Why delivered credential metadata was refused. The text names no value. */
internal enum class DeliveredMetadataRefusal(val text: String) {
    /** A secret arrived in a response this wallet did not decrypt itself (or an advertised one was not encrypted). */
    NOT_ENCRYPTED("the secret was not delivered in an encrypted response"),

    /** The response's `credential_metadata` or its secret member is not in the required form. */
    MALFORMED("the delivered metadata is malformed"),

    /** A seed was delivered but the response carries no `notification_id`. */
    NO_NOTIFICATION_ID("the response carries a secret but no notification_id"),

    /** A Deferred Credential Response carried a seed: not supported in this version, even when encrypted. */
    DEFERRED_SEED("a deferred credential response cannot deliver a secret"),

    /** An advertised seed did not arrive: it is unavailable, never invented. */
    SEED_UNAVAILABLE("the delivered secret is unavailable for this issuance"),

    /** The credential type's designated namespace is absent from the delivered seeds. */
    NAMESPACE_ABSENT("the delivered secret has no seed for the credential's namespace"),

    /** The credential carries no readable commitment to check the secret against. */
    NO_COMMITMENT("the credential carries no usable commitment for the delivered secret"),

    /** The secret does not open the credential's commitment. */
    MISMATCH("the delivered secret does not match the credential's commitment"),

    /** This keystore cannot hold the secret. */
    NO_STORAGE("this wallet cannot store the delivered secret"),

    /**
     * The engine completed an issuance whose Credential Response only this wallet could open, and the wallet holds no
     * such response (the app restarted mid-flow, the key was dropped, or the credential count does not match): the
     * credentials are unavailable and nothing is invented.
     */
    RESPONSE_UNAVAILABLE("the encrypted credential response is not available in this wallet"),
}

/** One received credential, as far as the receipt check needs it. */
internal class DeliveredCredential(val format: String, val credential: String, val notificationId: String?) {
    override fun toString() = "DeliveredCredential(redacted)"
}

/** The outcome of checking one credential response's delivered metadata. */
internal sealed class DeliveredMetadataVerdict {
    /** The issuer delivered no metadata: nothing to store, behaviour unchanged. */
    data object None : DeliveredMetadataVerdict()

    /**
     * Store [entries] with EVERY credential of the response: one `{type, value}` entry per response-level member,
     * values exactly as received (privatedata-spec 5A.2, section 6). They can hold the seed.
     */
    class Accept(val entries: JsonArray) : DeliveredMetadataVerdict() {
        override fun toString() = "Accept(redacted)"
    }

    /** The response must not be stored: not one of its credentials. */
    class Refuse(val reason: DeliveredMetadataRefusal) : DeliveredMetadataVerdict()
}

/** Whether [c] commits to a seed (carries an `ssc`): a credential that cannot be used for its pseudonym without it. */
private fun needsSeed(c: DeliveredCredential): Boolean {
    val ssc = when {
        c.format.equals("mso_mdoc", ignoreCase = true) -> SecretSeedCommitment.sscOfMdoc(c.credential)
        c.format.contains("sd-jwt", ignoreCase = true) -> SecretSeedCommitment.sscOfSdJwt(c.credential)
        else -> null
    }
    ssc?.fill(0)
    return ssc != null
}

/**
 * Receipt of the response-level `credential_metadata` the issuer delivers (privatedata-spec 5A; OpenID4VCI 1.1). A pure
 * check of the WHOLE response, run BEFORE anything is stored: a refusal means no credential of the response is stored.
 *
 * Only the member [SecretSeedDelivery.MEMBER] is interpreted: the response must have been JWE-encrypted and carry a
 * `notification_id`, the member must be well formed ([SecretSeedDelivery.parseDelivery]), and the seed of
 * [secretNamespace] must open the `ssc` of EVERY credential of the response (`SHA256(secret_seed) == ssc`). The seeds of
 * other namespaces are stored as received. Every other member is stored uninterpreted, in the order received.
 *
 * The check never produces display metadata: the one function that does ([SecretSeedDelivery.mergeDisplay]) takes the
 * object with the member stripped.
 */
internal object DeliveredCredentialMetadata {
    fun check(
        response: DeliveredResponseMetadata,
        credentials: List<DeliveredCredential>,
        secretNamespace: String,
        canStoreSecret: Boolean,
        /** The issuer metadata of the configuration advertised a seed (`namespaces`): the response must have been encrypted. */
        advertised: Boolean = false,
    ): DeliveredMetadataVerdict {
        if (advertised && !response.credentialMetadataEncryptedResponse) {
            return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NOT_ENCRYPTED)
        }
        val metadata = response.credentialMetadata ?: return if (advertised) {
            // The configuration advertised a seed and the response has none (a resumed completion that lost it, say).
            DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.SEED_UNAVAILABLE)
        } else {
            DeliveredMetadataVerdict.None
        }
        if (metadata.malformed) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.MALFORMED)
        // The entries as received: one per member, member values verbatim.
        val all = JsonArray(metadata.members.map { (member, value) -> JsonObject(mapOf("type" to JsonPrimitive(member), "value" to value)) })
        val seedMember = metadata.members[SecretSeedDelivery.MEMBER] ?: return when {
            advertised -> DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.SEED_UNAVAILABLE)
            metadata.members.isEmpty() -> DeliveredMetadataVerdict.None
            else -> DeliveredMetadataVerdict.Accept(all)
        }
        if (response.deferredResponse) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.DEFERRED_SEED)
        // Plain JSON never carries a secret: only a response this wallet decrypted itself counts as encrypted.
        if (!response.credentialMetadataEncryptedResponse) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NOT_ENCRYPTED)
        val seeds = SecretSeedDelivery.parseDelivery(seedMember) ?: return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.MALFORMED)
        if (credentials.none { !it.notificationId.isNullOrEmpty() }) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NO_NOTIFICATION_ID)
        if (!canStoreSecret) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NO_STORAGE)
        val hex = seeds[secretNamespace] ?: return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NAMESPACE_ABSENT)
        val seed = SecretSeedCommitment.seedFromHex(hex) ?: return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.MALFORMED)
        try {
            for (c in credentials) {
                val ssc = when {
                    c.format.equals("mso_mdoc", ignoreCase = true) -> SecretSeedCommitment.sscOfMdoc(c.credential)
                    c.format.contains("sd-jwt", ignoreCase = true) -> SecretSeedCommitment.sscOfSdJwt(c.credential)
                    else -> null
                } ?: return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NO_COMMITMENT)
                val ok = SecretSeedCommitment.opens(seed, ssc)
                ssc.fill(0)
                if (!ok) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.MISMATCH)
            }
            return DeliveredMetadataVerdict.Accept(all)
        } finally {
            seed.fill(0)
        }
    }
}
