// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.AuxiliaryDataShape
import org.siros.sdk.credentials.AuxiliaryDataShapes
import org.siros.sdk.credentials.AuxiliaryParse
import org.siros.sdk.credentials.AuxiliaryDataV01
import org.siros.sdk.credentials.LegacySecretMembers
import org.siros.sdk.credentials.SecretDelivery
import org.siros.sdk.credentials.SecretSeedCommitment
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

    /** The delivered secrets do not match what the issuer advertised for the configuration. */
    NAMESPACE_ABSENT("the delivered secret does not match what the issuer advertised"),

    /** The response carries a secret in a superseded shape (`org.siros.secret_seed`, `holder_commitments`, `psc`, ...): never read, never stored. */
    LEGACY_SECRET_MEMBER("the response carries a secret in a superseded shape"),

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

    /** The credential does not carry, at the path the issuer asked for, the commitment this wallet sent in the proofs. */
    HOLDER_COMMITMENT_MISSING("the credential does not hold the holder commitment that was sent"),

    /** A commitment claim in the credential is not in a representation this wallet can read (padded base64, hex, a text string in an mdoc, ...). */
    COMMITMENT_UNREADABLE("a commitment claim in the credential is not in a readable representation"),

    /** A response key was offered for the flow but the completion is plain: an encrypted response is never silently downgraded. */
    PLAIN_RESPONSE("the issuer answered in clear although an encrypted response was requested"),
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
    class Refuse(
        val reason: DeliveredMetadataRefusal,
        /** Where and what (a claim path and a shape, type and length only: NEVER a value); null when [reason] says it all. */
        val detail: String? = null,
    ) : DeliveredMetadataVerdict()
}

/**
 * Receipt of the response-level `credential_metadata` the issuer delivers (privatedata-spec 5A; OpenID4VCI 1.1). A pure
 * check of the WHOLE response, run BEFORE anything is stored: a refusal means no credential of the response is stored.
 *
 * Only the Credential Auxiliary Data v0.1 member (`auxiliary_data`) is interpreted: the response must have been
 * JWE-encrypted and carry a `notification_id`, the member must be well formed, and every delivered opening must open
 * the commitment its credentials carry. A member of a superseded shape ([LegacySecretMembers]) refuses the response
 * ([DeliveredMetadataRefusal.LEGACY_SECRET_MEMBER]). Every other member is stored uninterpreted, in the order received.
 */
internal object DeliveredCredentialMetadata {
    fun check(
        response: DeliveredResponseMetadata,
        credentials: List<DeliveredCredential>,
        canStoreSecret: Boolean,
        /** The issuer metadata of the configuration advertised a seed (`namespaces`): the response must have been encrypted. */
        advertised: Boolean = false,
        /** The adapter the issuer's advertisement selected (never sniffed from the response). */
        shape: AuxiliaryDataShape = AuxiliaryDataV01,
        /** What the issuer advertised for the configuration (slots), when known: a shape may require the delivery to match it. */
        advertisement: org.siros.sdk.credentials.AuxiliaryAdvertisement? = null,
        /** The commitments this wallet put in the key proofs of the request (Auxiliary Data v0.1): the credentials must hold them. */
        holderCommitments: List<org.siros.sdk.credentials.HolderCommitment> = emptyList(),
    ): DeliveredMetadataVerdict {
        // A secret in a superseded shape is never read and never stored, whatever else the response carries (and before any other check).
        response.credentialMetadata?.takeIf { !it.malformed }?.let {
            if (it.legacyMemberPresent || LegacySecretMembers.carriedBy(JsonObject(it.members))) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.LEGACY_SECRET_MEMBER)
        }
        holdsHolderCommitments(credentials, holderCommitments)?.let { return it }
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
        val members = JsonObject(metadata.members)
        // A secret in a shape the issuer did not advertise is never stored uninterpreted, and no other adapter is guessed from it.
        if (AuxiliaryDataShapes.all.any { it.id != shape.id && it.carriesSecret(members) }) {
            return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.MALFORMED)
        }
        if (!shape.carriesSecret(members)) return when {
            advertised -> DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.SEED_UNAVAILABLE)
            metadata.members.isEmpty() -> DeliveredMetadataVerdict.None
            else -> DeliveredMetadataVerdict.Accept(all)
        }
        if (response.deferredResponse) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.DEFERRED_SEED)
        // Plain JSON never carries a secret: only a response this wallet decrypted itself counts as encrypted.
        if (!response.credentialMetadataEncryptedResponse) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NOT_ENCRYPTED)
        val deliveries = (shape.parseDeliveries(members) as? AuxiliaryParse.Parsed)?.deliveries
            ?: return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.MALFORMED)
        try {
            // A secret needs a notification id and somewhere to be kept; a response whose only entries are ignored extensions has none.
            if (deliveries.isNotEmpty()) {
                if (credentials.none { !it.notificationId.isNullOrEmpty() }) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NO_NOTIFICATION_ID)
                if (!canStoreSecret) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NO_STORAGE)
            }
            val toVerify = shape.deliveriesToVerify(deliveries, advertisement)
                ?: return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NAMESPACE_ABSENT)
            return verifyAll(shape, toVerify, credentials, all)
        } finally {
            deliveries.forEach { it.bytes.fill(0) }
        }
    }

    /**
     * Spec: after issuance the wallet MUST check that the claim at each `to_issuer` path holds the commitment it sent. A claim that is
     * absent or different on any credential refuses the response (an optional entry the issuer left out entirely is allowed).
     */
    private fun holdsHolderCommitments(credentials: List<DeliveredCredential>, sent: List<org.siros.sdk.credentials.HolderCommitment>): DeliveredMetadataVerdict.Refuse? {
        val missing = DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.HOLDER_COMMITMENT_MISSING)
        for (h in sent) {
            for (c in credentials) {
                when (val claim = org.siros.sdk.credentials.AuxiliaryDataV01.claimStatus(c.format, c.credential, h.path, h.encoding)) {
                    // Only a genuinely absent OPTIONAL claim is skipped; a malformed or ambiguous one is refused either way.
                    org.siros.sdk.credentials.AuxiliaryDataV01.Claim.Absent -> if (h.required) return missing
                    is org.siros.sdk.credentials.AuxiliaryDataV01.Claim.Invalid -> return unreadable(h.path, claim.shape)
                    is org.siros.sdk.credentials.AuxiliaryDataV01.Claim.Value -> {
                        val same = java.security.MessageDigest.isEqual(claim.bytes, h.commitment)
                        claim.bytes.fill(0)
                        if (!same) return missing
                    }
                }
            }
        }
        return null
    }

    /** The refusal of a commitment claim this wallet cannot read: names the path and the SHAPE found (never the value). */
    private fun unreadable(path: List<String>, shape: String): DeliveredMetadataVerdict.Refuse {
        val detail = "claim at path $path is $shape"
        timber.log.Timber.w("Delivered credential refused: $detail")
        return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.COMMITMENT_UNREADABLE, detail)
    }

    private fun verifyAll(
        shape: AuxiliaryDataShape,
        toVerify: List<SecretDelivery>,
        credentials: List<DeliveredCredential>,
        all: JsonArray,
    ): DeliveredMetadataVerdict {
        for (delivery in toVerify) {
            for (c in credentials) {
                val commitment = shape.commitmentOf(c.format, c.credential, delivery) ?: run {
                    // Absent stays "no commitment"; a claim that is there but unreadable names its path and shape.
                    val status = org.siros.sdk.credentials.AuxiliaryDataV01.claimStatus(c.format, c.credential, delivery.path, delivery.encoding)
                    return if (shape.id == org.siros.sdk.credentials.AuxiliaryDataV01.id && status is org.siros.sdk.credentials.AuxiliaryDataV01.Claim.Invalid) {
                        unreadable(delivery.path, status.shape)
                    } else {
                        DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NO_COMMITMENT)
                    }
                }
                val ok = SecretSeedCommitment.opens(delivery.bytes, commitment)
                commitment.fill(0)
                if (!ok) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.MISMATCH)
            }
        }
        return DeliveredMetadataVerdict.Accept(all)
    }
}
