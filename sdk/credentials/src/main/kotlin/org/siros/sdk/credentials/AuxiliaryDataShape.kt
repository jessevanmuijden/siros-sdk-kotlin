// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/**
 * A secret an issuer delivers to the wallet, normalised: where it belongs (the claims [path] it commits to, or the legacy
 * namespace), the hash [alg] of the commitment and the secret [bytes] (the "opening"). The caller owns [bytes] and zeroes them.
 */
class SecretDelivery(val path: List<String>, val alg: String, val bytes: ByteArray) {
    override fun toString() = "SecretDelivery(path=$path, alg=$alg, redacted)"
}

/**
 * A commitment the wallet gives the issuer, normalised: the claims [path] it is for, the hash [alg], whether the issuer
 * [required] it, and the [commitment] value itself.
 */
class HolderCommitment(val path: List<String>, val alg: String, val required: Boolean, val commitment: ByteArray) {
    override fun toString() = "HolderCommitment(path=$path, alg=$alg, required=$required, redacted)"
}

/** What a configuration advertises it will deliver ([toWallet]) and wants ([toIssuer]), normalised. Names and slots, never values. */
class AuxiliaryAdvertisement(val toWallet: List<Slot>, val toIssuer: List<Slot>) {
    class Slot(val path: List<String>, val alg: String, val required: Boolean = false)
}

/** The outcome of reading an issuer's advertisement for one configuration. */
sealed interface AuxiliarySelection {
    /** The configuration advertises nothing of this kind. */
    object None : AuxiliarySelection

    /** A well-formed advertisement of [shape]: its adapter reads the response and places the commitments. */
    class Selected(val shape: AuxiliaryDataShape, val advertisement: AuxiliaryAdvertisement) : AuxiliarySelection

    /** Anything else (two shapes at once, a value where only names may be, a bad entry): the configuration is not offered. */
    object Malformed : AuxiliarySelection
}

/** The result of reading the delivered members of a decrypted response. */
sealed interface AuxiliaryParse {
    class Parsed(val deliveries: List<SecretDelivery>) : AuxiliaryParse

    /** The members are not in the required form: nothing of the response is stored. */
    object Malformed : AuxiliaryParse
}

/**
 * One wire shape of "auxiliary data" (secrets to the wallet, commitments to the issuer). The rest of the SDK works on the
 * normalised model ([SecretDelivery], [HolderCommitment]); everything specific to a shape lives in its adapter. The adapter is
 * chosen by what the ISSUER ADVERTISES ([AuxiliaryDataShapes.select]), never sniffed from a response, and every adapter fails
 * closed.
 */
interface AuxiliaryDataShape {
    /** A stable name for logs and tests. */
    val id: String

    /** Reads this shape's advertisement from [config]: [AuxiliarySelection.None] when it has none of this shape's members. */
    fun advertisement(config: CredentialConfiguration): AuxiliarySelection

    /** Whether [metadata] (a response `credential_metadata`) carries a member that holds a secret in this shape. */
    fun carriesSecret(metadata: JsonObject): Boolean

    /** The secrets of [metadata]; [AuxiliaryParse.Malformed] when a secret-bearing member is not in the required form. */
    fun parseDeliveries(metadata: JsonObject): AuxiliaryParse

    /**
     * Which of [deliveries] the wallet must check against the credential (and keep as its secret): for the credential type whose
     * designated namespace is [secretNamespace]. Null when a delivery the shape requires is absent.
     */
    fun deliveriesToVerify(deliveries: List<SecretDelivery>, secretNamespace: String, advertised: AuxiliaryAdvertisement?): List<SecretDelivery>?

    /**
     * The commitment [delivery] must open, read from the issued [credential] of [format]: the credential's own claim. Null when the
     * credential carries none (unreadable, absent, wrong form). The caller zeroes the result.
     */
    fun commitmentOf(format: String, credential: String, delivery: SecretDelivery): ByteArray?

    /** [metadata] without its secret-bearing members: the only form display code may see. */
    fun stripFromMetadata(metadata: JsonObject): JsonObject

    /** The key-proof claims that carry [commitments] (signed with the proof, identical in every proof of a request). */
    fun placeInProof(commitments: List<HolderCommitment>): Map<String, JsonElement>
}

/** The registry of adapters and the rule for choosing one. */
object AuxiliaryDataShapes {
    /** Every adapter this SDK knows, in no priority: a configuration may advertise exactly one of them. */
    val all: List<AuxiliaryDataShape> get() = listOf(LegacyOrgSirosShape)

    /**
     * The adapter for [config]: the one whose advertisement it carries. A configuration that advertises more than one shape,
     * or whose advertisement of one is malformed, is [AuxiliarySelection.Malformed] (fail closed, never guessed).
     */
    fun select(config: CredentialConfiguration): AuxiliarySelection {
        val results = all.map { it.advertisement(config) }
        if (results.any { it is AuxiliarySelection.Malformed }) return AuxiliarySelection.Malformed
        val selected = results.filterIsInstance<AuxiliarySelection.Selected>()
        return when (selected.size) {
            0 -> AuxiliarySelection.None
            1 -> selected.single()
            else -> AuxiliarySelection.Malformed
        }
    }
}

/**
 * The legacy shape (privatedata-spec 5A): the response `credential_metadata` member [SecretSeedDelivery.MEMBER] maps a
 * namespace to 32 lowercase hex characters; the advertisement is the same member with `{"namespaces": [...]}`; the holder
 * pseudonym commitment goes into the proof as the claim [PSC_CLAIM] (base64url, 32 bytes). Normalised: a delivery's path is
 * `[namespace]`, alg `sha-256`.
 */
object LegacyOrgSirosShape : AuxiliaryDataShape {
    override val id = "org.siros.legacy"

    /** The proof claim carrying the `psc`. */
    const val PSC_CLAIM = "org.siros.psc"
    const val ALG = "sha-256"

    override fun advertisement(config: CredentialConfiguration): AuxiliarySelection =
        when (val a = SecretSeedDelivery.classifyAdvertisement(config.credentialMetadata?.secretSeed)) {
            SecretSeedDelivery.Advertisement.None -> AuxiliarySelection.None
            SecretSeedDelivery.Advertisement.Malformed -> AuxiliarySelection.Malformed
            is SecretSeedDelivery.Advertisement.Valid ->
                AuxiliarySelection.Selected(this, AuxiliaryAdvertisement(a.namespaces.map { AuxiliaryAdvertisement.Slot(listOf(it), ALG) }, emptyList()))
        }

    override fun carriesSecret(metadata: JsonObject): Boolean = SecretSeedDelivery.MEMBER in metadata

    override fun parseDeliveries(metadata: JsonObject): AuxiliaryParse {
        val member = metadata[SecretSeedDelivery.MEMBER] ?: return AuxiliaryParse.Parsed(emptyList())
        val seeds = SecretSeedDelivery.parseDelivery(member) ?: return AuxiliaryParse.Malformed
        val out = ArrayList<SecretDelivery>(seeds.size)
        for ((ns, hex) in seeds) {
            val bytes = SecretSeedCommitment.seedFromHex(hex) ?: run { out.forEach { it.bytes.fill(0) }; return AuxiliaryParse.Malformed }
            out += SecretDelivery(listOf(ns), ALG, bytes)
        }
        return AuxiliaryParse.Parsed(out)
    }

    override fun deliveriesToVerify(deliveries: List<SecretDelivery>, secretNamespace: String, advertised: AuxiliaryAdvertisement?): List<SecretDelivery>? =
        deliveries.firstOrNull { it.path == listOf(secretNamespace) }?.let { listOf(it) }

    override fun commitmentOf(format: String, credential: String, delivery: SecretDelivery): ByteArray? = when {
        format.equals("mso_mdoc", ignoreCase = true) -> SecretSeedCommitment.sscOfMdoc(credential)
        format.contains("sd-jwt", ignoreCase = true) -> SecretSeedCommitment.sscOfSdJwt(credential)
        else -> null
    }

    override fun stripFromMetadata(metadata: JsonObject): JsonObject = SecretSeedDelivery.stripped(metadata)

    override fun placeInProof(commitments: List<HolderCommitment>): Map<String, JsonElement> {
        if (commitments.isEmpty()) return emptyMap()
        // One psc, in one claim: anything else this shape cannot express is refused rather than dropped.
        val psc = commitments.singleOrNull()?.takeIf { it.path == listOf("psc") && it.alg == ALG }
            ?: throw WalletException("The legacy shape can carry only the psc commitment", errorCode = "holder_commitment_unsupported")
        return mapOf(PSC_CLAIM to kotlinx.serialization.json.JsonPrimitive(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(psc.commitment)))
    }
}
