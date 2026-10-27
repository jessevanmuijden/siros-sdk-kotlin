// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/**
 * A secret an issuer delivers to the wallet, normalised: where it belongs (the claims [path] it commits to, or the legacy
 * namespace), the hash [alg] of the commitment and the secret [bytes] (the "opening"). The caller owns [bytes] and zeroes them.
 */
class SecretDelivery(val path: List<String>, val alg: String, val bytes: ByteArray) {
    /** How the claim at [path] writes the commitment (the advertised `encoding`; null: the format's default); set from the advertisement at receipt. */
    var encoding: String? = null

    override fun toString() = "SecretDelivery(path=$path, alg=$alg, redacted)"
}

/**
 * A commitment the wallet gives the issuer, normalised: the claims [path] it is for, the hash [alg], whether the issuer
 * [required] it, and the [commitment] value itself.
 */
class HolderCommitment(val path: List<String>, val alg: String, val required: Boolean, val commitment: ByteArray, val encoding: String? = null) {
    override fun toString() = "HolderCommitment(path=$path, alg=$alg, required=$required, redacted)"
}

/** What a configuration advertises it will deliver ([toWallet]) and wants ([toIssuer]), normalised. Names and slots, never values. */
class AuxiliaryAdvertisement(val toWallet: List<Slot>, val toIssuer: List<Slot>) {
    /** [encoding]: how the claim at [path] writes the commitment (`base64url`, `base64`, `hex`); null: the format's default (SD-JWT unpadded base64url, mdoc a byte string). */
    class Slot(val path: List<String>, val alg: String, val required: Boolean = false, val encoding: String? = null)
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
    fun deliveriesToVerify(deliveries: List<SecretDelivery>, advertised: AuxiliaryAdvertisement?): List<SecretDelivery>?

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
    val all: List<AuxiliaryDataShape> get() = listOf(AuxiliaryDataV01)

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
