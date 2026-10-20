// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import java.time.LocalDate
import java.time.format.DateTimeParseException
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.NymPseudonym
import org.siros.sdk.credentials.mdoc.DocumentMdoc

// The handlers of the nym_auth rulebook's functions. Everything that names `birth_date`, `ssc`, `psc`, the
// credential's doctype namespace, `age_check` or `pseudonym-v1-sha256` lives here (and in the nymauth adapter); the
// presenter and the wallet reach it only through the [CircuitZkFunctionHandler] hooks.

private const val COMMITMENT_BYTES = 32

/** Whether the credential's claims sit in exactly one namespace, the one its doctype names (the layout the nym_auth circuits bind). */
private fun doctypeNamespaceOnly(credential: DocumentMdoc) = credential.issuerSigned.nameSpaces.keys == setOf(credential.docType)

private fun elementBytes(document: DocumentMdoc, name: String): ByteArray? {
    val v = doctypeElement(document, name) ?: return null
    return if (v.type == CBORType.ByteString) v.GetByteString() else null
}

/**
 * `pseudonym-v1-sha256`: needs the seed its config derives from (the device `private_seed` or the
 * issuer-delivered `secret_seed`) and a user value where the config takes one.
 */
object PseudonymFunctionHandler : CircuitZkFunctionHandler {
    override val functionId = "pseudonym"

    override fun witnessNeeds(function: CircuitZkFunction): Set<CircuitZkWitnessKind> {
        val info = (function.params["config"] as? kotlinx.serialization.json.JsonPrimitive)
            ?.takeIf { it.isString }?.content?.let(NymPseudonym::describe)
            ?: return setOf(CircuitZkWitnessKind.NOT_HELD_BY_WALLET)
        return buildSet {
            add(
                when (info.seedKind) {
                    org.siros.sdk.credentials.NymSeedKind.PRIVATE -> CircuitZkWitnessKind.PRIVATE_SEED
                    org.siros.sdk.credentials.NymSeedKind.SECRET -> CircuitZkWitnessKind.SECRET_SEED
                },
            )
            if (info.userValue) add(CircuitZkWitnessKind.USER_VALUE)
        }
    }

    override fun holds(function: CircuitZkFunction, credential: DocumentMdoc) = true

    // The circuit reads ssc and birth_date from the doctype namespace and does not check that no other namespace holds
    // an attribute of the same name: a credential with a decoy or extra namespace is never proved.
    override fun admitsCredential(function: CircuitZkFunction, credential: DocumentMdoc) = doctypeNamespaceOnly(credential)

    private fun config(function: CircuitZkFunction) =
        (function.params["config"] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content?.let(NymPseudonym::describe)

    override fun needsVerifierId(function: CircuitZkFunction) = config(function)?.verifierId == true

    override fun needsSecretSeed(function: CircuitZkFunction) = config(function)?.seedKind == org.siros.sdk.credentials.NymSeedKind.SECRET

    override fun verifierContext(function: CircuitZkFunction) =
        (function.params["verifier_context"] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content

    override fun commitmentCheck(
        function: CircuitZkFunction,
        credential: DocumentMdoc,
        witness: CircuitZkFunctionWitness,
        provider: CircuitZkWitnessProvider,
        issuer: String?,
    ): CircuitZkCommitmentCheck {
        when (config(function)?.seedKind) {
            // psc: the commitment in the credential must be the one this wallet derives.
            org.siros.sdk.credentials.NymSeedKind.PRIVATE -> {
                val psc = elementBytes(credential, "psc") ?: return CircuitZkCommitmentCheck.DEVICE_COMMITMENT_FAILS
                if (!provider.privateSeedMatches(credential.docType, issuer, psc)) return CircuitZkCommitmentCheck.DEVICE_COMMITMENT_FAILS
            }
            // ssc: SHA256(secret_seed) == ssc. The seed is caller-supplied, so it is never used on trust; ssc is read from
            // the doctype namespace only, as one 32-byte bstr, so the value checked is the value the circuit binds.
            org.siros.sdk.credentials.NymSeedKind.SECRET -> {
                val ssc = elementBytes(credential, "ssc")?.takeIf { it.size == COMMITMENT_BYTES } ?: return CircuitZkCommitmentCheck.DELIVERED_COMMITMENT_FAILS
                val seed = witness.secretSeed ?: return CircuitZkCommitmentCheck.DELIVERED_COMMITMENT_FAILS
                val digest = java.security.MessageDigest.getInstance("SHA-256").digest(seed)
                val ok = java.security.MessageDigest.isEqual(digest, ssc)
                digest.fill(0)
                if (!ok) return CircuitZkCommitmentCheck.DELIVERED_COMMITMENT_FAILS
            }
            null -> Unit
        }
        return CircuitZkCommitmentCheck.HOLDS
    }
}

/**
 * The value of the element [name] in the credential's own doctype namespace (the namespace a nym_auth
 * credential carries its claims in, and the one the circuit binds), or null when that namespace or element
 * is absent or the element occurs more than once there. The same element name in another namespace is
 * never consulted, so a pre-check cannot read a different value than the circuit proves.
 */
internal fun doctypeElement(document: DocumentMdoc, name: String): CBORObject? =
    org.siros.sdk.credentials.SecretSeedCommitment.doctypeElement(document, name)

/** `age_check`: `birth_date` must lie within `ge`..`le`. Needs no private input from the wallet. */
object AgeCheckFunctionHandler : CircuitZkFunctionHandler {
    override val functionId = "age_check"

    override fun witnessNeeds(function: CircuitZkFunction): Set<CircuitZkWitnessKind> = emptySet()

    override fun admitsCredential(function: CircuitZkFunction, credential: DocumentMdoc) = doctypeNamespaceOnly(credential)

    override fun holds(function: CircuitZkFunction, credential: DocumentMdoc): Boolean {
        val birth = birthDate(credential) ?: return false
        val ge = bound(function, "ge")
        val le = bound(function, "le")
        if (ge == null && le == null) return false
        return (ge == null || !birth.isBefore(ge)) && (le == null || !birth.isAfter(le))
    }

    private fun bound(function: CircuitZkFunction, key: String): LocalDate? {
        val s = (function.params[key] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        return try { LocalDate.parse(s) } catch (e: DateTimeParseException) { null }
    }

    private fun birthDate(credential: DocumentMdoc): LocalDate? {
        val value = doctypeElement(credential, "birth_date") ?: return null
        val text = if (value.isTagged) value.UntagOne() else value
        if (text.type != CBORType.TextString) return null
        return try { LocalDate.parse(text.AsString()) } catch (e: DateTimeParseException) { null }
    }
}

