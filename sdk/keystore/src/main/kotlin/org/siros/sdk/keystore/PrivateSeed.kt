// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.security.MessageDigest

/**
 * A wallet root secret that can derive labelled secrets without ever handing
 * out the key itself.
 *
 * Internal on purpose: a public generic derivation primitive on a keystore
 * would let any SDK consumer call it with the seed label and read the seed. The
 * keystores keep their `mainKey` behind it and expose only the purpose-bound
 * [HolderWitnessSource]; tests supply a fixed root instead.
 */
internal interface RootSecret {
    /**
     * `HKDF-SHA256(root, salt = empty, info)[:length]`.
     *
     * @param info The full HKDF info input, label included; see [PrivateSeed] for the one in use.
     * @param length Output length in bytes, at most 32.
     * @throws org.siros.sdk.credentials.KeystoreException if the root is not available (a locked keystore).
     */
    fun deriveSecret(info: ByteArray, length: Int): ByteArray
}

/**
 * The holder's `private_seed` for a credential type AT AN ISSUER, and its commitment (privatedata-spec 2.7, section 5.4.1).
 *
 * `private_seed = HKDF-SHA256(root, salt = empty, info = "org.siros.private_seed/v2" || lp(credentialType) || lp(issuer))[:16]`,
 * `psc = SHA256(private_seed)`, where `lp(x)` is the 2-byte big-endian length of the UTF-8 bytes of `x` followed by
 * those bytes (injective: `("ab", "c")` and `("a", "bc")` differ). The seed is stable per (credential type, issuer): it
 * does not depend on a credential id, a batch or an issuance, so every batch, issuance and renewal at one issuer commits
 * to the same `psc`, and different issuers see different `psc` values for the same person.
 *
 * `credentialType` is an opaque caller-supplied string (a doctype, a vct) and `issuer` is the Credential Issuer
 * Identifier EXACTLY as the credential stores it (`credentialIssuerIdentifier`): both are UTF-8 encoded, never
 * interpreted and never normalised (a trailing slash gives another seed). An empty field, or one longer than 65535
 * bytes, is refused ([IllegalArgumentException], no value in its message): no seed is derived. The label `v1` was never
 * released and is withdrawn.
 *
 * The root is the container `mainKey` (via [JweKeystore]), not a PRF output:
 * `mainKey` is the same on every passkey and device of an account, while PRF
 * outputs differ per passkey and would change the seed on a second passkey.
 * The label is defined in privatedata-spec SPEC.md section 5.4.1.
 *
 * # Permanence
 *
 * `mainKey` MUST NEVER be rotated or re-keyed: doing so changes every seed
 * and so every `psc`. No such code exists today. `mainKey` is generated once,
 * when a first container is created ([JweKeystore.unlock] with an empty
 * container), and every later export re-encrypts under the same key; adding
 * a passkey only wraps the same `mainKey` for another PRF key. Losing the
 * container and creating a new one is, necessarily, a new root.
 *
 * The seed never leaves this module except as a witness handed to the
 * configured prover (see [HolderWitnessSource]): it is not returned, logged,
 * stored or cached, and appears in no exception message. Every call derives it
 * afresh, so a locked keystore yields nothing. This class and [RootSecret] are
 * internal; no public member of a keystore derives a secret.
 */
internal class PrivateSeed(private val root: RootSecret) {

    /** `SHA256(private_seed)` for [credentialType] at [issuer]: the value the issuer receives in the credential request. */
    fun psc(credentialType: String, issuer: String): ByteArray {
        val seed = derive(credentialType, issuer)
        try {
            return MessageDigest.getInstance("SHA-256").digest(seed)
        } finally {
            seed.fill(0)
        }
    }

    /**
     * Whether [psc] is the commitment this wallet derives for [credentialType] at [issuer].
     * Fail-closed: anything but an exact 32-byte match is `false`, and a
     * wallet that gets `false` must not use the seed.
     *
     * @throws org.siros.sdk.credentials.KeystoreException if the keystore is locked.
     * @throws IllegalArgumentException if [credentialType] or [issuer] is refused (empty or over 65535 bytes).
     */
    fun matchesCommitment(credentialType: String, issuer: String, psc: ByteArray): Boolean {
        val expected = psc(credentialType, issuer)
        return psc.size == expected.size && MessageDigest.isEqual(expected, psc)
    }

    /** The 16-byte seed. Internal on purpose: callers get `psc` and the check, never the seed. */
    internal fun derive(credentialType: String, issuer: String): ByteArray = root.deriveSecret(info(credentialType, issuer), SEED_BYTES)

    internal companion object {
        /** The derivation label, including its version. */
        const val LABEL = "org.siros.private_seed/v2"

        /** The rulebook's `private_seed` length. */
        const val SEED_BYTES = 16

        private const val MAX_FIELD_BYTES = 65535

        /** The HKDF `info`: the label, then each field with its 2-byte big-endian length. */
        fun info(credentialType: String, issuer: String): ByteArray =
            LABEL.toByteArray(Charsets.UTF_8) + lp(credentialType) + lp(issuer)

        private fun lp(field: String): ByteArray {
            val bytes = field.toByteArray(Charsets.UTF_8)
            require(bytes.isNotEmpty() && bytes.size <= MAX_FIELD_BYTES) { "private_seed input refused" }
            return byteArrayOf((bytes.size shr 8).toByte(), bytes.size.toByte()) + bytes
        }
    }
}

/**
 * The purpose-bound view of a wallet's private seed: the only way outside this
 * module to use it. It offers the commitment the issuer receives, and a
 * [CircuitZkPresenter] that feeds the seed to its prover; it has no generic
 * derivation, and no member returns the seed or hands out a witness provider.
 *
 * Implemented by [JweKeystore] and [WscdKeystoreAdapter] over the container
 * `mainKey`, and by [FixedRootHolderWitnessSource] for demos and tests.
 *
 * What stays reachable, by design: the presenter passes the seed as a witness
 * to the [CircuitZkProver] the host supplies, so a host's own prover sees it.
 * The host app is inside the wallet's trust boundary; the seed is protected from
 * verifiers, issuers and other apps, not from the app that embeds the SDK.
 */
interface HolderWitnessSource {
    /**
     * `SHA256(private_seed)` for [credentialType] at [issuer] (the Credential Issuer Identifier exactly as the credential
     * stores it): the commitment that issuer receives. Another issuer string is another commitment.
     *
     * @throws IllegalArgumentException if either is empty or over 65535 bytes.
     */
    fun privateSeedCommitment(credentialType: String, issuer: String): ByteArray

    /**
     * A presenter whose witnesses come from this source's seed.
     *
     * @param userValue The user-supplied value for functions that take one, if any.
     */
    fun circuitZkPresenter(
        prover: CircuitZkProver,
        circuits: org.siros.sdk.credentials.CircuitZkCircuitSource,
        validator: org.siros.sdk.credentials.CircuitZkRequestValidator,
        handlers: List<CircuitZkFunctionHandler> = DEFAULT_CIRCUIT_ZK_HANDLERS,
        residency: ZkProverResidency? = null,
        userValue: ByteArray? = null,
        serving: org.siros.sdk.credentials.CircuitZkServing? = org.siros.sdk.credentials.SharedCircuitZkServing,
    ): CircuitZkPresenter
}

/** [HolderWitnessSource] over a [PrivateSeed]. */
internal class SeedBackedWitnessSource(private val seeds: PrivateSeed) : HolderWitnessSource {
    override fun privateSeedCommitment(credentialType: String, issuer: String): ByteArray = seeds.psc(credentialType, issuer)

    override fun circuitZkPresenter(
        prover: CircuitZkProver,
        circuits: org.siros.sdk.credentials.CircuitZkCircuitSource,
        validator: org.siros.sdk.credentials.CircuitZkRequestValidator,
        handlers: List<CircuitZkFunctionHandler>,
        residency: ZkProverResidency?,
        userValue: ByteArray?,
        serving: org.siros.sdk.credentials.CircuitZkServing?,
    ): CircuitZkPresenter =
        CircuitZkPresenter(prover, circuits, validator, HolderWitnessProvider(seeds, userValue), handlers, residency, serving)
}

/**
 * A [HolderWitnessSource] over a key the caller supplies, for demos and tests:
 * `HKDF-SHA256(rootKey, info)`, the same derivation a keystore applies to its
 * `mainKey`. It holds no wallet secret; the root is the caller's own.
 */
class FixedRootHolderWitnessSource(rootKey: ByteArray) : HolderWitnessSource {
    private val delegate = SeedBackedWitnessSource(
        PrivateSeed(object : RootSecret {
            private val key = rootKey.copyOf()
            override fun deriveSecret(info: ByteArray, length: Int): ByteArray =
                EncryptedContainer.hkdfSha256(key, ByteArray(0), info, length)
        }),
    )

    override fun privateSeedCommitment(credentialType: String, issuer: String): ByteArray = delegate.privateSeedCommitment(credentialType, issuer)

    override fun circuitZkPresenter(
        prover: CircuitZkProver,
        circuits: org.siros.sdk.credentials.CircuitZkCircuitSource,
        validator: org.siros.sdk.credentials.CircuitZkRequestValidator,
        handlers: List<CircuitZkFunctionHandler>,
        residency: ZkProverResidency?,
        userValue: ByteArray?,
        serving: org.siros.sdk.credentials.CircuitZkServing?,
    ): CircuitZkPresenter = delegate.circuitZkPresenter(prover, circuits, validator, handlers, residency, userValue, serving)
}
