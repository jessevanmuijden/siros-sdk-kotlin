// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.security.MessageDigest

/**
 * Why [NymPseudonym.derive] refused its arguments.
 *
 * These are API-misuse errors of the derivation itself. They are NOT the
 * rulebook's "unsatisfiable request" verdicts (a `verifier_context` over 64
 * bytes, an unobtainable `verifier_id`, ...): those belong to the wallet,
 * and the derivation accepts any length of any input it is given.
 */
enum class NymPseudonymReason {
    /** The config id is not in the config table. */
    UNKNOWN_CONFIG,

    /** The config needs an input the caller did not supply. */
    MISSING_INPUT,

    /** The config does not use an input the caller supplied. */
    UNUSED_INPUT,

    /** The seed is not the length the config's seed kind requires. */
    WRONG_SEED_LENGTH,
}

/** Raised by [NymPseudonym.derive] on API misuse. The message never contains seed material. */
class NymPseudonymError(
    val reason: NymPseudonymReason,
    message: String,
) : SirosException(message, errorCode = "nym_pseudonym_${reason.name.lowercase()}")

/**
 * Which of the `nym_auth` attestation's two seeds a config derives from. Both are held by the wallet:
 * the `private_seed` is derived on the device, the `secret_seed` is delivered by the issuer (it is
 * shared with the issuer by design) and checked against `ssc` before every use.
 */
enum class NymSeedKind(val bytes: Int) {
    /** `secret_seed`, opened from `ssc`; shared with the issuer, delivered to the wallet. Rulebook: 16 bytes. */
    SECRET(16),

    /** `private_seed`, opened from `psc`; derived on the device, never leaves it. Rulebook: 16 bytes. */
    PRIVATE(16),
}

/** How a config builds the 32-byte `prover_input`. */
internal enum class NymProverInput {
    /** Null: 32 zero bytes. The caller must not supply a value. */
    NONE,

    /** `SHA256(user-supplied value)`. */
    SHA256_OF_USER_VALUE,
}

/** How a config builds the 32-byte `verifier_input`. */
internal enum class NymVerifierInput {
    /** Null: 32 zero bytes. The caller must supply neither `verifier_id` nor `verifier_context`. */
    NONE,

    /** `SHA256(verifier_id)`. */
    SHA256_OF_ID,

    /** `SHA256(SHA256(verifier_id) || SHA256(verifier_context))`. */
    SHA256_OF_ID_AND_CONTEXT,
}

/** One row of the config table. The DST is derived from [id]. */
internal data class NymConfig(
    val id: String,
    val seed: NymSeedKind,
    val proverInput: NymProverInput,
    val verifierInput: NymVerifierInput,
)

/**
 * What a pseudonym config needs from the caller, for code that has to decide
 * whether it can supply it.
 *
 * @property seedKind Which seed the config derives from: the holder's device-derived
 *   `private_seed` ([NymSeedKind.PRIVATE]) or the issuer-delivered `secret_seed` ([NymSeedKind.SECRET]).
 * @property userValue The config takes a user-supplied value as `prover_input`.
 * @property verifierId The config uses a `verifier_id`.
 * @property verifierContext The config also uses a `verifier_context`.
 */
data class NymConfigInfo(
    val seedKind: NymSeedKind,
    val userValue: Boolean,
    val verifierId: Boolean,
    val verifierContext: Boolean,
)

/**
 * The rulebook's pseudonym function `pseudonym` (v0.4; `pseudonym-v1-sha256` before):
 * `SHA256(DST || seed || prover_input || verifier_input)`, with
 * `DST = "nym_auth/v1/<config>"` (UTF-8) and no separators.
 *
 * Pure and stateless: no seed is logged, returned or cached, and nothing here
 * knows about wallet state, trust, matching or storage. This is the reference
 * for the fake prover and for tests that recompute a presentation's
 * pseudonym; it is unrelated to the legacy [DefaultZkPseudonymDeriver].
 *
 * `verifier_id` is an opaque, caller-supplied UTF-8 string: this code never
 * builds it, never inspects its prefix, and does not know how verifiers are
 * named.
 */
object NymPseudonym {
    private const val DST_PREFIX = "nym_auth/v1/"
    private const val INPUT_BYTES = 32

    /**
     * The config table (rulebook v0.4). A new configuration is a new entry;
     * nothing else changes.
     */
    internal val configs: Map<String, NymConfig> = listOf(
        NymConfig("known-offender-matching-ssc", NymSeedKind.SECRET, NymProverInput.NONE, NymVerifierInput.SHA256_OF_ID),
        NymConfig("known-offender-matching-psc", NymSeedKind.PRIVATE, NymProverInput.NONE, NymVerifierInput.SHA256_OF_ID),
        NymConfig("account-recovery-ssc", NymSeedKind.SECRET, NymProverInput.NONE, NymVerifierInput.SHA256_OF_ID_AND_CONTEXT),
        NymConfig("user-managed-pseudonym-xsite-ssc", NymSeedKind.SECRET, NymProverInput.SHA256_OF_USER_VALUE, NymVerifierInput.NONE),
    ).associateBy { it.id }

    /** What [config] needs from the caller, or null for an unknown config. */
    fun describe(config: String): NymConfigInfo? = configs[config]?.let {
        NymConfigInfo(
            seedKind = it.seed,
            userValue = it.proverInput != NymProverInput.NONE,
            verifierId = it.verifierInput != NymVerifierInput.NONE,
            verifierContext = it.verifierInput == NymVerifierInput.SHA256_OF_ID_AND_CONTEXT,
        )
    }

    /**
     * Derives the 32-byte pseudonym.
     *
     * @param config A config id from the table, e.g. `known-offender-matching-ssc`.
     * @param seed The `secret_seed` or `private_seed` the config uses, at that seed's exact length.
     * @param proverInput The user-supplied value, for configs that hash one; otherwise must be null.
     * @param verifierId The opaque `verifier_id` string, for configs that use one; otherwise must be null.
     *   Its value form is defined by the rulebook / trust framework and produced by the PDP (for example
     *   `x509_san_dns`: the Client Identifier INCLUDING its prefix, `x509_san_dns:<dns name>`; `semantic`: `semantic_id:` plus the ETSI id).
     *   It is hashed byte-for-byte as UTF-8: no lower-casing, trimming or prefix handling happens here.
     * @param verifierContext The `verifier_context` string, for configs that use one; otherwise must be null.
     *   Any length is accepted; the rulebook's 1-64 byte limit is the wallet's satisfiability check.
     * @throws NymPseudonymError on an unknown config, a missing or unused input, or a wrong seed length.
     */
    fun derive(
        config: String,
        seed: ByteArray,
        proverInput: ByteArray? = null,
        verifierId: String? = null,
        verifierContext: String? = null,
    ): ByteArray {
        val entry = configs[config]
            ?: throw NymPseudonymError(NymPseudonymReason.UNKNOWN_CONFIG, "Unknown nym_auth config '$config'")
        if (seed.size != entry.seed.bytes) {
            throw NymPseudonymError(
                NymPseudonymReason.WRONG_SEED_LENGTH,
                "Config '$config' needs a ${entry.seed.bytes}-byte ${entry.seed.name.lowercase()} seed, got ${seed.size} bytes",
            )
        }

        val usesProverInput = entry.proverInput != NymProverInput.NONE
        val usesVerifierId = entry.verifierInput != NymVerifierInput.NONE
        val usesVerifierContext = entry.verifierInput == NymVerifierInput.SHA256_OF_ID_AND_CONTEXT
        checkInput(config, "prover_input", usesProverInput, proverInput != null)
        checkInput(config, "verifier_id", usesVerifierId, verifierId != null)
        checkInput(config, "verifier_context", usesVerifierContext, verifierContext != null)

        val proverBytes = when (entry.proverInput) {
            NymProverInput.NONE -> ByteArray(INPUT_BYTES)
            NymProverInput.SHA256_OF_USER_VALUE -> sha256(proverInput!!)
        }
        val verifierBytes = when (entry.verifierInput) {
            NymVerifierInput.NONE -> ByteArray(INPUT_BYTES)
            NymVerifierInput.SHA256_OF_ID -> sha256(verifierId!!.toByteArray(Charsets.UTF_8))
            NymVerifierInput.SHA256_OF_ID_AND_CONTEXT -> sha256(
                sha256(verifierId!!.toByteArray(Charsets.UTF_8)),
                sha256(verifierContext!!.toByteArray(Charsets.UTF_8)),
            )
        }
        return sha256(
            (DST_PREFIX + entry.id).toByteArray(Charsets.UTF_8),
            seed,
            proverBytes,
            verifierBytes,
        )
    }

    private fun checkInput(config: String, name: String, used: Boolean, supplied: Boolean) {
        if (used && !supplied) {
            throw NymPseudonymError(NymPseudonymReason.MISSING_INPUT, "Config '$config' needs $name")
        }
        if (!used && supplied) {
            throw NymPseudonymError(NymPseudonymReason.UNUSED_INPUT, "Config '$config' does not use $name")
        }
    }

    private fun sha256(vararg parts: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        for (part in parts) digest.update(part)
        return digest.digest()
    }
}
