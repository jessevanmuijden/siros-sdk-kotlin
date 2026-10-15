// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import org.siros.sdk.credentials.SignerSecurityProperties
import org.siros.sdk.keystore.AttestationChain
import org.siros.sdk.keystore.AuthenticationFactor
import org.siros.sdk.keystore.MigrationResult
import org.siros.sdk.keystore.ScaAuthenticationCapability
import org.siros.sdk.keystore.ScaSignSession
import org.siros.sdk.keystore.ScaSignature
import org.siros.sdk.keystore.Signer
import org.siros.sdk.keystore.SignerKeyInfo

/**
 * A [Signer] whose keys really sign (ES256), for tests that check a KB-JWT the way a
 * verifier does. [scaFactors] are what its SCA sign reports having applied, and what
 * the KB-JWT may therefore claim; null models a signer that cannot reach two categories.
 */
class ScaTestSigner(
    private val scaFactors: List<AuthenticationFactor>?,
    /** Models the user cancelling the PIN prompt that starts the sign. */
    private val userCancels: Boolean = false,
) : Signer {
    private val keys = LinkedHashMap<String, ECKey>()
    var scaSigns = 0
        private set
    var plainSigns = 0
        private set

    override suspend fun generateKey(algorithm: String): String {
        val key = ECKeyGenerator(Curve.P_256).keyIDFromThumbprint(true).generate()
        keys[key.keyID] = key
        return key.keyID
    }

    override suspend fun sign(keyId: String, data: ByteArray): ByteArray {
        plainSigns++
        return rawSign(keyId, data)
    }

    private fun rawSign(keyId: String, data: ByteArray): ByteArray =
        ECDSASigner(keys.getValue(keyId)).sign(JWSHeader(JWSAlgorithm.ES256), data).decode()

    override suspend fun scaAuthenticationCapability(keyId: String) =
        if (scaFactors == null) ScaAuthenticationCapability.cannot("single factor") else ScaAuthenticationCapability(true)

    override suspend fun beginScaSign(keyId: String): ScaSignSession {
        if (userCancels) throw org.siros.sdk.credentials.TransactionDataError(org.siros.sdk.credentials.TransactionDataReason.DECLINED, "cancelled")
        val applied = scaFactors ?: throw ScaSignSession.insufficient("single factor")
        return object : ScaSignSession {
            override val declaredFactors = applied
            override suspend fun sign(data: ByteArray): ScaSignature {
                scaSigns++
                return ScaSignature(rawSign(keyId, data), applied)
            }
        }
    }

    override suspend fun listKeys() = keys.keys.map { SignerKeyInfo(it, "ES256") }
    override suspend fun deleteKey(keyId: String) { keys.remove(keyId) }
    override suspend fun attestationChain(keyId: String): AttestationChain? = null
    override suspend fun exportPublicKey(keyId: String) = keys.getValue(keyId).toPublicJWK().toJSONString().toByteArray()
    override suspend fun migrateKey(keyId: String, targetPlugin: String): MigrationResult =
        throw UnsupportedOperationException()
    override suspend fun securityProperties(keyId: String) = SignerSecurityProperties(keyStorage = listOf("software"))
}
