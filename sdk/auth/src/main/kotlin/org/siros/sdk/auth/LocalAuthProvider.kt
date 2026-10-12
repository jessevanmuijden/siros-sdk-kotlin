// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.auth

import org.siros.sdk.credentials.AuthException
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import timber.log.Timber
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * A fully local [AuthProvider] backed by Android KeyStore.
 *
 * This provider implements the WebAuthn authenticator model entirely
 * on-device, without delegating to the system Credential Manager picker.
 * It works on API 28+ and does not require Google Play Services or any
 * external credential provider to be installed.
 *
 * Keys are generated in Android KeyStore (hardware-backed when available)
 * and credential metadata is stored in app-private SharedPreferences.
 *
 * @param context Application or Activity context.
 */
class LocalAuthProvider(
    private val context: Context,
    private val requireUserAuth: Boolean = true,
) : AuthProvider {

    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private val credStore = LocalCredentialStore(context)
    private val json = Json { ignoreUnknownKeys = true }
    private val androidOrigin: String by lazy { computeAndroidOrigin(context) }

    /** Credential ID from the most recent register/authenticate call. */
    var lastCredentialId: ByteArray? = null
        private set

    /** PRF output from the most recent register/authenticate call. */
    var lastPrfOutput: PrfOutput? = null

    /**
     * Remove the most recently registered credential from local storage.
     * Call this when the backend rejects the registration (e.g. origin mismatch)
     * to avoid leaving orphaned passkeys that show up in "Welcome back".
     */
    fun rollbackLastRegistration() {
        val credId = lastCredentialId ?: return
        val alias = keyAlias(credId)
        credStore.delete(b64url(credId))
        try { keyStore.deleteEntry(alias) } catch (_: Exception) {}
        lastCredentialId = null
        lastPrfOutput = null
        Timber.i("LocalAuthProvider: rolled back last registration")
    }

    override suspend fun register(options: RegisterOptions): RegisterResult {
        // Generate a random credential ID
        val credentialId = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val keyAlias = keyAlias(credentialId)

        // Generate EC P-256 key pair in Android KeyStore
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE
        )
        val keySpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(requireUserAuth)
            .apply {
                if (requireUserAuth && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(
                        0, // require auth every use
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                    )
                }
            }
            .build()
        keyPairGenerator.initialize(keySpec)
        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = keyPair.public as ECPublicKey

        // Build authenticator data
        val rpIdHash = sha256(options.rpId.toByteArray(Charsets.UTF_8))
        val flags: Byte = (FLAGS_UP.toInt() or FLAGS_UV.toInt() or FLAGS_AT.toInt()).toByte() // UP + UV + AT
        val counter = 1
        val aaguid = SIROS_AAGUID
        val coseKey = ecPublicKeyToCose(publicKey)
        val authData = buildAuthData(rpIdHash, flags, counter, credentialId, coseKey)

        // Build client data JSON
        val clientDataJson = buildClientDataJson(
            type = "webauthn.create",
            challenge = b64url(options.challenge),
            origin = androidOrigin,
        )

        // Build attestation object (fmt: "none")
        val attestationObject = buildAttestationObject(authData)

        // Compute PRF output if requested
        val prfOutput = options.prfSalt?.let { salt ->
            computePrf(credentialId, salt)
        }

        // Store credential metadata
        credStore.save(
            LocalCredentialEntry(
                credentialId = b64url(credentialId),
                keyAlias = keyAlias,
                rpId = options.rpId,
                userHandle = b64url(options.userId),
                userName = options.userName,
                userDisplayName = options.userDisplayName,
                signCount = counter,
                createdAt = System.currentTimeMillis(),
            )
        )

        lastCredentialId = credentialId
        lastPrfOutput = prfOutput

        Timber.i("LocalAuthProvider: registered credential for RP ${options.rpId}")

        return RegisterResult(
            credentialId = credentialId,
            attestationObject = attestationObject,
            clientDataJSON = clientDataJson,
            prfOutput = prfOutput,
        )
    }

    override suspend fun authenticate(options: AuthenticateOptions): AuthenticateResult {
        // Find matching credentials. When no explicit allowCredentials list is
        // given, narrow to prfSaltsByCredential's candidates if present (this
        // provider always resolves a single concrete credential itself rather
        // than delegating to a system picker, so - unlike a discoverable
        // multi-account flow - there's no ambiguity to preserve here).
        val candidates = credStore.getByRpId(options.rpId)
        val allowedIds = options.allowCredentials?.map { b64url(it.id) }?.toSet()
            ?: options.prfSaltsByCredential?.map { (credId, _) -> b64url(credId) }?.toSet()
        val credential = if (allowedIds != null) {
            candidates.firstOrNull { it.credentialId in allowedIds }
        } else {
            candidates.firstOrNull()
        } ?: throw AuthException("No matching credential found for RP ${options.rpId}")

        val credentialId = b64urlDecode(credential.credentialId)

        // Increment sign counter
        val newCount = credential.signCount + 1
        credStore.save(credential.copy(signCount = newCount))

        // Build authenticator data (no attested credential data for assertion)
        val rpIdHash = sha256(options.rpId.toByteArray(Charsets.UTF_8))
        val flags: Byte = (FLAGS_UP.toInt() or FLAGS_UV.toInt()).toByte() // UP + UV
        val authData = buildAuthData(rpIdHash, flags, newCount)

        // Build client data JSON
        val clientDataJson = buildClientDataJson(
            type = "webauthn.get",
            challenge = b64url(options.challenge),
            origin = androidOrigin,
        )

        // Sign: SHA-256(authData || SHA-256(clientDataJSON))
        val clientDataHash = sha256(clientDataJson)
        val signedData = authData + clientDataHash

        val privateKeyEntry = keyStore.getEntry(credential.keyAlias, null) as? KeyStore.PrivateKeyEntry
            ?: throw AuthException("Key not found in keystore: ${credential.keyAlias}")
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(privateKeyEntry.privateKey)
        sig.update(signedData)
        val signature = sig.sign()

        // Compute PRF output if requested - prefer the per-credential salt for
        // whichever credential was actually selected above (mirrors WebAuthn's
        // evalByCredential), falling back to a single shared salt.
        val prfSaltForCredential = options.prfSaltsByCredential
            ?.firstOrNull { (credId, _) -> b64url(credId) == credential.credentialId }
            ?.second
            ?: options.prfSalt
        val prfOutput = prfSaltForCredential?.let { salt ->
            computePrf(credentialId, salt)
        }

        lastCredentialId = credentialId
        lastPrfOutput = prfOutput

        Timber.i("LocalAuthProvider: authenticated with credential")

        return AuthenticateResult(
            credentialId = credentialId,
            authenticatorData = authData,
            clientDataJSON = clientDataJson,
            signature = signature,
            userHandle = b64urlDecode(credential.userHandle),
            prfOutput = prfOutput,
        )
    }

    override suspend fun getPrfOutput(credentialId: ByteArray, salt: ByteArray, rpId: String): PrfOutput {
        return computePrf(credentialId, salt)
    }

    // ── CBOR / attestation helpers ──────────────────────────────────

    /**
     * Build a CBOR-encoded attestation object with fmt "none".
     * Hand-coded CBOR to avoid pulling in a CBOR library.
     */
    private fun buildAttestationObject(authData: ByteArray): ByteArray {
        // CBOR map(3): { "fmt": "none", "attStmt": {}, "authData": <bytes> }
        val fmt = cborTextString("fmt")
        val fmtVal = cborTextString("none")
        val attStmt = cborTextString("attStmt")
        val attStmtVal = byteArrayOf(0xA0.toByte()) // empty map
        val authDataKey = cborTextString("authData")
        val authDataVal = cborByteString(authData)

        val buf = ByteBuffer.allocate(1 + fmt.size + fmtVal.size + attStmt.size + attStmtVal.size + authDataKey.size + authDataVal.size)
        buf.put(0xA3.toByte()) // map(3)
        buf.put(fmt)
        buf.put(fmtVal)
        buf.put(attStmt)
        buf.put(attStmtVal)
        buf.put(authDataKey)
        buf.put(authDataVal)
        return buf.array()
    }

    /**
     * Build authenticator data.
     * For registration: includes attested credential data (credentialId + COSE key).
     * For assertion: just rpIdHash + flags + counter.
     */
    private fun buildAuthData(
        rpIdHash: ByteArray,
        flags: Byte,
        signCount: Int,
        credentialId: ByteArray? = null,
        coseKey: ByteArray? = null,
    ): ByteArray {
        val base = ByteBuffer.allocate(37)
        base.put(rpIdHash) // 32 bytes
        base.put(flags)
        base.putInt(signCount)
        val baseBytes = base.array()

        if (credentialId == null || coseKey == null) {
            return baseBytes
        }

        // Attested credential data: AAGUID (16) + credIdLen (2) + credId + COSE key
        val atData = ByteBuffer.allocate(16 + 2 + credentialId.size + coseKey.size)
        atData.put(SIROS_AAGUID)
        atData.putShort(credentialId.size.toShort())
        atData.put(credentialId)
        atData.put(coseKey)
        return baseBytes + atData.array()
    }

    /**
     * Encode an EC P-256 public key as a COSE_Key (RFC 9052).
     * Returns CBOR bytes for: { 1: 2, 3: -7, -1: 1, -2: x, -3: y }
     */
    private fun ecPublicKeyToCose(key: ECPublicKey): ByteArray {
        val x = key.w.affineX.toByteArray().padOrTrimTo32()
        val y = key.w.affineY.toByteArray().padOrTrimTo32()

        // Hand-coded CBOR map(5)
        val items = mutableListOf<ByteArray>()
        items.add(cborInt(1)); items.add(cborInt(2))        // kty: EC2
        items.add(cborInt(3)); items.add(cborNegInt(6))     // alg: ES256 (-7)
        items.add(cborNegInt(0)); items.add(cborInt(1))     // crv: P-256
        items.add(cborNegInt(1)); items.add(cborByteString(x)) // x
        items.add(cborNegInt(2)); items.add(cborByteString(y)) // y

        val totalSize = items.sumOf { it.size }
        val buf = ByteBuffer.allocate(1 + totalSize)
        buf.put(0xA5.toByte()) // map(5)
        items.forEach { buf.put(it) }
        return buf.array()
    }

    /**
     * Build the clientDataJSON per the WebAuthn spec.
     */
    private fun buildClientDataJson(type: String, challenge: String, origin: String): ByteArray {
        // Must be exact JSON format expected by WebAuthn servers
        val json = """{"type":"$type","challenge":"$challenge","origin":"$origin","crossOrigin":false}"""
        return json.toByteArray(Charsets.UTF_8)
    }

    /**
     * Software PRF for this dev/test provider: HMAC-SHA-256 keyed with the
     * credential ID plus [PRF_KEY_MATERIAL], over the salt.
     *
     * Since we can't export the private key from Android KeyStore, we use the
     * credential ID as HMAC key material combined with the salt. This gives a
     * deterministic, credential-bound pseudorandom output - not a secret one
     * (a credential ID is public), which is why this provider is dev/test
     * only and why the production [CredentialManagerAuthProvider] fails
     * closed rather than falling back to anything like it.
     *
     * Documented divergence from the Swift SDK's `LocalAuthProvider`, which
     * keys the same HMAC with the credential ID alone. Neither provider's
     * credentials roam, so a container sealed by one is never presented to
     * the other; reconciling would only re-key existing dev wallets.
     */
    private fun computePrf(credentialId: ByteArray, salt: ByteArray): PrfOutput {
        val hmac = Mac.getInstance("HmacSHA256")
        hmac.init(SecretKeySpec(credentialId + PRF_KEY_MATERIAL, "HmacSHA256"))
        hmac.update(salt)
        return PrfOutput(first = hmac.doFinal())
    }

    // ── CBOR encoding primitives ────────────────────────────────────

    private fun cborInt(value: Int): ByteArray {
        // Major type 0: unsigned integer
        return if (value < 24) {
            byteArrayOf(value.toByte())
        } else if (value < 256) {
            byteArrayOf(0x18, value.toByte())
        } else {
            byteArrayOf(0x19, (value shr 8).toByte(), value.toByte())
        }
    }

    private fun cborNegInt(value: Int): ByteArray {
        // Major type 1: negative integer (encodes -1-value)
        return if (value < 24) {
            byteArrayOf((0x20 or value).toByte())
        } else if (value < 256) {
            byteArrayOf(0x38, value.toByte())
        } else {
            byteArrayOf(0x39, (value shr 8).toByte(), value.toByte())
        }
    }

    private fun cborTextString(s: String): ByteArray {
        val bytes = s.toByteArray(Charsets.UTF_8)
        val header = cborMajorWithLen(3, bytes.size)
        return header + bytes
    }

    private fun cborByteString(bytes: ByteArray): ByteArray {
        val header = cborMajorWithLen(2, bytes.size)
        return header + bytes
    }

    private fun cborMajorWithLen(major: Int, len: Int): ByteArray {
        val base = major shl 5
        return if (len < 24) {
            byteArrayOf((base or len).toByte())
        } else if (len < 256) {
            byteArrayOf((base or 24).toByte(), len.toByte())
        } else {
            byteArrayOf((base or 25).toByte(), (len shr 8).toByte(), len.toByte())
        }
    }

    // ── Utility ─────────────────────────────────────────────────────

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun keyAlias(credentialId: ByteArray): String =
        "siros_passkey_${b64url(credentialId)}"

    private fun ByteArray.padOrTrimTo32(): ByteArray {
        return when {
            size == 32 -> this
            size > 32 -> copyOfRange(size - 32, size)
            else -> ByteArray(32 - size) + this
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        private val decoder = java.util.Base64.getUrlDecoder()

        private fun b64url(data: ByteArray): String = encoder.encodeToString(data)
        private fun b64urlDecode(data: String): ByteArray = decoder.decode(data)

        /**
         * Compute the `android:apk-key-hash:<base64url-sha256>` origin
         * from the app's signing certificate, matching the format that
         * Android's FIDO2 / Credential Manager uses for WebAuthn origins.
         */
        fun computeAndroidOrigin(context: Context): String {
            val certBytes = getSigningCertBytes(context)
            val sha256 = MessageDigest.getInstance("SHA-256").digest(certBytes)
            val hash = encoder.encodeToString(sha256)
            val origin = "android:apk-key-hash:$hash"
            Timber.d("Computed Android origin: $origin")
            return origin
        }

        @Suppress("DEPRECATION")
        private fun getSigningCertBytes(context: Context): ByteArray {
            val packageName = context.packageName
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val signingInfo = context.packageManager
                    .getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                    .signingInfo
                    ?: throw AuthException("No signing info available")
                val cert = if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners.first()
                } else {
                    signingInfo.signingCertificateHistory.first()
                }
                cert.toByteArray()
            } else {
                context.packageManager
                    .getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                    .signatures!!
                    .first()
                    .toByteArray()
            }
        }

        // SIROS Foundation AAGUID (randomly generated, stable)
        private val SIROS_AAGUID = byteArrayOf(
            0x53, 0x49, 0x52, 0x4F, // SIRO
            0x53, 0x2D, 0x57, 0x41, // S-WA
            0x4C, 0x4C, 0x45, 0x54, // LLET
            0x2D, 0x4B, 0x45, 0x59, // -KEY
        )

        // Static material mixed into PRF HMAC to prevent credential ID alone from being the key
        private val PRF_KEY_MATERIAL = "SIROS-LOCAL-PRF-v1".toByteArray(Charsets.UTF_8)

        // WebAuthn authenticator data flags
        private const val FLAGS_UP: Byte = 0x01       // User Present
        private const val FLAGS_UV: Byte = 0x04       // User Verified
        private const val FLAGS_AT: Byte = 0x40       // Attested credential data
    }
}

// ── Local credential metadata store ─────────────────────────────

@Serializable
internal data class LocalCredentialEntry(
    val credentialId: String,
    val keyAlias: String,
    val rpId: String,
    val userHandle: String,
    val userName: String,
    val userDisplayName: String,
    val signCount: Int,
    val createdAt: Long,
)

/**
 * Simple SharedPreferences-backed store for local credential metadata.
 * Keys live in Android KeyStore; this only stores the mapping.
 */
internal class LocalCredentialStore(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences(
        PREFS_NAME, Context.MODE_PRIVATE
    )
    private val json = Json { ignoreUnknownKeys = true }

    fun getAll(): List<LocalCredentialEntry> {
        val raw = prefs.getString(KEY_ENTRIES, null) ?: return emptyList()
        return json.decodeFromString(ListSerializer(LocalCredentialEntry.serializer()), raw)
    }

    fun getByRpId(rpId: String): List<LocalCredentialEntry> =
        getAll().filter { it.rpId == rpId }

    fun save(entry: LocalCredentialEntry) {
        val entries = getAll().toMutableList()
        entries.removeAll { it.credentialId == entry.credentialId }
        entries.add(entry)
        persist(entries)
    }

    fun delete(credentialId: String) {
        val entries = getAll().toMutableList()
        entries.removeAll { it.credentialId == credentialId }
        persist(entries)
    }

    fun clear() {
        prefs.edit().remove(KEY_ENTRIES).apply()
    }

    private fun persist(entries: List<LocalCredentialEntry>) {
        val raw = json.encodeToString(ListSerializer(LocalCredentialEntry.serializer()), entries)
        prefs.edit().putString(KEY_ENTRIES, raw).apply()
    }

    companion object {
        private const val PREFS_NAME = "siros_local_passkeys"
        private const val KEY_ENTRIES = "entries"
    }
}
