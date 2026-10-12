// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.auth

import android.content.Context
import org.siros.sdk.credentials.AuthException
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import timber.log.Timber

/**
 * [AuthProvider] implementation backed by Android Credential Manager.
 *
 * Uses [CreatePublicKeyCredentialRequest] for registration and
 * [GetPublicKeyCredentialOption] for authentication — both accept/return
 * the standard WebAuthn JSON serialization.
 *
 * @param context Activity or Application context. For passkey UI, pass the Activity context.
 */
class CredentialManagerAuthProvider(
    private val context: Context,
) : AuthProvider, WscdAutoEnrollHint {

    private val credentialManager = CredentialManager.create(context)
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * The credential ID from the most recent register/authenticate call.
     * Used by [SirosWallet] to persist the credential for future PRF evaluations.
     */
    var lastCredentialId: ByteArray? = null
        private set

    /**
     * The PRF output from the most recent register/authenticate call.
     * Null if the authenticator did not support PRF.
     */
    var lastPrfOutput: PrfOutput? = null
        private set

    /**
     * The top-level WebAuthn `PublicKeyCredential.authenticatorAttachment`
     * (`"platform"` or `"cross-platform"`) from the most recent
     * [authenticate] call, or null if the response didn't include it (older
     * OS/API versions, or the platform simply doesn't report it - this is
     * parsed defensively, absence is not an error). See
     * [WscdAutoEnrollHint]'s doc comment for why this is only ever a
     * heuristic signal, never a real capability check.
     */
    var lastAuthenticatorAttachment: String? = null
        private set

    override val hintedWscdPluginId: String = "fido2"

    /**
     * `"cross-platform"` means a roaming authenticator (e.g. a YubiKey) was
     * used to log in, rather than the device's own platform biometric -
     * exactly the kind of physical authenticator the fido2 previewSign
     * plugin needs. See [WscdAutoEnrollHint]'s doc comment for why this is
     * a heuristic, not confirmation that this specific key supports
     * previewSign.
     */
    override fun suggestsWscdCapableDevice(): Boolean =
        lastAuthenticatorAttachment == "cross-platform"

    override suspend fun register(options: RegisterOptions): RegisterResult {
        val requestJson = buildCreationOptionsJson(options)
        Timber.d("CreatePublicKeyCredentialRequest prepared")

        val request = CreatePublicKeyCredentialRequest(requestJson)
        val response = credentialManager.createCredential(context, request)

        if (response !is CreatePublicKeyCredentialResponse) {
            throw AuthException("Unexpected credential response type: ${response::class.simpleName}")
        }

        return parseRegistrationResponse(response.registrationResponseJson).also {
            lastCredentialId = it.credentialId
            lastPrfOutput = it.prfOutput
        }
    }

    override suspend fun authenticate(options: AuthenticateOptions): AuthenticateResult {
        val requestJson = buildRequestOptionsJson(options)
        Timber.d("GetPublicKeyCredentialOption prepared")

        val credentialOption = GetPublicKeyCredentialOption(requestJson)
        val request = GetCredentialRequest(listOf(credentialOption))
        val response = credentialManager.getCredential(context, request)

        val credential = response.credential
        if (credential !is PublicKeyCredential) {
            throw AuthException("Unexpected credential type: ${credential::class.simpleName}")
        }

        return parseAuthenticationResponse(credential.authenticationResponseJson).also {
            lastCredentialId = it.credentialId
            lastPrfOutput = it.prfOutput
            lastAuthenticatorAttachment = json.parseToJsonElement(credential.authenticationResponseJson)
                .jsonObject["authenticatorAttachment"]?.jsonPrimitive?.contentOrNull
        }
    }

    override suspend fun getPrfOutput(credentialId: ByteArray, salt: ByteArray, rpId: String): PrfOutput {
        // Issue a standalone credentials.get with PRF extension for the given credential+salt.
        // The challenge is a random throwaway — we only care about the PRF output.
        val challenge = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val requestJson = buildJsonObject {
            put("challenge", b64url(challenge))
            put("rpId", rpId)
            put("timeout", 60000)
            put("userVerification", "required")
            put("allowCredentials", buildJsonArray {
                add(buildJsonObject {
                    put("type", "public-key")
                    put("id", b64url(credentialId))
                })
            })
            put("extensions", buildJsonObject {
                put("prf", buildJsonObject {
                    put("eval", buildJsonObject {
                        put("first", b64url(salt))
                    })
                })
            })
        }.toString()

        val credentialOption = GetPublicKeyCredentialOption(requestJson)
        val request = GetCredentialRequest(listOf(credentialOption))
        val response = credentialManager.getCredential(context, request)
        val credential = response.credential
        if (credential !is PublicKeyCredential) {
            throw AuthException("Unexpected credential type: ${credential::class.simpleName}")
        }

        return extractPrfOutput(credential.authenticationResponseJson)
            ?: throw AuthException("PRF extension not supported by this authenticator")
    }

    // ── JSON builders ───────────────────────────────────────────────

    private fun buildCreationOptionsJson(options: RegisterOptions): String {
        val obj = buildJsonObject {
            put("challenge", b64url(options.challenge))
            put("rp", buildJsonObject {
                put("id", options.rpId)
                put("name", options.rpName)
            })
            put("user", buildJsonObject {
                put("id", b64url(options.userId))
                put("name", options.userName)
                put("displayName", options.userDisplayName)
            })
            put("pubKeyCredParams", buildJsonArray {
                add(buildJsonObject { put("type", "public-key"); put("alg", -7) })   // ES256
                add(buildJsonObject { put("type", "public-key"); put("alg", -257) }) // RS256
            })
            put("timeout", 60000)
            put("attestation", options.attestation)

            val sel = options.authenticatorSelection ?: AuthenticatorSelection()
            put("authenticatorSelection", buildJsonObject {
                sel.authenticatorAttachment?.let { put("authenticatorAttachment", it) }
                put("residentKey", sel.residentKey)
                put("userVerification", sel.userVerification)
            })

            // PRF extension — request evaluation if salt is provided
            options.prfSalt?.let { salt ->
                put("extensions", buildJsonObject {
                    put("prf", buildJsonObject {
                        put("eval", buildJsonObject {
                            put("first", b64url(salt))
                        })
                    })
                })
            }
        }
        return obj.toString()
    }

    private fun buildRequestOptionsJson(options: AuthenticateOptions): String {
        val obj = buildJsonObject {
            put("challenge", b64url(options.challenge))
            put("rpId", options.rpId)
            put("timeout", 60000)
            put("userVerification", options.userVerification)

            // allowCredentials: explicit list takes priority; otherwise derive
            // it from evalByCredential's candidate credential IDs so the
            // system picker is filtered to exactly the passkeys we have
            // salts for.
            val effectiveAllowCredentials = options.allowCredentials
                ?: options.prfSaltsByCredential?.map { (credId, _) -> AllowCredential(id = credId) }
            effectiveAllowCredentials?.let { creds ->
                put("allowCredentials", buildJsonArray {
                    creds.forEach { cred ->
                        add(buildJsonObject {
                            put("type", cred.type)
                            put("id", b64url(cred.id))
                        })
                    }
                })
            }

            // PRF extension for authentication. evalByCredential lets each
            // candidate credential (different accounts, or multiple passkeys
            // on one account) use its own salt in a single ceremony - the
            // authenticator evaluates PRF using whichever credential the
            // user actually selects, so the caller never has to guess which
            // account will be used before the ceremony completes. Falls back
            // to a single shared salt (eval.first) if no per-credential
            // salts were given.
            if (!options.prfSaltsByCredential.isNullOrEmpty()) {
                put("extensions", buildJsonObject {
                    put("prf", buildJsonObject {
                        put("evalByCredential", buildJsonObject {
                            options.prfSaltsByCredential.forEach { (credId, salt) ->
                                put(b64url(credId), buildJsonObject {
                                    put("first", b64url(salt))
                                })
                            }
                        })
                    })
                })
            } else {
                options.prfSalt?.let { salt ->
                    put("extensions", buildJsonObject {
                        put("prf", buildJsonObject {
                            put("eval", buildJsonObject {
                                put("first", b64url(salt))
                            })
                        })
                    })
                }
            }
        }
        return obj.toString()
    }

    // ── Response parsers ────────────────────────────────────────────

    private fun parseRegistrationResponse(responseJson: String): RegisterResult {
        val obj = json.parseToJsonElement(responseJson).jsonObject
        val response = obj["response"]?.jsonObject
            ?: throw AuthException("Missing 'response' in registration response")

        val id = obj["rawId"]?.jsonPrimitive?.content
            ?: obj["id"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing credential id")
        val attestationObject = response["attestationObject"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing attestationObject")
        val clientDataJSON = response["clientDataJSON"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing clientDataJSON")

        return RegisterResult(
            credentialId = b64urlDecode(id),
            attestationObject = b64urlDecode(attestationObject),
            clientDataJSON = b64urlDecode(clientDataJSON),
            prfOutput = extractPrfOutput(responseJson),
        )
    }

    private fun parseAuthenticationResponse(responseJson: String): AuthenticateResult {
        val obj = json.parseToJsonElement(responseJson).jsonObject
        val response = obj["response"]?.jsonObject
            ?: throw AuthException("Missing 'response' in authentication response")

        val id = obj["rawId"]?.jsonPrimitive?.content
            ?: obj["id"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing credential id")
        val authenticatorData = response["authenticatorData"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing authenticatorData")
        val clientDataJSON = response["clientDataJSON"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing clientDataJSON")
        val signature = response["signature"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing signature")
        val userHandle = response["userHandle"]?.jsonPrimitive?.content

        return AuthenticateResult(
            credentialId = b64urlDecode(id),
            authenticatorData = b64urlDecode(authenticatorData),
            clientDataJSON = b64urlDecode(clientDataJSON),
            signature = b64urlDecode(signature),
            userHandle = userHandle?.let { b64urlDecode(it) },
            prfOutput = extractPrfOutput(responseJson),
        )
    }

    /**
     * Extract PRF output from a WebAuthn response JSON.
     * Returns null if the PRF extension was not evaluated.
     */
    private fun extractPrfOutput(responseJson: String): PrfOutput? {
        val obj = json.parseToJsonElement(responseJson).jsonObject
        val extensions = obj["clientExtensionResults"]?.jsonObject ?: return null
        val prf = extensions["prf"]?.jsonObject ?: return null
        val results = prf["results"]?.jsonObject ?: return null
        val first = results["first"]?.jsonPrimitive?.content ?: return null
        val second = results["second"]?.jsonPrimitive?.content
        return PrfOutput(
            first = b64urlDecode(first),
            second = second?.let { b64urlDecode(it) },
        )
    }

    companion object {
        private val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        private val decoder = java.util.Base64.getUrlDecoder()

        private fun b64url(data: ByteArray): String = encoder.encodeToString(data)
        private fun b64urlDecode(data: String): ByteArray = decoder.decode(data)
    }
}
