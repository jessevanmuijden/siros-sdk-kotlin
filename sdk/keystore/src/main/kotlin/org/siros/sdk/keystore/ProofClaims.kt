// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.serialization.json.JsonArray
import org.siros.sdk.credentials.KeystoreException
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Proof-JWT claims of any JSON type, as the plain Java values nimbus serialises: the one conversion every keystore uses, so the
 * same claim is byte-identical whichever keystore signs it. Fail closed: a claim a signer cannot carry faithfully is refused,
 * never altered or dropped.
 */
internal object ProofClaims {
    /** Claims the keystore itself sets in a key proof; a caller's claim of the same name would silently replace them. */
    private val RESERVED = setOf("aud", "iat", "nonce", "iss", "exp", "jti", "nbf", "sub")
    private const val MAX_DEPTH = 8

    fun toJava(claims: Map<String, JsonElement>, allowReserved: Set<String> = emptySet()): Map<String, Any> =
        claims.mapValues { (name, value) ->
            if (name in RESERVED && name !in allowReserved) {
                throw KeystoreException("The proof claim \"$name\" is set by the keystore and cannot be supplied")
            }
            convert(value, 0)
        }

    private fun convert(v: JsonElement, depth: Int): Any {
        if (depth > MAX_DEPTH) throw KeystoreException("A proof claim is nested too deeply to carry")
        return when (v) {
            is JsonNull -> throw KeystoreException("A proof claim cannot carry a JSON null")
            is JsonPrimitive -> when {
                v.isString -> v.content
                v.content == "true" || v.content == "false" -> v.content.toBoolean()
                else -> v.content.toLongOrNull() ?: throw KeystoreException("A proof claim number is not an integer")
            }
            is JsonArray -> v.map { convert(it, depth + 1) }
            is JsonObject -> v.mapValues { convert(it.value, depth + 1) }
        }
    }
}
