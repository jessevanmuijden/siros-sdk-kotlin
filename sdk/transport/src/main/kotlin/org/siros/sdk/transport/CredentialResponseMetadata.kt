package org.siros.sdk.transport

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The response-level `credential_metadata` object of an OpenID4VCI 1.1 Credential Response (and Deferred
 * Credential Response), as the WALLET reads it from the response it decrypted itself (openid/OpenID4VCI#721;
 * privatedata-spec section 5A): the engine never sees it. ONE object per response: it applies to every credential
 * in the response.
 *
 * This is NOT the display metadata of the credential store: it is the object the issuer's response delivers,
 * which is shared with display data and may carry the issuer-delivered `auxiliary_data`. [members] is kept
 * as received, every member verbatim (unknown ones included, in order), so the receipt can store each exactly.
 * A consumer interprets only the members it knows.
 *
 * A value that is not a JSON object decodes as the [malformed] placeholder, which carries no data and which a
 * consumer MUST refuse the issuance on (decoding it as a flag rather than an exception keeps the rest of the
 * frame, notably each `notification_id`, readable so the refusal can be reported to the issuer).
 *
 * It can hold a secret: [toString] shows no member, and nothing here is logged.
 */
@Serializable(with = ResponseCredentialMetadataSerializer::class)
class ResponseCredentialMetadata(
    val members: JsonObject = JsonObject(emptyMap()),
    val malformed: Boolean = false,
) {
    override fun toString() = "ResponseCredentialMetadata(${if (malformed) "malformed" else "redacted"})"

    override fun equals(other: Any?) = other is ResponseCredentialMetadata && malformed == other.malformed && members == other.members

    override fun hashCode() = members.hashCode() * 31 + malformed.hashCode()
}

/**
 * Decodes the response-level `credential_metadata` a PLAIN issuer response relays on `flow_complete`, keeping only the
 * display-only members [DISPLAY_MEMBERS] (`display`, `claims`) and ignoring every other member. An extension member (a
 * `auxiliary_data`, say) is never taken from the engine's frame: it is read only from a response the wallet
 * decrypted itself. Anything but a JSON object is the malformed placeholder, as in [ResponseCredentialMetadataSerializer].
 */
internal object DisplayOnlyCredentialMetadataSerializer : KSerializer<ResponseCredentialMetadata> {
    val DISPLAY_MEMBERS: Set<String> = setOf("display", "claims")

    override val descriptor: SerialDescriptor = JsonObject.serializer().descriptor

    override fun deserialize(decoder: Decoder): ResponseCredentialMetadata {
        val element = (decoder as? JsonDecoder ?: throw SerializationException("credential metadata decodes from JSON only"))
            .decodeJsonElement()
        val obj = element as? JsonObject ?: return ResponseCredentialMetadata(malformed = true)
        return ResponseCredentialMetadata(JsonObject(obj.filterKeys { it in DISPLAY_MEMBERS }))
    }

    override fun serialize(encoder: Encoder, value: ResponseCredentialMetadata) = ResponseCredentialMetadataSerializer.serialize(encoder, value)
}

/** Decodes the response-level object without ever throwing for its content: anything but an object is the malformed placeholder. */
internal object ResponseCredentialMetadataSerializer : KSerializer<ResponseCredentialMetadata> {
    override val descriptor: SerialDescriptor = JsonObject.serializer().descriptor

    override fun deserialize(decoder: Decoder): ResponseCredentialMetadata {
        val element = (decoder as? JsonDecoder ?: throw SerializationException("credential metadata decodes from JSON only"))
            .decodeJsonElement()
        return (element as? JsonObject)?.let { ResponseCredentialMetadata(it) } ?: ResponseCredentialMetadata(malformed = true)
    }

    override fun serialize(encoder: Encoder, value: ResponseCredentialMetadata) {
        (encoder as? JsonEncoder ?: throw SerializationException("credential metadata encodes to JSON only"))
            .encodeJsonElement(value.members)
    }
}

/**
 * Decodes `credential_response_encrypted` without ever throwing: only a JSON boolean `true`
 * is true; absent, `false` or any other shape (a string, number, object) is false, which is the safe
 * direction (a secret then is refused as not encrypted) and keeps the frame decodable.
 */
internal object EncryptedResponseFlagSerializer : KSerializer<Boolean> {
    override val descriptor: SerialDescriptor = kotlinx.serialization.descriptors.PrimitiveSerialDescriptor(
        "org.siros.sdk.transport.EncryptedResponseFlag",
        kotlinx.serialization.descriptors.PrimitiveKind.BOOLEAN,
    )

    override fun deserialize(decoder: Decoder): Boolean {
        val element = (decoder as? JsonDecoder ?: throw SerializationException("flag decodes from JSON only"))
            .decodeJsonElement()
        return element is JsonPrimitive && !element.isString && element.content == "true"
    }

    override fun serialize(encoder: Encoder, value: Boolean) = encoder.encodeBoolean(value)
}

/**
 * What the wallet knows about the response-level metadata of one issuance, so wallet code reads it the same way
 * whichever transport carried the completion. It comes from the Credential Response the wallet decrypted itself.
 */
interface DeliveredResponseMetadata {
    /** The response-level `credential_metadata`; null when the issuer delivered none. */
    val credentialMetadata: ResponseCredentialMetadata?

    /**
     * True only when the issuer's response was a JWE this wallet opened. A secret in a response with this false
     * came over plain JSON.
     */
    val credentialMetadataEncryptedResponse: Boolean

    /**
     * Whether this answers a Deferred Credential Response. Seed delivery over a deferred response is not supported
     * (privatedata-spec 5A.2) and is refused.
     */
    val deferredResponse: Boolean get() = false
}

/**
 * Decodes `redacted_members` without ever throwing: an array of strings is the set of withheld member names; absent is
 * empty; any other shape (not an array, a non-string element) cannot be trusted to say what was withheld, so it reads as
 * everything the marker can list being withheld: the safe direction (nothing is then recovered or substituted).
 * The marker lists the renewal material only (`refresh_token`, `dpop_jwk`, `dpop_key_id`): the engine never holds the
 * credential metadata, so it has nothing of that to withhold.
 */
internal object RedactedMembersSerializer : KSerializer<Set<String>> {
    val ALL: Set<String> = setOf("refresh_token", "dpop_jwk", "dpop_key_id")

    override val descriptor: SerialDescriptor = kotlinx.serialization.json.JsonElement.serializer().descriptor

    override fun deserialize(decoder: Decoder): Set<String> {
        val element = (decoder as? JsonDecoder ?: throw SerializationException("redacted_members decodes from JSON only"))
            .decodeJsonElement()
        if (element !is kotlinx.serialization.json.JsonArray) return ALL
        val names = element.map { e -> (e as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return ALL }
        return names.toSet()
    }

    override fun serialize(encoder: Encoder, value: Set<String>) {
        (encoder as? JsonEncoder ?: throw SerializationException("redacted_members encodes to JSON only"))
            .encodeJsonElement(kotlinx.serialization.json.JsonArray(value.sorted().map { JsonPrimitive(it) }))
    }
}
