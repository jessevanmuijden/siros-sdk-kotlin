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
 * Credential Response), as the wallet engine relays it on the flow-complete message
 * (openid/OpenID4VCI#721; privatedata-spec section 5A). ONE object per response: it applies to every credential
 * in the response.
 *
 * This is NOT the display metadata of the credential store: it is the object the issuer's response delivers,
 * which is shared with display data and may carry the issuer-delivered `org.siros.secret_seed`. [members] is kept
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
 * Decodes `credential_metadata_encrypted_response` without ever throwing: only a JSON boolean `true`
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
 * The delivered-metadata members shared by both transports' flow-complete results, so wallet code reads them the
 * same way whichever transport carried the result.
 */
interface DeliveredResponseMetadata {
    /** The response-level `credential_metadata`; null when the issuer delivered none. */
    val credentialMetadata: ResponseCredentialMetadata?

    /**
     * `credential_metadata_encrypted_response`: true only when the issuer's response was JWE-decrypted by the engine.
     * Absent means false; a secret in a response with this false came over plain JSON.
     */
    val credentialMetadataEncryptedResponse: Boolean

    /**
     * `redacted_members`: on a REPLAYED or resumed completion, exactly the members that were present and withheld, from
     * `credential_metadata`, `credential_metadata_encrypted_response`, `refresh_token`, `dpop_jwk` and `dpop_key_id`
     * (the credentials and every other member are kept). A listed member is NOT RECOVERABLE: it is never invented,
     * reused from an earlier flow or substituted. A live completion has no marker. Empty means nothing was withheld.
     */
    val redactedMembers: Set<String> get() = emptySet()

    /**
     * Whether this completion answers a Deferred Credential Response. Seed delivery over a deferred response is not
     * supported (privatedata-spec 5A.2) and is refused. Today's engine frames carry no such member, so this is false until
     * the engine relays one; the engine, as the OpenID4VCI client, refuses it first.
     */
    val deferredResponse: Boolean get() = false

    /** Whether the delivered metadata (and with it any secret) was withheld: its object or its encryption flag is listed. */
    val credentialMetadataRedacted: Boolean
        get() = "credential_metadata" in redactedMembers || "credential_metadata_encrypted_response" in redactedMembers

    /** Whether the renewal material (`refresh_token`, `dpop_jwk`, `dpop_key_id`) was withheld, wholly or in part: renewal of the issuance is then unavailable. */
    val renewalMaterialRedacted: Boolean
        get() = redactedMembers.any { it == "refresh_token" || it == "dpop_jwk" || it == "dpop_key_id" }
}

/**
 * Decodes `redacted_members` without ever throwing: an array of strings is the set of withheld member names; absent is
 * empty; any other shape (not an array, a non-string element) cannot be trusted to say what was withheld, so it reads as
 * everything the marker can list being withheld: the safe direction (nothing is then recovered or substituted).
 */
internal object RedactedMembersSerializer : KSerializer<Set<String>> {
    val ALL: Set<String> = setOf("credential_metadata", "credential_metadata_encrypted_response", "refresh_token", "dpop_jwk", "dpop_key_id")

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
