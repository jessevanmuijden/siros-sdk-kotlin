// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonObject

/**
 * The secret-bearing members of the SUPERSEDED delivery shapes (privatedata-spec 5A and the holder-commitment / psc forms): removed from
 * this SDK, which understands only Credential Auxiliary Data (`auxiliary_data`). They are known here for one purpose: an issuer that still
 * sends one is REFUSED (a response carrying one stores nothing; a configuration advertising one is not offered), never interpreted and
 * never stored uninterpreted next to a secret it might hold.
 */
object LegacySecretMembers {
    /** The `credential_metadata` member names of the removed shapes. */
    val MEMBERS: Set<String> = setOf(
        "org.siros.secret_seed",
        "org.siros.holder_commitments",
        "org.siros.psc",
        "holder_commitments",
        "secret_members",
    )

    /** Whether the response `credential_metadata` [metadata] carries a member of a removed shape. */
    fun carriedBy(metadata: JsonObject): Boolean = metadata.keys.any { it in MEMBERS }
}

/**
 * Whether a metadata object carried a member of a removed shape, WITHOUT keeping what it held: decodes any JSON value (a null
 * included) to [PRESENT]. A value-free marker, so a secret never sits in a data class or its `toString`.
 */
@kotlinx.serialization.Serializable(with = LegacyMemberPresenceSerializer::class)
enum class LegacyMemberPresence { ABSENT, PRESENT }

internal object LegacyMemberPresenceSerializer : kotlinx.serialization.KSerializer<LegacyMemberPresence> {
    override val descriptor: kotlinx.serialization.descriptors.SerialDescriptor = kotlinx.serialization.json.JsonElement.serializer().descriptor

    override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): LegacyMemberPresence {
        // Whatever the value (an object, a string, null), only that the member was there is kept.
        (decoder as? kotlinx.serialization.json.JsonDecoder ?: throw kotlinx.serialization.SerializationException("decodes from JSON only"))
            .decodeJsonElement()
        return LegacyMemberPresence.PRESENT
    }

    override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: LegacyMemberPresence) {
        (encoder as? kotlinx.serialization.json.JsonEncoder ?: throw kotlinx.serialization.SerializationException("encodes to JSON only"))
            .encodeJsonElement(kotlinx.serialization.json.JsonNull)
    }
}
