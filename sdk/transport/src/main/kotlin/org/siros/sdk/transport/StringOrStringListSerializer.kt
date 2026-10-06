// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.transport

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

/**
 * Reads a JSON array of strings, or a bare string as a one-element list;
 * always writes an array.
 *
 * `transaction_data_hashes_alg` in an OpenID4VP request entry is an array
 * (Appendix B), while older orchestrators and verifiers send a single string.
 * Typing the member as a plain string made every conformant array fail to
 * decode, and a failed decode of a sign request is dropped, so the flow just
 * stalled; typing it as a plain list would do the same to the string form.
 * Anything else (a number, an object, an array holding a non-string) is a
 * [SerializationException] rather than being coerced.
 */
internal object StringOrStringListSerializer : KSerializer<List<String>> {
    private val listSerializer = ListSerializer(String.serializer())
    override val descriptor: SerialDescriptor = listSerializer.descriptor

    override fun deserialize(decoder: Decoder): List<String> {
        val input = decoder as? JsonDecoder ?: return listSerializer.deserialize(decoder)
        return when (val element: JsonElement = input.decodeJsonElement()) {
            is JsonPrimitive -> {
                if (!element.isString) throw SerializationException("expected a string or an array of strings")
                listOf(element.content)
            }
            is JsonArray -> element.map {
                (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content
                    ?: throw SerializationException("expected an array of strings")
            }
            else -> throw SerializationException("expected a string or an array of strings")
        }
    }

    override fun serialize(encoder: Encoder, value: List<String>) =
        listSerializer.serialize(encoder, value)
}
