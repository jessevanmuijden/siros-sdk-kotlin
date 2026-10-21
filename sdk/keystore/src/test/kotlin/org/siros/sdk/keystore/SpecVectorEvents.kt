package org.siros.sdk.keystore

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

/**
 * The privatedata-spec 2.8/3.0 round-trip vectors carry placeholder events
 * (`{"type":"credential-added","credentialId":"..."}`: no `schemaVersion`, a type no schema version defines),
 * yet expect an unchanged rewrite. Spec 2.8 section 6 requires a reader to REFUSE to rewrite such a
 * container, so the two cannot both hold (see PrivateDataSchemaV4Test.vectorPlaceholderEventsAreRefused).
 *
 * These tests exercise everything ELSE in the vectors, so they replace each placeholder event by a real
 * one of the same position and remaining members (`new_credential`, `schemaVersion` = the state's), in
 * the input and in the expected state alike. Nothing but `type` and `schemaVersion` of those events changes.
 */
internal fun JsonObject.withRealEvents(): JsonObject {
    fun fix(plaintext: JsonObject): JsonObject {
        val version = (plaintext["S"] as? JsonObject)?.get("schemaVersion") ?: JsonPrimitive(4)
        val events = (plaintext["events"] as? JsonArray) ?: return plaintext
        val real = JsonArray(
            events.map { e ->
                val o = e.jsonObject
                JsonObject(mapOf("type" to JsonPrimitive("new_credential"), "schemaVersion" to version) + o.filterKeys { it != "type" && it != "schemaVersion" })
            },
        )
        return JsonObject(plaintext + ("events" to real))
    }
    // Only the older round-trip vectors have placeholder events; the schema-version-* and extensions-*
    // vectors use real events and some of them test exactly the refusal of those.
    val id = (this["id"] as? kotlinx.serialization.json.JsonPrimitive)?.content.orEmpty()
    if (id.startsWith("schema-version-") || id.startsWith("extensions-")) return this
    var out = this
    (out["inputs"] as? JsonObject)?.let { inputs ->
        (inputs["plaintextState"] as? JsonObject)?.let { out = JsonObject(out + ("inputs" to JsonObject(inputs + ("plaintextState" to fix(it))))) }
    }
    (out["expected"] as? JsonObject)?.let { expected ->
        (expected["roundTripState"] as? JsonObject)?.let { out = JsonObject(out + ("expected" to JsonObject(expected + ("roundTripState" to fix(it))))) }
    }
    return out
}
