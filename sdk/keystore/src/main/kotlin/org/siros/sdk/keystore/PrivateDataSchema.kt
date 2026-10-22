package org.siros.sdk.keystore

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.UnsupportedSchemaVersionException
import org.siros.sdk.credentials.UnsupportedSchemaVersionException.Kind

/**
 * The WalletStateContainer schema versions this SDK implements (privatedata-spec 3.0, section 6).
 *
 * The SDK holds `S` as a snapshot and carries `events` through untouched; it neither folds nor
 * merges events and emits none. What it must do is know when it is about to rewrite something it
 * does not understand, and refuse.
 */
internal object PrivateDataSchema {
    /** The version written for new and migrated state. Migrating 3 to 4 only sets this number. */
    const val CURRENT_VERSION = 4

    /** `S.schemaVersion` values this SDK rewrites. Versions 1 and 2 store private keys differently (version 3) and are not migrated here. */
    val REWRITABLE_STATE_VERSIONS = 3..4

    /** Event `schemaVersion` values this SDK implements (the readable range, 1 to 4). */
    val EVENT_VERSIONS = 1..4

    /** The `wallet-frontend` event types of versions 1 to 3 (`WalletStateSchemaVersion1/3`, `WalletStateOperations`). */
    private val EVENT_TYPES_V1_TO_V3 = setOf(
        "new_credential", "delete_credential",
        "new_keypair", "delete_keypair",
        "new_presentation", "delete_presentation",
        "alter_settings",
        "save_credential_issuance_session", "delete_credential_issuance_session",
    )

    /** Defined from version 4. A reader accepts it stamped 3 or 4 (containers written before spec 3.0 carry 3); a writer emits 4 ([ExtensionEvents]). */
    private const val SET_EXTENSION = "set_extension"

    /**
     * Null when [plaintext] (the decrypted WalletStateContainer) may be rewritten; otherwise the
     * reason it may not. A plaintext without `S` (the legacy Kotlin-only layout) is rebuilt as
     * current state, as before.
     */
    fun rewriteBlocker(plaintext: JsonObject?): UnsupportedSchemaVersionException? {
        if (plaintext == null) return null
        val state = plaintext["S"] as? JsonObject
        if (state != null) {
            // wallet-frontend treats an absent schemaVersion as 1.
            val v = intOrNull(state["schemaVersion"])
            if (v == null || v !in REWRITABLE_STATE_VERSIONS) {
                return UnsupportedSchemaVersionException(
                    "Private data has S.schemaVersion ${state["schemaVersion"] ?: "(absent)"}; " +
                        "this SDK rewrites versions $REWRITABLE_STATE_VERSIONS only, so it will not rewrite the container",
                    Kind.STATE_VERSION, v,
                )
            }
        }
        for (event in (plaintext["events"] as? JsonArray).orEmpty()) {
            val e = event as? JsonObject
            val type = (e?.get("type") as? JsonPrimitive)?.takeIf { it.isString }?.content
            val v = intOrNull(e?.get("schemaVersion"))
            if (v == null || v !in EVENT_VERSIONS) {
                return UnsupportedSchemaVersionException(
                    "Private data holds an event with schemaVersion ${e?.get("schemaVersion") ?: "(absent)"} " +
                        "(type ${type ?: "?"}); this SDK implements event versions $EVENT_VERSIONS, so it will not rewrite the container",
                    Kind.EVENT_VERSION, v, type,
                )
            }
            val known = type != null && (type in EVENT_TYPES_V1_TO_V3 || (type == SET_EXTENSION && v >= 3))
            if (!known) {
                return UnsupportedSchemaVersionException(
                    "Private data holds an event of type ${type ?: "(none)"} (schemaVersion $v) that this SDK's schema versions do not define; " +
                        "it will not rewrite the container",
                    Kind.EVENT_TYPE, v, type,
                )
            }
        }
        return null
    }

    /**
     * A JSON number whose VALUE is an integer that fits a Long (`4`, `4.0`, `4e9`), else null: a string or a fractional number is
     * not one. The one decoder for every integer the SDK reads from an event (version, id, timestamp), so ordering, collision and
     * live-entry detection agree with the version check on what a number is.
     */
    fun longOrNull(e: kotlinx.serialization.json.JsonElement?): Long? {
        val p = e as? JsonPrimitive ?: return null
        if (p.isString) return null
        val n = p.content.toBigDecimalOrNull() ?: return null
        if (n.signum() == 0) return 0L
        // Rejected by magnitude BEFORE any integer is built: a short literal such as 4e100000000 must not be expanded into a huge
        // number (memory) just to be found out of range. Every step is overflow-safe: scale arithmetic is done in Long, and an
        // ArithmeticException (stripTrailingZeros overflowing the scale of 100e2147483647) means out of range too.
        return try {
            val s = n.stripTrailingZeros()
            if (s.scale() > 0) return null // fractional
            if (s.precision().toLong() - s.scale().toLong() > 19L) return null // more integer digits than a Long can hold
            val i = s.toBigIntegerExact()
            if (i.bitLength() <= 63) i.toLong() else null
        } catch (_: ArithmeticException) {
            null
        }
    }

    /** A JSON number whose VALUE is an integer in the Int range (4, 4.0, 4e0), else null: a string "4" or 4.5 is not a version. */
    private fun intOrNull(e: kotlinx.serialization.json.JsonElement?): Int? = longOrNull(e)?.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()

    private fun JsonArray?.orEmpty(): List<kotlinx.serialization.json.JsonElement> = this ?: emptyList()
}
