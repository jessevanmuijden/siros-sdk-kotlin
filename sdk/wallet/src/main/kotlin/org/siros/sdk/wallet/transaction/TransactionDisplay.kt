// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.wallet.TransactionConsentEntry
import org.siros.sdk.wallet.TransactionConsentField
import org.siros.sdk.wallet.TransactionConsentRequest

/**
 * Builds the consent model (contract section 5; EC TS12 v1.0.1 3.3) from a
 * validated request. Everything shown comes from the wallet's own decoding of
 * `raw` and from the type metadata, never from the orchestrator's hint.
 *
 * Fail closed (TS12 3.3.1): if a localised parameter name or the required
 * `affirmative_action_label` is not available, the transaction is refused.
 * Every string that reaches the screen is checked by [DisplayText]: a value
 * with control, format or bidi characters, or one that is too long, is
 * refused rather than shown (and never truncated, which could hide part of an
 * amount).
 *
 * For the four built-in types the members their schemas require can never be
 * shown below a floor level ([BuiltInFloor]), whatever the (possibly
 * unauthenticated) metadata says.
 */
internal class TransactionDisplayBuilder(
    private val source: TransactionMetadataSource,
    private val locale: String,
) {
    suspend fun build(
        validated: ValidatedTransactionData,
        verifier: String?,
        requestSigned: Boolean?,
        disclosures: List<org.siros.sdk.wallet.TransactionDisclosure> = emptyList(),
    ): TransactionConsentRequest {
        val entries = validated.entries.map { buildEntry(it, validated.trust) }
        val names = validated.entries.flatMap { e -> e.contexts.mapNotNull { credentialName(it) } }.distinct()
        return TransactionConsentRequest(
            verifier = verifier?.let { DisplayText.label(it, "verifier") },
            credentialName = names.takeIf { it.isNotEmpty() }?.joinToString(", "),
            entries = entries,
            requestSigned = requestSigned,
            locale = locale,
            disclosures = disclosures.map {
                it.copy(
                    credentialName = it.credentialName?.let { n -> DisplayText.label(n, "credential name") },
                    claims = it.claims?.map { c -> DisplayText.label(c, "claim name") },
                )
            },
        )
    }

    /**
     * One entry's model. An entry bound to several credentials is built from
     * each credential's metadata and must come out identical: labels or levels
     * that disagree between the credentials the user is presenting are refused.
     */
    private suspend fun buildEntry(entry: ValidatedTransactionEntry, trust: MetadataTrust): TransactionConsentEntry {
        val models = entry.contexts.map { buildEntryFor(entry, it, trust) }
        if (models.any { it != models.first() }) {
            throw unavailable("The credentials a transaction is bound to describe it differently")
        }
        return models.first()
    }

    private suspend fun buildEntryFor(entry: ValidatedTransactionEntry, ctx: ScaCredentialContext, trust: MetadataTrust): TransactionConsentEntry {
        val typeEntry = ctx.typeEntry
            ?: throw unavailable("The type metadata has no entry for the transaction type, so no localised labels exist")

        val claims = claimsOf(entry, ctx, typeEntry, trust)
        val labels = uiLabelsOf(entry, ctx, typeEntry, trust)

        val affirmative = labels.localized("affirmative_action_label")
            ?: throw unavailable("The required affirmative_action_label is not available")
        val fields = fieldsOf(entry.payload, claims, BuiltInFloor.of(entry.type, typeEntry))
        return TransactionConsentEntry(
            title = labels.localized("transaction_title"),
            typeName = TypeNames.of(entry.type),
            fields = fields,
            affirmativeLabel = affirmative,
            denialLabel = labels.localized("denial_action_label"),
            securityHint = labels.localized("security_hint"),
        )
    }

    // ── claim metadata (TS12 3.3.2) ────────────────────────────────

    private class Claim(val path: List<String>, val level: Int, val labels: List<Pair<String, String>>)

    private suspend fun claimsOf(entry: ValidatedTransactionEntry, ctx: ScaCredentialContext, typeEntry: JsonObject, trust: MetadataTrust): List<Claim> {
        val inline = typeEntry["claims"]
        val uri = typeEntry["claims_uri"]
        if (inline != null && uri != null) throw unavailable("A transaction data type has both claims and claims_uri")
        val array: JsonElement = when {
            inline != null -> inline
            uri is JsonPrimitive && uri.isString -> parse(ReferencedDocuments.fetch(source, ctx.credential, entry.type, "claims_uri", uri.content, trust))
            else -> throw unavailable("The type metadata gives no claim metadata")
        }
        val list = array as? JsonArray ?: throw unavailable("Claim metadata is not an array")
        return list.map { c ->
            val obj = c as? JsonObject ?: throw unavailable("A claim metadata entry is not an object")
            val path = (obj["path"] as? JsonArray)?.map {
                (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: throw unavailable("A claim path holds a non-string")
            } ?: throw unavailable("A claim metadata entry has no path")
            val level = when (val v = obj["visualisation"]) {
                null -> DEFAULT_LEVEL
                is JsonPrimitive -> v.intOrNull?.takeIf { it in 1..4 } ?: throw unavailable("visualisation must be 1 to 4")
                else -> throw unavailable("visualisation must be 1 to 4")
            }
            val labels = (obj["display"] as? JsonArray)?.mapNotNull { d ->
                val o = d as? JsonObject ?: return@mapNotNull null
                val tag = ((o["lang"] ?: o["locale"]) as? JsonPrimitive)?.contentOrNull
                val label = (o["label"] as? JsonPrimitive)?.contentOrNull
                if (tag != null && !label.isNullOrEmpty()) tag to label else null
            }.orEmpty()
            Claim(path, level, labels)
        }
    }

    // ── UI elements catalogue (TS12 3.3.3) ─────────────────────────

    private class Catalogue(private val map: Map<String, List<Pair<String, String>>>, private val locale: String) {
        fun localized(key: String): String? = map[key]?.let { pick(it, locale) }?.let { DisplayText.label(it, key) }
    }

    private suspend fun uiLabelsOf(entry: ValidatedTransactionEntry, ctx: ScaCredentialContext, typeEntry: JsonObject, trust: MetadataTrust): Catalogue {
        val inline = typeEntry["ui_labels"]
        val uri = typeEntry["ui_labels_uri"]
        if (inline != null && uri != null) throw unavailable("A transaction data type has both ui_labels and ui_labels_uri")
        val doc: JsonElement = when {
            inline != null -> inline
            uri is JsonPrimitive && uri.isString -> parse(ReferencedDocuments.fetch(source, ctx.credential, entry.type, "ui_labels_uri", uri.content, trust))
            else -> throw unavailable("The type metadata gives no UI labels")
        }
        val obj = doc as? JsonObject ?: throw unavailable("The UI labels catalogue is not an object")
        val map = obj.mapValues { (_, v) ->
            (v as? JsonArray)?.mapNotNull { item ->
                val o = item as? JsonObject ?: return@mapNotNull null
                val lang = (o["lang"] as? JsonPrimitive)?.contentOrNull
                val value = (o["value"] as? JsonPrimitive)?.contentOrNull
                if (lang != null && !value.isNullOrEmpty()) lang to value else null
            }.orEmpty()
        }
        return Catalogue(map, locale)
    }

    // ── fields ─────────────────────────────────────────────────────

    private fun fieldsOf(payload: JsonObject, claims: List<Claim>, floor: Map<List<String>, Int>): List<TransactionConsentField> {
        val byPath = claims.associateBy { it.path }
        val out = mutableListOf<TransactionConsentField>()
        fun walk(path: List<String>, element: JsonElement) {
            if (element is JsonObject) {
                element.forEach { (k, v) -> walk(path + k, v) }
                return
            }
            val claim = byPath[listOf("payload") + path]
            val label = claim?.labels?.let { pick(it, locale) }
            // The metadata's level, never lower than the floor for a member the schema requires.
            val level = minOf(claim?.level ?: DEFAULT_LEVEL, floor[path] ?: 4)
            if (label == null) {
                // A value the issuer marked as omittable may go unlabelled (never one under the floor); anything else must be shown, so it needs a name.
                if (claim != null && level == 4) return
                throw unavailable("No localised name for a transaction parameter")
            }
            val raw = (element as? JsonPrimitive)?.content ?: element.toString()
            out += TransactionConsentField(DisplayText.label(label, "parameter name"), DisplayText.value(raw), level)
        }
        walk(emptyList(), payload)
        // Stable: level 1 first, payload order within a level.
        return out.sortedBy { it.level }
    }

    private fun credentialName(ctx: ScaCredentialContext): String? {
        val display = (ctx.metadata["display"] as? JsonArray)?.mapNotNull { d ->
            val o = d as? JsonObject ?: return@mapNotNull null
            val tag = ((o["locale"] ?: o["lang"]) as? JsonPrimitive)?.contentOrNull
            val name = (o["name"] as? JsonPrimitive)?.contentOrNull
            if (tag != null && !name.isNullOrEmpty()) tag to name else null
        }.orEmpty()
        val name: String? = pick(display, locale) ?: (ctx.metadata["name"] as? JsonPrimitive)?.contentOrNull
        return name?.let { DisplayText.label(it, "credential name") }
    }

    private fun parse(text: String): JsonElement = try {
        Json.parseToJsonElement(text)
    } catch (e: Exception) {
        throw TransactionDataError(TransactionDataReason.METADATA_UNAVAILABLE, "A referenced metadata document is not JSON", e)
    }

    private fun unavailable(why: String) = TransactionDataError(TransactionDataReason.METADATA_UNAVAILABLE, why)

    companion object {
        /** `visualisation` default (TS12 3.3.1). */
        const val DEFAULT_LEVEL = 3

        /**
         * The entry of [options] (language tag to value) for [locale]: the
         * exact tag, then the same primary language, then English; `null` if
         * none of those exists. Deliberately no "first listed" fallback: a
         * payment is not shown with a label in a language the user may not
         * read; the transaction is refused instead. Tags compare
         * case-insensitively.
         */
        fun pick(options: List<Pair<String, String>>, locale: String): String? {
            if (options.isEmpty()) return null
            val want = locale.lowercase().replace('_', '-')
            val lang = want.substringBefore('-')
            return options.firstOrNull { it.first.lowercase() == want }?.second
                ?: options.firstOrNull { it.first.lowercase().substringBefore('-') == lang }?.second
                ?: options.firstOrNull { it.first.lowercase().substringBefore('-') == "en" }?.second
        }
    }
}

/**
 * What may reach the consent screen. Control (Cc), format (Cf, which holds the
 * bidi overrides/isolates U+202A-202E and U+2066-2069 and the zero-width
 * characters), line/paragraph separators, private-use, unassigned and
 * unpaired-surrogate characters are refused, as is anything over the length
 * limit. Ordinary spaces are fine. Refusing (not stripping or truncating)
 * keeps what the user sees identical to what the verifier will act on.
 */
internal object DisplayText {
    /** Longest payload value shown (a mandate text is at most 1000 in the TS12 schema). */
    const val MAX_VALUE = 2_000

    /** Longest label, title or hint (TS12 3.3.3 allows up to 250). */
    const val MAX_LABEL = 500

    private val forbidden = setOf(
        Character.CONTROL, Character.FORMAT, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR,
        Character.PRIVATE_USE, Character.UNASSIGNED, Character.SURROGATE,
    ).map { it.toInt() }.toSet()

    /** Whether [s] is safe to show and within [max]. */
    fun isSafe(s: String, max: Int): Boolean =
        s.length <= max && s.codePoints().noneMatch { Character.getType(it) in forbidden }

    /** A transaction value; refused as an invalid entry (it came from the verifier). */
    fun value(s: String): String =
        if (isSafe(s, MAX_VALUE)) s else throw TransactionDataError(
            TransactionDataReason.INVALID_ENTRY,
            "A transaction value contains characters that cannot be shown safely, or is too long",
        )

    /** A label, name, title or hint (it came from metadata or the wallet's own identification of the verifier). */
    fun label(s: String, what: String): String =
        if (isSafe(s, MAX_LABEL)) s else throw TransactionDataError(
            TransactionDataReason.METADATA_UNAVAILABLE,
            "A $what contains characters that cannot be shown safely, or is too long",
        )
}

/**
 * The lowest level (highest number) at which each schema-required member of a
 * built-in type may be shown. Unauthenticated metadata cannot push these below
 * the floor: for a payment, amount, currency and payee name are level 1, the
 * rest of what the schema requires level 2.
 */
internal object BuiltInFloor {
    private val floors: Map<String, Map<List<String>, Int>> = mapOf(
        "urn:eudi:sca:payment:1" to mapOf(
            listOf("amount") to 1, listOf("currency") to 1, listOf("payee", "name") to 1,
            listOf("payee", "id") to 2, listOf("transaction_id") to 2,
        ),
        "urn:eudi:sca:login_risk_transaction:1" to mapOf(listOf("action") to 1, listOf("transaction_id") to 2),
        "urn:eudi:sca:account_access:1" to mapOf(listOf("transaction_id") to 2),
        "urn:eudi:sca:emandate:1" to mapOf(listOf("transaction_id") to 2),
    )

    /**
     * The floor for an entry of [type] whose metadata entry is [typeEntry]. A
     * custom type that names a built-in schema by URN (`"schema":
     * "urn:eudi:sca:payment:1"`, as TS12's own example does) gets that
     * built-in's floor.
     */
    fun of(type: String, typeEntry: JsonObject?): Map<List<String>, Int> {
        floors[type]?.let { return it }
        val named = (typeEntry?.get("schema") as? JsonPrimitive)?.takeIf { it.isString }?.content
        return named?.let { floors[it] } ?: emptyMap()
    }
}

/** The names EC TS12 5.3 gives the built-in types. */
internal object TypeNames {
    private val names = mapOf(
        "urn:eudi:sca:payment:1" to "Payment Confirmation",
        "urn:eudi:sca:login_risk_transaction:1" to "Login, Risk-based Authentication",
        "urn:eudi:sca:account_access:1" to "Payment Account Information Access",
        "urn:eudi:sca:emandate:1" to "E-mandate",
    )

    /** The 5.3 name of a built-in type, or [type] itself. */
    fun of(type: String): String = names[type] ?: type

    /** The 5.3 name of a built-in type, or `null`. */
    fun builtIn(type: String): String? = names[type]
}
