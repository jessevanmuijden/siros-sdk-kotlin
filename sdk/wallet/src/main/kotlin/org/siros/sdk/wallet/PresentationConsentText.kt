// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import android.content.Context
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale
import org.siros.sdk.credentials.AgeForm
import org.siros.sdk.credentials.ComparisonOp
import org.siros.sdk.credentials.ConsentItem
import org.siros.sdk.credentials.PresentationConsentRequest
import org.siros.sdk.credentials.ValueType
import org.siros.sdk.credentials.PseudonymScope

/** The consent strings the SDK owns, one key per sentence; arguments are positional (see the string resources). */
enum class ConsentString(internal val res: Int) {
    TITLE(R.string.siros_consent_title),
    SHARE(R.string.siros_consent_share),
    CANCEL(R.string.siros_consent_cancel),
    VERIFIER_PROVE(R.string.siros_consent_verifier_prove),
    VERIFIER_SHARE(R.string.siros_consent_verifier_share),
    AGE_BETWEEN(R.string.siros_consent_age_between),
    AGE_AT_LEAST(R.string.siros_consent_age_at_least),
    AGE_AT_MOST(R.string.siros_consent_age_at_most),
    PSEUDONYM(R.string.siros_consent_pseudonym),
    PSEUDONYM_ISSUER_CAN_LINK(R.string.siros_consent_pseudonym_issuer),
    FOOTER(R.string.siros_consent_footer),
    CLAIM(R.string.siros_consent_claim),
    LEGACY_PSEUDONYM(R.string.siros_consent_legacy_pseudonym),
    PREDICATE_EQ(R.string.siros_consent_predicate_eq),
    PREDICATE_NE(R.string.siros_consent_predicate_ne),
    PREDICATE_LT(R.string.siros_consent_predicate_lt),
    PREDICATE_LE(R.string.siros_consent_predicate_le),
    PREDICATE_GT(R.string.siros_consent_predicate_gt),
    PREDICATE_GE(R.string.siros_consent_predicate_ge),
    PREDICATE_IN(R.string.siros_consent_predicate_in),
    PREDICATE_DATE_EQ(R.string.siros_consent_predicate_date_eq),
    PREDICATE_DATE_NE(R.string.siros_consent_predicate_date_ne),
    PREDICATE_DATE_LT(R.string.siros_consent_predicate_date_lt),
    PREDICATE_DATE_LE(R.string.siros_consent_predicate_date_le),
    PREDICATE_DATE_GT(R.string.siros_consent_predicate_date_gt),
    PREDICATE_DATE_GE(R.string.siros_consent_predicate_date_ge),
    PREDICATE_DATE_IN(R.string.siros_consent_predicate_date_in),
}

/** Resolves a [ConsentString] with its arguments. The wallet's implementation reads the SDK's string resources. */
fun interface ConsentStrings {
    fun get(key: ConsentString, vararg args: Any): String
}

/** One credential of the request as the user reads it. */
data class ConsentScreenEntry(
    /** The credential's display name, if known. */
    val credentialName: String?,
    /** The issuer's display name, if known. */
    val issuerName: String?,
    /** One sentence per item, in order. */
    val lines: List<String>,
)

/** The `verifier_id` for display: [shortened] for the screen, [full] on expand or long-press. Never altered otherwise. */
data class ConsentVerifierDetail(val shortened: String, val full: String)

/** The text of a [PresentationConsentRequest]. */
data class ConsentScreen(
    val title: String,
    /** "{name} is asking you to prove:" (or "share:" when a claim is disclosed). */
    val header: String,
    val entries: List<ConsentScreenEntry>,
    /** "No other personal data is shared." */
    val footer: String,
    /** The verifier id value, with no type label; null when the request uses none. */
    val verifierDetail: ConsentVerifierDetail?,
    val shareLabel: String,
    val cancelLabel: String,
)

/**
 * Turns a [PresentationConsentRequest] into the SDK's wording: hard-coded in the SDK's resources (default
 * locale, sv, fi, el, pt), parameterised per item and never concatenated. The trust framework and the
 * `verifier_id_type` never appear in it. Nothing here logs; callers must not log the result either.
 */
class PresentationConsentText(
    private val strings: ConsentStrings,
    private val locale: Locale = Locale.getDefault(),
    /**
     * Specialised renderers of a predicate function, by function id. Without one the function is rendered as an
     * age when its declaration says so ([ConsentItem.Predicate.age]), else by the comparison wording (date-specific sentences for a date claim, generic ones for numbers and strings).
     * A host adds one to word a function in its own domain terms.
     */
    private val predicateRenderers: Map<String, (ConsentItem.Predicate) -> List<String>> = emptyMap(),
) {

    /** Fails (throws) on an item this wording does not cover rather than showing a consent that omits it. */
    fun render(request: PresentationConsentRequest): ConsentScreen {
        val name = request.verifier.label
        val allItems = request.entries.flatMap { it.items }
        val disclosesClaims = allItems.any { it is ConsentItem.Claim || it is ConsentItem.LegacyPseudonym }
        return ConsentScreen(
            title = strings.get(ConsentString.TITLE),
            header = strings.get(if (disclosesClaims) ConsentString.VERIFIER_SHARE else ConsentString.VERIFIER_PROVE, name),
            entries = request.entries.map { e ->
                ConsentScreenEntry(e.credential.name, e.credential.issuer, e.items.flatMap { lines(it, name) })
            },
            footer = strings.get(ConsentString.FOOTER),
            verifierDetail = request.verifier.verifierId?.let { ConsentVerifierDetail(shortenMiddle(it), it) },
            shareLabel = strings.get(ConsentString.SHARE),
            cancelLabel = strings.get(ConsentString.CANCEL),
        )
    }

    private fun lines(item: ConsentItem, verifierName: String): List<String> = when (item) {
        is ConsentItem.Predicate -> (predicateRenderers[item.functionId] ?: ::predicateLines)(item)
        is ConsentItem.Pseudonym -> {
            require(item.scope == PseudonymScope.PER_VERIFIER && !item.crossSite && item.verifierContext == null) { "unsupported pseudonym scope" }
            listOf(strings.get(if (item.remappableByIssuer) ConsentString.PSEUDONYM_ISSUER_CAN_LINK else ConsentString.PSEUDONYM, verifierName))
        }
        is ConsentItem.LegacyPseudonym -> listOf(strings.get(ConsentString.LEGACY_PSEUDONYM, verifierName))
        is ConsentItem.Claim -> listOf(strings.get(ConsentString.CLAIM, item.name))
    }

    /** An age (approved wording) when the item carries one, else one sentence per condition. */
    private fun predicateLines(item: ConsentItem.Predicate): List<String> {
        item.age?.let { return listOf(ageLine(it)) }
        val claim = item.claim.display
        val sentences = item.conditions.map { c ->
            val date = item.valueType == ValueType.DATE
            val key = when (c.op) {
                ComparisonOp.EQ -> if (date) ConsentString.PREDICATE_DATE_EQ else ConsentString.PREDICATE_EQ
                ComparisonOp.NE -> if (date) ConsentString.PREDICATE_DATE_NE else ConsentString.PREDICATE_NE
                ComparisonOp.LT -> if (date) ConsentString.PREDICATE_DATE_LT else ConsentString.PREDICATE_LT
                ComparisonOp.LE -> if (date) ConsentString.PREDICATE_DATE_LE else ConsentString.PREDICATE_LE
                ComparisonOp.GT -> if (date) ConsentString.PREDICATE_DATE_GT else ConsentString.PREDICATE_GT
                ComparisonOp.GE -> if (date) ConsentString.PREDICATE_DATE_GE else ConsentString.PREDICATE_GE
                ComparisonOp.IN -> if (date) ConsentString.PREDICATE_DATE_IN else ConsentString.PREDICATE_IN
            }
            strings.get(key, claim, c.values.joinToString(", ") { value(item.valueType, it) })
        }
        // No "the value is not shared" reassurance: a proof of `country == SE` does reveal the value. The sentences say what is proved.
        return sentences
    }

    private fun ageLine(form: AgeForm): String = when (form) {
        is AgeForm.Between -> strings.get(ConsentString.AGE_BETWEEN, date(form.from), date(form.to), form.minYears, form.maxYears)
        is AgeForm.AtLeast -> strings.get(ConsentString.AGE_AT_LEAST, form.years)
        is AgeForm.AtMost -> strings.get(ConsentString.AGE_AT_MOST, form.years)
    }

    /** An operand as the user reads it: a date in the locale's form, anything else as the verifier sent it. */
    private fun value(type: ValueType, v: String): String = if (type == ValueType.DATE) date(v) else v

    /** The date as the user's locale writes it; the input is a validated RFC 3339 full-date. */
    private fun date(iso: String): String =
        DateTimeFormatter.ofLocalizedDate(FormatStyle.LONG).withLocale(locale).format(LocalDate.parse(iso))

    companion object {
        /** The longest `verifier_id` shown whole; a longer one keeps its start and end (a DID, an x509 SAN). */
        const val MAX_DETAIL_CODE_POINTS = 40
        private const val KEEP_CODE_POINTS = 18

        /** [id] with its middle replaced by an ellipsis when it is long. For display only: never use the result as the id. */
        fun shortenMiddle(id: String): String {
            val n = id.codePointCount(0, id.length)
            if (n <= MAX_DETAIL_CODE_POINTS) return id
            val head = id.substring(0, id.offsetByCodePoints(0, KEEP_CODE_POINTS))
            val tail = id.substring(id.offsetByCodePoints(0, n - KEEP_CODE_POINTS))
            return "$head…$tail"
        }

        /** The wording from [context]'s resources, in the locale it is running in. */
        fun forContext(context: Context): PresentationConsentText =
            PresentationConsentText(ConsentStrings { key, args -> context.getString(key.res, *args) }, context.resources.configuration.locales[0])
    }
}
