// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import java.math.BigDecimal
import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.mdoc.DocumentMdoc

/** The type of the claim a predicate function tests (and so of its operands). */
enum class ValueType(val wire: String) {
    DATE("date"), NUMBER("number"), STRING("string"), BOOL("bool");

    companion object {
        fun ofWire(w: String): ValueType? = values().firstOrNull { it.wire == w }
    }
}

/** A comparison a predicate function can make. Ordering comparisons apply to dates and numbers only. */
enum class ComparisonOp(val wire: String, val ordering: Boolean) {
    EQ("eq", false), NE("ne", false), LT("lt", true), LE("le", true), GT("gt", true), GE("ge", true), IN("in", false);

    companion object {
        fun ofWire(w: String): ComparisonOp? = values().firstOrNull { it.wire == w }
    }
}

/** One comparison of a predicate: [op] against [values] (one operand, or the set of an `in`), as text of the claim's type. */
data class Condition(val op: ComparisonOp, val values: List<String>)

/** The claim a predicate is about: its [path] and the credential's OWN display label for it (never invented), if it has one. */
data class ClaimRef(val path: List<String>, val label: String?) {
    /** The label, else the path. */
    val display: String get() = label ?: path.joinToString(".")
}

/** A claim value read from a credential, as text of [type]. */
data class ClaimValue(val type: ValueType, val text: String)

/** What a credential holds at a claim path. */
sealed interface ClaimLookup {
    /** The claim is not in the credential: a predicate over it cannot hold. */
    object Absent : ClaimLookup

    /** The claim is there. */
    data class Found(val value: ClaimValue) : ClaimLookup

    /** This reader cannot read that path or format: the pre-check is skipped, never guessed. */
    object Unsupported : ClaimLookup
}

/** Where a predicate function takes its claim from. */
sealed interface ClaimSource {
    /** Always the same claim (`age_check` is about `birth_date`). */
    data class Fixed(val path: List<String>) : ClaimSource

    /** The function's `claim` parameter: a string (one path element) or an array of strings. */
    object FromParam : ClaimSource
}

/**
 * The declaration of one predicate function: what it tests, so that consent, the local pre-check and the
 * cross-query rule can be driven by data. The set of `circuit_zk` functions is open-ended; adding one is
 * declaring it here (and registering its validator rules and prover).
 *
 * A function's params are a CONJUNCTION of comparisons on one claim: each param named in [comparisons] is one
 * [Condition] (`ge` + `le` is a range). Any other param refuses the request.
 *
 * @property comparisons param name to comparison, in display order.
 * @property minSpan The function's declared minimum selectivity, or null if it declares none (then no merge rule
 *   applies to it). For a date claim: calendar days, inclusive (`le - ge + 1`); for a number: `le - ge`. Needs
 *   `ge` and `le` only.
 * @property ageSpecialisation Renders as an age (born between / at least / at most). Needs a date claim. The age wording says
 *   the exact birth date is not shared, so it is used ONLY when every condition of the request is a single `ge` or `le`
 *   bound; a function that also declares `eq` (or `in`, `ne`, `lt`, `gt`) renders with the generic wording, which states
 *   every comparison.
 * @property doctypeNamespaceOnly The circuit binds the credential's own doctype namespace, so a credential whose
 *   claims are not in exactly that one namespace is never proved (a decoy or extra namespace).
 */
class PredicateFunction(
    val id: String,
    val claim: ClaimSource,
    val valueType: ValueType,
    val comparisons: Map<String, ComparisonOp>,
    val minSpan: Long? = null,
    val ageSpecialisation: Boolean = false,
    val doctypeNamespaceOnly: Boolean = false,
) {
    init {
        require(comparisons.isNotEmpty()) { "$id declares no comparison" }
        for (op in comparisons.values) {
            require(!op.ordering || valueType == ValueType.DATE || valueType == ValueType.NUMBER) { "$id: ${op.wire} on ${valueType.wire}" }
        }
        val ge = comparisons.filterValues { it == ComparisonOp.GE }.keys
        val le = comparisons.filterValues { it == ComparisonOp.LE }.keys
        if (minSpan != null) {
            require(comparisons.size == 2 && ge.size == 1 && le.size == 1) { "$id: a span needs exactly ge and le" }
            require(valueType == ValueType.DATE || (valueType == ValueType.NUMBER && !ageSpecialisation)) { "$id: unsupported span type" }
        }
        if (ageSpecialisation) require(valueType == ValueType.DATE) { "$id: age rendering needs a date claim" }
        require(minSpan == null || minSpan >= 0) { "$id: negative minSpan" }
    }

    private val geParam get() = comparisons.entries.first { it.value == ComparisonOp.GE }.key
    private val leParam get() = comparisons.entries.first { it.value == ComparisonOp.LE }.key

    /** A function item read through this declaration. */
    class Parsed(val claimPath: List<String>, val conditions: List<Condition>)

    /** The claim path and conditions of [fn], or null when its params are not exactly what this declaration allows. */
    fun parse(fn: CircuitZkFunction): Parsed? {
        if (fn.id != id) return null
        val path = when (claim) {
            is ClaimSource.Fixed -> claim.path
            ClaimSource.FromParam -> claimParam(fn.params["claim"] ?: return null) ?: return null
        }
        val allowed = comparisons.keys + setOf("source") + (if (claim == ClaimSource.FromParam) setOf("claim") else emptySet())
        if (fn.params.keys.any { it !in allowed }) return null
        // The rulebook example's item `source` ({"path": [claim]}) is accepted only when it names the claim this function
        // is about; any other source is a parameter the wallet does not support, so the request is refused.
        fn.params["source"]?.let { src ->
            val o = src as? kotlinx.serialization.json.JsonObject ?: return null
            if (o.keys != setOf("path") || claimParam(o["path"]!!) != path) return null
        }
        val conditions = comparisons.mapNotNull { (param, op) ->
            val raw = fn.params[param] ?: return@mapNotNull null
            val values = if (op == ComparisonOp.IN) {
                val a = (raw as? JsonArray)?.map { operand(it) ?: return null } ?: return null
                if (a.isEmpty() || a.toSet().size != a.size) return null
                a
            } else {
                listOf(operand(raw) ?: return null)
            }
            Condition(op, values)
        }
        if (conditions.isEmpty()) return null
        return Parsed(path, conditions)
    }

    internal fun claimParam(e: JsonElement): List<String>? = when (e) {
        is JsonPrimitive -> if (e.isString && e.content.isNotEmpty()) listOf(e.content) else null
        is JsonArray -> e.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString && p.content.isNotEmpty() }?.content ?: return null }
            .takeIf { it.isNotEmpty() }
        else -> null
    }

    /** One operand as text of [valueType], or null when it is not a well-formed one. */
    internal fun operand(e: JsonElement): String? {
        val p = e as? JsonPrimitive ?: return null
        return when (valueType) {
            ValueType.DATE -> p.content.takeIf { p.isString && PredicateFunctions.date(it) != null }
            ValueType.NUMBER -> p.content.takeIf { !p.isString && PredicateFunctions.number(it) != null }
            ValueType.STRING -> p.content.takeIf { p.isString }
            ValueType.BOOL -> p.content.takeIf { !p.isString && (it == "true" || it == "false") }
        }
    }

    /** The age of a `ge`/`le` date predicate, for an [ageSpecialisation]. */
    internal fun ageForm(conditions: List<Condition>, today: LocalDate): AgeForm? {
        if (!ageSpecialisation) return null
        // The age wording is only true when nothing else about the date is revealed: every condition is one ge or le bound.
        if (conditions.isEmpty() || conditions.any { it.op != ComparisonOp.GE && it.op != ComparisonOp.LE } ||
            conditions.count { it.op == ComparisonOp.GE } > 1 || conditions.count { it.op == ComparisonOp.LE } > 1
        ) return null
        val ge = conditions.firstOrNull { it.op == ComparisonOp.GE }?.values?.single()
        val le = conditions.firstOrNull { it.op == ComparisonOp.LE }?.values?.single()
        val gd = PredicateFunctions.date(ge)
        val ld = PredicateFunctions.date(le)
        // Born on `le` is the youngest holder the range admits, born on `ge` the oldest.
        fun years(born: LocalDate) = ChronoUnit.YEARS.between(born, today).toInt().coerceAtLeast(0)
        return when {
            gd != null && ld != null -> AgeForm.Between(ge!!, le!!, years(ld), years(gd))
            ld != null -> AgeForm.AtLeast(years(ld))
            gd != null -> AgeForm.AtMost(years(gd))
            else -> null
        }
    }

    /** The `ge` and `le` operands of [conditions] (for the span rule), or null. */
    internal fun bounds(conditions: List<Condition>): Pair<String?, String?> =
        conditions.firstOrNull { it.op == ComparisonOp.GE }?.values?.single() to conditions.firstOrNull { it.op == ComparisonOp.LE }?.values?.single()

    internal val geName get() = geParam
    internal val leName get() = leParam
}

/**
 * The registry of predicate functions the wallet can describe, pre-check and merge-check. A function in a
 * plan that is not declared here (and is not a pseudonym or the legacy disclosure) cannot be described to the
 * user, so the request is refused before consent.
 */
class PredicateFunctions(functions: List<PredicateFunction>) {
    private val byId: Map<String, PredicateFunction> = functions.associateBy { it.id }.also {
        require(it.size == functions.size) { "duplicate predicate function id" }
    }

    operator fun get(id: String): PredicateFunction? = byId[id]

    /** The ids of the declared functions. */
    val ids: Set<String> get() = byId.keys

    /** The consent item for [fn], or null (undeclared function, or params the declaration does not allow). [namespace] is the credential's doctype namespace. */
    fun item(fn: CircuitZkFunction, claims: List<ClaimMeta>, today: LocalDate, namespace: String? = null): ConsentItem.Predicate? {
        val f = byId[fn.id] ?: return null
        val parsed = f.parse(fn) ?: return null
        // The credential's claim metadata is `[namespace, elementId]`; a predicate's path is relative to the doctype
        // namespace the circuit binds. Only that namespace's claim is labelled, never another one's of the same name.
        val label = claims.firstOrNull { it.path == parsed.claimPath || (namespace != null && it.path == listOf(namespace) + parsed.claimPath) }
            ?.label?.takeIf { it.isNotBlank() }
        return ConsentItem.Predicate(fn.id, ClaimRef(parsed.claimPath, label), f.valueType, parsed.conditions, f.ageForm(parsed.conditions, today))
    }

    /**
     * The local satisfiability pre-check of [plan] against what [reader] finds in the credential: false when a
     * predicate definitely does not hold (claim absent, wrong type, or the comparison is false); true when it holds
     * OR cannot be judged (a path or format the reader does not support): the pre-check never guesses. It is only a
     * convenience so the user is not asked to consent to something that will be refused; the prover decides.
     */
    fun precheck(plan: CircuitZkPlan, reader: (path: List<String>, type: ValueType) -> ClaimLookup): Boolean {
        for (fn in plan.functions) {
            val f = byId[fn.id] ?: continue
            val parsed = f.parse(fn) ?: return false
            when (val found = reader(parsed.claimPath, f.valueType)) {
                ClaimLookup.Absent -> return false
                ClaimLookup.Unsupported -> continue
                is ClaimLookup.Found -> if (!holds(f.valueType, parsed.conditions, found.value)) return false
            }
        }
        return true
    }

    /** Whether [fn] holds for the credential [reader] reads: the pre-check of one function (same judgement as [precheck]). */
    fun holdsFor(fn: CircuitZkFunction, reader: (path: List<String>, type: ValueType) -> ClaimLookup): Boolean =
        precheck(CircuitZkPlan(listOf(fn)), reader)

    /**
     * The cross-query rule: the proofs of one request together reveal the INTERSECTION of the predicates on a
     * claim. For plans answered with the SAME credential, per claim path: the `ge` bounds are intersected (max),
     * the `le` bounds (min), and where a function involved DECLARES a minimum selectivity ([PredicateFunction.minSpan])
     * the strictest declared minimum must still hold (`age_check`: at least 365 days). Functions that declare none
     * have no merge rule. An unreadable bound is false, never "cannot compare, so fine".
     */
    fun mergeRuleOk(plans: List<CircuitZkPlan>): Boolean {
        class Acc(var lower: String? = null, var upper: String? = null, var min: Long = 0, var type: ValueType = ValueType.DATE)
        val groups = LinkedHashMap<List<String>, Acc>()
        for (fn in plans.flatMap { it.functions }) {
            val f = byId[fn.id] ?: continue
            val min = f.minSpan ?: continue
            val parsed = f.parse(fn) ?: return false
            val (ge, le) = f.bounds(parsed.conditions)
            val acc = groups.getOrPut(parsed.claimPath) { Acc(type = f.valueType) }
            if (acc.type != f.valueType) return false
            acc.min = maxOf(acc.min, min)
            if (ge != null && (acc.lower == null || compare(f.valueType, ge, acc.lower!!) > 0)) acc.lower = ge
            if (le != null && (acc.upper == null || compare(f.valueType, le, acc.upper!!) < 0)) acc.upper = le
        }
        for (acc in groups.values) {
            val lo = acc.lower ?: continue
            val hi = acc.upper ?: continue
            // Compared exactly: a numeric span is a BigDecimal and may exceed any primitive (never narrowed to Long).
            val tooNarrow = when (acc.type) {
                ValueType.DATE -> ChronoUnit.DAYS.between(date(lo), date(hi)) + 1 < acc.min
                else -> !numberSpanAtLeast(lo, hi, acc.min)
            }
            if (tooNarrow) return false
        }
        return true
    }

    companion object {
        /** `age_check` of the rulebook: `birth_date` within `ge`..`le`, at least 365 days wide, shown as an age. */
        val AGE_CHECK = PredicateFunction(
            id = CircuitZkRuleSet.AGE_CHECK,
            claim = ClaimSource.Fixed(listOf("birth_date")),
            valueType = ValueType.DATE,
            comparisons = linkedMapOf("ge" to ComparisonOp.GE, "le" to ComparisonOp.LE),
            minSpan = 365,
            ageSpecialisation = true,
            doctypeNamespaceOnly = true,
        )

        /** The rulebook's functions: `age_check`. */
        val DEFAULT = PredicateFunctions(listOf(AGE_CHECK))

        private val FULL_DATE = Regex("\\d{4}-\\d{2}-\\d{2}")
        private val NUMBER = Regex("-?\\d+(\\.\\d+)?([eE][+-]?\\d+)?")

        /** A strict RFC 3339 full-date (`YYYY-MM-DD`), or null. */
        fun date(s: String?): LocalDate? =
            s?.takeIf { FULL_DATE.matches(it) }?.let { try { LocalDate.parse(it) } catch (e: DateTimeParseException) { null } }

        /** A JSON number literal, or null. */
        fun number(s: String?): BigDecimal? = s?.takeIf { NUMBER.matches(it) }?.let { try { BigDecimal(it) } catch (e: NumberFormatException) { null } }

        /** The ordering of two well-formed operands of [type] (strings by code point). */
        internal fun compareOperands(type: ValueType, a: String, b: String): Int = compare(type, a, b)

        /** Whether `lo..hi` is at least [min] wide: dates in inclusive calendar days, numbers as `hi - lo`, compared exactly. */
        internal fun spanAtLeast(type: ValueType, lo: String, hi: String, min: Long): Boolean = when (type) {
            ValueType.DATE -> ChronoUnit.DAYS.between(date(lo), date(hi)) + 1 >= min
            else -> numberSpanAtLeast(lo, hi, min)
        }

        /**
         * Whether `hi - lo >= min`, computed exactly (arbitrary precision, never narrowed to a primitive). Refused (false) when the
         * exact difference would need more than [MAX_SPAN_SCALE_GAP] digits of alignment (e.g. `1e999999999 - 1`): a bound that
         * cannot be compared exactly is never "wide enough", and a request cannot make the wallet build a billion-digit number.
         */
        private fun numberSpanAtLeast(lo: String, hi: String, min: Long): Boolean {
            val l = number(lo)!!
            val h = number(hi)!!
            if (Math.abs(h.scale().toLong() - l.scale().toLong()) > MAX_SPAN_SCALE_GAP) return false
            return h.subtract(l).compareTo(BigDecimal.valueOf(min)) >= 0
        }

        private const val MAX_SPAN_SCALE_GAP = 4096L

        private fun compare(type: ValueType, a: String, b: String): Int = when (type) {
            ValueType.DATE -> date(a)!!.compareTo(date(b)!!)
            ValueType.NUMBER -> number(a)!!.compareTo(number(b)!!)
            else -> a.compareTo(b)
        }

        /** Whether [value] satisfies every [conditions]. A value of another type does not. Pure; shared with the vectors. */
        fun holds(type: ValueType, conditions: List<Condition>, value: ClaimValue): Boolean {
            if (value.type != type) return false
            return conditions.all { c ->
                when (c.op) {
                    ComparisonOp.EQ -> same(type, value.text, c.values[0])
                    ComparisonOp.NE -> !same(type, value.text, c.values[0])
                    ComparisonOp.IN -> c.values.any { same(type, value.text, it) }
                    ComparisonOp.LT -> compare(type, value.text, c.values[0]) < 0
                    ComparisonOp.LE -> compare(type, value.text, c.values[0]) <= 0
                    ComparisonOp.GT -> compare(type, value.text, c.values[0]) > 0
                    ComparisonOp.GE -> compare(type, value.text, c.values[0]) >= 0
                }
            }
        }

        private fun same(type: ValueType, a: String, b: String) = if (type == ValueType.STRING || type == ValueType.BOOL) a == b else compare(type, a, b) == 0

        /**
         * A claim reader over an mdoc: only a one-element path in the credential's own doctype namespace (the
         * namespace nym_auth binds) is read; anything else is [ClaimLookup.Unsupported]. A duplicated element is
         * absent; a value of another CBOR type than [ValueType] is a [ClaimLookup.Found] of a mismatching type
         * (so no comparison holds).
         */
        fun mdocReader(document: DocumentMdoc): (List<String>, ValueType) -> ClaimLookup = { path, type ->
            if (path.size != 1) {
                ClaimLookup.Unsupported
            } else {
                val v = SecretSeedCommitment.doctypeElement(document, path[0])
                if (v == null) ClaimLookup.Absent else ClaimLookup.Found(read(v, type))
            }
        }

        /** Largest decimal exponent magnitude, and mantissa size in bits, a claim number may have before it is expanded to text. */
        private const val MAX_NUMBER_EXPONENT = 1000
        private const val MAX_NUMBER_MANTISSA_BITS = 4096

        /** Largest binary exponent magnitude of a CBOR bigfloat (tag 5), and the largest bignum (tag 2/3) in bytes. */
        private const val MAX_BIGFLOAT_EXPONENT = 4096
        private const val MAX_BIGNUM_BYTES = MAX_NUMBER_MANTISSA_BITS / 8

        /**
         * Whether the tagged CBOR number [v0] (its content is [v]) is small enough to convert: a bignum by its byte length, a
         * decimal fraction or bigfloat by its exponent and mantissa, all checked on the encoded items before anything is expanded.
         */
        private fun rawNumberWithinBounds(v0: CBORObject, v: CBORObject): Boolean {
            // The exponent and mantissa are read as PLAIN integers or bignums by their encoding: a nested decimal fraction or
            // bigfloat there (4([4([100000000, 1]), 1])) is refused, never converted to look at its size.
            fun mantissaOk(m: CBORObject): Boolean = when {
                !m.isTagged && m.type == CBORType.Integer -> m.AsNumber().ToEInteger().GetUnsignedBitLengthAsEInteger()
                    .compareTo(com.upokecenter.numbers.EInteger.FromInt32(MAX_NUMBER_MANTISSA_BITS)) <= 0
                m.isTagged && m.tagCount == 1 && (m.HasMostOuterTag(2) || m.HasMostOuterTag(3)) -> {
                    val bytes = m.UntagOne()
                    !bytes.isTagged && bytes.type == CBORType.ByteString && bytes.GetByteString().size <= MAX_BIGNUM_BYTES
                }
                else -> false
            }
            fun exponentWithin(e: CBORObject, limit: Int): Boolean =
                !e.isTagged && e.type == CBORType.Integer && e.AsNumber().ToEInteger().Abs().compareTo(com.upokecenter.numbers.EInteger.FromInt32(limit)) <= 0
            return when {
                v.type == CBORType.ByteString -> !v.isTagged && v.GetByteString().size <= MAX_BIGNUM_BYTES
                v.type == CBORType.Array && v.size() == 2 -> {
                    val limit = if (v0.HasMostOuterTag(5)) MAX_BIGFLOAT_EXPONENT else MAX_NUMBER_EXPONENT
                    exponentWithin(v[0], limit) && mantissaOk(v[1])
                }
                else -> false
            }
        }

        /**
         * The plain decimal text of [d], or null when expanding it would be unreasonable: a CBOR decimal fraction or bigfloat
         * such as `[100000000, 1]` (1E+100000000) would otherwise become ~100M characters before consent. Refused (the reader
         * then reports a mismatching type, so no comparison holds): the bound is checked on the exponent and mantissa, before
         * any expansion.
         */
        private fun boundedPlain(d: com.upokecenter.numbers.EDecimal): String? {
            if (d.exponent.Abs().compareTo(com.upokecenter.numbers.EInteger.FromInt32(MAX_NUMBER_EXPONENT)) > 0) return null
            if (d.unsignedMantissa.GetUnsignedBitLengthAsEInteger().compareTo(com.upokecenter.numbers.EInteger.FromInt32(MAX_NUMBER_MANTISSA_BITS)) > 0) return null
            return BigDecimal(d.toString()).toPlainString()
        }

        internal fun read(v0: CBORObject, type: ValueType): ClaimValue {
            val v = if (v0.isTagged) v0.UntagOne() else v0
            val mismatch = ClaimValue(if (type == ValueType.STRING) ValueType.BOOL else ValueType.STRING, "")
            return when (type) {
                ValueType.DATE -> if (v.type == CBORType.TextString && date(v.AsString()) != null) ClaimValue(type, v.AsString()) else mismatch
                ValueType.STRING -> if (v.type == CBORType.TextString) ClaimValue(type, v.AsString()) else mismatch
                ValueType.BOOL -> if (v.type == CBORType.Boolean) ClaimValue(type, v.isTrue.toString()) else mismatch
                // A tagged number (bignum 2/3, decimal fraction 4, bigfloat 5) is a number, not a mismatching type.
                ValueType.NUMBER -> if (listOf(2, 3, 4, 5).any { v0.HasMostOuterTag(it) }) {
                    // Bound the RAW exponent and mantissa before any conversion: ToEDecimal of a bigfloat [-100000000, 1] needs 5^100000000.
                    if (!rawNumberWithinBounds(v0, v)) return mismatch
                    runCatching { v0.AsNumber() }.getOrNull()?.takeIf { it.IsFinite() }
                        ?.let { n -> boundedPlain(n.ToEDecimal())?.let { ClaimValue(type, it) } } ?: mismatch
                } else when (v.type) {
                    CBORType.Integer -> ClaimValue(type, v.AsNumber().ToEInteger().toString())
                    CBORType.FloatingPoint -> v.AsDoubleValue().takeIf { it.isFinite() }?.let { ClaimValue(type, BigDecimal(it).toPlainString()) } ?: mismatch
                    else -> mismatch
                }
            }
        }
    }
}
