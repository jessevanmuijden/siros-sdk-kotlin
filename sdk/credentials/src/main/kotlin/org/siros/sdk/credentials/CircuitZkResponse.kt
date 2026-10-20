// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORObject
import java.util.Base64
import kotlinx.serialization.json.JsonPrimitive

/** One value of `results`: a pseudonym or a predicate outcome. */
sealed interface ResultValue {
    /** A pseudonym: a byte string whose length the item's `prf` sets (32 for `sha-256`, 48 for `hashdh-bls12381g1`). */
    class Pseudonym(bytes: ByteArray) : ResultValue {
        /** A copy of the pseudonym bytes. */
        val bytes: ByteArray = bytes.copyOf()

        init {
            require(bytes.size == SHA256_SIZE || bytes.size == HASHDH_SIZE) { "A pseudonym is $SHA256_SIZE or $HASHDH_SIZE bytes, got ${bytes.size}" }
        }

        override fun equals(other: Any?) = other is Pseudonym && bytes.contentEquals(other.bytes)

        override fun hashCode() = bytes.contentHashCode()

        override fun toString() = "Pseudonym(${bytes.size} bytes)"

        companion object {
            /** The size for `prf` `sha-256`, in bytes. */
            const val SHA256_SIZE = 32

            /** The size for `prf` `hashdh-bls12381g1`, in bytes. */
            const val HASHDH_SIZE = 48
        }
    }

    /** `true`: a predicate that holds. There is no `false`. */
    object Predicate : ResultValue {
        override fun toString() = "Predicate(true)"
    }
}

/**
 * A `ZkpPresentation` of the rulebook v0.4 ("Presentation encoding"), the value of one element of `vp_token[queryId]`
 * once base64url-encoded (without padding):
 *
 * ```
 * ZkpPresentation = {
 *   "system_id" => tstr, "proof" => bstr, "issuer_key_set" => [+ bstr],
 *   ? "proof_time" => tdate, "results" => { + tstr => ResultValue } }
 * ```
 *
 * @property systemId A `system_id` the request OFFERED (`system_id_values`); the verifier's registry maps it to a proof system.
 * @property proof The proof bytes, opaque here.
 * @property issuerKeySet For `mso_mdoc`: the DER Document Signer certificates, leaf first, taken from the credential's own
 *   `issuerAuth` `x5chain`; at most [MAX_KEYS] of at most [MAX_KEY_BYTES] bytes each. The verifier validates them through
 *   its trust evaluation and takes the issuer key from the validated certificate.
 * @property proofTime The circuit's time input in the exact 20-byte form ([ProofTime]); REQUIRED for `mso_mdoc`, so the
 *   presenter always sets it for that source format.
 * @property results One result per `return` handle of the request, none skipped.
 */
class CircuitZkResponsePresentation(
    val systemId: String,
    proof: ByteArray,
    issuerKeySet: List<ByteArray>,
    val proofTime: String?,
    results: Map<String, ResultValue>,
) {
    val proof: ByteArray = proof.copyOf()
    val issuerKeySet: List<ByteArray> = issuerKeySet.map { it.copyOf() }
    val results: Map<String, ResultValue> = LinkedHashMap(results)

    init {
        require(systemId.isNotEmpty()) { "system_id is non-empty" }
        require(proof.isNotEmpty()) { "an empty proof" }
        require(issuerKeySet.size in 1..MAX_KEYS) { "issuer_key_set has ${issuerKeySet.size} elements (1..$MAX_KEYS)" }
        require(issuerKeySet.all { it.size in 1..MAX_KEY_BYTES }) { "an issuer_key_set element is empty or over $MAX_KEY_BYTES bytes" }
        require(proofTime == null || ProofTime.isValid(proofTime)) { "proof_time is not the exact 20-byte form" }
        require(results.isNotEmpty()) { "no results" }
    }

    /** The CBOR encoding: definite lengths, `results` keys sorted by their UTF-8 bytes. */
    fun encode(): ByteArray {
        val map = CBORObject.NewOrderedMap()
        map[CBORObject.FromObject("system_id")] = CBORObject.FromObject(systemId)
        map[CBORObject.FromObject("proof")] = CBORObject.FromObject(proof)
        map[CBORObject.FromObject("issuer_key_set")] = CBORObject.NewArray().also { a -> issuerKeySet.forEach { a.Add(CBORObject.FromObject(it)) } }
        proofTime?.let { map[CBORObject.FromObject("proof_time")] = CBORObject.FromObjectAndTag(it, 0) }
        val out = CBORObject.NewOrderedMap()
        results.entries.sortedWith { a, b -> compareUtf8(a.key, b.key) }.forEach { (handle, value) ->
            out[CBORObject.FromObject(handle)] = when (value) {
                is ResultValue.Pseudonym -> CBORObject.FromObject(value.bytes)
                ResultValue.Predicate -> CBORObject.True
            }
        }
        map[CBORObject.FromObject("results")] = out
        return map.EncodeToBytes()
    }

    /** [encode] as base64url without padding: the element of `vp_token[queryId]`. */
    fun toBase64Url(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(encode())

    /** The element as the JSON string a `vp_token` array holds. */
    fun toJson(): JsonPrimitive = JsonPrimitive(toBase64Url())

    override fun toString() = "CircuitZkResponsePresentation(systemId=$systemId, results=${results.keys})"

    companion object {
        /** Most elements of `issuer_key_set`. */
        const val MAX_KEYS = 8

        /** Largest element of `issuer_key_set`, in bytes. */
        const val MAX_KEY_BYTES = 4096

        private fun compareUtf8(a: String, b: String): Int {
            val x = a.toByteArray(Charsets.UTF_8)
            val y = b.toByteArray(Charsets.UTF_8)
            for (i in 0 until minOf(x.size, y.size)) {
                val d = (x[i].toInt() and 0xff) - (y[i].toInt() and 0xff)
                if (d != 0) return d
            }
            return x.size - y.size
        }
    }
}

/**
 * The stable refusal codes of the `zkp_req` response conformance vectors
 * (`spec/zkp-req-vectors/zkp_req_response`, from siros-dc-matcher `docs/zkp_req_response.md`).
 */
enum class CircuitZkResponseError(val code: String) {
    RESPONSE_NOT_PARSEABLE("response_not_parseable"),
    DUPLICATE_MEMBER("duplicate_member"),
    QUERY_ID_MISSING("query_id_missing"),
    PRESENTATIONS_NOT_ARRAY("presentations_not_array"),
    PRESENTATIONS_EMPTY("presentations_empty"),
    PRESENTATIONS_MULTIPLE_NOT_ALLOWED("presentations_multiple_not_allowed"),
    PRESENTATION_NOT_STRING("presentation_not_string"),
    PRESENTATION_NOT_BASE64URL("presentation_not_base64url"),
    CBOR_MALFORMED("cbor_malformed"),
    CBOR_INDEFINITE_LENGTH("cbor_indefinite_length"),
    CBOR_TRAILING_BYTES("cbor_trailing_bytes"),
    CBOR_DUPLICATE_KEY("cbor_duplicate_key"),
    PRESENTATION_NOT_MAP("presentation_not_map"),
    PRESENTATION_KEY_NOT_TEXT("presentation_key_not_text"),
    PRESENTATION_UNKNOWN_MEMBER("presentation_unknown_member"),
    PRESENTATION_MEMBER_MISSING("presentation_member_missing"),
    PRESENTATION_MEMBER_WRONG_TYPE("presentation_member_wrong_type"),
    SYSTEM_ID_NOT_OFFERED("system_id_not_offered"),
    PROOF_EMPTY("proof_empty"),
    ISSUER_KEY_SET_EMPTY("issuer_key_set_empty"),
    ISSUER_KEY_SET_TOO_MANY("issuer_key_set_too_many"),
    ISSUER_KEY_NOT_BYTES("issuer_key_not_bytes"),
    ISSUER_KEY_EMPTY("issuer_key_empty"),
    ISSUER_KEY_TOO_LARGE("issuer_key_too_large"),
    PROOF_TIME_MISSING("proof_time_missing"),
    PROOF_TIME_NOT_TDATE("proof_time_not_tdate"),
    PROOF_TIME_FORM("proof_time_form"),
    RESULT_KEY_NOT_TEXT("result_key_not_text"),
    RESULT_HANDLE_UNEXPECTED("result_handle_unexpected"),
    RESULT_HANDLE_MISSING("result_handle_missing"),
    RESULT_FUNCTION_UNKNOWN("result_function_unknown"),
    RESULT_WRONG_TYPE("result_wrong_type"),
    RESULT_NOT_SATISFIED("result_not_satisfied"),
    PSEUDONYM_PRF_UNKNOWN("pseudonym_prf_unknown"),
    PSEUDONYM_WRONG_LENGTH("pseudonym_wrong_length"),
}

/**
 * Checks the `zkp_req` entry of a `vp_token` against the request it answers: shape and binding to the request, not the
 * proof or any certificate (a mirror of siros-dc-matcher's `zkp_req_response::validate_response`; the first rule broken,
 * in the spec's order, is the one reported). The wallet runs it on the response it built, so it never sends one a verifier
 * must refuse. Strict everywhere: CBOR `null` and JSON `null` are type errors, repeated members and keys are refused, no
 * item type is skipped (a request item whose function has no result shape refuses the response).
 *
 * @param predicateFunctionIds Ids of the predicate functions whose result is `true` (default: `age_check`).
 */
object CircuitZkResponseValidator {
    private val MEMBERS = listOf("system_id", "proof", "issuer_key_set", "proof_time", "results")
    private val REQUIRED = listOf("system_id", "proof", "issuer_key_set", "results")
    private const val SOURCE_MSO_MDOC = "mso_mdoc"
    private const val PRF_SHA256 = "sha-256"
    private const val PRF_HASHDH = "hashdh-bls12381g1"

    /** The first rule [vpTokenText] breaks against [plan] (the query is `plan.raw`), or null when it is valid. */
    fun validate(
        plan: CircuitZkPlan,
        vpTokenText: String,
        predicateFunctionIds: Set<String> = setOf(CircuitZkRuleSet.AGE_CHECK),
    ): CircuitZkResponseError? {
        val token = StrictJson.parse(vpTokenText) as? StrictJson.Obj ?: return CircuitZkResponseError.RESPONSE_NOT_PARSEABLE
        if (token.members.map { it.first }.toSet().size != token.members.size) return CircuitZkResponseError.DUPLICATE_MEMBER
        val queryId = (plan.raw["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return CircuitZkResponseError.QUERY_ID_MISSING
        val entry = token.members.firstOrNull { it.first == queryId }?.second ?: return CircuitZkResponseError.QUERY_ID_MISSING
        val presentations = (entry as? StrictJson.Arr)?.items ?: return CircuitZkResponseError.PRESENTATIONS_NOT_ARRAY
        if (presentations.isEmpty()) return CircuitZkResponseError.PRESENTATIONS_EMPTY
        // DCQL: `multiple` omitted means false, i.e. at most one presentation.
        if (presentations.size > 1 && (plan.raw["multiple"] as? JsonPrimitive)?.takeIf { !it.isString }?.content != "true") {
            return CircuitZkResponseError.PRESENTATIONS_MULTIPLE_NOT_ALLOWED
        }
        for (p in presentations) checkPresentation(plan, p, predicateFunctionIds)?.let { return it }
        return null
    }

    private fun checkPresentation(plan: CircuitZkPlan, element: StrictJson, predicates: Set<String>): CircuitZkResponseError? {
        val text = (element as? StrictJson.Str)?.value ?: return CircuitZkResponseError.PRESENTATION_NOT_STRING
        if (!isUnpaddedBase64Url(text)) return CircuitZkResponseError.PRESENTATION_NOT_BASE64URL
        val bytes = Base64.getUrlDecoder().decode(text)
        val decoded = StrictCbor.decode(bytes)
        val item = decoded.getOrElse { e ->
            return when ((e as StrictCbor.Failed).failure) {
                StrictCbor.Failure.MALFORMED -> CircuitZkResponseError.CBOR_MALFORMED
                StrictCbor.Failure.INDEFINITE -> CircuitZkResponseError.CBOR_INDEFINITE_LENGTH
                StrictCbor.Failure.TRAILING -> CircuitZkResponseError.CBOR_TRAILING_BYTES
                StrictCbor.Failure.DUPLICATE_KEY -> CircuitZkResponseError.CBOR_DUPLICATE_KEY
            }
        }
        val map = item as? StrictCbor.Map ?: return CircuitZkResponseError.PRESENTATION_NOT_MAP
        val members = ArrayList<Pair<String, StrictCbor>>()
        for ((k, v) in map.entries) {
            members.add((k as? StrictCbor.Text ?: return CircuitZkResponseError.PRESENTATION_KEY_NOT_TEXT).value to v)
        }
        if (members.any { it.first !in MEMBERS }) return CircuitZkResponseError.PRESENTATION_UNKNOWN_MEMBER
        fun find(name: String) = members.firstOrNull { it.first == name }?.second
        for (m in REQUIRED) if (find(m) == null) return CircuitZkResponseError.PRESENTATION_MEMBER_MISSING
        val wrong = CircuitZkResponseError.PRESENTATION_MEMBER_WRONG_TYPE
        val systemId = (find("system_id") as? StrictCbor.Text ?: return wrong).value
        val proof = (find("proof") as? StrictCbor.Bytes ?: return wrong).value
        val keys = (find("issuer_key_set") as? StrictCbor.Arr ?: return wrong).items
        val results = (find("results") as? StrictCbor.Map ?: return wrong).entries

        // Binding to the offer, fail closed: a request that stated no `system_id_values` offered nothing.
        if (plan.circuitFilter?.circuitIds?.contains(systemId) != true) return CircuitZkResponseError.SYSTEM_ID_NOT_OFFERED
        if (proof.isEmpty()) return CircuitZkResponseError.PROOF_EMPTY
        checkIssuerKeySet(keys)?.let { return it }
        checkProofTime(plan, find("proof_time"))?.let { return it }
        return checkResults(plan, results, predicates)
    }

    private fun checkIssuerKeySet(keys: List<StrictCbor>): CircuitZkResponseError? {
        if (keys.isEmpty()) return CircuitZkResponseError.ISSUER_KEY_SET_EMPTY
        if (keys.size > CircuitZkResponsePresentation.MAX_KEYS) return CircuitZkResponseError.ISSUER_KEY_SET_TOO_MANY
        for (k in keys) {
            val bytes = (k as? StrictCbor.Bytes ?: return CircuitZkResponseError.ISSUER_KEY_NOT_BYTES).value
            if (bytes.isEmpty()) return CircuitZkResponseError.ISSUER_KEY_EMPTY
            if (bytes.size > CircuitZkResponsePresentation.MAX_KEY_BYTES) return CircuitZkResponseError.ISSUER_KEY_TOO_LARGE
        }
        return null
    }

    /** `proof_time` is required for `mso_mdoc` (every approved circuit checks the MSO validity period), optional otherwise. */
    private fun checkProofTime(plan: CircuitZkPlan, item: StrictCbor?): CircuitZkResponseError? {
        if (item == null) return if (plan.sourceFormat == SOURCE_MSO_MDOC) CircuitZkResponseError.PROOF_TIME_MISSING else null
        val tag = item as? StrictCbor.Tag
        if (tag == null || tag.tag != 0L) return CircuitZkResponseError.PROOF_TIME_NOT_TDATE
        val text = (tag.item as? StrictCbor.Text ?: return CircuitZkResponseError.PROOF_TIME_NOT_TDATE).value
        return if (ProofTime.isValid(text)) null else CircuitZkResponseError.PROOF_TIME_FORM
    }

    private fun checkResults(plan: CircuitZkPlan, results: List<Pair<StrictCbor, StrictCbor>>, predicates: Set<String>): CircuitZkResponseError? {
        val named = results.map { (k, v) -> (k as? StrictCbor.Text ?: return CircuitZkResponseError.RESULT_KEY_NOT_TEXT).value to v }
        val wanted = plan.functions.map { it.handle }.toSet()
        if (named.any { it.first !in wanted }) return CircuitZkResponseError.RESULT_HANDLE_UNEXPECTED
        if (plan.functions.any { f -> named.none { it.first == f.handle } }) return CircuitZkResponseError.RESULT_HANDLE_MISSING
        for (function in plan.functions) {
            val value = named.first { it.first == function.handle }.second
            when {
                function.id == CircuitZkRuleSet.PSEUDONYM -> {
                    val want = when ((function.params["prf"] as? JsonPrimitive)?.takeIf { it.isString }?.content) {
                        PRF_SHA256 -> ResultValue.Pseudonym.SHA256_SIZE
                        PRF_HASHDH -> ResultValue.Pseudonym.HASHDH_SIZE
                        else -> return CircuitZkResponseError.PSEUDONYM_PRF_UNKNOWN
                    }
                    val bytes = (value as? StrictCbor.Bytes ?: return CircuitZkResponseError.RESULT_WRONG_TYPE).value
                    if (bytes.size != want) return CircuitZkResponseError.PSEUDONYM_WRONG_LENGTH
                }
                function.id in predicates -> when ((value as? StrictCbor.Bool)?.value) {
                    true -> Unit
                    // An unsatisfiable predicate is a decline, not a result.
                    false -> return CircuitZkResponseError.RESULT_NOT_SATISFIED
                    null -> return CircuitZkResponseError.RESULT_WRONG_TYPE
                }
                else -> return CircuitZkResponseError.RESULT_FUNCTION_UNKNOWN
            }
        }
        return null
    }

    /** Strict unpadded base64url (alphabet `A-Z a-z 0-9 - _`, canonical final character), not decoded. */
    internal fun isUnpaddedBase64Url(s: String): Boolean {
        if (s.length % 4 == 1 || !s.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }) return false
        val last = s.lastOrNull() ?: return true
        val v = when (last) {
            in 'A'..'Z' -> last - 'A'
            in 'a'..'z' -> last - 'a' + 26
            in '0'..'9' -> last - '0' + 52
            '-' -> 62
            else -> 63
        }
        return when (s.length % 4) {
            2 -> v and 0x0F == 0
            3 -> v and 0x03 == 0
            else -> true
        }
    }
}
