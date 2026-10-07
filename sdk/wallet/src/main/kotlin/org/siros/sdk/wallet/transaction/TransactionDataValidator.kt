// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.keystore.AuthenticationFactor
import org.siros.sdk.keystore.TransactionBinding

/**
 * The transport-independent form of a presentation request that carries
 * `transaction_data` (contract section 3).
 *
 * @property entries the verifier's entries, in the verifier's order.
 * @property responseMode the OpenID4VP `response_mode` of the request.
 * @property credentials which stored credentials answer which DCQL query id.
 * @property requestSigned whether the request was signed; `null` when the
 *   transport does not know (the engine and WMP deliver it already verified).
 */
internal class TransactionDataRequest(
    val entries: List<TransactionDataEntry>,
    val responseMode: String?,
    val credentials: Map<String, List<StoredCredential>>,
    val audience: String? = null,
    val nonce: String? = null,
    val verifier: String? = null,
    val requestSigned: Boolean? = null,
    /** What the presentation will disclose, for the consent screen. */
    val disclosures: List<DisclosureInput> = emptyList(),
)

/** One credential of the presentation and what it will disclose, as the wiring knows it before validation. */
internal class DisclosureInput(val queryId: String?, val credentialName: String?, val claims: List<String>?)

/** One credential an entry is bound to, with the metadata it was validated against. */
internal class ScaCredentialContext(
    val credential: StoredCredential,
    /** The credential's SD-JWT VC type metadata document. */
    val metadata: JsonObject,
    /** The `transaction_data_types` entry for the entry's type, if the metadata has one. */
    val typeEntry: JsonObject?,
)

/** An entry that passed every check of contract section 4 up to the hash algorithm. */
internal class ValidatedTransactionEntry(
    val raw: String,
    val type: String,
    val credentialIds: List<String>,
    val payload: JsonObject,
    /** The verifier's list of acceptable hash algorithms; `null` when it gave none. */
    val hashAlgs: List<String>?,
    val contexts: List<ScaCredentialContext>,
)

/** What one DCQL query's KB-JWT carries: the algorithm and the hashes of the entries bound to it. */
internal class QueryHashes(val hashAlg: String, val hashes: List<String>)

/** The outcome of a successful validation: everything needed to ask for consent and then sign. */
internal class ValidatedTransactionData(
    val entries: List<ValidatedTransactionEntry>,
    val responseMode: String,
    private val byQuery: Map<String, QueryHashes>,
    /** Whether the metadata that drove this validation was authenticated by pins. */
    internal val trust: MetadataTrust = MetadataTrust(),
) {
    /** The DCQL query ids some entry is bound to, in first-mention order. */
    fun boundQueryIds(): List<String> = byQuery.keys.toList()

    /** The hashes for the credential(s) answering [queryId], or `null` when no entry is bound to it. */
    fun hashesFor(queryId: String): QueryHashes? = byQuery[queryId]

    /**
     * The KB-JWT binding for the credential answering [queryId], or `null`
     * when no entry is bound to it (that presentation is then unchanged).
     *
     * @throws TransactionDataError `INSUFFICIENT_AUTHENTICATION_FACTORS`
     *   when [factors] span fewer than two categories.
     */
    fun bindingFor(queryId: String, factors: List<AuthenticationFactor>): TransactionBinding? {
        val h = byQuery[queryId] ?: return null
        return TransactionBinding(h.hashes, h.hashAlg, responseMode, factors)
    }
}

/**
 * Validates a `transaction_data` request (contract section 4, steps 1 to 7),
 * failing closed: the first problem throws a [TransactionDataError] and
 * nothing may be signed.
 */
internal class TransactionDataValidator(private val source: TransactionMetadataSource) {

    suspend fun validate(request: TransactionDataRequest): ValidatedTransactionData {
        if (request.entries.isEmpty() || request.entries.size > MAX_ENTRIES) {
            throw error(TransactionDataReason.INVALID_ENTRY, "transaction_data must hold between 1 and $MAX_ENTRIES entries")
        }
        val responseMode = request.responseMode?.takeIf { it.isNotBlank() }
            ?: throw error(
                TransactionDataReason.INVALID_ENTRY,
                "The request carries transaction_data but no response_mode, which the key binding JWT must echo",
            )

        val metadataByCredential = HashMap<Long, JsonObject>()
        val trust = MetadataTrust()
        val validated = request.entries.map { entry -> validateEntry(entry, request, metadataByCredential, trust) }
        val result = ValidatedTransactionData(validated, responseMode, chooseHashes(validated), trust)
        trust.warnOnce()
        return result
    }

    private suspend fun validateEntry(
        entry: TransactionDataEntry,
        request: TransactionDataRequest,
        metadataCache: MutableMap<Long, JsonObject>,
        trust: MetadataTrust,
    ): ValidatedTransactionEntry {
        // 1. Decode raw ourselves; the orchestrator's hint only has to agree.
        val decoded = TransactionDataDecoder.decode(entry)

        // 2. Each credential_id must name a query the user answers with a credential.
        val credentials = decoded.credentialIds.flatMap { id ->
            request.credentials[id]?.takeIf { it.isNotEmpty() }
                ?: throw error(
                    TransactionDataReason.INVALID_ENTRY,
                    "credential_ids names '$id', which no presented credential answers",
                )
        }.distinctBy { it.id }

        val contexts = credentials.map { credential ->
            // 3. SD-JWT VC only (EC TS12 v1.0.1 covers nothing else).
            if (credential.format !in SD_JWT_FORMATS) {
                throw error(
                    TransactionDataReason.UNSUPPORTED_FORMAT,
                    "transaction_data is bound to a ${credential.format} credential; only SD-JWT VC is supported",
                )
            }
            val metadata = metadataCache[credential.id]
                ?: (source.typeMetadata(credential)
                    ?: throw error(TransactionDataReason.METADATA_UNAVAILABLE, "The credential's type metadata is not available"))
                    .also {
                        metadataCache[credential.id] = it
                        trust.noteTypeMetadata(credential)
                    }

            // 4. The credential must be an SCA attestation (TS12 3: top-level category).
            if ((metadata["category"] as? JsonPrimitive)?.takeIf { it.isString }?.content != SCA_CATEGORY) {
                throw error(TransactionDataReason.NOT_SCA_ATTESTATION, "The credential's type is not an SCA attestation")
            }

            // 5. Type support (TS12 3.2 step 2, plus the built-in types).
            val types = when (val t = metadata["transaction_data_types"]) {
                null -> null
                is JsonObject -> t
                else -> throw error(TransactionDataReason.METADATA_UNAVAILABLE, "transaction_data_types is not an object")
            }
            val typeEntry = when (val te = types?.get(decoded.type)) {
                null -> null
                is JsonObject -> te
                else -> throw error(TransactionDataReason.METADATA_UNAVAILABLE, "A transaction_data_types entry is not an object")
            }
            if (typeEntry == null && !TransactionSchemas.isBuiltIn(decoded.type)) {
                throw error(
                    TransactionDataReason.UNSUPPORTED_TYPE,
                    "transaction_data type '${decoded.type}' is not declared by the credential's type metadata",
                )
            }

            // 6. Schema.
            validatePayload(decoded, credential, typeEntry, trust)
            ScaCredentialContext(credential, metadata, typeEntry)
        }

        // 7. The hash algorithm is chosen per credential once every entry is validated (chooseHashes).
        return ValidatedTransactionEntry(
            decoded.raw, decoded.type, decoded.credentialIds, decoded.payload, decoded.hashAlgs, contexts,
        )
    }

    /**
     * The payload must satisfy the built-in schema of a built-in type and, if
     * the type's metadata entry names one, that schema too.
     */
    private suspend fun validatePayload(
        decoded: DecodedTransactionData,
        credential: StoredCredential,
        typeEntry: JsonObject?,
        trust: MetadataTrust,
    ) {
        val payload: JsonElement = decoded.payload
        if (TransactionSchemas.isBuiltIn(decoded.type)) {
            violation(decoded, bounded { TransactionSchemas.validateBuiltIn(decoded.type, payload) })
        }
        if (typeEntry == null) return

        val embedded = typeEntry["schema"]
        val uri = typeEntry["schema_uri"]
        if (embedded != null && uri != null) {
            throw error(TransactionDataReason.METADATA_UNAVAILABLE, "A transaction data type has both schema and schema_uri")
        }
        val schema: JsonElement? = when {
            embedded is JsonObject -> embedded
            embedded is JsonPrimitive && embedded.isString -> {
                // TS12's own example names a built-in type by URN here.
                if (!TransactionSchemas.isBuiltIn(embedded.content)) {
                    // A bare URI in `schema` is ambiguous (4.1 says embedded schema, 3.2 step 3 a URI): refuse.
                    throw error(TransactionDataReason.UNSUPPORTED_TYPE, "Unrecognised schema reference '${embedded.content}'")
                }
                // The type's own built-in schema was checked above; check any other one named.
                if (embedded.content != decoded.type) {
                    violation(decoded, bounded { TransactionSchemas.validateBuiltIn(embedded.content, payload) })
                }
                null
            }
            embedded != null -> throw error(TransactionDataReason.METADATA_UNAVAILABLE, "schema is neither an object nor a string")
            uri is JsonPrimitive && uri.isString -> fetchSchema(decoded.type, uri.content, credential, trust)
            uri != null -> throw error(TransactionDataReason.METADATA_UNAVAILABLE, "schema_uri is not a string")
            TransactionSchemas.isBuiltIn(decoded.type) -> null
            else -> throw error(TransactionDataReason.UNSUPPORTED_TYPE, "The type '${decoded.type}' names no schema")
        }
        if (schema != null) {
            val problems = bounded { TransactionSchemas.validate(schema, payload) }
            violation(decoded, problems)
        }
    }

    private suspend fun fetchSchema(type: String, uri: String, credential: StoredCredential, trust: MetadataTrust): JsonElement {
        val text = ReferencedDocuments.fetch(source, credential, type, "schema_uri", uri, trust)
        return try {
            kotlinx.serialization.json.Json.parseToJsonElement(text)
        } catch (e: Exception) {
            throw error(TransactionDataReason.METADATA_UNAVAILABLE, "The schema at $uri is not JSON", e)
        } catch (e: StackOverflowError) {
            throw error(TransactionDataReason.METADATA_UNAVAILABLE, "The schema at $uri nests too deeply", e)
        }
    }

    /** Runs a schema check, turning an unusable schema, a timeout or any failure into a refusal. */
    private fun <T> bounded(check: () -> T): T = try {
        check()
    } catch (e: TransactionSchemas.UnusableSchema) {
        throw error(TransactionDataReason.METADATA_UNAVAILABLE, e.message ?: "The schema cannot be used", e)
    }

    private fun violation(decoded: DecodedTransactionData, problems: List<String>) {
        if (problems.isEmpty()) return
        throw error(
            TransactionDataReason.SCHEMA_VIOLATION,
            "The payload of '${decoded.type}' does not satisfy its schema: ${problems.take(3).joinToString("; ")}",
        )
    }

    /**
     * The KB-JWT of a credential carries ONE `transaction_data_hashes_alg`
     * for all the entries bound to it, so for each query the algorithm is the
     * first one (in the verifier's preference order for its first entry) that
     * is supported and acceptable to every entry bound to that query; an
     * entry that lists none accepts `sha-256` only (OpenID4VP default).
     */
    private fun chooseHashes(entries: List<ValidatedTransactionEntry>): Map<String, QueryHashes> {
        val queryIds = entries.flatMap { it.credentialIds }.distinct()
        return queryIds.associateWith { queryId ->
            val bound = entries.indices.filter { queryId in entries[it].credentialIds }
            val acceptable = bound.map { entries[it].hashAlgs ?: listOf(TransactionDataHashing.DEFAULT) }
            val alg = acceptable.first().firstOrNull { a ->
                a in TransactionDataHashing.SUPPORTED && acceptable.all { a in it }
            } ?: throw error(
                TransactionDataReason.UNSUPPORTED_HASH_ALGORITHM,
                "No hash algorithm is supported and acceptable to every transaction bound to '$queryId'",
            )
            QueryHashes(alg, bound.map { TransactionDataHashing.hash(entries[it].raw, alg) })
        }
    }

    private fun error(reason: TransactionDataReason, message: String, cause: Throwable? = null) =
        TransactionDataError(reason, message, cause)

    companion object {
        /** `category` of an SCA attestation's type metadata (EC TS12 v1.0.1 3). */
        const val SCA_CATEGORY = "urn:eu:europa:ec:eudi:sua:sca"

        /** More entries than any real request carries; bounds the work a hostile one can cause. */
        const val MAX_ENTRIES = 32

        private val SD_JWT_FORMATS = setOf("dc+sd-jwt", "vc+sd-jwt")
    }
}
