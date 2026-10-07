// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.Integrity
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason

/** Fetching a document a `transaction_data_types` entry references, honouring EC TS12 4.1.2. */
internal object ReferencedDocuments {
    /**
     * The text of [uri], the value of [member] (`schema_uri`, `claims_uri`,
     * `ui_labels_uri`) of the entry for [type].
     *
     * If the credential carries `transaction_data_types['<type>'].<member>#integrity`
     * the document must match it (TS12 4.1.2: the wallet SHALL verify). A
     * claim that is present but not a string is a refusal, never "no pin".
     *
     * @throws TransactionDataError `METADATA_UNAVAILABLE` when the document
     *   cannot be fetched or does not match its integrity claim.
     */
    suspend fun fetch(
        source: TransactionMetadataSource,
        credential: StoredCredential,
        type: String,
        member: String,
        uri: String,
        trust: MetadataTrust? = null,
    ): String {
        val cached: String? = trust?.documents?.get(uri)
        val text = if (cached != null) cached else download(source, uri, trust)
        val claim = CredentialUtils.parseJwtPayload(credential.raw)?.get("transaction_data_types['$type'].$member#integrity")
        val pinned = when {
            claim == null -> null
            claim is JsonPrimitive && claim.isString -> claim.content
            else -> throw TransactionDataError(
                TransactionDataReason.METADATA_UNAVAILABLE,
                "The credential's integrity claim for $member is not a string",
            )
        }
        if (pinned == null) trust?.noteUnpinnedDocument()
        if (pinned != null && !Integrity.matches(text.toByteArray(Charsets.UTF_8), pinned)) {
            throw TransactionDataError(
                TransactionDataReason.METADATA_UNAVAILABLE,
                "The document at $uri does not match the credential's integrity claim",
            )
        }
        return text
    }

    /** Fetches [uri] once and remembers it for the rest of the validation. */
    private suspend fun download(source: TransactionMetadataSource, uri: String, trust: MetadataTrust?): String {
        val fetched = source.document(uri)
            ?: throw TransactionDataError(TransactionDataReason.METADATA_UNAVAILABLE, "The document at $uri is not available")
        trust?.documents?.put(uri, fetched)
        return fetched
    }
}
