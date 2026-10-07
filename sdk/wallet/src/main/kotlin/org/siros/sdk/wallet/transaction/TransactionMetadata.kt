// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import kotlinx.serialization.json.JsonObject
import org.siros.sdk.credentials.StoredCredential

/**
 * Where the transaction data pipeline gets the type metadata of an SCA
 * attestation and the documents it references. Every call must be bounded in
 * time and size, and every failure is reported as `null`, which the pipeline
 * turns into a refusal: unreachable metadata is a refusal, never a skip.
 */
internal interface TransactionMetadataSource {
    /**
     * The SD-JWT VC type metadata document of [credential]'s `vct` (EC TS12
     * 4.1.1: SD-JWT VC sections 6.3.1 and 6.3.4), already checked against the
     * credential's `vct#integrity` when it carries one; `null` when it cannot
     * be obtained or does not match.
     */
    suspend fun typeMetadata(credential: StoredCredential): JsonObject?

    /** The text of the document at [uri] (a `schema_uri`), or `null`. */
    suspend fun document(uri: String): String?
}
