// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.StoredCredential
import timber.log.Timber

/**
 * Whether what drives one validation (display labels, schemas, type support)
 * was authenticated by the issuer's `vct#integrity` / `...#integrity` pins.
 *
 * Pins are not mandatory, so metadata from a compromised registry can pass
 * unnoticed; the display floor for the built-in types limits what such
 * metadata can hide, and this records that it happened. [warnOnce] logs ONE
 * fixed sentence per validation and nothing else: no vct, URL, host, issuer,
 * credential, transaction field or exception text, because device logs are
 * readable by other tooling and what card a user holds is itself private.
 * It never changes a decision.
 */
internal class MetadataTrust {
    /** `true` until something was used without a pin. */
    @Volatile
    var pinned: Boolean = true
        private set

    private var warned = false

    /** Documents fetched during this validation, by URL, so display does not fetch them again (each fetch can take seconds). */
    internal val documents = java.util.concurrent.ConcurrentHashMap<String, String>()

    /** Notes that [credential]'s type metadata is used; unpinned unless it carries a `vct#integrity`. */
    fun noteTypeMetadata(credential: StoredCredential) {
        val claim = CredentialUtils.parseJwtPayload(credential.raw)?.get("vct#integrity")
        if (!(claim is JsonPrimitive && claim.isString)) pinned = false
    }

    /** Notes that a referenced document was fetched without an `#integrity` claim to check it against. */
    fun noteUnpinnedDocument() {
        pinned = false
    }

    /** Emits the warning if anything was unpinned, once per validation. */
    @Synchronized
    fun warnOnce() {
        if (pinned || warned) return
        warned = true
        Timber.w(WARNING)
    }

    companion object {
        /** The only text ever logged about this. */
        const val WARNING = "SCA type metadata is not authenticated by vct#integrity; display and schema come from an unpinned source"
    }
}
