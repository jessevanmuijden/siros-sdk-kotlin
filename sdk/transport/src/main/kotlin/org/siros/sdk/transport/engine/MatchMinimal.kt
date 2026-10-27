// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.transport.engine

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * What the engine learns of the wallet's credential matching: how many queries the wallet can answer (the length of `matches`) and, when
 * none, a fixed CODE for why. It reads nothing else, and the wallet's credentials are not its business: no credential id, no format, no
 * credential type, no claim names, no free text (a free-text reason carried the requested types and the number of credentials stored).
 * The local consent step keeps all of that; only this engine-bound message is trimmed.
 */
@Serializable
data class MatchRef(
    /** The verifier's own query id this wallet can answer (the engine decodes it as `credential_query_id`). */
    @SerialName("credential_query_id") val credentialQueryId: String? = null,
)

/** The `no_match_reason` codes. The same list is used by every SDK; a reason that is not one of the shapes below is sent as [UNSPECIFIED]. */
object NoMatchCodes {
    const val NO_MATCHING_CREDENTIAL = "no_matching_credential"
    const val CREDENTIALS_EXHAUSTED = "credentials_exhausted"
    const val REQUEST_NOT_ANSWERABLE = "request_not_answerable"
    const val NO_SELECTION = "no_selection"
    const val UNSPECIFIED = "unspecified"

    private val SHAPE = Regex("[a-z0-9_]{1,64}")

    /** [reason] as it may leave the device: only a code-shaped value (`^[a-z0-9_]{1,64}$`), anything else - free text - becomes [UNSPECIFIED]; null stays null. */
    fun wire(reason: String?): String? = when {
        reason == null -> null
        SHAPE.matches(reason) -> reason
        else -> UNSPECIFIED
    }
}
