// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonObject

/**
 * The secret-bearing members of the SUPERSEDED delivery shapes (privatedata-spec 5A and the holder-commitment / psc forms): removed from
 * this SDK, which understands only Credential Auxiliary Data (`auxiliary_data`). They are known here for one purpose: an issuer that still
 * sends one is REFUSED (a response carrying one stores nothing; a configuration advertising one is not offered), never interpreted and
 * never stored uninterpreted next to a secret it might hold.
 */
object LegacySecretMembers {
    /** The `credential_metadata` member names of the removed shapes. */
    val MEMBERS: Set<String> = setOf(
        "org.siros.secret_seed",
        "org.siros.holder_commitments",
        "org.siros.psc",
        "holder_commitments",
        "secret_members",
    )

    /** Whether the response `credential_metadata` [metadata] carries a member of a removed shape. */
    fun carriedBy(metadata: JsonObject): Boolean = metadata.keys.any { it in MEMBERS }
}
