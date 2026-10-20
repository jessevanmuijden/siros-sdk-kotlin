// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.CircuitZkConsentSummary
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.wallet.dcapi.DCAPIRequest

/**
 * The consent summary of a `circuit_zk` [plan] for a host to show: no
 * credential values. The verifier is named from authenticated sources only: the
 * name from the trust decision, else the verified client identifier of a signed
 * request, else the platform-attested [origin].
 */
fun circuitZkConsentSummary(plan: CircuitZkPlan, trust: TrustResult, request: DCAPIRequest, origin: String): CircuitZkConsentSummary {
    val label = trust.entityName
        ?: request.clientId?.takeIf { request.keyMaterial != null }?.let { ClientIdScheme.parse(it).displayName }
        ?: origin
    return CircuitZkConsentSummary.from(plan, label)
}
