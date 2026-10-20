// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.ZkCircuitDescriptor

/** A catalog `system` at one `systemVersion`: the granularity at which a prover is trusted to drive a circuit. */
data class CircuitZkSystemKey(val system: String, val systemVersion: String)

/**
 * One proof system behind [CatalogCircuitZkProver]: everything that is specific to how a catalog system
 * turns a `circuit_zk` plan into a proof and the plan's results. The dispatcher has already checked that the
 * descriptor is the chosen circuit, published, active and not deprecated; the adapter checks the rest of what
 * it needs and refuses (an [CircuitZkError.AccessDenied]) at the first thing it cannot prove.
 */
interface CircuitZkSystemAdapter {
    /** The (system, version) pairs this adapter drives. Any other pair is refused, whatever its descriptor says. */
    val systems: Set<CircuitZkSystemKey>

    /** Whether a proof can be produced at all (a native half is present). A false answer refuses every request. */
    val canProve: Boolean get() = true

    /**
     * The functions a claimed catalog entry is offered for, for entries that declare none themselves
     * (see `CircuitZkCircuitSource.fromManifest`); null when the entry declares its own.
     */
    fun declaredFunctions(descriptor: ZkCircuitDescriptor): Set<String>? = null

    /** Whether [circuit] can serve [plan] with this adapter: cheap, no I/O. */
    fun admits(circuit: CircuitZkCircuit, plan: CircuitZkPlan): Boolean

    /** Proves [input] with the circuit [descriptor] describes. */
    suspend fun prove(descriptor: ZkCircuitDescriptor, input: CircuitZkProveInput): CircuitZkProveOutput

    /** Drops resident prover memory. */
    fun release() {}

    /** [descriptor]'s circuit was retired by a catalog refresh: drop resident memory and caches derived from it. */
    suspend fun retire(descriptor: ZkCircuitDescriptor) {}
}

/**
 * The explicit registry of what may prove a catalog circuit, keyed by (system, systemVersion). A pair no
 * adapter claims has no prover: it is refused, never routed to a default and never to the fake. Claiming a
 * pair twice is a programming error.
 */
class CircuitZkSystemRegistry(val adapters: List<CircuitZkSystemAdapter>) {
    private val byKey: Map<CircuitZkSystemKey, CircuitZkSystemAdapter>

    init {
        val map = LinkedHashMap<CircuitZkSystemKey, CircuitZkSystemAdapter>()
        for (adapter in adapters) {
            for (key in adapter.systems) {
                require(map.put(key, adapter) == null) { "circuit_zk system $key is claimed by two adapters" }
            }
        }
        byKey = map
    }

    /** The adapter for exactly ([system], [systemVersion]); null when none claims it or the version is unknown. */
    fun adapterFor(system: String, systemVersion: String?): CircuitZkSystemAdapter? =
        systemVersion?.let { byKey[CircuitZkSystemKey(system, it)] }

    /** What `CircuitZkCircuitSource.fromManifest` should declare for [descriptor]. */
    fun declaredFunctions(descriptor: ZkCircuitDescriptor): Set<String>? =
        adapterFor(descriptor.system, descriptor.systemVersion)?.declaredFunctions(descriptor)

    /** Whether [circuit] has an adapter that admits [plan]. */
    fun admits(circuit: CircuitZkCircuit, plan: CircuitZkPlan): Boolean =
        adapterFor(circuit.system, circuit.systemVersion)?.admits(circuit, plan) == true

    /** Whether some adapter can produce a proof. */
    val canProve: Boolean get() = adapters.any { it.canProve }

    fun release() {
        adapters.forEach { it.release() }
    }

    /** Tells the adapter that claims [descriptor]'s system that the circuit was retired. */
    suspend fun retire(descriptor: ZkCircuitDescriptor) {
        adapterFor(descriptor.system, descriptor.systemVersion)?.retire(descriptor)
    }
}
