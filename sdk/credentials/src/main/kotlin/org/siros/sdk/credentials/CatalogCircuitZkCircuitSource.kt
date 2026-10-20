// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

/**
 * The `circuit_zk` circuit table backed by the circuit catalog: the circuits of the last catalog manifest (or, before any
 * has been fetched, of the descriptors the client has cached), as the default prover can serve them. It starts empty,
 * so until a catalog is known no `circuit_zk` request matches (fail closed), and the wallet's catalog refresh keeps it
 * current ([update]); a circuit the catalog retires leaves the table with the next refresh.
 *
 * Pass one as `WalletConfig.circuitZkCircuits`; the wallet it is given to updates it. Thread-safe: [circuits] reads an
 * immutable snapshot.
 */
class CatalogCircuitZkCircuitSource : CircuitZkCircuitSource {
    @Volatile private var snapshot: List<CircuitZkCircuit> = emptyList()

    override fun circuits(): List<CircuitZkCircuit> = snapshot

    /** Replaces the table with the circuits of [manifest]; [declare] says which functions a claimed entry is offered for. */
    fun update(manifest: ZkManifest, declare: (ZkCircuitDescriptor) -> Set<String>?) {
        snapshot = CircuitZkCircuitSource.fromManifest(manifest, declare)
    }

    /** Replaces the table with the circuits of cached [descriptors] (offline start, before any manifest). */
    fun update(descriptors: Collection<ZkCircuitDescriptor>, declare: (ZkCircuitDescriptor) -> Set<String>?) =
        update(ZkManifest(circuits = descriptors.toList()), declare)
}
