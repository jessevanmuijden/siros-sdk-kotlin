// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Kotlin initializes a class's properties in textual order, and `wallet`'s initializer builds the WalletConfig (buildWalletConfig ->
 * buildWscdKeystore -> registerFido2OnSigner), which writes into these fields. A field declared BELOW `wallet` is still null then: the
 * write throws, buildWscdKeystore's catch turns that into a dropped keystore, and the initial wallet silently loses its WSCD keystores
 * (a real regression caught in review of the typed-ahead PIN change). Pinned structurally because the view model needs an Activity to
 * construct; the JVM lists declared fields in declaration order.
 */
class WalletViewModelInitOrderTest {
    @Test
    fun fieldsTheWalletInitializerWritesAreDeclaredBeforeTheWallet() {
        val names = WalletViewModel::class.java.declaredFields.map { it.name }
        val wallet = names.indexOf("wallet")
        assertTrue("field 'wallet' not found in $names", wallet >= 0)
        for (field in listOf("fido2RegisteredTransport", "fido2StateRestored", "wscdAdapterByPlugin")) {
            val at = names.indexOf(field)
            assertTrue("$field is declared after 'wallet' (or missing): its initializer would not have run when the wallet is built", at in 0 until wallet)
        }
    }
}
