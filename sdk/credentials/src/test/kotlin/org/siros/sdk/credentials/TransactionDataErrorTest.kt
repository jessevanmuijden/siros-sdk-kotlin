package org.siros.sdk.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TransactionDataErrorTest {
    /** The contract's reason list (ts12-sdk-core-contract.md section 9), shared with the Swift SDK. */
    private val contractCodes = listOf(
        "disabled", "invalidEntry", "inconsistentWithOrchestrator", "unsupportedFormat",
        "notScaAttestation", "unsupportedType", "schemaViolation", "metadataUnavailable",
        "unsupportedHashAlgorithm", "insufficientAuthenticationFactors", "noConsentHandler", "declined",
    )

    @Test
    fun `reason codes are exactly the contract's, in order`() {
        assertEquals(contractCodes, TransactionDataReason.values().map { it.code })
    }

    @Test
    fun `declined answers access_denied and every refusal invalid_transaction_data`() {
        for (reason in TransactionDataReason.values()) {
            val expected = if (reason == TransactionDataReason.DECLINED) "access_denied" else "invalid_transaction_data"
            assertEquals(reason.code, expected, reason.verifierError)
        }
    }

    @Test
    fun `the error is a SirosException carrying the reason`() {
        val e = TransactionDataError(TransactionDataReason.SCHEMA_VIOLATION, "bad payload")

        assertTrue(e is SirosException)
        assertEquals(TransactionDataReason.SCHEMA_VIOLATION, e.reason)
        assertEquals("transaction_data_schema_violation", e.errorCode)
        assertEquals("invalid_transaction_data", e.verifierError)
        assertEquals("bad payload", e.message)
    }
}
