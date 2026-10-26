package org.siros.sdk.keystore

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import uniffi.siros_wscd_manager.FfiAuthCallback
import uniffi.siros_wscd_manager.FfiAuthFactor
import uniffi.siros_wscd_manager.FfiAuthFactors
import uniffi.siros_wscd_manager.FfiFactorCapability
import uniffi.siros_wscd_manager.FfiFactorCategory
import uniffi.siros_wscd_manager.FfiPinFailure
import uniffi.siros_wscd_manager.FfiSignOptions
import uniffi.siros_wscd_manager.FfiSignOutcome
import uniffi.siros_wscd_manager.FfiSignature
import uniffi.siros_wscd_manager.FfiWscdException

/**
 * The SCA sign (`signWithFactors`) under the SDK's PIN failure handling: the same bounded re-prompts and typed failures as every
 * other WSCD call, with this session's own prompt state, and the PIN buffers still wiped. A fake authenticator that checks the
 * PIN it is given stands behind the real callback class.
 */
class FactorSigningPinFailureTest {
    private class Host(vararg answers: String) : AuthProvider {
        private val queue = ArrayDeque(answers.toList())
        val requests = mutableListOf<PinRequest>()
        override fun requestPin(pluginId: String): ByteArray = error("the request-carrying overload is used")
        override fun requestPin(request: PinRequest): ByteArray {
            requests += request
            return (queue.removeFirstOrNull() ?: throw IllegalStateException("user cancelled")).toByteArray()
        }
        override fun requestWebauthnAssertion(pluginId: String, challenge: ByteArray, rpId: String, allowedCredentials: List<ByteArray>): ByteArray =
            throw UnsupportedOperationException()
    }

    /** Checks the PIN the plugin asks for against [correct]; [refusal] is what a wrong one is answered with. */
    private class Authenticator(
        private val correct: String,
        private val refusal: FfiPinFailure = FfiPinFailure.Invalid,
    ) : FactorSigningBackend {
        val seen = mutableListOf<String>()
        val buffers = mutableListOf<ByteArray>()
        override fun capability(kid: String) = FfiFactorCapability(true, false, null)
        override fun pluginIdOf(kid: String) = "r2ps"
        override fun signWithFactors(kid: String, data: ByteArray, options: FfiSignOptions, auth: FfiAuthCallback): FfiSignOutcome {
            val pin = auth.requestPin("r2ps")
            buffers += pin
            seen += String(pin)
            if (String(pin) != correct) throw FfiWscdException.Pin(refusal, "refused")
            return FfiSignOutcome(
                FfiSignature(byteArrayOf(7)),
                FfiAuthFactors(
                    listOf(
                        FfiAuthFactor(FfiFactorCategory.POSSESSION, "key_in_remote_wscd"),
                        FfiAuthFactor(FfiFactorCategory.KNOWLEDGE, "pin_6_or_more_digits"),
                    ),
                    true,
                    null,
                ),
            )
        }
    }

    private fun signing(backend: FactorSigningBackend, host: Host) = FactorSigning(backend, { AuthCallbackBridge(host) })

    @Test
    fun `a wrong PIN is asked for again with the wrong-PIN notice and the sign then succeeds`() = runTest {
        val backend = Authenticator(correct = "123456")
        val host = Host("000000", "123456") // the PIN typed ahead, then the corrected one
        val signature = signing(backend, host).begin("k").use { it.sign(ByteArray(1)) }

        assertEquals(listOf("000000", "123456"), backend.seen)
        assertEquals(listOf(PinRequest.Enter("r2ps", null), PinRequest.Enter("r2ps", PinPromptNotice.WRONG_PIN)), host.requests)
        assertEquals(2, signature.factors.size)
        assertTrue("every buffer given to the plugin is wiped", backend.buffers.all { b -> b.all { it == 0.toByte() } })
    }

    @Test
    fun `a blocked or auth-blocked key is a typed failure with no second submission`() = runTest {
        for ((reason, expected) in listOf(
            FfiPinFailure.Blocked to WscdPinFailure.KEY_BLOCKED,
            FfiPinFailure.AuthBlocked to WscdPinFailure.REPLUG_REQUIRED,
        )) {
            val backend = Authenticator(correct = "123456", refusal = reason)
            val host = Host("000000", "111111")
            val e = try {
                signing(backend, host).begin("k").use { it.sign(ByteArray(1)) }
                fail("expected a typed PIN failure")
                return@runTest
            } catch (e: WscdPinException) {
                e
            }
            assertEquals(expected, e.failure)
            assertEquals("one submission only for $reason", listOf("000000"), backend.seen)
            assertTrue(backend.buffers.all { b -> b.all { it == 0.toByte() } })
        }
    }

    @Test
    fun `a PIN that keeps being refused ends after the stated number of submissions`() = runTest {
        val backend = Authenticator(correct = "999999")
        val host = Host("000000", "111111", "222222", "333333", "444444")
        try {
            signing(backend, host).begin("k").use { it.sign(ByteArray(1)) }
            fail("expected the sign to end")
        } catch (e: WscdPinException) {
            assertEquals(WscdPinFailure.TOO_MANY_ATTEMPTS, e.failure)
        }
        assertEquals(PinPrompter.MAX_PIN_ATTEMPTS, backend.seen.size)
        assertTrue(backend.buffers.all { b -> b.all { it == 0.toByte() } })
    }

    @Test
    fun `two sessions never share prompt state`() = runTest {
        val backend = Authenticator(correct = "123456")
        val factorSigning = FactorSigning(backend, { AuthCallbackBridge(Host("000000", "123456")) })
        factorSigning.begin("k").use { it.sign(ByteArray(1)) } // a wrong PIN, then the right one: notice WRONG_PIN inside
        val second = Host("123456")
        FactorSigning(backend, { AuthCallbackBridge(second) }).begin("k").use { it.sign(ByteArray(1)) }
        assertEquals(listOf(PinRequest.Enter("r2ps", null)), second.requests)
    }
}
