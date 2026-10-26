package org.siros.sdk.keystore

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import uniffi.siros_wscd_manager.FfiPinFailure
import uniffi.siros_wscd_manager.FfiWscdException

/**
 * Drives the SDK's PIN handling the way the native side does: a fake authenticator calls the SDK's
 * [FfiAuthCallback] (`requestNewPin` / `requestPin`) and answers with the [FfiWscdException.Pin] failures the real plugin
 * returns, through [PinPrompter.run] exactly as [UniFFISigner] runs its WSCD calls. No hardware is involved.
 */
class PinPromptingTest {
    /** A host whose answers are scripted; every request it sees is recorded, and so is every buffer it handed out. */
    private class Host(vararg answers: String) : AuthProvider {
        private val queue = ArrayDeque(answers.toList())
        val requests = mutableListOf<PinRequest>()
        val handedOut = mutableListOf<ByteArray>()
        override fun requestPin(pluginId: String): ByteArray = error("the request-carrying overload is used")
        override fun requestPin(request: PinRequest): ByteArray {
            requests += request
            val next = queue.removeFirstOrNull() ?: throw IllegalStateException("user cancelled")
            return next.toByteArray().also { handedOut += it }
        }
        override fun requestWebauthnAssertion(pluginId: String, challenge: ByteArray, rpId: String, allowedCredentials: List<ByteArray>): ByteArray =
            throw UnsupportedOperationException()
    }

    /** What the authenticator side does with the PIN it gets: a fresh key (no PIN) sets one, otherwise it checks one. */
    private class FakeAuthenticator(private val minLength: UInt, private var pin: String? = null, private val enforced: UInt = minLength) {
        var setPins = 0
        var calls = 0
        fun ceremony(auth: uniffi.siros_wscd_manager.FfiAuthCallback) {
            calls++
            val current = pin
            if (current == null) {
                val chosen = String(auth.requestNewPin("fido2", minLength))
                if (chosen.codePointCount(0, chosen.length).toUInt() < enforced) {
                    throw FfiWscdException.Pin(FfiPinFailure.TooShort(minLength), "too short")
                }
                pin = chosen
                setPins++
            } else {
                if (String(auth.requestPin("fido2")) != current) throw FfiWscdException.Pin(FfiPinFailure.Invalid, "wrong")
            }
        }
    }

    private fun bridge(host: Host?) = AuthCallbackBridge(host)

    @Test
    fun `a fresh key is asked to choose a PIN twice and gets the confirmed one`() {
        val host = Host("1234", "1234")
        val auth = FakeAuthenticator(minLength = 4u)
        val b = bridge(host)
        b.prompter.run { auth.ceremony(b) }

        assertEquals(1, auth.setPins)
        assertEquals(
            listOf(
                PinRequest.Choose("fido2", 4, confirm = false, notice = null),
                PinRequest.Choose("fido2", 4, confirm = true, notice = null),
            ),
            host.requests,
        )
        // the confirmation buffer is wiped; the one handed to the plugin is the first
        assertTrue(host.handedOut[1].all { it == 0.toByte() })
    }

    @Test
    fun `two PINs that differ are asked for again, with the mismatch notice, and the mistyped ones are wiped`() {
        val host = Host("1234", "1235", "5678", "5678")
        val auth = FakeAuthenticator(minLength = 4u)
        val b = bridge(host)
        b.prompter.run { auth.ceremony(b) }

        assertEquals(1, auth.setPins)
        assertEquals(PinPromptNotice.MISMATCH, (host.requests[2] as PinRequest.Choose).notice)
        assertFalse((host.requests[2] as PinRequest.Choose).confirm)
        assertTrue("first mistyped PIN wiped", host.handedOut[0].all { it == 0.toByte() })
        assertTrue("its confirmation wiped", host.handedOut[1].all { it == 0.toByte() })
        assertEquals("5678", String(host.handedOut[2]))
    }

    @Test
    fun `the minimum length counts characters, not bytes, and a short PIN is never confirmed or sent`() {
        // "éé" is four bytes but two characters; the minimum is four characters
        val host = Host("éé", "éééé", "éééé")
        val auth = FakeAuthenticator(minLength = 4u)
        val b = bridge(host)
        b.prompter.run { auth.ceremony(b) }

        assertEquals(1, auth.calls)
        assertEquals(PinPromptNotice.TOO_SHORT, (host.requests[1] as PinRequest.Choose).notice)
        assertFalse("no confirmation asked for the short one", (host.requests[1] as PinRequest.Choose).confirm)
        assertEquals(3, host.requests.size)
        assertTrue(host.handedOut[0].all { it == 0.toByte() })
    }

    @Test
    fun `a host that keeps mistyping ends the ceremony as a cancelled authentication after a bounded number of rounds`() {
        val host = Host("1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888")
        val b = bridge(host)
        try {
            b.requestNewPin("fido2", 4u)
            fail("expected a cancelled authentication")
        } catch (e: FfiWscdException.AuthCancelled) {
            // expected
        }
        assertEquals(PinPrompter.MAX_CHOOSE_ROUNDS * 2, host.requests.size)
        assertTrue("every typed buffer wiped", host.handedOut.all { h -> h.all { it == 0.toByte() } })
    }

    @Test
    fun `a PIN the authenticator found too short is asked for again with that notice and the operation runs again`() {
        // the authenticator announces a minimum of 4 but its own rule (after normalisation, say) turns out to be 6
        val host = Host("abcd", "abcd", "abcdef", "abcdef")
        val auth = FakeAuthenticator(minLength = 4u, enforced = 6u)
        val b = bridge(host)
        b.prompter.run { auth.ceremony(b) }

        assertEquals(2, auth.calls)
        assertEquals(1, auth.setPins)
        assertEquals(PinPromptNotice.TOO_SHORT, (host.requests[2] as PinRequest.Choose).notice)
    }

    @Test
    fun `a wrong PIN is asked for again as an ENTER prompt with the wrong-PIN notice`() {
        val host = Host("0000", "4321")
        val auth = FakeAuthenticator(minLength = 4u, pin = "4321")
        val b = bridge(host)
        b.prompter.run { auth.ceremony(b) }

        assertEquals(2, auth.calls)
        assertEquals(PinRequest.Enter("fido2", null), host.requests[0])
        assertEquals(PinRequest.Enter("fido2", PinPromptNotice.WRONG_PIN), host.requests[1])
    }

    private fun failureEnds(reason: FfiPinFailure): WscdPinFailure {
        val b = bridge(Host())
        var calls = 0
        try {
            b.prompter.run { calls++; throw FfiWscdException.Pin(reason, "refused") }
            fail("expected the ceremony to end")
        } catch (e: WscdPinException) {
            assertEquals("never retried", 1, calls)
            return e.failure
        }
        throw AssertionError()
    }

    @Test
    fun `a blocked PIN, an auth-blocked key and an unexpected not-set end the ceremony with a typed failure and no retry`() {
        assertEquals(WscdPinFailure.KEY_BLOCKED, failureEnds(FfiPinFailure.Blocked))
        assertEquals(WscdPinFailure.REPLUG_REQUIRED, failureEnds(FfiPinFailure.AuthBlocked))
        assertEquals(WscdPinFailure.INTERNAL, failureEnds(FfiPinFailure.NotSet))
    }

    @Test
    fun `every PIN the user can fix is retried a bounded number of times and then ends the ceremony`() {
        for (reason in listOf(FfiPinFailure.TooShort(4u), FfiPinFailure.TooLong, FfiPinFailure.InvalidEncoding, FfiPinFailure.PolicyViolation, FfiPinFailure.Invalid)) {
            val b = bridge(Host())
            var calls = 0
            try {
                b.prompter.run {
                    calls++
                    if (calls > 10) throw AssertionError("the retry is not bounded")
                    throw FfiWscdException.Pin(reason, "refused")
                }
                fail("expected the ceremony to end for $reason")
            } catch (e: WscdPinException) {
                assertEquals(WscdPinFailure.TOO_MANY_ATTEMPTS, e.failure)
            }
            assertEquals("tries for $reason", PinPrompter.MAX_PIN_ATTEMPTS, calls)
        }
    }

    @Test
    fun `an exception of any other type from the host never crosses the native boundary as itself`() {
        // no host: cancelled
        try {
            bridge(null).requestNewPin("fido2", 4u)
            fail()
        } catch (e: FfiWscdException.AuthCancelled) {
            // expected
        }
        // a host that crashes
        try {
            bridge(Host()).requestPin("fido2")
            fail()
        } catch (e: FfiWscdException.AuthCancelled) {
            assertFalse("no stack trace in the message", e.message.orEmpty().contains("IllegalStateException"))
        }
    }

    @Test
    fun `an AuthProvider that only knows the old method still answers ENTER and refuses CHOOSE`() {
        val old = object : AuthProvider {
            override fun requestPin(pluginId: String): ByteArray = "1234".toByteArray()
            override fun requestWebauthnAssertion(pluginId: String, challenge: ByteArray, rpId: String, allowedCredentials: List<ByteArray>): ByteArray =
                throw UnsupportedOperationException()
        }
        assertArrayEquals("1234".toByteArray(), old.requestPin(PinRequest.Enter("fido2")))
        try {
            old.requestPin(PinRequest.Choose("fido2", 4, confirm = false))
            fail()
        } catch (e: UnsupportedOperationException) {
            // expected
        }
        // and through the bridge the refusal is a cancelled authentication
        try {
            AuthCallbackBridge(old).requestNewPin("fido2", 4u)
            fail()
        } catch (e: FfiWscdException.AuthCancelled) {
            // expected
        }
    }

    @Test
    fun `code points are counted on valid UTF-8 only`() {
        assertEquals(4, PinPrompter.codePoints("ab😀c".toByteArray()))
        assertNull(PinPrompter.codePoints(byteArrayOf(0xC3.toByte())))
    }

    // ── a PIN typed ahead of the ceremony ──

    /** What the sample does: the SDK's [TypedAheadPin] answers the first request, the user answers the rest. */
    private class TypedAheadHost(val typedAhead: TypedAheadPin, vararg answers: String) : AuthProvider {
        private val queue = ArrayDeque(answers.toList())
        val requests = mutableListOf<PinRequest>()
        override fun requestPin(pluginId: String): ByteArray = error("the request-carrying overload is used")
        override fun requestPin(request: PinRequest): ByteArray {
            requests += request
            typedAhead.take(request)?.let { return it }
            return (queue.removeFirstOrNull() ?: throw IllegalStateException("user cancelled")).toByteArray()
        }
        override fun requestWebauthnAssertion(pluginId: String, challenge: ByteArray, rpId: String, allowedCredentials: List<ByteArray>): ByteArray =
            throw UnsupportedOperationException()
    }

    @Test
    fun `a typed-ahead PIN the key rejected is never sent again, by the retry or by a following signer call`() {
        val typedAhead = TypedAheadPin()
        typedAhead.hold("0000".toByteArray())
        val host = TypedAheadHost(typedAhead, "4321", "4321")
        val sent = mutableListOf<String>()
        fun ceremony(auth: uniffi.siros_wscd_manager.FfiAuthCallback) {
            val pin = String(auth.requestPin("fido2"))
            sent += pin
            if (pin != "4321") throw FfiWscdException.Pin(FfiPinFailure.Invalid, "wrong")
        }
        // first call: the typed-ahead PIN is rejected, the user corrects it
        var b = AuthCallbackBridge(host)
        b.prompter.run { ceremony(b) }
        // a following signer call of the same flow (its own bridge, no notice)
        b = AuthCallbackBridge(host)
        b.prompter.run { ceremony(b) }

        assertEquals(listOf("0000", "4321", "4321"), sent)
        assertEquals(PinPromptNotice.WRONG_PIN, (host.requests[1] as PinRequest.Enter).notice)
    }

    @Test
    fun `a typed-ahead PIN is wiped when the first request cannot use it`() {
        for (request in listOf<PinRequest>(PinRequest.Choose("fido2", 4, confirm = false), PinRequest.Enter("fido2", PinPromptNotice.WRONG_PIN))) {
            val typedAhead = TypedAheadPin()
            val pin = "0000".toByteArray()
            typedAhead.hold(pin)
            assertNull(typedAhead.take(request))
            assertTrue("wiped", pin.all { it == 0.toByte() })
            assertNull("and gone", typedAhead.take(PinRequest.Enter("fido2")))
        }
    }

    @Test
    fun `a PIN refused for its encoding on ENTER asks again with an ENTER notice and never reuses the typed-ahead one`() {
        val typedAhead = TypedAheadPin()
        typedAhead.hold("12\u00003".toByteArray()) // a NUL: the plugin answers InvalidEncoding
        val host = TypedAheadHost(typedAhead, "1234")
        val sent = mutableListOf<String>()
        val b = AuthCallbackBridge(host)
        b.prompter.run {
            val pin = String(b.requestPin("fido2"))
            sent += pin
            if (pin.contains('\u0000')) throw FfiWscdException.Pin(FfiPinFailure.InvalidEncoding, "NUL")
        }
        assertEquals(PinPromptNotice.NOT_ACCEPTED, (host.requests[1] as PinRequest.Enter).notice)
        assertEquals(listOf("12\u00003", "1234"), sent)
    }
}
