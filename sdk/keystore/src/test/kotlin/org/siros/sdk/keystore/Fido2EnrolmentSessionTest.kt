package org.siros.sdk.keystore

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import uniffi.siros_wscd_manager.FfiAuthenticatorInfo
import uniffi.siros_wscd_manager.FfiClientPinState
import uniffi.siros_wscd_manager.FfiEnrolmentSuitability

/** The "discover, then ask" enrolment, with a scripted authenticator description and a scripted user: no hardware. */
class Fido2EnrolmentSessionTest {
    private val aaguidA = ByteArray(16) { 1 }
    private val aaguidB = ByteArray(16) { 2 }

    private fun info(
        pin: Fido2PinState,
        min: Int = 4,
        aaguid: ByteArray = aaguidA,
        suitability: Fido2Suitability = Fido2Suitability.Suitable,
        retries: Int? = if (pin == Fido2PinState.SET) 8 else null,
    ) = Fido2AuthenticatorInfo(listOf("FIDO_2_1"), aaguid, pin, min, false, retries, listOf(1, 2), emptyList(), emptyMap(), suitability)

    /** A key that is described [descriptions] one after the other (the last one repeats) and a user who types [answers] in order. */
    private class Script(private val descriptions: List<Fido2AuthenticatorInfo>, answers: List<String?>) {
        private val answerQueue = ArrayDeque(answers)
        var describes = 0
        val requests = mutableListOf<PinRequest>()
        val handedOut = mutableListOf<ByteArray>()
        var secondTaps = 0
        suspend fun describe(): Fido2AuthenticatorInfo = descriptions[minOf(describes++, descriptions.size - 1)]
        suspend fun ask(request: PinRequest): ByteArray? {
            requests += request
            val next = answerQueue.removeFirstOrNull() ?: return null
            return next.toByteArray().also { handedOut += it }
        }
    }

    private fun session(s: Script) = Fido2EnrolmentSession(s::describe, s::ask)

    @Test
    fun anUnsuitableKeyIsRefusedBeforeAnyPinIsAsked() = runTest {
        val s = Script(listOf(info(Fido2PinState.NOT_SET, suitability = Fido2Suitability.Unsuitable("no previewSign"))), listOf("123456"))
        var ran = false
        try {
            session(s).enrol { ran = true }
            fail("enrolled an unsuitable key")
        } catch (e: Fido2EnrolmentException) {
            assertEquals(Fido2EnrolmentFailure.UNSUITABLE, e.failure)
            assertEquals("no previewSign", e.reason)
        }
        assertTrue("no dialog before the refusal", s.requests.isEmpty())
        assertFalse(ran)
        assertEquals(1, s.describes)
    }

    @Test
    fun aBlockedPinIsUnsuitableEvenIfTheLibraryCalledItSuitable() = runTest {
        val s = Script(listOf(info(Fido2PinState.SET, retries = 0)), listOf("123456"))
        try {
            session(s).enrol { }
            fail()
        } catch (e: Fido2EnrolmentException) {
            assertEquals(Fido2EnrolmentFailure.UNSUITABLE, e.failure)
        }
        assertTrue(s.requests.isEmpty())
    }

    @Test
    fun aKeyWithAPinIsAskedToEnter_describedTwice_andTheCeremonyIsAnsweredOnce() = runTest {
        val s = Script(listOf(info(Fido2PinState.SET)), listOf("246810"))
        val session = session(s)
        var taps = 0
        val result = session.enrol(onSecondTap = { taps++ }) {
            val a = session.answer(PinRequest.Enter("fido2"))
            assertArrayEquals("246810".toByteArray(), a)
            assertNull("the PIN is sent once", session.answer(PinRequest.Enter("fido2")))
            "done"
        }
        assertEquals("done", result.value)
        assertEquals(listOf<PinRequest>(PinRequest.Enter("fido2")), s.requests)
        assertEquals(2, s.describes)
        assertEquals(1, taps)
        assertArrayEquals(aaguidA, result.info.aaguid)
    }

    @Test
    fun aKeyWithoutAPinIsAskedToChooseAndConfirm_theMinimumLengthComesFromTheKey() = runTest {
        val s = Script(listOf(info(Fido2PinState.NOT_SET, min = 6)), listOf("1234", "654321", "654321"))
        val session = session(s)
        session.enrol {
            // Both prompts of PinPrompter.choose are answered from the confirmed PIN.
            assertArrayEquals("654321".toByteArray(), session.answer(PinRequest.Choose("fido2", 6, confirm = false)))
            assertArrayEquals("654321".toByteArray(), session.answer(PinRequest.Choose("fido2", 6, confirm = true)))
            assertNull(session.answer(PinRequest.Choose("fido2", 6, confirm = false)))
        }
        // Too short -> asked again with the notice; then choose + confirm.
        assertEquals(PinPromptNotice.TOO_SHORT, (s.requests[1] as PinRequest.Choose).notice)
        assertEquals(listOf(false, false, true), s.requests.map { (it as PinRequest.Choose).confirm })
        assertTrue(s.requests.all { (it as PinRequest.Choose).minLength == 6 })
    }

    @Test
    fun aMismatchedConfirmationAsksAgain_andEveryRefusedBufferIsWiped() = runTest {
        val s = Script(listOf(info(Fido2PinState.NOT_SET)), listOf("111111", "222222", "333333", "333333"))
        val session = session(s)
        session.enrol { }
        assertEquals(PinPromptNotice.MISMATCH, (s.requests[2] as PinRequest.Choose).notice)
        // The first and the mismatching second buffers are wiped.
        assertTrue(s.handedOut[0].all { it == 0.toByte() })
        assertTrue(s.handedOut[1].all { it == 0.toByte() })
    }

    @Test
    fun aKeyThatChangedBetweenTheTapsRestartsTheDialog_andTheOldPinIsNeverUsed() = runTest {
        // Tap 1: no PIN. Tap 2: a PIN is set (a different key). The dialog is asked again to ENTER.
        val s = Script(
            listOf(info(Fido2PinState.NOT_SET), info(Fido2PinState.SET, aaguid = aaguidB), info(Fido2PinState.SET, aaguid = aaguidB)),
            listOf("111111", "111111", "909090"),
        )
        val session = session(s)
        val result = session.enrol {
            assertArrayEquals("909090".toByteArray(), session.answer(PinRequest.Enter("fido2")))
        }
        assertEquals(listOf(false, true), s.requests.take(2).map { (it as PinRequest.Choose).confirm })
        assertTrue("then the dialog that fits the key it now is", s.requests[2] is PinRequest.Enter)
        assertTrue("the PIN typed for the other key is wiped", s.handedOut[0].all { it == 0.toByte() })
        assertEquals(3, s.describes)
        assertArrayEquals(aaguidB, result.info.aaguid)
    }

    @Test
    fun aChangedMinimumLengthOrAaguidIsAChange_aChangedRetryCounterIsNot() = runTest {
        val base = info(Fido2PinState.SET)
        assertFalse(base.sameEnrolmentSituationAs(info(Fido2PinState.SET, min = 8)))
        assertFalse(base.sameEnrolmentSituationAs(info(Fido2PinState.SET, aaguid = aaguidB)))
        assertFalse(base.sameEnrolmentSituationAs(info(Fido2PinState.NOT_SET)))
        assertTrue(base.sameEnrolmentSituationAs(info(Fido2PinState.SET, retries = 5)))
    }

    @Test
    fun aKeyThatKeepsChangingGivesUp_andNoCeremonyRuns() = runTest {
        val flip = (0 until 12).map { info(Fido2PinState.SET, min = 4 + it) }
        val s = Script(flip, List(12) { "123456" })
        var ran = false
        try {
            session(s).enrol { ran = true }
            fail()
        } catch (e: Fido2EnrolmentException) {
            assertEquals(Fido2EnrolmentFailure.KEY_CHANGED, e.failure)
        }
        assertFalse(ran)
        assertTrue(s.handedOut.all { b -> b.all { it == 0.toByte() } })
    }

    @Test
    fun theSecondDescriptionBeingUnsuitableRefusesAndWipesThePin() = runTest {
        val s = Script(listOf(info(Fido2PinState.SET), info(Fido2PinState.SET, suitability = Fido2Suitability.Unsuitable("x"))), listOf("123456"))
        var ran = false
        try {
            session(s).enrol { ran = true }
            fail()
        } catch (e: Fido2EnrolmentException) {
            assertEquals(Fido2EnrolmentFailure.UNSUITABLE, e.failure)
        }
        assertFalse(ran)
        assertTrue(s.handedOut.single().all { it == 0.toByte() })
    }

    @Test
    fun aPromptOfAnotherKindThanTheDialogWasBuiltForFailsClosedAsKeyChanged() = runTest {
        val s = Script(listOf(info(Fido2PinState.SET)), listOf("246810"))
        val session = session(s)
        try {
            session.enrol {
                // The ceremony asks to CHOOSE although the dialog entered: the key is not the one described.
                try {
                    session.answer(PinRequest.Choose("fido2", 4, confirm = false))
                    fail("answered a prompt of the wrong kind")
                } catch (e: Fido2EnrolmentException) {
                    throw e
                }
            }
            fail()
        } catch (e: Fido2EnrolmentException) {
            assertEquals(Fido2EnrolmentFailure.KEY_CHANGED, e.failure)
        }
        assertTrue("the PIN is wiped", s.handedOut.single().all { it == 0.toByte() })
        assertNull(session.answer(PinRequest.Enter("fido2")))
    }

    @Test
    fun aChooseOfAnotherMinimumLengthIsAChangedKeyToo() = runTest {
        val s = Script(listOf(info(Fido2PinState.NOT_SET, min = 6)), listOf("654321", "654321"))
        val session = session(s)
        try {
            session.enrol { session.answer(PinRequest.Choose("fido2", 4, confirm = false)) }
            fail()
        } catch (e: Fido2EnrolmentException) {
            assertEquals(Fido2EnrolmentFailure.KEY_CHANGED, e.failure)
        }
    }

    @Test
    fun aRetryPromptIsNeverAnsweredWithThePinThatWasRefused() = runTest {
        val s = Script(listOf(info(Fido2PinState.SET)), listOf("246810"))
        val session = session(s)
        session.enrol {
            assertNull(session.answer(PinRequest.Enter("fido2", PinPromptNotice.WRONG_PIN)))
            assertNull("and it is gone", session.answer(PinRequest.Enter("fido2")))
        }
        assertTrue(s.handedOut.single().all { it == 0.toByte() })
    }

    @Test
    fun thePinIsWipedAfterTheCeremony_whateverItsOutcome() = runTest {
        val s = Script(listOf(info(Fido2PinState.SET)), listOf("246810"))
        val session = session(s)
        try {
            session.enrol { throw IllegalStateException("boom") }
            fail()
        } catch (e: IllegalStateException) {
            assertEquals("boom", e.message)
        }
        assertTrue(s.handedOut.single().all { it == 0.toByte() })
        assertNull(session.answer(PinRequest.Enter("fido2")))
    }

    @Test
    fun aPromptOfAnotherPluginIsNeitherAnsweredNorConsumed() = runTest {
        val enter = Script(listOf(info(Fido2PinState.SET)), listOf("246810"))
        val se = session(enter)
        se.enrol {
            assertNull(se.answer(PinRequest.Enter("r2ps")))
            assertArrayEquals("the held PIN is still there for the FIDO2 prompt", "246810".toByteArray(), se.answer(PinRequest.Enter("fido2")))
        }
        val choose = Script(listOf(info(Fido2PinState.NOT_SET)), listOf("654321", "654321"))
        val sc = session(choose)
        sc.enrol {
            assertNull(sc.answer(PinRequest.Choose("r2ps", 4, confirm = false)))
            assertNull(sc.answer(PinRequest.Choose("r2ps", 4, confirm = true)))
            assertArrayEquals("654321".toByteArray(), sc.answer(PinRequest.Choose("fido2", 4, confirm = false)))
            assertArrayEquals("654321".toByteArray(), sc.answer(PinRequest.Choose("fido2", 4, confirm = true)))
        }
    }

    @Test
    fun theCollectedPinIsWipedEvenAfterTheCeremonyConsumedItThroughAnswer() = runTest {
        for (fail in listOf(false, true)) {
            val s = Script(listOf(info(Fido2PinState.SET)), listOf("246810"))
            val session = session(s)
            var handed: ByteArray? = null
            try {
                session.enrol {
                    handed = session.answer(PinRequest.Enter("fido2"))
                    assertArrayEquals("246810".toByteArray(), handed)
                    if (fail) throw IllegalStateException("boom")
                }
            } catch (e: IllegalStateException) {
                assertTrue(fail)
            }
            assertTrue("fail=$fail: the buffer answer() handed out is wiped after the ceremony", handed!!.all { it == 0.toByte() })
            assertTrue(s.handedOut.single().all { it == 0.toByte() })
        }
        // The same for a CHOOSE whose confirmation consumed the held PIN.
        val c = Script(listOf(info(Fido2PinState.NOT_SET)), listOf("654321", "654321"))
        val sc = session(c)
        var confirmed: ByteArray? = null
        sc.enrol {
            sc.answer(PinRequest.Choose("fido2", 4, confirm = false))?.fill(0)
            confirmed = sc.answer(PinRequest.Choose("fido2", 4, confirm = true))
        }
        assertTrue(confirmed!!.all { it == 0.toByte() })
    }

    @Test
    fun cancellingTheDialogEndsTheEnrolmentWithoutASecondTap() = runTest {
        val s = Script(listOf(info(Fido2PinState.SET)), emptyList())
        try {
            session(s).enrol(onSecondTap = { fail("asked for a second tap after a cancel") }) { }
            fail()
        } catch (e: Fido2EnrolmentException) {
            assertEquals(Fido2EnrolmentFailure.CANCELLED, e.failure)
        }
        assertEquals(1, s.describes)
    }

    @Test
    fun aKeyWithoutPinSupportAsksNothing() = runTest {
        val s = Script(listOf(info(Fido2PinState.UNSUPPORTED)), emptyList())
        val session = session(s)
        val r = session.enrol { assertNull(session.answer(PinRequest.Enter("fido2"))); 7 }
        assertEquals(7, r.value)
        assertTrue(s.requests.isEmpty())
    }

    @Test
    fun theLibrarysDescriptionIsMappedFieldByField() {
        val ffi = FfiAuthenticatorInfo(
            listOf("FIDO_2_0", "FIDO_2_1"), ByteArray(16) { it.toByte() }, FfiClientPinState.NOT_SET, 6u, true, null,
            listOf(1u, 2u), listOf("hmac-secret"), mapOf("clientPin" to false), FfiEnrolmentSuitability.Unsuitable("why"),
        )
        val i = ffi.toSdk()
        assertEquals(Fido2PinState.NOT_SET, i.clientPin)
        assertEquals(6, i.minPinLength)
        assertTrue(i.forcePinChange)
        assertNull(i.pinRetries)
        assertEquals(listOf(1, 2), i.pinUvAuthProtocols)
        assertEquals("00010203-0405-0607-0809-0a0b0c0d0e0f", i.aaguidString)
        assertEquals(Fido2Suitability.Unsuitable("why"), i.suitability)
        // The AAGUID is a copy.
        i.aaguid.fill(9)
        assertEquals("00010203-0405-0607-0809-0a0b0c0d0e0f", i.aaguidString)
        assertNotNull(i.toString())
    }
}
