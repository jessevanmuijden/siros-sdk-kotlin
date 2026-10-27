// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import androidx.annotation.StringRes
import timber.log.Timber

/** Why a FIDO2 enrolment ended before the key was enrolled. A short localised text for the user is [messageRes]. */
enum class Fido2EnrolmentFailure(@StringRes val messageRes: Int) {
    /** The authenticator cannot be enrolled as it is (see [Fido2EnrolmentException.reason]); asked before any PIN was collected. */
    UNSUITABLE(R.string.siros_enrol_unsuitable),

    /** The authenticator presented differs from the one the user was asked about, or changed while the ceremony started. */
    KEY_CHANGED(R.string.siros_enrol_key_changed),

    /** The user declined to type (or choose) a PIN. */
    CANCELLED(R.string.siros_enrol_cancelled),
}

/** An enrolment that ended without a key. Carries only the [failure], the key's [info] and the library's [reason] text - never PIN material. */
class Fido2EnrolmentException(
    val failure: Fido2EnrolmentFailure,
    val info: Fido2AuthenticatorInfo? = null,
    /** For [Fido2EnrolmentFailure.UNSUITABLE]: why, in the library's English text (logs and support; not localised). */
    val reason: String? = null,
) : Exception("FIDO2 enrolment ended: $failure")

/** The outcome of an enrolment: what the ceremony returned and the authenticator it ran against (its [Fido2AuthenticatorInfo.aaguid] names the model). */
class Fido2Enrolment<T>(val value: T, val info: Fido2AuthenticatorInfo)

/**
 * "Discover, then ask": the enrolment of a FIDO2 security key with a dialog that fits the key actually presented.
 *
 * 1. FIRST TAP: describe the authenticator ([describe]; no PIN is asked for or sent). An authenticator that cannot be
 *    enrolled is refused here, before any PIN is collected.
 * 2. ASK: the dialog fits the key - ENTER the PIN of a key that has one, CHOOSE (and confirm) one for a key that has
 *    none, nothing for a key without PIN support. The user types with the key set aside.
 * 3. SECOND TAP (or the same connection, over USB): describe AGAIN and compare the PIN state, minimum PIN length and AAGUID
 *    with what the dialog was built for. Any difference discards the typed PIN and restarts at step 2 with what the key now
 *    says: a PIN is never sent on the strength of the first description.
 * 4. CEREMONY: [ceremony] (register + activate the lifecycle) runs; the PIN prompts it raises are answered from the collected
 *    PIN by [answer], which the host's AuthProvider consults FIRST. A prompt of another kind than the dialog was built for
 *    (the key changed after the second description) is refused and the enrolment fails with
 *    [Fido2EnrolmentFailure.KEY_CHANGED]; the typed PIN is gone after the ceremony, whatever its outcome.
 *
 * Every PIN buffer this class holds or receives and does not hand on is wiped. The suitability the library reports is
 * advisory until it has been checked on hardware. One instance serves one enrolment; [answer] may be called from another thread.
 */
class Fido2EnrolmentSession(
    private val describe: suspend () -> Fido2AuthenticatorInfo,
    private val ask: suspend (PinRequest) -> ByteArray?,
    private val pluginId: String = "fido2",
) {
    constructor(manager: WscdManager, ask: suspend (PinRequest) -> ByteArray?) : this(manager::describeFido2Authenticator, ask)

    /**
     * The prompt contract of the ceremony ([chooseMinLength] null: ENTER, else CHOOSE of that minimum length), which lives for the
     * WHOLE ceremony, and the one-shot [pin], which is null once it has been handed out or refused.
     */
    private class Held(var pin: ByteArray?, val chooseMinLength: Int?)

    private val lock = Any()
    private var held: Held? = null

    /** Every buffer [answer] handed to the host (the PIN itself or a copy of it): all are wiped when the ceremony ends. */
    private val issued = mutableListOf<ByteArray>()
    private var keyChanged = false

    /**
     * The PIN collected for the CURRENT loop iteration, between [collect] returning it and it either being installed into [held]
     * (the re-description after it matched) or discarded (a restart, an unsuitable re-description, [clear] in between). [clear]
     * reaches it here even while the second [describe] call is still in flight - nothing else does, since it is not yet [held].
     */
    private var pending: ByteArray? = null

    /**
     * Set by [clear]: a PIN already wiped by it must never be installed into [held] afterward, even if the describe call that was
     * racing it goes on to succeed. Sticky for the life of this session - one session serves one [enrol] call.
     */
    private var invalidated = false

    /**
     * Runs the enrolment: [onSecondTap] is called when the user has to present the key again (after the PIN was typed; over USB
     * the key is still in place and a host shows nothing), then [ceremony] runs with the collected PIN ready for [answer].
     */
    suspend fun <T> enrol(onSecondTap: () -> Unit = {}, ceremony: suspend () -> T): Fido2Enrolment<T> {
        synchronized(lock) { keyChanged = false }
        var info = describe()
        var restarts = 0
        while (true) {
            refuseIfUnsuitable(info)
            val collected = collect(info)
            synchronized(lock) {
                if (invalidated) {
                    collected?.fill(0)
                    throw Fido2EnrolmentException(Fido2EnrolmentFailure.CANCELLED, info)
                }
                pending = collected
            }
            val fresh: Fido2AuthenticatorInfo
            try {
                onSecondTap()
                fresh = describe()
            } catch (e: Throwable) {
                collected?.fill(0)
                throw e
            }
            if (!info.sameEnrolmentSituationAs(fresh)) {
                collected?.fill(0)
                Timber.i("The security key presented differs from the one the PIN dialog was built for; asking again")
                if (++restarts > MAX_RESTARTS) throw Fido2EnrolmentException(Fido2EnrolmentFailure.KEY_CHANGED, fresh)
                info = fresh
                continue
            }
            try {
                refuseIfUnsuitable(fresh)
            } catch (e: Fido2EnrolmentException) {
                collected?.fill(0)
                throw e
            }
            synchronized(lock) {
                if (invalidated) {
                    // clear() ran (and wiped collected, the same array as pending) while the second describe() above was in flight;
                    // it must never be installed just because that describe() went on to succeed anyway.
                    pending = null
                    throw Fido2EnrolmentException(Fido2EnrolmentFailure.CANCELLED, fresh)
                }
                held?.pin?.fill(0)
                held = collected?.let { Held(it, if (info.clientPin == Fido2PinState.NOT_SET) info.minPinLength else null) }
                pending = null
                issued.clear()
            }
            try {
                return Fido2Enrolment(ceremony(), fresh)
            } catch (e: Throwable) {
                if (synchronized(lock) { keyChanged }) throw Fido2EnrolmentException(Fido2EnrolmentFailure.KEY_CHANGED, fresh).also { it.addSuppressed(e) }
                throw e
            } finally {
                clear()
                // answer() hands the collected buffer itself to the ceremony and clears `held`, so clear() above no longer reaches it:
                // wipe it here, after a successful AND a failed ceremony.
                collected?.fill(0)
            }
        }
    }

    /**
     * The collected PIN for a prompt of the ceremony, or null when the host has to ask (a retry notice, no PIN collected). An ENTER
     * answers a first ENTER prompt; a CHOOSE answers both prompts (choose, confirm) of a CHOOSE built for the same minimum length.
     * A prompt for another plugin gets null and leaves the PIN alone. A prompt of the other kind wipes the PIN and throws [Fido2EnrolmentException] ([Fido2EnrolmentFailure.KEY_CHANGED]).
     */
    fun answer(request: PinRequest): ByteArray? = synchronized(lock) {
        // A prompt of ANOTHER plugin (a shared AuthProvider asks for r2ps, say) is not ours to answer: null, and the held PIN is
        // neither returned nor consumed.
        if (request.pluginId != pluginId) return null
        val h = held ?: return null
        val matches = when (request) {
            is PinRequest.Enter -> h.chooseMinLength == null
            is PinRequest.Choose -> h.chooseMinLength != null && request.minLength == h.chooseMinLength
        }
        if (!matches) {
            h.pin?.fill(0)
            h.pin = null
            keyChanged = true
            throw Fido2EnrolmentException(Fido2EnrolmentFailure.KEY_CHANGED)
        }
        if (request.notice != null) {
            // A retry: the PIN just sent was refused, so it is never sent again.
            h.pin?.fill(0)
            h.pin = null
            return null
        }
        // The PIN was handed out already (or refused): the host asks, but the prompt was checked against the contract above.
        val pin = h.pin ?: return null
        when (request) {
            is PinRequest.Enter -> {
                h.pin = null
                pin.also { issued += it }
            }
            is PinRequest.Choose -> if (!request.confirm) {
                pin.copyOf().also { issued += it }
            } else {
                h.pin = null
                pin.also { issued += it }
            }
        }
    }

    /**
     * Wipes what is still held AND the PIN of a loop iteration in flight (collected but not yet installed into [held] - the second
     * describe() call this is racing may still be waiting), and invalidates this session for good: a PIN wiped here is never
     * installed afterward, even if that describe() goes on to succeed. Called when the ceremony ends; call it too when the host
     * abandons the enrolment.
     */
    fun clear() = synchronized(lock) {
        held?.pin?.fill(0)
        pending?.fill(0)
        pending = null
        issued.forEach { it.fill(0) }
        issued.clear()
        held = null
        invalidated = true
    }

    private fun refuseIfUnsuitable(info: Fido2AuthenticatorInfo) {
        val s = info.suitability
        if (s is Fido2Suitability.Unsuitable) throw Fido2EnrolmentException(Fido2EnrolmentFailure.UNSUITABLE, info, s.reason)
        // Fail closed, whatever the library says: a PIN with no attempts left cannot be entered.
        if (info.clientPin == Fido2PinState.SET && info.pinRetries == 0) {
            throw Fido2EnrolmentException(Fido2EnrolmentFailure.UNSUITABLE, info, "the PIN is blocked")
        }
    }

    /** The PIN the dialog collects for [info]; null for a key without PIN support. The user cancelling ends the enrolment. */
    private suspend fun collect(info: Fido2AuthenticatorInfo): ByteArray? = when (info.clientPin) {
        Fido2PinState.UNSUPPORTED -> null
        Fido2PinState.SET -> ask(PinRequest.Enter(pluginId)) ?: throw Fido2EnrolmentException(Fido2EnrolmentFailure.CANCELLED, info)
        Fido2PinState.NOT_SET -> choose(info)
    }

    private suspend fun choose(info: Fido2AuthenticatorInfo): ByteArray {
        val min = info.minPinLength
        var notice: PinPromptNotice? = null
        repeat(PinPrompter.MAX_CHOOSE_ROUNDS) {
            val first = ask(PinRequest.Choose(pluginId, min, confirm = false, notice = notice))
                ?: throw Fido2EnrolmentException(Fido2EnrolmentFailure.CANCELLED, info)
            val length = PinPrompter.codePoints(first)
            if (length == null) {
                first.fill(0)
                notice = PinPromptNotice.NOT_ACCEPTED
                return@repeat
            }
            if (length < min) {
                first.fill(0)
                notice = PinPromptNotice.TOO_SHORT
                return@repeat
            }
            val again = try {
                ask(PinRequest.Choose(pluginId, min, confirm = true, notice = null))
            } catch (e: Throwable) {
                first.fill(0)
                throw e
            } ?: run {
                first.fill(0)
                throw Fido2EnrolmentException(Fido2EnrolmentFailure.CANCELLED, info)
            }
            val same = java.security.MessageDigest.isEqual(first, again)
            again.fill(0)
            if (same) return first
            first.fill(0)
            notice = PinPromptNotice.MISMATCH
        }
        throw Fido2EnrolmentException(Fido2EnrolmentFailure.CANCELLED, info)
    }

    private companion object {
        /** How many times a changed key may restart the dialog before the enrolment gives up. */
        const val MAX_RESTARTS = 2
    }
}
