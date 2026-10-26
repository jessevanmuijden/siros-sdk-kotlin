// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import androidx.annotation.StringRes
import timber.log.Timber
import uniffi.siros_wscd_manager.FfiAuthCallback
import uniffi.siros_wscd_manager.FfiPinFailure
import uniffi.siros_wscd_manager.FfiWscdException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest

/**
 * Why a PIN is being asked for again. `null` on a request means the first time. The matching short, localised text is
 * [messageRes] (the "too short" one takes the minimum length as `%1$d`).
 */
enum class PinPromptNotice(@StringRes val messageRes: Int) {
    TOO_SHORT(R.string.siros_pin_notice_too_short),
    TOO_LONG(R.string.siros_pin_notice_too_long),
    NOT_ACCEPTED(R.string.siros_pin_notice_not_accepted),
    MISMATCH(R.string.siros_pin_notice_mismatch),
    WRONG_PIN(R.string.siros_pin_notice_wrong),
}

/**
 * What the WSCD wants the host to ask the user. The host answers with the PIN bytes (UTF-8), or throws to cancel.
 */
sealed interface PinRequest {
    val pluginId: String
    val notice: PinPromptNotice?

    /** The user ENTERS the PIN already set on the authenticator. */
    data class Enter(override val pluginId: String, override val notice: PinPromptNotice? = null) : PinRequest

    /**
     * The authenticator has no PIN: the user CHOOSES one of at least [minLength] characters. The SDK asks twice, once with
     * [confirm] false and once with it true, and compares the two answers itself - a host just shows "Choose a PIN" or
     * "Confirm the PIN" and returns what was typed.
     */
    data class Choose(
        override val pluginId: String,
        val minLength: Int,
        val confirm: Boolean,
        override val notice: PinPromptNotice? = null,
    ) : PinRequest
}

/** Why a PIN ceremony ended without a usable PIN. A short localised text for the user is [messageRes]. */
enum class WscdPinFailure(@StringRes val messageRes: Int) {
    /** The authenticator's PIN is blocked; only a reset of the key helps. */
    KEY_BLOCKED(R.string.siros_pin_error_blocked),

    /** The authenticator refuses PIN use until it is unplugged and plugged in again. */
    REPLUG_REQUIRED(R.string.siros_pin_error_replug),

    /** The authenticator said no PIN is set at a point the SDK had already handled that: not the user's doing. */
    INTERNAL(R.string.siros_pin_error_internal),

    /** The user was asked again [PinPrompter.MAX_PIN_ATTEMPTS] times and the PIN was still refused. */
    TOO_MANY_ATTEMPTS(R.string.siros_pin_error_too_many),
}

/** A PIN ceremony that cannot continue; carries only the [failure], never PIN material. */
class WscdPinException(val failure: WscdPinFailure, cause: Throwable? = null) :
    Exception("PIN ceremony ended: $failure", cause)

/**
 * The PIN prompting of ONE signer operation: turns the WSCD's two PIN callbacks into [PinRequest]s for the host, does the
 * "choose a PIN" confirmation, and carries the "why again" notice from one attempt to the next.
 *
 * Not thread-safe by design: one instance serves one operation.
 */
internal class PinPrompter(private val provider: AuthProvider?) {
    private var enterNotice: PinPromptNotice? = null
    private var chooseNotice: PinPromptNotice? = null

    /** What the last prompt asked: the authenticator's answer to a PIN does not say whether it was typed to ENTER or to CHOOSE. */
    private var lastAskedEnter = false

    /** The notice for the next ENTER prompt, set by [onPinFailure]. */
    fun enter(pluginId: String): ByteArray {
        val p = provider ?: throw FfiWscdException.AuthCancelled("No AuthProvider configured")
        lastAskedEnter = true
        return p.requestPin(PinRequest.Enter(pluginId, enterNotice))
    }

    /**
     * The user chooses a PIN of at least [minLength] characters (Unicode code points, as the authenticator counts them; the
     * plugin re-checks after normalisation and answers TooShort if it still disagrees) and types it twice. Asked at most
     * [MAX_CHOOSE_ROUNDS] times; every buffer that is not returned is wiped.
     */
    fun choose(pluginId: String, minLength: Int): ByteArray {
        val p = provider ?: throw FfiWscdException.AuthCancelled("No AuthProvider configured")
        lastAskedEnter = false
        var notice = chooseNotice
        repeat(MAX_CHOOSE_ROUNDS) {
            val first = p.requestPin(PinRequest.Choose(pluginId, minLength, confirm = false, notice = notice))
            val length = codePoints(first)
            if (length == null) {
                first.fill(0)
                notice = PinPromptNotice.NOT_ACCEPTED
                return@repeat
            }
            if (length < minLength) {
                first.fill(0)
                notice = PinPromptNotice.TOO_SHORT
                return@repeat
            }
            val again = try {
                p.requestPin(PinRequest.Choose(pluginId, minLength, confirm = true, notice = null))
            } catch (e: Exception) {
                first.fill(0)
                throw e
            }
            val same = MessageDigest.isEqual(first, again)
            again.fill(0)
            if (same) return first
            first.fill(0)
            notice = PinPromptNotice.MISMATCH
        }
        throw FfiWscdException.AuthCancelled("No PIN was chosen")
    }

    /**
     * Decides what a [FfiWscdException.Pin] from the WSCD means. Returns normally when the operation should be run again
     * (the next prompt carries the matching notice) and throws when it must not.
     */
    fun onPinFailure(e: FfiWscdException.Pin, attempt: Int) {
        val failure = e.reason
        Timber.w("PIN ceremony refused (attempt $attempt of $MAX_PIN_ATTEMPTS): ${failure.javaClass.simpleName}")
        when (failure) {
            is FfiPinFailure.Blocked -> throw WscdPinException(WscdPinFailure.KEY_BLOCKED, e)
            is FfiPinFailure.AuthBlocked -> throw WscdPinException(WscdPinFailure.REPLUG_REQUIRED, e)
            is FfiPinFailure.NotSet -> throw WscdPinException(WscdPinFailure.INTERNAL, e)
            // A PIN refused for what it is (not for being wrong): a NEW PIN is asked for again with the specific notice; one typed
            // to ENTER (a NUL in it, say) is asked for again with an ENTER notice, which also makes the next ENTER ineligible
            // for a PIN typed ahead - that one is the PIN just refused.
            is FfiPinFailure.TooShort ->
                if (lastAskedEnter) enterNotice = PinPromptNotice.NOT_ACCEPTED else chooseNotice = PinPromptNotice.TOO_SHORT
            is FfiPinFailure.TooLong ->
                if (lastAskedEnter) enterNotice = PinPromptNotice.NOT_ACCEPTED else chooseNotice = PinPromptNotice.TOO_LONG
            is FfiPinFailure.PolicyViolation, is FfiPinFailure.InvalidEncoding ->
                if (lastAskedEnter) enterNotice = PinPromptNotice.NOT_ACCEPTED else chooseNotice = PinPromptNotice.NOT_ACCEPTED
            is FfiPinFailure.Invalid -> enterNotice = PinPromptNotice.WRONG_PIN
        }
        if (attempt >= MAX_PIN_ATTEMPTS) throw WscdPinException(WscdPinFailure.TOO_MANY_ATTEMPTS, e)
    }

    /**
     * Runs [operation] (one WSCD call that may ask for a PIN, given the callback to hand it) and re-runs it after a PIN the
     * authenticator refused for a reason the user can fix, at most [MAX_PIN_ATTEMPTS] times in all. A wrong PIN costs a
     * retry on the authenticator itself, hence the small bound.
     */
    fun <T> run(operation: () -> T): T {
        var attempt = 1
        while (true) {
            try {
                return operation()
            } catch (e: FfiWscdException.Pin) {
                onPinFailure(e, attempt)
                attempt++
            }
        }
    }

    companion object {
        /** Total tries of one operation, the first one included. */
        const val MAX_PIN_ATTEMPTS = 3

        /** How many times the user is asked to choose (and confirm) a PIN within ONE callback. */
        const val MAX_CHOOSE_ROUNDS = 3

        /** The number of code points of the UTF-8 [pin], or null when it is not valid UTF-8. The decoded copy is wiped. */
        internal fun codePoints(pin: ByteArray): Int? {
            val decoder = Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            val chars = CharBuffer.allocate(pin.size)
            return try {
                val result = decoder.decode(ByteBuffer.wrap(pin), chars, true)
                if (result.isError || result.isOverflow) {
                    null
                } else {
                    chars.flip()
                    Character.codePointCount(chars, 0, chars.length)
                }
            } finally {
                chars.array().fill('\u0000')
            }
        }
    }
}

/**
 * The callback boundary of a PIN prompt: an exception of a type the native side does not know would reach it as
 * `UnexpectedUniFFICallbackError` carrying the whole Kotlin stack trace, so anything but an [FfiWscdException] (a host that
 * cancelled, a host that cannot ask) becomes a cancelled authentication with a short message (never PIN material). The
 * cause is logged here.
 */
internal inline fun <T> promptFailsAsCancelled(prompt: () -> T): T = try {
    prompt()
} catch (e: FfiWscdException) {
    throw e
} catch (e: Exception) {
    Timber.w("PIN prompt failed: ${e.javaClass.simpleName}")
    throw FfiWscdException.AuthCancelled("The PIN prompt did not complete")
}

/** The native side's view of the host: the three auth callbacks, with PIN prompts going through [prompter]. */
internal class AuthCallbackBridge(
    private val provider: AuthProvider?,
    val prompter: PinPrompter = PinPrompter(provider),
) : FfiAuthCallback {
    override fun requestPin(pluginId: String): ByteArray = promptFailsAsCancelled { prompter.enter(pluginId) }

    override fun requestNewPin(pluginId: String, minLength: UInt): ByteArray =
        promptFailsAsCancelled { prompter.choose(pluginId, minLength.coerceAtMost(Int.MAX_VALUE.toUInt()).toInt()) }

    override fun requestWebauthnAssertion(
        pluginId: String,
        challenge: ByteArray,
        rpId: String,
        allowedCredentials: List<ByteArray>,
    ): ByteArray {
        val host = provider ?: throw FfiWscdException.AuthCancelled("No AuthProvider configured")
        return host.requestWebauthnAssertion(pluginId, challenge, rpId, allowedCredentials)
    }
}

/**
 * A PIN the user typed BEFORE the ceremony started (a host that cannot ask mid-ceremony, e.g. while an NFC key is held in
 * place). It answers the FIRST PIN request of the ceremony and is gone after it, whatever the request: used when that is a
 * first ENTER, wiped otherwise. A PIN the key refused is therefore never sent a second time (each submission costs a try on
 * the authenticator's own counter), and a retry - which carries a notice - always asks the user.
 */
class TypedAheadPin {
    private var held: ByteArray? = null

    /** Holds [pin] for the next ceremony; a PIN still held is wiped. */
    @Synchronized
    fun hold(pin: ByteArray) {
        held?.fill(0)
        held = pin
    }

    /** The held PIN when [request] is a first ENTER (and then it is no longer held), else null; either way it is gone. */
    @Synchronized
    fun take(request: PinRequest): ByteArray? {
        val pin = held ?: return null
        held = null
        if (request is PinRequest.Enter && request.notice == null) return pin
        pin.fill(0)
        return null
    }

    /** Wipes what is still held, when the ceremony ends. */
    @Synchronized
    fun clear() {
        held?.fill(0)
        held = null
    }
}
