package org.siros.sdk.sample

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.siros.sdk.flow.FlowStepCatalog
import org.siros.sdk.wallet.WalletState

/**
 * Localized display support for [FlowStepCatalog]'s raw FlowStep tokens.
 * Ordering/progress-fraction logic lives in the SDK now
 * ([FlowStepCatalog.flowStepProgress]) - this file only owns the
 * app-specific localized label mapping.
 */

private val STEP_LABEL_RES: Map<String, Int> = mapOf(
    "parsing_offer" to R.string.flow_step_parsing_offer,
    "offer_parsed" to R.string.flow_step_offer_parsed,
    "fetching_metadata" to R.string.flow_step_fetching_metadata,
    "metadata_fetched" to R.string.flow_step_metadata_fetched,
    "evaluating_trust" to R.string.flow_step_evaluating_trust,
    "trust_evaluated" to R.string.flow_step_trust_evaluated,
    "awaiting_selection" to R.string.flow_step_awaiting_selection,
    "authorization_required" to R.string.flow_step_authorization_required,
    "exchanging_token" to R.string.flow_step_exchanging_token,
    "token_obtained" to R.string.flow_step_token_obtained,
    "requesting_credential" to R.string.flow_step_requesting_credential,
    "deferred" to R.string.flow_step_deferred,
    "parsing_request" to R.string.flow_step_parsing_request,
    "request_parsed" to R.string.flow_step_request_parsed,
    "evaluating_verifier_trust" to R.string.flow_step_evaluating_verifier_trust,
    "match_credentials" to R.string.flow_step_match_credentials,
    "awaiting_consent" to R.string.flow_step_awaiting_consent,
    "credential_selection" to R.string.flow_step_credential_selection,
    "submitting_response" to R.string.flow_step_submitting_response,
    "waiting_for_reader" to R.string.flow_step_waiting_for_reader,
    "reader_connected" to R.string.flow_step_reader_connected,
    // Client-side steps the wallet reports before the engine's first progress
    // event (WalletState.FlowActive.STEP_*): connecting, then the issuer
    // entitlement/metadata work. They share a few labels rather than each
    // getting its own, since they last well under a second apiece on a good
    // network and the raw token is still shown as the diagnostic line.
    WalletState.FlowActive.STEP_INITIALIZING to R.string.flow_step_initializing,
    WalletState.FlowActive.STEP_CONNECTING_ENGINE to R.string.flow_step_initializing,
    WalletState.FlowActive.STEP_ESTABLISHING_SESSION to R.string.flow_step_initializing,
    WalletState.FlowActive.STEP_CHECKING_ENTITLEMENT to R.string.flow_step_fetching_metadata,
    WalletState.FlowActive.STEP_PREPARING_ISSUANCE to R.string.flow_step_fetching_metadata,
    WalletState.FlowActive.STEP_STARTING_FLOW to R.string.flow_step_initializing,
    // Client-only status - see SirosWallet.kt's sign_presentation ZK-proof
    // handling, not part of FlowStepCatalog's server-mirrored vocabulary.
    "computing_proof" to R.string.flow_step_computing_proof,
)

/** Localized label resource for a raw FlowStep token, falling back to a generic "Processing…" for unrecognized tokens. */
fun flowStepLabelRes(step: String): Int = STEP_LABEL_RES[step] ?: R.string.flow_step_unknown

/** See [FlowStepCatalog.flowStepProgress]. */
fun flowStepProgress(flowType: String, step: String): Float? =
    FlowStepCatalog.flowStepProgress(flowType, step)

/**
 * Smooths the discrete, step-completion-driven progress fraction from
 * [FlowStepCatalog.flowStepProgress] into a continuously-animating display
 * value, so the flow-active UI never sits visibly frozen for the full
 * duration of a long-running step (most notably native ZK proof
 * computation, which can take real wall-clock time with zero intermediate
 * progress signal from the underlying Rust/Longfellow library).
 *
 * Real step-completion updates always win: [onRealProgress] snaps
 * [displayProgress] up to the genuine value immediately (never regressing -
 * see [FlowStepCatalog]'s monotonic-max guidance) and raises the ceiling
 * [run] is allowed to creep toward. Between real updates, [run] eases
 * [displayProgress] a little further forward on a fixed tick, capped at
 * [creepCap] past the last genuine value, so the bar visibly keeps moving
 * without ever claiming a step is closer to done than it actually is (the
 * cap always leaves headroom below where the *next* real step would land).
 *
 * Pure Kotlin/coroutines, no Compose or Android dependency, so it's unit
 * testable under a [kotlinx.coroutines.test.TestDispatcher] independent of
 * any UI.
 */
class FlowProgressAnimator(
    private val tickIntervalMs: Long = 150L,
    private val creepCap: Float = 0.08f,
    private val creepFactor: Float = 0.12f,
) {
    private val _displayProgress = MutableStateFlow(0f)
    val displayProgress: StateFlow<Float> = _displayProgress.asStateFlow()

    /** Last genuine (non-null) value passed to [onRealProgress]. */
    private var realFloor = 0f

    /** How far the creep in [run] is currently allowed to advance toward. */
    private var ceiling = creepCap.coerceIn(0f, 1f)

    /**
     * Reports a genuine step-progress fraction (or null if the current step
     * isn't recognized - see [flowStepProgress]). No-op on null or on a
     * value that doesn't advance past what's already been reported, so a
     * step retried after a transient error can't visibly move the bar
     * backward.
     */
    fun onRealProgress(value: Float?) {
        if (value == null || value <= realFloor) return
        realFloor = value
        ceiling = (realFloor + creepCap).coerceIn(0f, 1f)
        _displayProgress.value = maxOf(_displayProgress.value, value)
    }

    /**
     * Runs the creep ticker until its coroutine is cancelled - call from a
     * `LaunchedEffect(flowId) { animator.run() }` (or equivalent) scoped to
     * the lifetime of a single flow, so a fresh animator/coroutine starts
     * per flow rather than carrying state across flows.
     */
    suspend fun run() {
        while (true) {
            delay(tickIntervalMs)
            val current = _displayProgress.value
            if (current < ceiling) {
                val next = current + (ceiling - current) * creepFactor
                _displayProgress.value = next.coerceAtMost(ceiling)
            }
        }
    }
}
