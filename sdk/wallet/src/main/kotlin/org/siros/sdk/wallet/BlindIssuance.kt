// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import java.util.concurrent.ConcurrentHashMap
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import org.siros.sdk.transport.CredentialResponseEncryptionRequest
import org.siros.sdk.transport.DeliveredResponseMetadata
import org.siros.sdk.transport.ResponseCredentialMetadata

/**
 * The wallet could not do what the engine asked for an encrypted issuance. The message names no content.
 * [notificationId] is the `notification_id` of a response the wallet DID decrypt but rejected, so the issuer can still be told
 * (`credential_failure`); null when nothing could be read.
 */
internal class BlindIssuanceException(message: String, val notificationId: String? = null) : Exception(message)

/**
 * The only members of an opened Credential Response the engine may learn, because it must act on them: EXACTLY ONE of
 * [credentialCount] (1..[MAX_CREDENTIAL_COUNT], credentials issued) or [transactionId] (deferred, with the optional [interval]).
 */
internal class BlindIssuanceControl(val credentialCount: Int?, val transactionId: String?, val interval: Int?) {
    companion object {
        /** The engine refuses a larger `credential_count`. */
        const val MAX_CREDENTIAL_COUNT = 256
    }
}

/**
 * The Credential Response(s) of one issuance as the wallet opened them: the credentials, the response-level
 * `credential_metadata` and the `notification_id` never left the wallet, so the engine could not read them.
 * Nothing here prints a value.
 */
internal class OpenedIssuance(
    val credentials: List<String>,
    override val credentialMetadata: ResponseCredentialMetadata?,
    val notificationId: String?,
    /** True when the credentials arrived in a Deferred Credential Response. */
    override val deferredResponse: Boolean,
) : DeliveredResponseMetadata {
    /** Only a response the wallet itself decrypted is an [OpenedIssuance]. */
    override val credentialMetadataEncryptedResponse: Boolean get() = true

    override fun toString() = "OpenedIssuance(redacted)"
}

/**
 * Per-flow key and opened-response state for the engine-blind issuance of OpenID4VCI: the wallet generates the
 * credential-response encryption key, opens the issuer's JWE, and keeps what is in it.
 *
 * A key is generated fresh for EVERY `generate_proof` request (a c_nonce retry sends a new request and so gets a new
 * key; the key of the request that produced the issuer's reply is the latest one) and lives only here, in memory.
 * [drop] and [clear] forget a flow's key and everything opened for it.
 */
internal class BlindIssuance(
    /** Generates the key for a negotiated pair; replaceable so a test can pause generation. */
    private val keyFactory: (String, String) -> CredentialResponseKey? = { alg, enc -> CredentialResponseKey.generate(alg, enc) },
    /** Milliseconds, for the grace of a stale flow; replaceable so a test can use virtual time. */
    private val clock: () -> Long = System::currentTimeMillis,
    /** Runs at the start of [offer], before it claims anything; lets a test pause a caller between its own liveness check and the claim. */
    private val beforeClaim: () -> Unit = {},
    /** Runs inside [drop]'s critical section, between removing the marker and removing the state; lets a test prove the two are one step. */
    private val duringDrop: () -> Unit = {},
) {
    private class FlowState(val generation: Int) {
        @Volatile var key: CredentialResponseKey? = null
        /** When the socket this flow lived on was replaced (NOT_STALE: it was not). The key is gone then; opened responses wait out a grace. */
        @Volatile var staleAt: Long = NOT_STALE
        val opened = mutableListOf<OpenedIssuance>()
    }

    private val flows = ConcurrentHashMap<String, FlowState>()

    /**
     * The flows a response key was OFFERED for, as a fact of its own: it outlives the key, which a socket replacement clears
     * ([markStaleBefore]) while a completion buffered before the replacement can still arrive, and it is what tells a plaintext
     * completion apart from an encrypted one. Removed only when the flow ends or is dropped ([drop], [take]) or everything is
     * ([clear]) - never by [markStaleBefore] or [purgeStale]. Bounded FAIL-CLOSED: at [MAX_OFFERED_MARKERS] a NEW offer is refused
     * ([offer] throws) and no existing marker is ever evicted, because an evicted flow would lose the plaintext-completion
     * guard while its key and buffered completion are still alive. Guarded by [lock].
     */
    private val offeredFlows = HashSet<String>()

    /** Guards the claim of a flow's state and the insertion of its key against [clear], which ends every flow at once. */
    private val lock = Any()

    /**
     * Counts the session-wide teardowns ([clear]). A caller captures it BEFORE it checks that its session is alive and hands it to
     * [offer], which re-checks it under [lock] when it claims the flow's state: a teardown that runs between the caller's check and
     * the claim (the check and the claim are separate operations) is then noticed and the offer fails. A teardown after the claim
     * removes the claimed state, which [offer] notices when it stores the key.
     */
    @Volatile
    var epoch: Long = 0
        private set

    /**
     * The `generate_proof` step: returns the public JWK to answer with, or null to decline (the engine offered no
     * encryption). A previous key of the flow is replaced.
     *
     * @throws BlindIssuanceException when the issuer REQUIRES encryption and the wallet cannot provide a key for the
     *   negotiated pair: the issuance fails here, with a message that says why, instead of at the issuer.
     */
    fun offer(flowId: String, request: CredentialResponseEncryptionRequest?, generation: Int = NO_GENERATION, epoch: Long? = null): JsonObject? {
        beforeClaim()
        if (request == null) {
            flows[flowId]?.key = null
            return null
        }
        // The flow's state is claimed BEFORE the key is generated and the key is stored only while that very state is still
        // the flow's: a clear() or drop() that finishes during generation removes it, and the stale insertion is discarded
        // instead of resurrecting the flow (a handler can outlive the teardown that cancelled its scope).
        val state = synchronized(lock) {
            if (epoch != null && epoch != this.epoch) throw BlindIssuanceException("The session ended before its response key was requested")
            if (flowId !in offeredFlows && offeredFlows.size >= MAX_OFFERED_MARKERS) {
                throw BlindIssuanceException("Too many issuances are in flight to start another")
            }
            flows.compute(flowId) { _, old -> if (old == null || old.staleAt != NOT_STALE) FlowState(generation) else old }!!
        }
        val key = keyFactory(request.alg, request.enc)
        if (key == null) {
            state.key = null
            if (state.opened.isEmpty()) flows.remove(flowId, state)
            if (request.required) {
                throw BlindIssuanceException("The issuer requires an encrypted credential response (${request.alg}/${request.enc}) and this wallet cannot decrypt it")
            }
            return null
        }
        synchronized(lock) {
            // (A teardown during generation removed the state, so this identity check is what notices it; the epoch is checked at the claim.)
            if (flows[flowId] !== state) throw BlindIssuanceException("The issuance ended while its response key was being generated")
            // (A teardown after this is a teardown right after the offer returned: the state is out of the map and so is the key.)
            state.key = key
            offeredFlows.add(flowId)
        }
        return key.publicJwk
    }

    /**
     * The socket of connection [generation] replaced the ones before it: a flow that lived on an older one is dead on the
     * engine, so its private key is dropped now. What it already opened is kept for [purgeStale] (a completion that was
     * buffered before the replacement still has to be processed against it) and is NOT readable through a key any more.
     */
    fun markStaleBefore(generation: Int, now: Long = clock()) {
        for (state in flows.values) {
            if (state.generation < generation && state.staleAt == NOT_STALE) {
                state.key = null
                state.staleAt = now
            }
        }
    }

    /** Forgets the flows that went stale at least [graceMs] ago. */
    fun purgeStale(graceMs: Long, now: Long = clock()) {
        flows.entries.removeIf { (_, s) -> s.staleAt != NOT_STALE && now - s.staleAt >= graceMs }
    }

    /**
     * The flow's engine session is gone: its private key is dropped now, but what it already opened stays readable for the
     * [purgeStale] grace period (a completion buffered before the loss is still processed against it). A flow with nothing opened
     * is forgotten at once.
     */
    fun retire(flowId: String, now: Long = clock()) {
        synchronized(lock) {
            val state = flows[flowId] ?: return
            state.key = null
            if (state.opened.isEmpty()) {
                flows.remove(flowId)
                offeredFlows.remove(flowId)
            } else if (state.staleAt == NOT_STALE) {
                state.staleAt = now
            }
        }
    }

    /**
     * The `decrypt_credential_response` step: opens [jwe] with the flow's key and keeps what it says. Returns what
     * the engine needs to continue (a deferred issuance's `transaction_id`), nothing else.
     *
     * @throws BlindIssuanceException when there is no key for the flow, the JWE does not decrypt, or what it
     *   decrypts to is not a Credential Response.
     */
    fun open(flowId: String, jwe: String, deferred: Boolean): BlindIssuanceControl {
        val state = flows[flowId]
        val key = state?.key ?: throw BlindIssuanceException("No credential response key exists for this flow")
        val plaintext = try {
            key.decrypt(jwe)
        } catch (e: IllegalArgumentException) {
            throw BlindIssuanceException(e.message ?: "The credential response could not be decrypted")
        }
        val body = try {
            Json.parseToJsonElement(plaintext) as? JsonObject
        } catch (e: Exception) {
            null
        } ?: throw BlindIssuanceException("The decrypted credential response is not a JSON object")
        val notificationIdEarly = (body["notification_id"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.takeIf { it.isNotEmpty() }
        // The shape limits the engine used to enforce: checked before anything is retained or handed on, with the decrypted
        // notification_id kept so the issuer can still be told.
        CredentialMetadataShape.violation(plaintext)?.let { throw BlindIssuanceException(it, notificationIdEarly) }
        val credentials = buildList {
            // OpenID4VCI 1.0 section 8.3: every `credentials` entry is an object whose `credential` member holds the credential. The
            // INNER string is stored; anything else (a bare string, an object or other non-string inner value) is refused. The one
            // pre-1.0 draft shape still accepted is a top-level `credential` that is itself a string.
            body["credential"]?.takeIf { it !is kotlinx.serialization.json.JsonNull }?.let {
                val legacy = it as? JsonPrimitive
                if (legacy == null || !legacy.isString || legacy.content.isEmpty()) throw BlindIssuanceException("The credential is not a string", notificationIdEarly)
                add(legacy.content)
            }
            (body["credentials"] as? JsonArray)?.forEach { add(credentialValue(it, notificationIdEarly)) }
        }
        val metadata = body["credential_metadata"]?.takeIf { it !is kotlinx.serialization.json.JsonNull }?.let {
            (it as? JsonObject)?.let { obj -> ResponseCredentialMetadata(obj) } ?: ResponseCredentialMetadata(malformed = true)
        }
        val notificationId = (body["notification_id"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.takeIf { it.isNotEmpty() }
        val transactionId = (body["transaction_id"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.takeIf { it.isNotEmpty() }
        val interval = (body["interval"] as? JsonPrimitive)?.intOrNull
        // Exactly one of credentials issued or deferred: both or neither is not a Credential Response the engine can act on.
        // Nothing is kept for a response that is refused, and its notification_id (if any) lets the issuer be told.
        if (transactionId != null && credentials.isNotEmpty()) {
            throw BlindIssuanceException("The credential response carries both credentials and a transaction_id", notificationId)
        }
        if (transactionId == null && credentials.isEmpty()) {
            throw BlindIssuanceException("The credential response carries neither credentials nor a transaction_id", notificationId)
        }
        if (credentials.size > BlindIssuanceControl.MAX_CREDENTIAL_COUNT) {
            throw BlindIssuanceException("The credential response carries more than ${BlindIssuanceControl.MAX_CREDENTIAL_COUNT} credentials", notificationId)
        }
        // A member of a superseded secret-bearing shape is refused on EVERY response of the flow, whatever it is (first, pending, deferred
        // or a later one): take() keeps only the last response's metadata, so a response refused only at the end would let an
        // earlier one's credentials through.
        if (metadata != null && !metadata.malformed && org.siros.sdk.credentials.LegacySecretMembers.carriedBy(JsonObject(metadata.members))) {
            throw BlindIssuanceException(DeliveredMetadataRefusal.LEGACY_SECRET_MEMBER.text, notificationId)
        }
        // A deferred issuance cannot deliver a secret (privatedata-spec 5A.2): neither a PENDING response (never handed to the receipt
        // check, its metadata is dropped below) nor the response to a Deferred Credential Request, so a seed in either is refused HERE,
        // the one place that sees the plaintext, with the notification_id so the issuer is told.
        if ((transactionId != null || deferred) && metadata != null && !metadata.malformed &&
            (org.siros.sdk.credentials.AuxiliaryDataShapes.all.any { it.carriesSecret(JsonObject(metadata.members)) } ||
                org.siros.sdk.credentials.LegacySecretMembers.carriedBy(JsonObject(metadata.members)))
        ) {
            throw BlindIssuanceException(DeliveredMetadataRefusal.DEFERRED_SEED.text, notificationId)
        }
        // Only a response that carries credentials is retained: a pending one (a transaction_id) is validated and answered but
        // keeps nothing, so repeated deferrals do not accumulate up to 1 MiB of metadata each.
        if (credentials.isNotEmpty()) {
            synchronized(state.opened) {
                state.opened += OpenedIssuance(credentials, metadata, notificationId, deferred)
            }
        }
        return if (transactionId != null) {
            BlindIssuanceControl(credentialCount = null, transactionId = transactionId, interval = interval)
        } else {
            BlindIssuanceControl(credentialCount = credentials.size, transactionId = null, interval = null)
        }
    }

    /**
     * The issuance at completion: every credential opened for the flow, in order, with the metadata and
     * `notification_id` of the response that carried them. Removes the flow's state: the key is gone after this.
     * Null when nothing was opened for the flow.
     */
    fun take(flowId: String): OpenedIssuance? {
        // The marker and the state go in ONE step under the lock that also validates a late key installation (see offer).
        val state = synchronized(lock) {
            offeredFlows.remove(flowId)
            flows.remove(flowId)
        } ?: return null
        val opened = synchronized(state.opened) { state.opened.toList() }
        if (opened.isEmpty()) return null
        val carriers = opened.filter { it.credentials.isNotEmpty() }
        val last = carriers.lastOrNull() ?: opened.last()
        return OpenedIssuance(
            credentials = carriers.flatMap { it.credentials },
            credentialMetadata = last.credentialMetadata,
            notificationId = last.notificationId,
            deferredResponse = last.deferredResponse,
        )
    }

    /** Forgets one flow's key and everything opened for it. */
    fun drop(flowId: String) {
        // One critical section: a key installation checks the flow's state and sets the marker under this same lock, so it can never
        // land between the two removals and leave a marker (a slot of the capacity) with no flow behind it.
        synchronized(lock) {
            offeredFlows.remove(flowId)
            duringDrop()
            flows.remove(flowId)
        }
    }

    /** How many flows are marked as offered (for tests: an orphaned marker would consume capacity). */
    internal fun offeredCount(): Int = synchronized(lock) { offeredFlows.size }

    /** Forgets every flow's key and everything opened (cancel, logout, a new connection). */
    fun clear() {
        synchronized(lock) {
            epoch++
            flows.clear()
            offeredFlows.clear()
        }
    }

    /** Whether something was opened for [flowId] and is still retained (a buffered completion can still be filled from it). */
    fun hasOpened(flowId: String): Boolean = flows[flowId]?.let { synchronized(it.opened) { it.opened.isNotEmpty() } } == true

    /** Whether a key is currently held for [flowId]. */
    fun holdsKey(flowId: String): Boolean = flows[flowId]?.key != null

    /**
     * Whether a response key was offered for [flowId] and the flow has not ended since, whatever became of the key itself (a socket
     * replacement drops it). A completion for such a flow that is not encrypted is a downgrade.
     */
    fun wasOffered(flowId: String): Boolean = synchronized(lock) { flowId in offeredFlows }

    companion object {
        /** A flow not tied to a connection generation (WMP) is never made stale by a socket replacement. */
        const val NO_GENERATION = Int.MAX_VALUE
        private const val NOT_STALE = Long.MIN_VALUE

        /** How many flows may have a response key offered at once; far above normal use. A further offer is refused (never an eviction). */
        const val MAX_OFFERED_MARKERS = 1024
    }

    private fun credentialValue(entry: JsonElement, notificationId: String?): String {
        val inner = ((entry as? JsonObject) ?: throw BlindIssuanceException("A credentials entry is not an object", notificationId))["credential"] as? JsonPrimitive
        if (inner == null || !inner.isString || inner.content.isEmpty()) throw BlindIssuanceException("A credentials entry has no credential string", notificationId)
        return inner.content
    }
}
