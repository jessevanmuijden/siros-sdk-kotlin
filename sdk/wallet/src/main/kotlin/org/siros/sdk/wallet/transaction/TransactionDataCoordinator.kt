// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.keystore.TransactionBinding
import org.siros.sdk.wallet.AuthenticationFactorsProvider
import org.siros.sdk.wallet.SigningOperation
import org.siros.sdk.wallet.TransactionConsentHandler
import org.siros.sdk.wallet.TransactionConsentRequest
import org.siros.sdk.wallet.TransactionLogEntry
import org.siros.sdk.wallet.TransactionLogStore
import org.siros.sdk.wallet.TransactionOutcome
import timber.log.Timber

/**
 * What a successful [TransactionDataCoordinator.process] hands to signing:
 * the KB-JWT binding for each DCQL query id an entry is bound to. A query not
 * in it is presented without transaction data.
 *
 * Signing must use exactly the credentials that were validated and shown (the
 * wiring signs the objects it validated, never ones re-read from the store
 * after the user's minutes of thought), and report a signing failure through
 * [signingFailed] so the log does not keep a "consented" record that never
 * produced a presentation.
 */
internal class ScaPresentationPlan(
    private val bindings: Map<String, TransactionBinding>,
    private val onSigningFailed: suspend () -> Unit = {},
) {
    fun bindingFor(queryId: String?): TransactionBinding? = queryId?.let { bindings[it] }

    /** Records that signing failed after consent (outcome `refused`, reason `signingFailed`). */
    suspend fun signingFailed() = onSigningFailed()
}

/**
 * The whole `transaction_data` pipeline for one request (contract section 4):
 * validate, show and obtain consent, establish authentication factors, and
 * log the outcome. Throws a [TransactionDataError] to refuse or decline, with
 * nothing signed; returns the plan to sign with otherwise.
 *
 * Validation and display (schema validation, hashing, document fetches) run
 * on [Dispatchers.Default] and the log's I/O on [Dispatchers.IO], never on the
 * caller's (typically main) thread.
 *
 * Nothing logged by this class contains a payload value, transaction id,
 * entity name, raw entry, hash, URL or an error message that might embed them;
 * only the reason code.
 */
internal class TransactionDataCoordinator(
    private val validator: TransactionDataValidator,
    private val display: TransactionDisplayBuilder,
    private val consentHandler: () -> TransactionConsentHandler?,
    private val factorsProvider: () -> AuthenticationFactorsProvider,
    private val log: () -> TransactionLogStore,
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val consentTimeoutMillis: Long = CONSENT_TIMEOUT_MILLIS,
) {
    /** Records [error] as a refusal of [request] and throws it. */
    suspend fun refuse(request: TransactionDataRequest, error: TransactionDataError): Nothing {
        record(request, null, TransactionOutcome.REFUSED, error.reason.code)
        throw error
    }

    /** Records a refusal of a request whose entries could not even be read (nothing but the verifier is known). */
    suspend fun recordUnreadable(verifier: String?, error: TransactionDataError) {
        record(
            TransactionDataRequest(emptyList(), null, emptyMap(), verifier = verifier), null,
            TransactionOutcome.REFUSED, error.reason.code, unreadable = true,
        )
    }

    suspend fun process(request: TransactionDataRequest): ScaPresentationPlan {
        val validated = try {
            withContext(Dispatchers.Default) { validator.validate(request) }
        } catch (e: TransactionDataError) {
            record(request, null, TransactionOutcome.REFUSED, e.reason.code)
            throw e
        }
        try {
            val consentModel = withContext(Dispatchers.Default) {
                display.build(
                    validated, request.verifier, request.requestSigned,
                    request.disclosures.map {
                        org.siros.sdk.wallet.TransactionDisclosure(
                            it.credentialName, it.claims, bindsTransaction = it.queryId != null && it.queryId in validated.boundQueryIds(),
                        )
                    },
                )
            }
            // One warning per validation, now that display has fetched what it needs.
            validated.trust.warnOnce()

            val provider = factorsProvider()
            requireFactorsCanBeEstablished(provider, validated, request)
            val handler = consentHandler() ?: throw TransactionDataError(
                TransactionDataReason.NO_CONSENT_HANDLER,
                "No consent handler is registered, so the transaction cannot be shown to the user",
            )
            if (!askUser(handler, consentModel)) {
                throw TransactionDataError(TransactionDataReason.DECLINED, "The user did not confirm the transaction")
            }
            val bindings = bind(provider, validated, request)
            record(request, validated, TransactionOutcome.CONSENTED, null)
            return ScaPresentationPlan(bindings) {
                record(request, validated, TransactionOutcome.REFUSED, SIGNING_FAILED)
            }
        } catch (e: TransactionDataError) {
            record(
                request, validated,
                if (e.reason == TransactionDataReason.DECLINED) TransactionOutcome.DECLINED else TransactionOutcome.REFUSED,
                e.reason.code,
            )
            throw e
        }
    }

    /** Refuses before the user reads anything if no two-category authentication can possibly follow. */
    private suspend fun requireFactorsCanBeEstablished(
        provider: AuthenticationFactorsProvider,
        validated: ValidatedTransactionData,
        request: TransactionDataRequest,
    ) {
        for (queryId in validated.boundQueryIds()) {
            val operation = SigningOperation(request.credentials.getValue(queryId).first())
            if (!canEstablish(provider, operation)) {
                throw TransactionDataError(
                    TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS,
                    "No two-category authentication can be established for this operation",
                )
            }
        }
    }

    /**
     * Asks the user. A handler that throws, is cancelled from its own scope, or
     * does not answer is a decline, never consent; only the wallet's own
     * coroutine being cancelled propagates.
     */
    private suspend fun askUser(handler: TransactionConsentHandler, model: TransactionConsentRequest): Boolean = try {
        withTimeoutOrNull(consentTimeoutMillis) { handler.confirm(model) } == true
    } catch (e: CancellationException) {
        currentCoroutineContext().ensureActive()
        Timber.w("The transaction consent handler was cancelled; treating it as declined")
        false
    } catch (e: Throwable) {
        if (e is VirtualMachineError) throw e
        Timber.w("The transaction consent handler failed (${e.javaClass.simpleName}); treating it as declined")
        false
    }

    /** The KB-JWT binding per bound query, with the factors established for each credential. */
    private suspend fun bind(
        provider: AuthenticationFactorsProvider,
        validated: ValidatedTransactionData,
        request: TransactionDataRequest,
    ): Map<String, TransactionBinding> {
        val bindings = LinkedHashMap<String, TransactionBinding>()
        for (queryId in validated.boundQueryIds()) {
            val credential = request.credentials.getValue(queryId).first()
            // A provider that fails has established nothing.
            val factors = try {
                provider.factorsFor(SigningOperation(credential))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Timber.w("The authentication factors provider failed (${e.javaClass.simpleName})")
                emptyList()
            }
            bindings[queryId] = validated.bindingFor(queryId, factors)!!
        }
        return bindings
    }

    private suspend fun canEstablish(provider: AuthenticationFactorsProvider, operation: SigningOperation): Boolean = try {
        provider.canEstablish(operation)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        false
    }

    /**
     * Writes the log record(s). A refusal is ONE record per request (the first
     * readable entry's type and id, or nothing if none is readable), so a
     * request with 32 broken entries cannot write 32; consented and declined
     * attempts get one per entry. Free-text fields are capped.
     */
    private suspend fun record(
        request: TransactionDataRequest,
        validated: ValidatedTransactionData?,
        outcome: TransactionOutcome,
        reason: String?,
        unreadable: Boolean = false,
    ) {
        val now = nowMillis()
        val credentialName = validated?.entries?.firstOrNull()?.contexts?.firstOrNull()
            ?.let { it.credential.metadata?.name ?: (it.metadata["name"] as? JsonPrimitive)?.contentOrNull }
            ?: request.credentials.values.firstOrNull()?.firstOrNull()?.metadata?.name
        val items: List<Pair<String?, JsonObject?>> = validated?.entries?.map { it.type to it.payload }
            ?: if (unreadable) listOf(null to null) else request.entries.map { e ->
                // Refused before validation finished: read what can be read, for the record only.
                runCatching { TransactionDataDecoder.decode(e) }.getOrNull()?.let { it.type to it.payload } ?: (null to null)
            }.let { readable -> listOf(readable.firstOrNull { it.first != null } ?: (null to null)) }
        val perRequest = if (outcome == TransactionOutcome.REFUSED) items.take(1) else items
        for ((type, payload) in perRequest) {
            try {
                withContext(Dispatchers.IO) {
                    log().append(
                        TransactionLogEntry(
                            transactionId = capped((payload?.get("transaction_id") as? JsonPrimitive)?.contentOrNull),
                            transactionType = capped(type),
                            typeName = type?.let { TypeNames.builtIn(it) },
                            entities = if (type != null && payload != null) entityNames(type, payload).mapValues { capped(it.value)!! } else emptyMap(),
                            verifier = capped(request.verifier),
                            credential = capped(credentialName),
                            timestampMillis = now,
                            outcome = outcome,
                            reason = reason,
                        ),
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Never include the exception: a store failure message may name what was being written.
                Timber.e("Could not record the transaction in the log (${e.javaClass.simpleName})")
            }
        }
    }

    companion object {
        /**
         * How long the user has to answer. go-wallet-backend's
         * `Session.RequestSign` gives up on a sign request after 3 minutes
         * (`time.NewTimer(3 * time.Minute)`, internal/engine/session.go), and
         * validation and display run before consent starts, so this stays well
         * below that: a confirmation given after the backend stopped waiting
         * would be wasted.
         */
        const val CONSENT_TIMEOUT_MILLIS = 120L * 1000

        /** The log reason of a presentation that failed to sign after consent. */
        const val SIGNING_FAILED = "signingFailed"

        /** Longest free-text field written to the log. */
        const val MAX_LOG_FIELD = 200

        /** [s] limited to [MAX_LOG_FIELD] characters, marked when cut (these are copied from attacker-controlled JSON). */
        fun capped(s: String?): String? =
            if (s == null || s.length <= MAX_LOG_FIELD) s else s.take(MAX_LOG_FIELD) + "…[truncated]"

        /** The entity names EC TS12 5.3 asks for, by built-in type; nothing else is copied out of the payload. */
        fun entityNames(type: String, payload: JsonObject): Map<String, String> {
            fun name(o: JsonElement?, member: String): String? =
                ((o as? JsonObject)?.get(member) as? JsonPrimitive)?.contentOrNull
            val out = linkedMapOf<String, String>()
            fun put(key: String, value: String?) { if (!value.isNullOrEmpty()) out[key] = value }
            when (type) {
                "urn:eudi:sca:payment:1" -> {
                    put("payee", name(payload["payee"], "name"))
                    put("pisp", name(payload["pisp"], "legal_name"))
                }
                "urn:eudi:sca:login_risk_transaction:1" -> put("service", (payload["service"] as? JsonPrimitive)?.contentOrNull)
                "urn:eudi:sca:account_access:1" -> put("aisp", name(payload["aisp"], "legal_name"))
                "urn:eudi:sca:emandate:1" -> {
                    val pp = payload["payment_payload"]
                    put("payee", name((pp as? JsonObject)?.get("payee"), "name"))
                    put("pisp", name((pp as? JsonObject)?.get("pisp"), "legal_name"))
                }
            }
            return out
        }
    }
}
