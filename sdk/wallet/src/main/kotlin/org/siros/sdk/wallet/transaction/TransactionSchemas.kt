// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import io.github.optimumcode.json.schema.JsonSchema
import io.github.optimumcode.json.schema.JsonSchemaLoader
import io.github.optimumcode.json.schema.ValidationError
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * JSON Schema validation of a `transaction_data.payload` (EC TS12 v1.0.1 3.2
 * step 4).
 *
 * Schemas are JSON Schema 2020-12. A schema never causes a fetch: the only
 * `$ref` this resolves is the one the built-in e-mandate schema makes to the
 * built-in payment schema, which is registered here; any other reference is
 * unresolvable and the schema is unusable ([UnusableSchema]).
 */
internal object TransactionSchemas {

    /** A schema that cannot be loaded (malformed, unsupported, or referencing something unavailable). */
    class UnusableSchema(message: String, cause: Throwable? = null) : Exception(message, cause)

    private val json = Json

    /** Compiled built-in schemas, by type. */
    private val builtIn: Map<String, JsonSchema> by lazy {
        Ts12Schemas.BY_TYPE.mapValues { (_, text) -> load(text) }
    }

    /** Whether [type] is one of the four TS12 built-in transaction data types. */
    fun isBuiltIn(type: String): Boolean = type in Ts12Schemas.BY_TYPE

    /** Violations of the built-in schema of [type] by [payload] (empty when valid). */
    fun validateBuiltIn(type: String, payload: JsonElement): List<String> =
        bounded { run(builtIn.getValue(type), payload) }

    /**
     * Violations of an issuer-supplied schema by [payload] (empty when valid).
     *
     * @throws UnusableSchema when [schema] cannot be loaded.
     */
    fun validate(schema: JsonElement, payload: JsonElement): List<String> =
        bounded { run(load(schema), payload) }

    private fun load(text: String): JsonSchema = load(json.parseToJsonElement(text))

    private fun load(schema: JsonElement): JsonSchema = try {
        JsonSchemaLoader.create()
            // The e-mandate schema's payment_payload is a $ref to the payment
            // schema by its file name.
            .register(json.parseToJsonElement(Ts12Schemas.PAYMENT), "/${Ts12Schemas.PAYMENT_FILE_NAME}")
            .fromJsonElement(schema)
    } catch (e: Exception) {
        throw UnusableSchema("The transaction data schema cannot be loaded: ${e.message}", e)
    } catch (e: StackOverflowError) {
        throw UnusableSchema("The transaction data schema nests too deeply", e)
    }

    private fun run(schema: JsonSchema, payload: JsonElement): List<String> {
        val errors = mutableListOf<ValidationError>()
        val valid = schema.validate(payload, errors::add)
        return if (valid) emptyList() else errors.map { "${it.objectPath}: ${it.message}" }.ifEmpty { listOf("invalid") }
    }

    /**
     * Runs [work] on a small dedicated pool under a hard time limit.
     *
     * Loading and validating an issuer-supplied schema against a
     * verifier-supplied payload is unbounded work (catastrophic regexes,
     * reference loops, huge exponents). A timeout cannot stop the worker
     * thread (a regex does not poll for interruption), so the pool is small
     * and its threads are daemons: an attacker can at worst keep those
     * threads busy, after which every further validation times out and is
     * refused (fail closed) until the process restarts. Any [Throwable]
     * the work throws, including [StackOverflowError], becomes
     * [UnusableSchema].
     */
    private fun <T> bounded(work: () -> T): T {
        val future = pool.submit<T> { work() }
        try {
            return future.get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            future.cancel(true)
            throw UnusableSchema("Validating the payload took too long", e)
        } catch (e: ExecutionException) {
            val cause = e.cause
            if (cause is UnusableSchema) throw cause
            throw UnusableSchema("Validating the payload failed: ${cause?.javaClass?.simpleName}", cause)
        } catch (e: RejectedExecutionException) {
            throw UnusableSchema("Validation is busy", e)
        }
    }

    /** Wall-clock limit for one load-and-validate; tests lower it. */
    @Volatile
    internal var timeoutMillis: Long = 3_000

    private val pool: ExecutorService = ThreadPoolExecutor(
        0, 4, 30, TimeUnit.SECONDS, SynchronousQueue(),
        { r -> Thread(r, "ts12-schema-validation").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )
}
