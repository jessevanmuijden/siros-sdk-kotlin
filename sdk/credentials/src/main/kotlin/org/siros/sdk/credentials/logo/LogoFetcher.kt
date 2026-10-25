// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.logo

import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okhttp3.OkHttpClient
import okhttp3.Request
import okio.Buffer

/** A redirect hop (or the request) broke the https-only / no-userinfo rule. */
private class LogoPolicyException : IOException("refused non-https or credentialed logo URL")

/** Outcome of [LogoFetcher.load]. Only [Loaded] carries something renderable. */
sealed interface LogoLoad {
    /** A clean PNG, produced by [LogoSanitizer.sanitizeBytes]. */
    class Loaded(val image: DisplayLogo.Image) : LogoLoad

    /** Permanent: the URI, response status or content is not acceptable. Safe to remember. */
    data class Rejected(val reason: LogoRejection) : LogoLoad

    /** Network error, timeout or 5xx. The same URI may succeed later; never remember this. */
    data class Transient(val cause: String) : LogoLoad
}

/**
 * Fetches an https display logo and runs the body through
 * [LogoSanitizer.sanitizeBytes]. Nothing but a sanitized PNG comes out.
 *
 * - https only, no userinfo, checked on the request and on every redirect hop
 *   (a network interceptor), so a redirect cannot downgrade to http or smuggle
 *   credentials. Redirects between http and https are not followed at all.
 * - The body is read through a streaming cap of [LogoSanitizer.MAX_DECODED_BYTES]
 *   and never buffered beyond it; a larger Content-Length is refused up front.
 * - A wall-clock [timeoutMillis] covers the whole call (connect to last byte).
 * - 4xx and bad content are [LogoLoad.Rejected]; I/O errors, timeouts and 5xx
 *   are [LogoLoad.Transient]. Nothing is cached here.
 * - Concurrent [load]s of the same URL share one request. The request is
 *   cancelled when every waiter has been cancelled.
 *
 * Cancellation of the calling coroutine propagates as `CancellationException`.
 */
class LogoFetcher(
    client: OkHttpClient = OkHttpClient(),
    val timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
) {
    init {
        require(timeoutMillis in 1..MAX_TIMEOUT_MILLIS) { "timeoutMillis must be in 1..$MAX_TIMEOUT_MILLIS" }
    }

    private val http: OkHttpClient = client.newBuilder()
        .followRedirects(true)
        .followSslRedirects(false)
        .callTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
        .addNetworkInterceptor { chain ->
            val url = chain.request().url
            if (!url.isHttps || url.username.isNotEmpty() || url.password.isNotEmpty()) {
                throw LogoPolicyException()
            }
            chain.proceed(chain.request())
        }
        .build()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Mutex()
    private val inFlight = HashMap<String, Flight>()

    private class Flight(val deferred: Deferred<LogoLoad>) {
        var waiters = 0
    }

    suspend fun load(uri: String): LogoLoad {
        val remote = when (val r = LogoSanitizer.sanitize(uri)) {
            is LogoResult.Rejected -> return LogoLoad.Rejected(r.reason)
            is LogoResult.Accepted -> r.logo as? DisplayLogo.Remote
                ?: return LogoLoad.Rejected(LogoRejection.UnsupportedScheme)
        }
        val flight = lock.withLock {
            inFlight.getOrPut(remote.url) {
                Flight(scope.async { fetch(remote.url) })
            }.also { it.waiters++ }
        }
        try {
            return flight.deferred.await()
        } finally {
            // Must finish even when this caller is cancelled: a skipped decrement
            // leaves a phantom waiter that keeps a completed flight (and its
            // possibly transient result) alive for later loads.
            withContext(NonCancellable) {
                lock.withLock {
                    flight.waiters--
                    if (flight.waiters == 0) {
                        if (inFlight[remote.url] === flight) inFlight.remove(remote.url)
                        if (flight.deferred.isActive) flight.deferred.cancel()
                    }
                }
            }
        }
    }

    /**
     * Runs the blocking call inside a cancellable continuation: cancelling the
     * flight (its last waiter left) calls [okhttp3.Call.cancel] at once, which
     * aborts a blocked connect, header read or body read. (A completion handler
     * on the job would only fire after the blocking call returned.)
     */
    private suspend fun fetch(url: String): LogoLoad = suspendCancellableCoroutine { cont ->
        val call = http.newCall(Request.Builder().url(url).build())
        cont.invokeOnCancellation { call.cancel() }
        cont.resume(blockingFetch(call))
    }

    private fun blockingFetch(call: okhttp3.Call): LogoLoad {
        return try {
            call.execute().use { response ->
                when {
                    response.code >= 500 -> LogoLoad.Transient("HTTP ${response.code}")
                    !response.isSuccessful -> LogoLoad.Rejected(LogoRejection.FetchRejected)
                    else -> {
                        val body = response.body ?: return LogoLoad.Rejected(LogoRejection.UndecodableImage)
                        val declared = body.contentLength()
                        if (declared > LogoSanitizer.MAX_DECODED_BYTES) {
                            return LogoLoad.Rejected(LogoRejection.TooLarge)
                        }
                        val buffer = Buffer()
                        val source = body.source()
                        val limit = LogoSanitizer.MAX_DECODED_BYTES + 1L
                        while (buffer.size < limit && source.read(buffer, limit - buffer.size) != -1L) { /* stream */ }
                        if (buffer.size > LogoSanitizer.MAX_DECODED_BYTES) {
                            return LogoLoad.Rejected(LogoRejection.TooLarge)
                        }
                        when (val r = LogoSanitizer.sanitizeBytes(buffer.readByteArray(), response.header("Content-Type"))) {
                            is LogoResult.Accepted -> LogoLoad.Loaded(r.logo as DisplayLogo.Image)
                            is LogoResult.Rejected -> LogoLoad.Rejected(r.reason)
                        }
                    }
                }
            }
        } catch (e: LogoPolicyException) {
            LogoLoad.Rejected(LogoRejection.InvalidUrl)
        } catch (e: IOException) {
            LogoLoad.Transient(e.javaClass.simpleName)
        }
    }

    companion object {
        const val DEFAULT_TIMEOUT_MILLIS = 10_000L
        const val MAX_TIMEOUT_MILLIS = 60_000L
    }
}
