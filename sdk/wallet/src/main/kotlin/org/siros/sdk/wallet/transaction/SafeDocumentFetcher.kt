// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import timber.log.Timber
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit

/**
 * Fetches a document whose URL an issuer or verifier chose (type metadata,
 * `schema_uri`, `claims_uri`, `ui_labels_uri`), without letting that party
 * aim the wallet at anything but a public HTTPS server.
 *
 * - A **fresh** client: no interceptors, cookie jar or authenticator, so
 *   nothing of the app's (tokens, tenant headers, cookies) can be attached.
 * - HTTPS only, no `user:password@` in the URL, no IP-literal host.
 * - A pinned [Dns] that refuses any name resolving to a non-public address
 *   (loopback, link-local such as 169.254.169.254, RFC 1918, CGNAT, ULA,
 *   multicast, unspecified, and IPv4-mapped forms of those). OkHttp connects
 *   to the very addresses this resolver returned, so there is no
 *   check-then-resolve-again gap.
 * - **No redirects** at all: a 3xx answer is a failure, so a public host cannot
 *   bounce the wallet to an internal one.
 * - A size cap and a wall-clock limit; any failure is `null` (the pipeline
 *   refuses on `null`, never skips).
 *
 * @param dns the resolver to pin; replaceable for tests.
 * @param allowInsecureHttp tests only: permit `http://`.
 * @param allowNonPublicAddresses tests only: permit loopback/private targets
 *   (a local mock server).
 */
internal class SafeDocumentFetcher(
    private val dns: Dns = Dns.SYSTEM,
    private val allowInsecureHttp: Boolean = false,
    private val allowNonPublicAddresses: Boolean = false,
    private val maxBytes: Long = MAX_DOCUMENT_BYTES,
    private val timeoutSeconds: Long = TIMEOUT_SECONDS,
) {
    /** The client used for every fetch; exposed so tests can assert it carries nothing of the app's. */
    internal fun buildClient(): OkHttpClient = OkHttpClient.Builder()
        .dns(if (allowNonPublicAddresses) dns else PublicOnlyDns(dns))
        .followRedirects(false)
        .followSslRedirects(false)
        .callTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .build()

    suspend fun get(uri: String): String? = withContext(Dispatchers.IO) {
        val url = fetchableUrl(uri) ?: return@withContext null
        try {
            buildClient().newCall(Request.Builder().url(url).get().build()).execute().use { response ->
                if (!response.isSuccessful) return@use null // includes every 3xx: redirects are not followed
                val source = response.body?.source() ?: return@use null
                // Read one byte past the cap to tell "exactly at" from "over".
                source.request(maxBytes + 1)
                if (source.buffer.size > maxBytes) return@use null
                source.readUtf8()
            }
        } catch (e: java.io.IOException) {
            Timber.w("Document fetch failed (${e.javaClass.simpleName})")
            null
        }
    }

    /** [uri] parsed, if it is a URL this fetcher may even try: https, no userinfo, no IP-literal host. */
    private fun fetchableUrl(uri: String): okhttp3.HttpUrl? {
        val url = uri.toHttpUrlOrNull() ?: return null
        val refused = (!url.isHttps && !allowInsecureHttp) ||
            url.username.isNotEmpty() || url.password.isNotEmpty() ||
            (!allowNonPublicAddresses && isIpLiteral(url.host))
        return if (refused) null else url
    }

    /** Resolves through [delegate] and refuses the whole answer if any address is not public. */
    internal class PublicOnlyDns(private val delegate: Dns) : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            val addresses = delegate.lookup(hostname)
            if (addresses.isEmpty() || addresses.any { !isPublic(it) }) {
                throw UnknownHostException("$hostname does not resolve to a public address")
            }
            return addresses
        }
    }

    companion object {
        /** Largest document accepted (a schema or label catalogue is a few KiB). */
        const val MAX_DOCUMENT_BYTES = 256L * 1024

        /** Wall-clock limit for one document fetch. */
        const val TIMEOUT_SECONDS = 10L

        /** Whether [host] is an IPv4 or IPv6 literal rather than a name. */
        fun isIpLiteral(host: String): Boolean =
            host.contains(':') || host.all { it.isDigit() || it == '.' } ||
                // IPv4 in hex/octal-ish dotted forms some stacks accept
                host.split('.').all { it.startsWith("0x", ignoreCase = true) || (it.isNotEmpty() && it.all(Char::isDigit)) }

        /** Whether [a] is a routable public address. */
        fun isPublic(a: InetAddress): Boolean {
            if (a.isAnyLocalAddress || a.isLoopbackAddress || a.isLinkLocalAddress ||
                a.isSiteLocalAddress || a.isMulticastAddress
            ) return false
            val b = a.address
            return when (a) {
                is Inet4Address -> {
                    val b0 = b[0].toInt() and 0xff
                    val b1 = b[1].toInt() and 0xff
                    !(b0 == 0 || (b0 == 100 && b1 in 64..127) || b0 >= 240 || (b0 == 192 && b1 == 0 && (b[2].toInt() and 0xff) == 0) ||
                        (b0 == 198 && b1 in 18..19))
                }
                is Inet6Address -> {
                    val b0 = b[0].toInt() and 0xff
                    // fc00::/7 unique local; fec0::/10 site local; ::ffff:0:0/96 mapped is unwrapped by InetAddress for v4
                    (b0 and 0xfe) != 0xfc && !(b0 == 0xfe && (b[1].toInt() and 0xc0) == 0xc0) &&
                        !(b.take(10).all { it.toInt() == 0 } && (b[10].toInt() and 0xff) == 0xff && (b[11].toInt() and 0xff) == 0xff)
                }
                else -> false
            }
        }
    }
}
