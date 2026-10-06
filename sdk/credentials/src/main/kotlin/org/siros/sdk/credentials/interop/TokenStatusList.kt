// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.interop

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import timber.log.Timber
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.Inflater

/**
 * IETF Token Status List - the revocation mechanism DIIP requires.
 *
 * A credential carries a `status.status_list` reference: an index plus the URI
 * of a Status List Token. That token is a JWS (`typ: statuslist+jwt`) whose
 * payload holds a zlib-compressed bit array; the bits at the credential's
 * index encode its status.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/15/">draft-ietf-oauth-status-list-15</a>
 */
object TokenStatusList {

    /** The entry widths the draft allows, in bits. */
    val ENTRY_WIDTHS = setOf(1, 2, 4, 8)

    /** Status values registered by the Token Status List draft. */
    object Status {
        const val VALID = 0x00
        const val INVALID = 0x01
        const val SUSPENDED = 0x02
    }

    /** The `status.status_list` object embedded in a credential. */
    data class Reference(val idx: Int, val uri: String)

    /** What a status lookup produced. */
    sealed class Resolution {
        /** The status bits found at the credential's index. */
        data class Found(val status: Int) : Resolution()

        /**
         * The status could not be established - typically an unreachable
         * list. A caller must treat this as a warning, not a revocation: a
         * wallet that hid every credential whose status endpoint is down
         * would be unusable offline.
         */
        data class Unavailable(val reason: String) : Resolution()
    }

    /**
     * A fetched status list, remembered so one list is fetched once per
     * session rather than once per credential that points at it.
     *
     * @param ttlSeconds the token's own `ttl`; 0 or absent means the entry is
     *        kept for the lifetime of the cache.
     */
    data class CacheEntry(
        val fetchedAtMillis: Long,
        val ttlSeconds: Long,
        val bits: Int,
        val list: ByteArray,
        /**
         * The issuer this token was authenticated for. A cached list must not
         * be handed to a credential from a different issuer: the `iss` check
         * happens on fetch, so reusing the entry across issuers - or reusing
         * an entry first fetched with no expected issuer - would bypass it.
         */
        val issuer: String? = null,
        /**
         * The token's own `exp`, in epoch millis. Enforced on every cache hit:
         * with no `ttl` the entry would otherwise be served for the life of
         * the process, long past the point where the issuer expected it to be
         * re-fetched, and would miss every revocation published since.
         */
        val expiresAtMillis: Long? = null,
    ) {
        // ByteArray needs these spelled out for a data class to compare by value.
        override fun equals(other: Any?): Boolean =
            this === other || (other is CacheEntry &&
                fetchedAtMillis == other.fetchedAtMillis &&
                ttlSeconds == other.ttlSeconds &&
                bits == other.bits &&
                issuer == other.issuer &&
                expiresAtMillis == other.expiresAtMillis &&
                list.contentEquals(other.list))

        override fun hashCode(): Int =
            ((((fetchedAtMillis.hashCode() * 31 + ttlSeconds.hashCode()) * 31 + bits) * 31 +
                issuer.hashCode()) * 31 + expiresAtMillis.hashCode()) * 31 + list.contentHashCode()
    }

    /** Read the Status List reference out of a credential's claims, if it has one. */
    fun extractReference(claims: JsonObject): Reference? {
        val statusList = (claims["status"] as? JsonObject)?.get("status_list") as? JsonObject ?: return null
        val idx = (statusList["idx"] as? JsonPrimitive)?.intOrNull ?: return null
        val uri = (statusList["uri"] as? JsonPrimitive)?.contentOrNull ?: return null
        if (idx < 0 || uri.isEmpty()) return null
        return Reference(idx, uri)
    }

    /**
     * Read the status at [idx] from a decompressed status list.
     *
     * Entries are packed [bits] at a time, least significant bits first
     * within each byte. Returns null when [bits] is not a legal width or the
     * index lies past the end of the list.
     */
    fun readStatusAtIndex(list: ByteArray, bits: Int, idx: Int): Int? {
        if (bits !in ENTRY_WIDTHS) return null
        if (idx < 0) return null
        val entriesPerByte = 8 / bits
        val byteIndex = idx / entriesPerByte
        if (byteIndex >= list.size) return null
        val shift = (idx % entriesPerByte) * bits
        val mask = (1 shl bits) - 1
        return (list[byteIndex].toInt() and 0xFF shr shift) and mask
    }

    /**
     * Hard cap on the inflated list, so a malformed or hostile stream cannot be
     * expanded into unbounded memory. A status list covering a million
     * credentials at one bit each is 125 KB, so this is far above anything
     * legitimate - and the bytes come from a URL the credential names, which is
     * not this wallet's to trust. Matches the Swift SDK's `Inflate`.
     */
    const val MAX_INFLATED_BYTES: Int = 64 * 1024 * 1024

    /**
     * Inflate the zlib-compressed `lst` member.
     *
     * The draft says DEFLATE with a zlib wrapper; a few issuers emit raw
     * DEFLATE instead, so a failed zlib pass is retried without the wrapper
     * rather than reported as a corrupt list.
     *
     * Bounded by [MAX_INFLATED_BYTES]: a small compressed payload can expand
     * without limit, and this runs on a credential refresh with whatever the
     * issuer's status-list URL served.
     */
    fun inflate(compressed: ByteArray): ByteArray? {
        for (nowrap in listOf(false, true)) {
            val inflater = Inflater(nowrap)
            try {
                inflater.setInput(compressed)
                val out = ByteArrayOutputStream(minOf(compressed.size * 4, MAX_INFLATED_BYTES))
                val buffer = ByteArray(8192)
                var overflowed = false
                while (!inflater.finished()) {
                    val n = inflater.inflate(buffer)
                    if (n == 0) {
                        if (inflater.needsInput() || inflater.needsDictionary()) break
                    }
                    if (out.size() + n > MAX_INFLATED_BYTES) {
                        Timber.w("Status list inflated past $MAX_INFLATED_BYTES bytes; refusing it")
                        overflowed = true
                        break
                    }
                    out.write(buffer, 0, n)
                }
                if (overflowed) return null
                if (inflater.finished()) return out.toByteArray()
            } catch (e: java.util.zip.DataFormatException) {
                Timber.d(e, "Status list did not inflate with nowrap=$nowrap")
            } finally {
                inflater.end()
            }
        }
        return null
    }
}

/**
 * Fetches, verifies and reads Status List Tokens.
 *
 * Holds the per-session cache, so construct one per wallet session and share
 * it across credentials: a list covering ten thousand credentials is fetched
 * once, not once per credential that points into it.
 *
 * @param httpGet fetches a URL, returning the body or null - the same
 *        injection point as [org.siros.sdk.credentials.VctmFetcher], so a
 *        host's own client, pinning and caching apply here too.
 * @param resolveIssuerKey resolves the Status List Token's signing key, given
 *        the token's issuer identifier and its header `kid`. Key resolution is
 *        always delegated this way: a certificate chain in the token header is
 *        deliberately not honoured - see [verifySignature] for why. A
 *        DID-identified issuer is answered through [DidResolver]; anything
 *        else is the host's to answer.
 * @param nowMillis time source, overridable for deterministic tests.
 */
class TokenStatusListClient(
    private val httpGet: suspend (String, Map<String, String>) -> String?,
    private val resolveIssuerKey: (suspend (issuer: String, kid: String?) -> JWK?)? = null,
    private val nowMillis: () -> Long = { System.currentTimeMillis() },
) {
    // A wallet shares one client across credentials and may refresh statuses
    // from more than one coroutine at a time, so this is read and written
    // concurrently from a public suspend API.
    private val cache = java.util.concurrent.ConcurrentHashMap<String, TokenStatusList.CacheEntry>()

    /**
     * Look up one credential's entry.
     *
     * @param expectedIssuer the issuer of the credential being checked. The
     *        Status List Token's `iss` must match it - otherwise anyone able
     *        to serve a URL could publish a status list for someone else's
     *        credentials. Null skips the check, which is only safe when the
     *        caller has no issuer to compare against.
     * @param clockToleranceSeconds leeway applied to the token's own `exp`
     *        and `nbf`, matching the tolerance used for signature checks.
     */
    suspend fun resolve(
        reference: TokenStatusList.Reference,
        expectedIssuer: String? = null,
        clockToleranceSeconds: Long = 0,
    ): TokenStatusList.Resolution {
        cache[reference.uri]?.let { entry ->
            val now = nowMillis()
            val withinTtl = entry.ttlSeconds <= 0 || now - entry.fetchedAtMillis < entry.ttlSeconds * 1000
            // The `iss` check ran when this entry was fetched, and it only
            // authenticated the token for THAT issuer. A different one - or an
            // entry first fetched without an expected issuer - has to go back
            // to the network rather than inherit that decision.
            val sameIssuer = entry.issuer == expectedIssuer
            val unexpired = entry.expiresAtMillis?.let { it + clockToleranceSeconds * 1000 >= now } ?: true
            if (withinTtl && sameIssuer && unexpired) {
                return TokenStatusList.readStatusAtIndex(entry.list, entry.bits, reference.idx)
                    ?.let { TokenStatusList.Resolution.Found(it) }
                    ?: TokenStatusList.Resolution.Unavailable(
                        "Index ${reference.idx} is outside the cached status list",
                    )
            }
        }

        val token = runCatching {
            httpGet(reference.uri, mapOf("Accept" to "application/statuslist+jwt"))
        }.getOrNull()?.trim()
            ?: return TokenStatusList.Resolution.Unavailable("Could not fetch the status list at ${reference.uri}")

        val jwt = runCatching { SignedJWT.parse(token) }.getOrNull()
            ?: return TokenStatusList.Resolution.Unavailable("Status list at ${reference.uri} is not a JWS")

        // §5.1: the token is typed so it cannot be confused with any other
        // JWS the same issuer signs.
        val typ = jwt.header.type?.toString()
        if (typ != "statuslist+jwt") {
            return TokenStatusList.Resolution.Unavailable("Unexpected Status List Token typ: $typ")
        }

        val claims = runCatching { jwt.jwtClaimsSet }.getOrNull()
            ?: return TokenStatusList.Resolution.Unavailable("Status List Token has no claims")

        val issuer = claims.issuer
        if (expectedIssuer != null && issuer != expectedIssuer) {
            return TokenStatusList.Resolution.Unavailable(
                "Status List Token was issued by $issuer, expected $expectedIssuer",
            )
        }
        // §5.1: `sub` binds the token to the URI it was served from.
        val subject = claims.subject
        if (subject != null && subject != reference.uri) {
            return TokenStatusList.Resolution.Unavailable(
                "Status List Token subject $subject does not match ${reference.uri}",
            )
        }

        val verified = runCatching { verifySignature(jwt, issuer) }.getOrElse { e ->
            return TokenStatusList.Resolution.Unavailable("Status List Token signature check failed: ${e.message}")
        }
        if (!verified) {
            return TokenStatusList.Resolution.Unavailable("Status List Token signature is not valid")
        }

        val now = nowMillis()
        val toleranceMillis = clockToleranceSeconds * 1000
        claims.expirationTime?.let {
            if (it.time + toleranceMillis < now) {
                return TokenStatusList.Resolution.Unavailable("Status List Token expired at $it")
            }
        }
        claims.notBeforeTime?.let {
            if (it.time - toleranceMillis > now) {
                return TokenStatusList.Resolution.Unavailable("Status List Token is not valid before $it")
            }
        }

        @Suppress("UNCHECKED_CAST")
        val statusList = claims.getClaim("status_list") as? Map<String, Any?>
            ?: return TokenStatusList.Resolution.Unavailable("Status List Token has no status_list claim")
        // Exactly, not `toInt()`: that truncates, so a published width of 1.5
        // would be read as 1 and pass the check below. `bits` decides how the
        // list is carved up, so a wrong width reads the wrong credential's
        // status.
        val bits = exactEntryWidth(statusList["bits"])
            ?: return TokenStatusList.Resolution.Unavailable("Status List Token declares no entry width")
        // Checked here rather than left to readStatusAtIndex, which can only
        // report "no status at this index" - a misleading thing to tell
        // someone debugging an issuer that published an illegal width.
        if (bits !in TokenStatusList.ENTRY_WIDTHS) {
            return TokenStatusList.Resolution.Unavailable(
                "Status List Token declares an entry width of $bits bits; the draft allows ${TokenStatusList.ENTRY_WIDTHS.joinToString()}",
            )
        }
        val lst = statusList["lst"] as? String
            ?: return TokenStatusList.Resolution.Unavailable("Status List Token carries no list")

        val inflated = runCatching { Base64.getUrlDecoder().decode(lst) }.getOrNull()
            ?.let { TokenStatusList.inflate(it) }
            ?: return TokenStatusList.Resolution.Unavailable("Status list could not be decompressed")

        val ttl = (statusList["ttl"] as? Number)?.toLong() ?: (claims.getClaim("ttl") as? Number)?.toLong() ?: 0L
        cache[reference.uri] = TokenStatusList.CacheEntry(
            fetchedAtMillis = now,
            ttlSeconds = ttl,
            bits = bits,
            list = inflated,
            issuer = expectedIssuer,
            expiresAtMillis = claims.expirationTime?.time,
        )

        return TokenStatusList.readStatusAtIndex(inflated, bits, reference.idx)
            ?.let { TokenStatusList.Resolution.Found(it) }
            ?: TokenStatusList.Resolution.Unavailable("Index ${reference.idx} is outside the status list")
    }

    /**
     * `bits` as an exact non-negative Int, or null when it is not an integer.
     *
     * The value comes from the Status List Token, which is not this wallet's
     * to trust before it has been verified - and a truncated width is worse
     * than a rejected one, since it still passes the legal-width check and
     * then reads the list wrongly.
     */
    internal fun exactEntryWidth(value: Any?): Int? = when (value) {
        is Int -> value
        is Long -> value.toInt().takeIf { it.toLong() == value }
        is Short, is Byte -> (value as Number).toInt()
        // BigInteger.intValueExact is API 31 and this SDK's minSdk is 28, so
        // the round trip through Int does the same job.
        is java.math.BigInteger -> value.toInt().takeIf { java.math.BigInteger.valueOf(it.toLong()) == value }
        is Number -> value.toDouble().takeIf { it == Math.floor(it) && !it.isInfinite() }?.toInt()
        else -> null
    }

    /**
     * Verify the token's signature with the key the Issuer published.
     *
     * Only that key. An `x5c` chain inside the token is just bytes the token
     * carries about itself: this reader has no trust anchors to validate it
     * against, so accepting one would let anyone able to serve the status list
     * URI sign whatever status they liked with a self-signed certificate, and
     * the Issuer's real key would never be consulted. That is a revocation
     * bypass, not a convenience.
     *
     * Which key an Issuer published is a trust decision, and it is made where
     * every other one is: [resolveIssuerKey] routes it to go-trust through the
     * backend. A token this reader cannot authenticate yields an unavailable
     * status - never a valid one.
     */
    private suspend fun verifySignature(jwt: SignedJWT, issuer: String?): Boolean {
        val resolver = resolveIssuerKey
        if (issuer == null || resolver == null) {
            throw IllegalStateException("no issuer key resolver available for the Status List Token")
        }
        val key = runCatching { resolver.invoke(issuer, jwt.header.keyID) }.getOrNull()
            ?: throw IllegalStateException("no published signing key for $issuer")

        val verifier = when (key) {
            is ECKey -> ECDSAVerifier(key.toECPublicKey())
            is RSAKey -> RSASSAVerifier(key.toRSAPublicKey())
            else -> throw IllegalStateException("unsupported Status List Token key type ${key.keyType}")
        }
        require(jwt.header.algorithm != JWSAlgorithm.NONE) { "unsecured Status List Token" }
        return jwt.verify(verifier)
    }
}
