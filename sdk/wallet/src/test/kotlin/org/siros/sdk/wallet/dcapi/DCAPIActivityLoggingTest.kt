// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The DC API activity sits between the verifier and the wallet, so what it logs must never carry
 * a request or response body (a nonce, a presentation, a pseudonym), the verifier's origin or an error description or an error description.
 * The activity cannot run on the JVM, so this reads its source: no log call may interpolate a payload.
 */
class DCAPIActivityLoggingTest {
    private val source = File("src/main/kotlin/org/siros/sdk/wallet/dcapi/DCAPIGetCredentialActivity.kt")

    @Test
    fun noLogCallInterpolatesARequestOrResponsePayload() {
        assertTrue("missing ${source.path}", source.exists())
        val payload = Regex("""\$\{?[\w.?]*(requestJson|responseJson|errorJson|description|origin|callingOrigin|verifierId)\b(?!\.length)""")
        val offending = source.readLines().withIndex()
            .filter { (_, line) -> line.contains("Timber.") && !line.trimStart().startsWith("//") && payload.containsMatchIn(line) }
        assertTrue("payload or origin logged at: ${offending.map { it.index + 1 to it.value.trim() }}", offending.isEmpty())
    }

    /** Timber prints a throwable's message, and a DC API refusal's message names the verifier and why it was refused. */
    @Test
    fun noLogCallPassesAThrowable() {
        assertTrue("missing ${source.path}", source.exists())
        val throwable = Regex("""Timber\.\w\(\s*(e|ex|t|throwable|error|cause)\s*[,)]""")
        val offending = source.readLines().withIndex()
            .filter { (_, line) -> !line.trimStart().startsWith("//") && throwable.containsMatchIn(line) }
        assertTrue("throwable logged at: ${offending.map { it.index + 1 to it.value.trim() }}", offending.isEmpty())
    }

    private val wallet = File("src/main/kotlin/org/siros/sdk/wallet/SirosWallet.kt")

    /** The DC API request path in SirosWallet: the request handler, its circuit_zk branch and the trust call they share. */
    private fun dcApiSections(): List<Pair<String, List<String>>> {
        assertTrue("missing ${wallet.path}", wallet.exists())
        val lines = wallet.readLines()
        val declaration = Regex("""^    (private |internal )?(suspend )?fun \w""")
        return listOf("suspend fun handleDCAPIRequest(", "private suspend fun handleCircuitZkDcApi(", "private suspend fun evaluateTrustDirect(")
            .map { marker ->
                val start = lines.indexOfFirst { it.startsWith("    $marker") || it.startsWith("    ${marker.removePrefix("private ")}") }
                assertTrue("section not found: $marker", start >= 0)
                var end = start + 1
                while (end < lines.size && !declaration.containsMatchIn(lines[end])) end++
                marker to lines.subList(start, end).mapIndexed { n, l -> "${start + n + 1}: $l" }
            }
    }

    /** The verifier id, origin, client id, subject id and the pseudonym values stay out of the log in SirosWallet's DC API path. */
    @Test
    fun walletDcApiPathLogsNoVerifierIdentifierOrPseudonym() {
        val identifying = Regex("""\$\{?[\w.?]*(subjectId|origin|clientId|verifierId|verifierIdentity|psc|ssc|pseudonym\w*|resolutionSubjectId)\b""", RegexOption.IGNORE_CASE)
        val offending = dcApiSections().flatMap { (_, ls) ->
            ls.filter { it.contains("Timber.") && !it.substringAfter(": ").trimStart().startsWith("//") && identifying.containsMatchIn(it) }
        }
        assertTrue("identifier logged in the wallet's DC API path: $offending", offending.isEmpty())
    }

    /** A throwable's message can carry the verifier id or a refusal's text, so the DC API path logs a coarse outcome. */
    @Test
    fun walletDcApiPathLogCallsPassNoThrowable() {
        val throwable = Regex("""Timber\.\w\(\s*(e|ex|t|throwable|error|cause)\s*[,)]""")
        val offending = dcApiSections().flatMap { (_, ls) -> ls.filter { throwable.containsMatchIn(it) } }
        assertTrue("throwable logged in the wallet's DC API path: $offending", offending.isEmpty())
    }
}
