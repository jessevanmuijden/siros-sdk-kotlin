// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

/**
 * The shape limits of the response-level `credential_metadata` of a Credential Response the wallet decrypted itself. The
 * engine used to enforce them (go-wallet-backend#463) before relaying; now that it cannot read the plaintext they are
 * enforced here, BEFORE anything is retained or handed to the receipt check:
 *
 * - at most [MAX_BYTES] of encoded JSON (UTF-8, as received),
 * - nesting depth at most [MAX_DEPTH] (the metadata object itself is depth 1; arrays count),
 * - at most [MAX_MEMBERS] members in any one object,
 * - member names of at most [MAX_KEY_BYTES] UTF-8 bytes,
 * - no duplicate member names at the top level of the metadata nor inside its `org.siros.secret_seed` object (elsewhere it is
 *   display data, kept as received).
 *
 * A scanner over the raw text, because a parsed tree has already lost duplicate names. Its messages name no value.
 */
internal object CredentialMetadataShape {
    const val MAX_BYTES = 1 shl 20
    const val MAX_DEPTH = 16
    const val MAX_MEMBERS = 256
    const val MAX_KEY_BYTES = 256

    /** Depth cap for the parts of the body outside the metadata, which have no business being deep. */
    private const val MAX_OTHER_DEPTH = 64
    private const val METADATA_MEMBER = "credential_metadata"
    private const val SEED_MEMBER = "org.siros.secret_seed"

    private class Violation(message: String) : Exception(message, null, false, false)

    /** The reason [body] (a decrypted Credential Response) must be refused, or null when its `credential_metadata` is within limits. */
    fun violation(body: String): String? = try {
        Scanner(body).scanBody()
        null
    } catch (v: Violation) {
        v.message
    }

    private class Scanner(private val s: String) {
        private var i = 0

        fun scanBody() {
            skipWs()
            if (peek() != '{') return fail("The credential response is not a JSON object")
            i++
            skipWs()
            if (peek() == '}') return
            while (true) {
                skipWs()
                val key = readString()
                skipWs()
                expect(':')
                skipWs()
                if (key == METADATA_MEMBER) {
                    val start = i
                    metadataValue(depth = 1, unique = true)
                    if (utf8Length(s, start, i) > MAX_BYTES) fail("The credential_metadata exceeds $MAX_BYTES bytes")
                } else {
                    skipValue(1)
                }
                skipWs()
                when (peek()) {
                    ',' -> i++
                    '}' -> return
                    else -> fail("The credential response is not valid JSON")
                }
            }
        }

        /** A value inside the metadata at [depth]; [unique] rejects duplicate member names of an object. */
        private fun metadataValue(depth: Int, unique: Boolean) {
            when (peek()) {
                '{' -> {
                    if (depth > MAX_DEPTH) fail("The credential_metadata nests deeper than $MAX_DEPTH")
                    i++
                    skipWs()
                    if (peek() == '}') { i++; return }
                    val seen = if (unique) HashSet<String>() else null
                    var members = 0
                    while (true) {
                        skipWs()
                        val key = readString()
                        if (utf8Length(key, 0, key.length) > MAX_KEY_BYTES) fail("A credential_metadata member name exceeds $MAX_KEY_BYTES bytes")
                        if (++members > MAX_MEMBERS) fail("A credential_metadata object has more than $MAX_MEMBERS members")
                        if (seen != null && !seen.add(key)) fail("The credential_metadata has a duplicate member name")
                        skipWs()
                        expect(':')
                        skipWs()
                        // Only the direct member of the top-level object that holds the seeds is checked for duplicates too.
                        metadataValue(depth + 1, unique = depth == 1 && key == SEED_MEMBER)
                        skipWs()
                        when (peek()) {
                            ',' -> i++
                            '}' -> { i++; return }
                            else -> fail("The credential response is not valid JSON")
                        }
                    }
                }
                '[' -> {
                    if (depth > MAX_DEPTH) fail("The credential_metadata nests deeper than $MAX_DEPTH")
                    i++
                    skipWs()
                    if (peek() == ']') { i++; return }
                    while (true) {
                        skipWs()
                        metadataValue(depth + 1, unique = false)
                        skipWs()
                        when (peek()) {
                            ',' -> i++
                            ']' -> { i++; return }
                            else -> fail("The credential response is not valid JSON")
                        }
                    }
                }
                else -> skipScalar()
            }
        }

        /** A value outside the metadata: only its extent matters, with a generous depth cap. */
        private fun skipValue(depth: Int) {
            if (depth > MAX_OTHER_DEPTH) fail("The credential response nests too deeply")
            when (peek()) {
                '{' -> {
                    i++
                    skipWs()
                    if (peek() == '}') { i++; return }
                    while (true) {
                        skipWs()
                        readString()
                        skipWs()
                        expect(':')
                        skipWs()
                        skipValue(depth + 1)
                        skipWs()
                        when (peek()) {
                            ',' -> i++
                            '}' -> { i++; return }
                            else -> fail("The credential response is not valid JSON")
                        }
                    }
                }
                '[' -> {
                    i++
                    skipWs()
                    if (peek() == ']') { i++; return }
                    while (true) {
                        skipWs()
                        skipValue(depth + 1)
                        skipWs()
                        when (peek()) {
                            ',' -> i++
                            ']' -> { i++; return }
                            else -> fail("The credential response is not valid JSON")
                        }
                    }
                }
                else -> skipScalar()
            }
        }

        private fun skipScalar() {
            if (peek() == '"') {
                readString()
                return
            }
            val start = i
            while (i < s.length && s[i] !in ",]} \t\r\n") i++
            if (i == start) fail("The credential response is not valid JSON")
        }

        /** A JSON string, decoded (escapes resolved) so name lengths and duplicates are judged on the real name. */
        private fun readString(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                if (i >= s.length) fail("The credential response is not valid JSON")
                val c = s[i++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        if (i >= s.length) fail("The credential response is not valid JSON")
                        when (val e = s[i++]) {
                            '"', '\\', '/' -> sb.append(e)
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (i + 4 > s.length) fail("The credential response is not valid JSON")
                                val code = s.substring(i, i + 4).toIntOrNull(16) ?: fail("The credential response is not valid JSON")
                                sb.append(code.toChar())
                                i += 4
                            }
                            else -> fail("The credential response is not valid JSON")
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        private fun skipWs() {
            while (i < s.length && s[i] in " \t\r\n") i++
        }

        private fun peek(): Char = if (i < s.length) s[i] else '\u0000'

        private fun expect(c: Char) {
            if (peek() != c) fail("The credential response is not valid JSON")
            i++
        }

        private fun fail(message: String): Nothing = throw Violation(message)
    }

    /** UTF-8 byte length of `s[from, to)` without allocating. */
    private fun utf8Length(s: String, from: Int, to: Int): Int {
        var n = 0
        var k = from
        while (k < to) {
            val c = s[k]
            n += when {
                c.code < 0x80 -> 1
                c.code < 0x800 -> 2
                c.isHighSurrogate() && k + 1 < to && s[k + 1].isLowSurrogate() -> { k++; 4 }
                else -> 3
            }
            k++
        }
        return n
    }
}
