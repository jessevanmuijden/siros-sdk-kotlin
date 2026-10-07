// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

/**
 * Detects an object with a repeated member name anywhere in a JSON text.
 *
 * `transaction_data` is shown to the user from this wallet's own decoding of
 * the entry, while the verifier acts on its own: if the two parsers resolve a
 * repeated key differently (first wins vs last wins) the user could confirm
 * one amount and the verifier execute another. kotlinx.serialization keeps
 * the last value without complaint, so duplicates are refused up front.
 * Names are compared after unescaping, so `"a"` and `"a"` collide.
 *
 * The text is assumed to be otherwise well formed (it is parsed properly
 * afterwards); on anything this scanner cannot follow it answers `true`,
 * which refuses the entry.
 */
internal object JsonDuplicateKeys {
    /** Deeper than any transaction_data entry needs; also keeps the parser that follows off the stack limit. */
    const val MAX_DEPTH = 64

    fun has(text: String): Boolean = try {
        val scanner = Scanner(text)
        scanner.skipWhitespace()
        val duplicate = scanner.value()
        scanner.skipWhitespace()
        duplicate || !scanner.atEnd()
    } catch (_: Exception) {
        // IllegalState, NumberFormat (a bad \u escape), IndexOutOfBounds...: cannot follow it.
        true
    } catch (_: StackOverflowError) {
        true
    }

    private class Scanner(private val s: String) {
        private var i = 0

        fun atEnd(): Boolean = i >= s.length

        fun skipWhitespace() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
        }

        /** Scans one value; returns true if a duplicate key was found inside it. */
        fun value(): Boolean {
            check(i < s.length)
            check(depth < MAX_DEPTH) { "nested too deeply" }
            return when (s[i]) {
                '{' -> obj()
                '[' -> array()
                '"' -> {
                    string()
                    false
                }
                else -> {
                    // number / true / false / null
                    val start = i
                    while (i < s.length && s[i] !in ",]} \t\n\r") i++
                    check(i > start)
                    false
                }
            }
        }

        private var depth = 0

        private fun obj(): Boolean {
            depth++
            try {
                return objBody()
            } finally {
                depth--
            }
        }

        private fun array(): Boolean {
            depth++
            try {
                return arrayBody()
            } finally {
                depth--
            }
        }

        private fun objBody(): Boolean {
            i++ // {
            val keys = HashSet<String>()
            var duplicate = false
            skipWhitespace()
            if (peek() == '}') {
                i++
                return false
            }
            while (true) {
                skipWhitespace()
                check(peek() == '"')
                if (!keys.add(string())) duplicate = true
                skipWhitespace()
                check(next() == ':')
                skipWhitespace()
                if (value()) duplicate = true
                skipWhitespace()
                when (next()) {
                    ',' -> continue
                    '}' -> return duplicate
                    else -> error("bad object")
                }
            }
        }

        private fun arrayBody(): Boolean {
            i++ // [
            var duplicate = false
            skipWhitespace()
            if (peek() == ']') {
                i++
                return false
            }
            while (true) {
                skipWhitespace()
                if (value()) duplicate = true
                skipWhitespace()
                when (next()) {
                    ',' -> continue
                    ']' -> return duplicate
                    else -> error("bad array")
                }
            }
        }

        /** Scans a string and returns its unescaped content. */
        private fun string(): String {
            i++ // opening quote
            val out = StringBuilder()
            while (true) {
                val c = next()
                when (c) {
                    '"' -> return out.toString()
                    '\\' -> when (val e = next()) {
                        '"', '\\', '/' -> out.append(e)
                        'b' -> out.append('\b')
                        'f' -> out.append('\u000C')
                        'n' -> out.append('\n')
                        'r' -> out.append('\r')
                        't' -> out.append('\t')
                        'u' -> {
                            check(i + 4 <= s.length)
                            out.append(s.substring(i, i + 4).toInt(16).toChar())
                            i += 4
                        }
                        else -> error("bad escape")
                    }
                    else -> out.append(c)
                }
            }
        }

        private fun peek(): Char {
            check(i < s.length)
            return s[i]
        }

        private fun next(): Char {
            check(i < s.length)
            return s[i++]
        }
    }
}
