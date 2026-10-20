// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

/**
 * A JSON tree that keeps what a map-based decoder loses: repeated object member names (in order) and the exact kind of every
 * value. Used where a repeated member or a `null` must be refused, not folded into "last wins" or "absent".
 */
internal sealed interface StrictJson {
    class Obj(val members: List<Pair<String, StrictJson>>) : StrictJson
    class Arr(val items: List<StrictJson>) : StrictJson
    class Str(val value: String) : StrictJson
    class Bool(val value: Boolean) : StrictJson
    object Null : StrictJson
    class Num(val text: String) : StrictJson

    companion object {
        private const val MAX_DEPTH = 64

        /** The tree of [text] (RFC 8259: one value, nothing after it), or null when it is not JSON. */
        fun parse(text: String): StrictJson? = try {
            Parser(text).parseDocument()
        } catch (e: IllegalArgumentException) {
            null
        } catch (e: StackOverflowError) {
            null
        }
    }

    private class Parser(private val s: String) {
        private var i = 0

        fun parseDocument(): StrictJson {
            skipWs()
            val v = value(0)
            skipWs()
            require(i == s.length) { "trailing content" }
            return v
        }

        private fun skipWs() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
        }

        private fun value(depth: Int): StrictJson {
            require(depth <= MAX_DEPTH) { "too deep" }
            require(i < s.length) { "eof" }
            return when (s[i]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> Str(string())
                't' -> literal("true", Bool(true))
                'f' -> literal("false", Bool(false))
                'n' -> literal("null", Null)
                else -> number()
            }
        }

        private fun literal(word: String, v: StrictJson): StrictJson {
            require(s.startsWith(word, i)) { "bad literal" }
            i += word.length
            return v
        }

        private fun obj(depth: Int): StrictJson {
            i++ // {
            val members = ArrayList<Pair<String, StrictJson>>()
            skipWs()
            if (peek() == '}') { i++; return Obj(members) }
            while (true) {
                skipWs()
                require(peek() == '"') { "member name" }
                val k = string()
                skipWs()
                require(peek() == ':') { "colon" }
                i++
                skipWs()
                members.add(k to value(depth + 1))
                skipWs()
                when (peek()) {
                    ',' -> i++
                    '}' -> { i++; return Obj(members) }
                    else -> throw IllegalArgumentException("object")
                }
            }
        }

        private fun arr(depth: Int): StrictJson {
            i++ // [
            val items = ArrayList<StrictJson>()
            skipWs()
            if (peek() == ']') { i++; return Arr(items) }
            while (true) {
                skipWs()
                items.add(value(depth + 1))
                skipWs()
                when (peek()) {
                    ',' -> i++
                    ']' -> { i++; return Arr(items) }
                    else -> throw IllegalArgumentException("array")
                }
            }
        }

        private fun peek(): Char {
            require(i < s.length) { "eof" }
            return s[i]
        }

        private fun string(): String {
            i++ // opening quote
            val sb = StringBuilder()
            while (true) {
                require(i < s.length) { "unterminated string" }
                val c = s[i++]
                when {
                    c == '"' -> return sb.toString()
                    c < ' ' -> throw IllegalArgumentException("control character in string")
                    c == '\\' -> {
                        require(i < s.length) { "escape" }
                        when (val e = s[i++]) {
                            '"', '\\', '/' -> sb.append(e)
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000c')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                require(i + 4 <= s.length) { "unicode escape" }
                                val hex = s.substring(i, i + 4)
                                require(hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) { "unicode escape" }
                                sb.append(hex.toInt(16).toChar())
                                i += 4
                            }
                            else -> throw IllegalArgumentException("escape")
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        private fun number(): StrictJson {
            val m = NUMBER.matchAt(s, i) ?: throw IllegalArgumentException("number")
            i += m.value.length
            return Num(m.value)
        }

        private companion object {
            val NUMBER = Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")
        }
    }
}
