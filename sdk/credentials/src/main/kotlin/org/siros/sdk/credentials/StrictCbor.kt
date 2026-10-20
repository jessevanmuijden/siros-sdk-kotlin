// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

/**
 * A strict CBOR reader (RFC 8949), only as far as a `ZkpPresentation` needs: definite lengths only, no duplicate map key
 * at any level (keys are compared structurally, so a repeated key is refused even with identical values), no bytes after
 * the item, nesting at most [MAX_DEPTH] levels. Integers and lengths in non-shortest form are accepted: this is not a
 * canonicality check. A mirror of the matcher's reader, so the same bytes get the same verdict.
 */
internal sealed interface StrictCbor {
    class Uint(val value: Long, val overflow: Boolean = false) : StrictCbor {
        override fun equals(other: Any?) = other is Uint && other.value == value && other.overflow == overflow
        override fun hashCode() = value.hashCode()
    }

    /** A negative integer; two negative integers are not distinguished (as in the matcher's reader). */
    object Nint : StrictCbor

    class Bytes(val value: ByteArray) : StrictCbor {
        override fun equals(other: Any?) = other is Bytes && other.value.contentEquals(value)
        override fun hashCode() = value.contentHashCode()
    }

    data class Text(val value: String) : StrictCbor
    data class Arr(val items: List<StrictCbor>) : StrictCbor
    class Map(val entries: List<Pair<StrictCbor, StrictCbor>>) : StrictCbor {
        override fun equals(other: Any?) = other is Map && other.entries == entries
        override fun hashCode() = entries.hashCode()
    }

    data class Tag(val tag: Long, val item: StrictCbor) : StrictCbor
    data class Bool(val value: Boolean) : StrictCbor

    /** null, undefined, floats and other simple values, as their raw bytes. */
    class Other(val raw: ByteArray) : StrictCbor {
        override fun equals(other: Any?) = other is Other && other.raw.contentEquals(raw)
        override fun hashCode() = raw.contentHashCode()
    }

    enum class Failure { MALFORMED, INDEFINITE, TRAILING, DUPLICATE_KEY }

    class Failed(val failure: Failure) : Exception(null, null, false, false)

    companion object {
        const val MAX_DEPTH = 16

        /** The one item in [bytes], or the [Failure] of the first rule broken. */
        fun decode(bytes: ByteArray): Result<StrictCbor> = try {
            val reader = Reader(bytes)
            val item = reader.item(0)
            if (reader.pos != bytes.size) throw Failed(Failure.TRAILING)
            Result.success(item)
        } catch (e: Failed) {
            Result.failure(e)
        }
    }

    private class Reader(private val b: ByteArray) {
        var pos = 0
        private fun remaining() = b.size - pos

        private fun take(n: Int): ByteArray {
            if (n < 0 || n > remaining()) throw Failed(Failure.MALFORMED)
            return b.copyOfRange(pos, pos + n).also { pos += n }
        }

        private fun argument(info: Int): Pair<Long, Boolean> {
            val width = when (info) {
                in 0..23 -> return info.toLong() to false
                24 -> 1
                25 -> 2
                26 -> 4
                27 -> 8
                else -> throw Failed(Failure.MALFORMED)
            }
            val raw = take(width)
            var acc = 0L
            raw.forEach { acc = (acc shl 8) or (it.toLong() and 0xff) }
            // A value of 2^63 or more does not fit a Long: kept as an overflow marker (only ever compared, never used as a length).
            return acc to (width == 8 && acc < 0)
        }

        private fun length(arg: Pair<Long, Boolean>): Int {
            if (arg.second || arg.first < 0 || arg.first > Int.MAX_VALUE) throw Failed(Failure.MALFORMED)
            return arg.first.toInt()
        }

        fun item(depth: Int): StrictCbor {
            if (depth > MAX_DEPTH) throw Failed(Failure.MALFORMED)
            val initial = take(1)[0].toInt() and 0xff
            val major = initial shr 5
            val info = initial and 0x1f
            if (major == 7) {
                return when (info) {
                    20 -> Bool(false)
                    21 -> Bool(true)
                    in 28..31 -> throw Failed(Failure.MALFORMED)
                    else -> {
                        val width = when (info) { 24 -> 1; 25 -> 2; 26 -> 4; 27 -> 8; else -> 0 }
                        Other(byteArrayOf(initial.toByte()) + take(width))
                    }
                }
            }
            if (info == 31) throw Failed(if (major in 2..5) Failure.INDEFINITE else Failure.MALFORMED)
            val arg = argument(info)
            return when (major) {
                0 -> Uint(arg.first, arg.second)
                1 -> Nint
                2, 3 -> {
                    val bytes = take(length(arg))
                    if (major == 2) {
                        Bytes(bytes)
                    } else {
                        val decoder = Charsets.UTF_8.newDecoder()
                            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                        Text(try { decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString() } catch (e: java.nio.charset.CharacterCodingException) { throw Failed(Failure.MALFORMED) })
                    }
                }
                4 -> {
                    val len = length(arg)
                    // Every element takes at least a byte: refuse impossible lengths before allocating for them.
                    if (len > remaining()) throw Failed(Failure.MALFORMED)
                    Arr(List(len) { item(depth + 1) })
                }
                5 -> {
                    val len = length(arg)
                    if (len > remaining()) throw Failed(Failure.MALFORMED)
                    val out = ArrayList<Pair<StrictCbor, StrictCbor>>(len)
                    repeat(len) {
                        val key = item(depth + 1)
                        val value = item(depth + 1)
                        if (out.any { it.first == key }) throw Failed(Failure.DUPLICATE_KEY)
                        out.add(key to value)
                    }
                    Map(out)
                }
                else -> Tag(arg.first, item(depth + 1))
            }
        }
    }
}
