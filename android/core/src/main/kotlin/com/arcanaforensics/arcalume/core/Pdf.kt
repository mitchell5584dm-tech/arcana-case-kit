package com.arcanaforensics.arcalume.core

import java.io.ByteArrayOutputStream
import java.util.Locale
import java.util.zip.Deflater

/**
 * A small PDF 1.4 writer: US Letter pages, the standard Helvetica and Courier fonts, lines,
 * filled boxes and JPEG images. Plain Kotlin so the exhibit packet is built and tested the
 * same way on the phone and on any JVM, with no network fonts and no third-party library.
 */
class Pdf(private val title: String, private val producer: String) {
    enum class Font(val res: String, val base: String) { REGULAR("F1", "Helvetica"), BOLD("F2", "Helvetica-Bold"), MONO("F3", "Courier") }

    class Image internal constructor(val id: Int, val width: Int, val height: Int, internal val jpeg: ByteArray, internal val components: Int)

    inner class Page internal constructor() {
        internal val ops = StringBuilder()
        internal val images = LinkedHashSet<Image>()

        fun text(x: Double, y: Double, s: String, font: Font = Font.REGULAR, size: Double = 10.0, gray: Double = 0.0) {
            ops.append("BT ").append(g(gray)).append(" g /").append(font.res).append(' ').append(n(size)).append(" Tf ")
                .append(n(x)).append(' ').append(n(y)).append(" Td (").append(escape(s)).append(") Tj ET\n")
        }

        fun line(x1: Double, y1: Double, x2: Double, y2: Double, width: Double = 0.5, gray: Double = 0.0) {
            ops.append(g(gray)).append(" G ").append(n(width)).append(" w ").append(n(x1)).append(' ').append(n(y1)).append(" m ")
                .append(n(x2)).append(' ').append(n(y2)).append(" l S\n")
        }

        fun box(x: Double, y: Double, w: Double, h: Double, fillGray: Double? = null, strokeGray: Double? = 0.0, width: Double = 0.75) {
            ops.append("q ")
            fillGray?.let { ops.append(g(it)).append(" g ") }
            strokeGray?.let { ops.append(g(it)).append(" G ").append(n(width)).append(" w ") }
            ops.append(n(x)).append(' ').append(n(y)).append(' ').append(n(w)).append(' ').append(n(h)).append(" re ")
            ops.append(when { fillGray != null && strokeGray != null -> "B"; fillGray != null -> "f"; else -> "S" }).append(" Q\n")
        }

        fun image(img: Image, x: Double, y: Double, w: Double, h: Double) {
            images += img
            ops.append("q ").append(n(w)).append(" 0 0 ").append(n(h)).append(' ').append(n(x)).append(' ').append(n(y)).append(" cm /Im").append(img.id).append(" Do Q\n")
        }
    }

    private val pages = ArrayList<Page>()
    private val imageList = ArrayList<Image>()

    val pageCount get() = pages.size

    fun newPage(): Page = Page().also { pages += it }
    fun page(i: Int): Page = pages[i]

    /** Adds a baseline or progressive JPEG; returns null if it is not a JPEG this can embed. */
    fun jpeg(bytes: ByteArray): Image? {
        val sof = jpegSize(bytes) ?: return null
        if (sof.third !in setOf(1, 3)) return null
        return Image(imageList.size + 1, sof.first, sof.second, bytes, sof.third).also { imageList += it }
    }

    fun bytes(createdPdfDate: String): ByteArray {
        val out = ByteArrayOutputStream()
        val offsets = ArrayList<Int>()
        fun obj(body: ByteArray) { offsets += out.size(); out.write("${offsets.size} 0 obj\n".latin1()); out.write(body); out.write("\nendobj\n".latin1()) }
        fun obj(body: String) = obj(body.latin1())

        out.write("%PDF-1.4\n%\u00e2\u00e3\u00cf\u00d3\n".latin1())
        // 1 catalog, 2 pages, 3-5 fonts, 6 info, then images, then page/content pairs.
        val firstImage = 7
        val firstPage = firstImage + imageList.size
        val kids = pages.indices.joinToString(" ") { "${firstPage + it * 2} 0 R" }
        obj("<< /Type /Catalog /Pages 2 0 R >>")
        obj("<< /Type /Pages /Kids [$kids] /Count ${pages.size} >>")
        for (f in Font.entries) obj("<< /Type /Font /Subtype /Type1 /BaseFont /${f.base} /Encoding /WinAnsiEncoding >>")
        obj("<< /Title (${escape(title)}) /Producer (${escape(producer)}) /Creator (${escape(producer)}) /CreationDate ($createdPdfDate) >>")
        for (img in imageList) {
            val cs = if (img.components == 1) "/DeviceGray" else "/DeviceRGB"
            val head = "<< /Type /XObject /Subtype /Image /Width ${img.width} /Height ${img.height} /ColorSpace $cs /BitsPerComponent 8 /Filter /DCTDecode /Length ${img.jpeg.size} >>\nstream\n"
            obj(head.latin1() + img.jpeg + "\nendstream".latin1())
        }
        val fontRes = Font.entries.mapIndexed { i, f -> "/${f.res} ${3 + i} 0 R" }.joinToString(" ")
        for ((i, p) in pages.withIndex()) {
            val contentId = firstPage + i * 2 + 1
            val xo = if (p.images.isEmpty()) "" else " /XObject << " + p.images.joinToString(" ") { "/Im${it.id} ${firstImage + it.id - 1} 0 R" } + " >>"
            obj("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 $W $H] /Resources << /Font << $fontRes >>$xo >> /Contents $contentId 0 R >>")
            val raw = p.ops.toString().latin1()
            val z = deflate(raw)
            obj("<< /Length ${z.size} /Filter /FlateDecode >>\nstream\n".latin1() + z + "\nendstream".latin1())
        }
        val xref = out.size()
        val sb = StringBuilder("xref\n0 ${offsets.size + 1}\n0000000000 65535 f \n")
        for (o in offsets) sb.append(String.format(Locale.ROOT, "%010d 00000 n \n", o))
        sb.append("trailer\n<< /Size ${offsets.size + 1} /Root 1 0 R /Info 6 0 R >>\nstartxref\n$xref\n%%EOF\n")
        out.write(sb.toString().latin1())
        return out.toByteArray()
    }

    companion object {
        const val W = 612.0
        const val H = 792.0

        private fun String.latin1() = toByteArray(Charsets.ISO_8859_1)
        private fun n(v: Double): String = if (v == Math.floor(v) && kotlin.math.abs(v) < 1e7) v.toLong().toString() else String.format(Locale.ROOT, "%.2f", v)
        private fun g(v: Double) = String.format(Locale.ROOT, "%.3f", v.coerceIn(0.0, 1.0))

        private fun deflate(b: ByteArray): ByteArray {
            val d = Deflater(Deflater.BEST_COMPRESSION)
            d.setInput(b); d.finish()
            val out = ByteArrayOutputStream()
            val buf = ByteArray(1 shl 14)
            while (!d.finished()) out.write(buf, 0, d.deflate(buf))
            d.end()
            return out.toByteArray()
        }

        /** Characters outside WinAnsi that have a close WinAnsi equivalent. */
        private val WINANSI_EXTRA = mapOf(
            '\u20AC' to 0x80, '\u201A' to 0x82, '\u0192' to 0x83, '\u201E' to 0x84, '\u2026' to 0x85, '\u2020' to 0x86, '\u2021' to 0x87,
            '\u02C6' to 0x88, '\u2030' to 0x89, '\u0160' to 0x8A, '\u2039' to 0x8B, '\u0152' to 0x8C, '\u017D' to 0x8E, '\u2018' to 0x91,
            '\u2019' to 0x92, '\u201C' to 0x93, '\u201D' to 0x94, '\u2022' to 0x95, '\u2013' to 0x96, '\u2014' to 0x97, '\u02DC' to 0x98,
            '\u2122' to 0x99, '\u0161' to 0x9A, '\u203A' to 0x9B, '\u0153' to 0x9C, '\u017E' to 0x9E, '\u0178' to 0x9F,
        )

        /** Maps text to WinAnsi codes; anything without an equivalent (emoji, non-Latin scripts) becomes '?'. */
        fun winAnsi(s: String): IntArray {
            val out = ArrayList<Int>(s.length)
            var i = 0
            while (i < s.length) {
                val c = s[i]
                when {
                    c == '\u200E' || c == '\u200F' || c == '\uFEFF' || c == '\u200B' || c == '\u200D' || c == '\uFE0F' -> {}
                    c == '\t' -> out += ' '.code
                    c == '\u00A0' || c == '\u202F' -> out += ' '.code
                    c.code in 0x20..0x7E || c.code in 0xA0..0xFF -> out += c.code
                    WINANSI_EXTRA.containsKey(c) -> out += WINANSI_EXTRA.getValue(c)
                    Character.isHighSurrogate(c) -> { out += '?'.code; i++ }
                    c.code < 0x20 -> {}
                    else -> out += '?'.code
                }
                i++
            }
            return out.toIntArray()
        }

        private fun escape(s: String): String {
            val sb = StringBuilder()
            for (code in winAnsi(s)) {
                when (code) {
                    '('.code, ')'.code, '\\'.code -> sb.append('\\').append(code.toChar())
                    else -> if (code < 0x80) sb.append(code.toChar()) else sb.append(String.format(Locale.ROOT, "\\%03o", code))
                }
            }
            return sb.toString()
        }

        // Standard Type 1 metrics (Adobe AFM) for codes 32..126; other codes use an average width.
        private val HELV = intArrayOf(278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,
            1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,
            333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584)
        private val HELV_BOLD = intArrayOf(278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,
            975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,
            333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,611,611,389,556,333,611,556,778,556,556,500,389,280,389,584)

        fun width(s: String, font: Font, size: Double): Double {
            var units = 0
            for (code in winAnsi(s)) {
                units += when (font) {
                    Font.MONO -> 600
                    Font.REGULAR -> if (code in 32..126) HELV[code - 32] else 556
                    Font.BOLD -> if (code in 32..126) HELV_BOLD[code - 32] else 611
                }
            }
            return units * size / 1000.0
        }

        /** Greedy word wrap to [maxWidth]; words longer than a line are broken. Keeps explicit newlines. */
        fun wrap(text: String, font: Font, size: Double, maxWidth: Double): List<String> {
            val out = ArrayList<String>()
            for (para in text.replace("\r\n", "\n").split('\n')) {
                if (para.isBlank()) { out += ""; continue }
                var line = StringBuilder()
                for (word0 in para.split(' ')) {
                    var word = word0
                    while (width(word, font, size) > maxWidth) {
                        if (line.isNotEmpty()) { out += line.toString(); line = StringBuilder() }
                        var k = word.length
                        while (k > 1 && width(word.substring(0, k), font, size) > maxWidth) k--
                        out += word.substring(0, k)
                        word = word.substring(k)
                    }
                    val cand = if (line.isEmpty()) word else "$line $word"
                    if (width(cand, font, size) <= maxWidth) line = StringBuilder(cand) else { out += line.toString(); line = StringBuilder(word) }
                }
                out += line.toString()
            }
            return out
        }

        /** Width, height and colour components from a JPEG's start-of-frame marker. */
        fun jpegSize(b: ByteArray): Triple<Int, Int, Int>? {
            if (b.size < 4 || (b[0].toInt() and 0xff) != 0xFF || (b[1].toInt() and 0xff) != 0xD8) return null
            var p = 2
            while (p + 9 < b.size) {
                if ((b[p].toInt() and 0xff) != 0xFF) { p++; continue }
                val m = b[p + 1].toInt() and 0xff
                if (m == 0xFF) { p++; continue }
                if (m == 0xD8 || m == 0x01 || m in 0xD0..0xD7) { p += 2; continue }
                val len = ((b[p + 2].toInt() and 0xff) shl 8) or (b[p + 3].toInt() and 0xff)
                if (m in 0xC0..0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC) {
                    val h = ((b[p + 5].toInt() and 0xff) shl 8) or (b[p + 6].toInt() and 0xff)
                    val w = ((b[p + 7].toInt() and 0xff) shl 8) or (b[p + 8].toInt() and 0xff)
                    val c = b[p + 9].toInt() and 0xff
                    return if (w > 0 && h > 0) Triple(w, h, c) else null
                }
                if (m == 0xDA || len < 2) return null
                p += 2 + len
            }
            return null
        }
    }
}
