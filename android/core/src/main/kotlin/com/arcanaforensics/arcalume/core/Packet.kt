package com.arcanaforensics.arcalume.core

import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Builds the exhibit packet (one PDF a clerk, judge, lawyer or the other side can read)
 * and the verification bundle (a ZIP of the untouched originals with SHA-256 sums, the
 * case manifest and the custody log, so anyone can check the packet against the files).
 *
 * The packet is laid out the way self-represented people are usually asked to file:
 * a cover page, an index of exhibits, a chronology, one tabbed section per exhibit with
 * its fingerprint and what its metadata says, page numbers and a stamp on every page,
 * and a fill-in declaration for authenticating the exhibits.
 */
object Packet {
    data class Input(
        val case: Case,
        val original: (Exhibit) -> ByteArray,
        /** A printable JPEG for an image exhibit (the app converts PNG/HEIC/WebP and applies rotation). */
        val printable: (Exhibit) -> ByteArray?,
        val ledgerHead: String,
        val ledgerEntries: Int,
        val tool: String,
        val now: Instant = Instant.now(),
        val zone: ZoneId = ZoneId.systemDefault(),
    )

    data class Built(val pdf: ByteArray, val pages: Int, val sha256: String)

    private const val M = 54.0            // margin
    private const val TOP = Pdf.H - 54.0
    private const val BOTTOM = 64.0
    private const val TEXT_W = Pdf.W - 2 * M

    private class Writer(val pdf: Pdf, val header: String) {
        lateinit var page: Pdf.Page
        var y = TOP
        var continued: String? = null

        fun newPage() {
            page = pdf.newPage()
            y = TOP
            continued?.let { label(it, Pdf.Font.BOLD, 9.0, gray = 0.35); y -= 4 }
        }

        fun need(h: Double) { if (y - h < BOTTOM) newPage() }

        fun label(s: String, font: Pdf.Font = Pdf.Font.REGULAR, size: Double = 10.0, x: Double = M, gray: Double = 0.0) {
            page.text(x, y - size, s, font, size, gray); y -= size + 3
        }

        fun para(s: String, font: Pdf.Font = Pdf.Font.REGULAR, size: Double = 10.0, indent: Double = 0.0, gray: Double = 0.0, after: Double = 6.0) {
            for (line in Pdf.wrap(s, font, size, TEXT_W - indent)) {
                need(size + 3)
                page.text(M + indent, y - size, line, font, size, gray)
                y -= size + 3
            }
            y -= after
        }

        fun rule(gray: Double = 0.6) { need(8.0); page.line(M, y - 3, Pdf.W - M, y - 3, 0.5, gray); y -= 9 }

        fun gap(h: Double) { y -= h }
    }

    fun build(input: Input, maxExhibits: Int = Int.MAX_VALUE): Built {
        val case = input.case.copy(exhibits = input.case.exhibits.take(maxExhibits))
        val pdf = Pdf("${case.displayTitle} - Exhibit packet", input.tool)
        val w = Writer(pdf, case.displayTitle)
        val local = DateTimeFormatter.ofPattern("MMMM d, yyyy").withZone(input.zone)
        val prepared = local.format(input.now)

        // ---- cover ----
        w.newPage()
        w.gap(110.0)
        w.page.box(M, w.y - 4, TEXT_W, 1.5, fillGray = 0.0, strokeGray = null)
        w.gap(22.0)
        if (case.court.isNotBlank()) w.para(case.court.uppercase(), Pdf.Font.BOLD, 12.0)
        w.para(case.displayTitle, Pdf.Font.BOLD, 22.0, after = 4.0)
        if (case.number.isNotBlank()) w.para("Case No. ${case.number}", Pdf.Font.REGULAR, 12.0)
        w.gap(18.0)
        w.para("EXHIBIT PACKET", Pdf.Font.BOLD, 28.0, after = 2.0)
        w.para("${case.exhibits.size} exhibit${if (case.exhibits.size != 1) "s" else ""}", Pdf.Font.REGULAR, 13.0)
        w.gap(18.0)
        if (case.party.isNotBlank()) w.para("Submitted by: ${case.party}", Pdf.Font.REGULAR, 12.0, after = 2.0)
        w.para("Prepared: $prepared", Pdf.Font.REGULAR, 12.0)
        w.gap(40.0)
        w.page.box(M, w.y - 4, TEXT_W, 1.5, fillGray = 0.0, strokeGray = null)
        w.gap(16.0)
        w.para("Every exhibit in this packet is listed with its SHA-256 fingerprint, a 64-character code computed from the exact bytes of the original file. " +
            "If even one byte of a file changes, its fingerprint changes. The original files and their fingerprints are kept in a separate verification bundle, " +
            "so anyone can confirm that what is printed here came from those files. The last page explains how to check.", size = 9.5, gray = 0.25)
        w.para("This packet was assembled with ${input.tool}, which runs on the phone without internet access. It reports what each file's own metadata says; " +
            "it does not certify that evidence is genuine or admissible. The court decides that.", size = 9.5, gray = 0.25)

        // ---- index ----
        w.newPage()
        w.para("INDEX OF EXHIBITS", Pdf.Font.BOLD, 16.0)
        val cols = doubleArrayOf(M, M + 52, M + 300, M + 390)
        fun indexHeader() {
            w.need(20.0)
            w.page.box(M, w.y - 15, TEXT_W, 16.0, fillGray = 0.9, strokeGray = null)
            for ((i, h) in listOf("Exhibit", "Description", "Date", "Fingerprint (start)").withIndex()) w.page.text(cols[i] + 3, w.y - 11, h, Pdf.Font.BOLD, 9.0)
            w.gap(20.0)
        }
        indexHeader()
        for ((i, e) in case.exhibits.withIndex()) {
            val desc = Pdf.wrap(e.title, Pdf.Font.REGULAR, 9.5, cols[2] - cols[1] - 8).take(3)
            val h = desc.size * 12.0 + 6
            if (w.y - h < BOTTOM) { w.newPage(); indexHeader() }
            w.page.text(cols[0] + 3, w.y - 10, label(i), Pdf.Font.BOLD, 9.5)
            desc.forEachIndexed { k, line -> w.page.text(cols[1] + 3, w.y - 10 - k * 12, line, Pdf.Font.REGULAR, 9.5) }
            w.page.text(cols[2] + 3, w.y - 10, shortDate(e.when_), Pdf.Font.REGULAR, 9.5)
            w.page.text(cols[3] + 3, w.y - 10, e.sha256.take(16), Pdf.Font.MONO, 9.0)
            w.gap(h)
            w.page.line(M, w.y + 2, Pdf.W - M, w.y + 2, 0.3, 0.75)
        }

        // ---- chronology ----
        val dated = case.exhibits.withIndex().filter { it.value.when_.isNotBlank() }.sortedBy { it.value.when_ }
        if (dated.isNotEmpty()) {
            w.gap(18.0)
            w.need(60.0)
            w.para("CHRONOLOGY", Pdf.Font.BOLD, 16.0)
            w.para("Exhibits in date order. A date entered by the person preparing the packet is marked \"stated\"; otherwise it is the date the file's own metadata gives.", size = 9.0, gray = 0.3)
            for ((i, e) in dated) {
                val src = if (e.eventDate.isNotBlank()) "stated" else "from file"
                w.para("${longDate(e.when_)}  -  ${label(i)}: ${e.title} ($src)", size = 10.0, after = 2.0)
            }
        }

        // ---- exhibits ----
        for ((i, e) in case.exhibits.withIndex()) {
            w.continued = null
            w.newPage()
            w.page.box(M, w.y - 46, TEXT_W, 46.0, fillGray = 0.12, strokeGray = null)
            w.page.text(M + 14, w.y - 31, label(i).uppercase(), Pdf.Font.BOLD, 22.0, gray = 1.0)
            w.gap(58.0)
            w.para(e.title, Pdf.Font.BOLD, 14.0, after = 4.0)
            if (e.description.isNotBlank()) w.para(e.description, size = 10.5)
            w.continued = "${label(i)} (continued) - ${e.title}"
            w.rule()
            details(w, e)
            content(w, e, input)
        }

        // ---- verification and declaration ----
        w.continued = null
        w.newPage()
        w.para("HOW TO VERIFY THESE EXHIBITS", Pdf.Font.BOLD, 16.0)
        w.para("The verification bundle that accompanies this packet holds each original file in the folder \"exhibits\" and a list of fingerprints in SHA256SUMS.txt. " +
            "To check a file, compute its SHA-256 and compare it with the list below:")
        w.para("Windows:   certutil -hashfile \"file name\" SHA256", Pdf.Font.MONO, 9.0, indent = 12.0, after = 1.0)
        w.para("Mac:       shasum -a 256 \"file name\"", Pdf.Font.MONO, 9.0, indent = 12.0, after = 1.0)
        w.para("Linux:     sha256sum \"file name\"", Pdf.Font.MONO, 9.0, indent = 12.0)
        for ((i, e) in case.exhibits.withIndex()) {
            w.need(28.0)
            w.para("${label(i)}  ${bundleName(i, e)}", Pdf.Font.BOLD, 9.0, after = 1.0)
            w.para(e.sha256, Pdf.Font.MONO, 8.5, indent = 12.0, after = 3.0)
        }
        w.gap(6.0)
        w.para("Custody log. Adding, numbering and exporting these exhibits was recorded in a hash-chained log (custody-log.jsonl in the bundle), " +
            "where every entry includes the fingerprint of the one before it, so an edited, reordered or deleted entry breaks the chain. At the time this packet was made the log had " +
            "${input.ledgerEntries} entr${if (input.ledgerEntries != 1) "ies" else "y"} and ended with:", size = 9.5)
        w.para(input.ledgerHead, Pdf.Font.MONO, 8.5, indent = 12.0)

        w.need(250.0)
        w.gap(8.0)
        w.para("DECLARATION AUTHENTICATING EXHIBITS", Pdf.Font.BOLD, 13.0)
        w.para("Template only, not legal advice. Courts word this differently; check your court's rules or self-help center and change it to match.", size = 8.5, gray = 0.35)
        val who = case.party.ifBlank { "______________________________" }
        w.para("I, $who, declare:")
        w.para("1.  I am a party to this case and have personal knowledge of the facts below.", indent = 12.0, after = 2.0)
        w.para("2.  Each exhibit listed in the index (${label(0)}${if (case.exhibits.size > 1) " through ${label(case.exhibits.size - 1)}" else ""}) is a true and accurate copy of the original file it names. " +
            "I obtained each one as described in its exhibit section, and I have not altered the originals.", indent = 12.0, after = 2.0)
        w.para("3.  The SHA-256 fingerprint printed for each exhibit was computed from the original file, which I can produce on request.", indent = 12.0, after = 10.0)
        w.para("I declare under penalty of perjury under the laws of ______________________ that the foregoing is true and correct.")
        w.gap(24.0)
        w.need(40.0)
        w.page.line(M, w.y, M + 220, w.y, 0.6); w.page.line(M + 280, w.y, Pdf.W - M, w.y, 0.6)
        w.gap(4.0)
        w.page.text(M, w.y - 9, "Signature", Pdf.Font.REGULAR, 9.0, 0.35); w.page.text(M + 280, w.y - 9, "Date", Pdf.Font.REGULAR, 9.0, 0.35)

        // ---- footers on every page ----
        val total = pdf.pageCount
        val left = listOfNotNull(case.displayTitle.take(60), case.number.takeIf { it.isNotBlank() }?.let { "No. $it" }).joinToString("  |  ")
        for (p in 0 until total) {
            val pg = pdf.page(p)
            pg.line(M, 46.0, Pdf.W - M, 46.0, 0.4, 0.7)
            pg.text(M, 34.0, left, Pdf.Font.REGULAR, 8.0, 0.35)
            val stamp = "${case.prefix}-${String.format(java.util.Locale.ROOT, "%06d", p + 1)}"
            val right = "Page ${p + 1} of $total"
            pg.text(Pdf.W - M - Pdf.width(right, Pdf.Font.REGULAR, 8.0), 34.0, right, Pdf.Font.REGULAR, 8.0, 0.35)
            pg.text(Pdf.W - M - Pdf.width(stamp, Pdf.Font.BOLD, 8.0), 24.0, stamp, Pdf.Font.BOLD, 8.0, 0.2)
        }
        val created = "D:" + DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(ZoneOffset.UTC).format(input.now) + "Z"
        val bytes = pdf.bytes(created)
        return Built(bytes, total, sha256Hex(bytes))
    }

    private fun details(w: Writer, e: Exhibit) {
        val rows = ArrayList<Pair<String, String>>()
        rows += "Original file" to e.fileName
        rows += "Added to case" to e.addedUtc
        if (e.eventDate.isNotBlank()) rows += "Date of event (stated)" to e.eventDate
        for (f in e.fields) rows += f.label to f.value
        e.chat?.let { c -> rows += "Messages" to "${c.messages}, ${c.first?.replace('T', ' ')} to ${c.last?.replace('T', ' ')}"; rows += "Participants" to c.participants.joinToString(", ") }
        val iso = Regex("^(\\d{4}-\\d{2}-\\d{2})T(\\d{2}:\\d{2}(:\\d{2})?)")
        for ((k, v0) in rows) {
            val v = iso.replace(v0) { "${it.groupValues[1]} ${it.groupValues[2]}" }
            val lines = Pdf.wrap(v, Pdf.Font.REGULAR, 9.5, TEXT_W - 130)
            w.need(lines.size * 12.0 + 2)
            w.page.text(M, w.y - 9.5, k, Pdf.Font.BOLD, 9.0, 0.25)
            lines.forEachIndexed { i, line -> w.page.text(M + 130, w.y - 9.5 - i * 12, line, Pdf.Font.REGULAR, 9.5) }
            w.gap(lines.size * 12.0 + 2)
        }
        w.need(28.0)
        w.page.text(M, w.y - 9.5, "SHA-256", Pdf.Font.BOLD, 9.0, 0.25)
        w.page.text(M + 130, w.y - 9.5, e.sha256.take(32), Pdf.Font.MONO, 9.0)
        w.page.text(M + 130, w.y - 21.5, e.sha256.drop(32), Pdf.Font.MONO, 9.0)
        w.gap(28.0)
        if (e.findings.isNotEmpty()) {
            w.gap(4.0)
            w.para("What the file's metadata shows", Pdf.Font.BOLD, 10.5, after = 3.0)
            for (f in e.findings) {
                val tag = when (f.level) { Finding.Level.OK -> "Confirmed"; Finding.Level.INFO -> "Note"; Finding.Level.WARN -> "Caution" }
                w.para("$tag: ${f.text}", size = 9.5, indent = 10.0, after = 3.0)
            }
        }
        w.rule()
    }

    private fun content(w: Writer, e: Exhibit, input: Input) {
        val bytes = input.original(e)
        if (e.kind.isImage || e.kind == Carve.Kind.TIFF) {
            val jpeg = input.printable(e)
            val img = jpeg?.let { w.pdf.jpeg(it) }
            if (img != null) {
                var avail = w.y - BOTTOM
                if (avail < 260) { w.newPage(); avail = w.y - BOTTOM }
                val scale = minOf(TEXT_W / img.width, avail / img.height)
                val dw = img.width * scale; val dh = img.height * scale
                w.page.box(M + (TEXT_W - dw) / 2 - 1, w.y - dh - 1, dw + 2, dh + 2, strokeGray = 0.6, width = 0.5)
                w.page.image(img, M + (TEXT_W - dw) / 2, w.y - dh, dw, dh)
                w.gap(dh + 8)
                return
            }
            w.para("This image could not be drawn here. The original file is in the verification bundle as ${bundleName(input.case.exhibits.indexOf(e), e)}.", gray = 0.3)
            return
        }
        val chat = runCatching { Chats.parse(e.fileName, bytes, input.zone) }.getOrNull()
        if (chat != null) {
            w.para("Transcript (${chat.messages.size} messages, in time order). Each line shows the date and time, the sender and the message as exported.", size = 9.0, gray = 0.3)
            var day = ""
            for (m in chat.messages) {
                val d = m.time.take(10)
                if (d != day) { day = d; w.need(30.0); w.gap(4.0); w.para(longDate(d), Pdf.Font.BOLD, 9.5, after = 2.0) }
                val head = "${m.time.substring(11, 16)}  ${m.sender}: "
                val lines = Pdf.wrap(head + m.text, Pdf.Font.REGULAR, 9.5, TEXT_W - 8)
                for ((k, line) in lines.withIndex()) {
                    w.need(12.5)
                    if (k == 0 && line.startsWith(head.trimEnd())) {
                        w.page.text(M + 4, w.y - 9.5, head, Pdf.Font.BOLD, 9.5)
                        w.page.text(M + 4 + Pdf.width(head, Pdf.Font.BOLD, 9.5), w.y - 9.5, line.removePrefix(head), Pdf.Font.REGULAR, 9.5)
                    } else w.page.text(M + 4, w.y - 9.5, line, Pdf.Font.REGULAR, 9.5)
                    w.gap(12.5)
                }
            }
            if (chat.messages.any { m -> Pdf.winAnsi(m.text).contains('?'.code) && !m.text.contains('?') }) {
                w.gap(4.0); w.para("Emoji and characters outside the Latin alphabet print as \"?\". The original export in the bundle has them exactly.", size = 8.5, gray = 0.35)
            }
            return
        }
        if (e.kind == Carve.Kind.TEXT || e.kind == Carve.Kind.EML || e.kind == Carve.Kind.XML || e.kind == Carve.Kind.HTML) {
            val text = bytes.toString(Charsets.UTF_8).removePrefix("\uFEFF")
            val shown = text.take(60_000)
            w.para("Text of the file:", Pdf.Font.BOLD, 9.5, after = 3.0)
            w.para(shown, Pdf.Font.MONO, 8.0)
            if (shown.length < text.length) w.para("Only the first 60,000 characters are printed. The complete file is in the verification bundle.", size = 8.5, gray = 0.35)
            return
        }
        w.para("This exhibit is a ${e.kind.label} and is not printed here. The original file is in the verification bundle as " +
            "${bundleName(input.case.exhibits.indexOf(e), e)}. Bring it on a device or USB drive if the court allows electronic exhibits.", gray = 0.25)
    }

    /** "Exhibit 1", "Exhibit 2", ... */
    fun label(i: Int) = "Exhibit ${i + 1}"

    fun bundleName(i: Int, e: Exhibit): String {
        val ext = e.fileName.substringAfterLast('.', "").lowercase().takeIf { it.length in 1..6 } ?: e.kind.ext
        val base = Evidence.safeName(e.title).substringBeforeLast(".$ext").take(50)
        return "exhibits/Exhibit-${String.format(java.util.Locale.ROOT, "%02d", i + 1)}-$base.$ext"
    }

    private fun shortDate(s: String): String = if (s.length >= 10) s.take(10) else s.ifBlank { "-" }

    private fun longDate(s: String): String = runCatching {
        val d = java.time.LocalDate.parse(s.take(10))
        d.format(DateTimeFormatter.ofPattern("EEEE, MMMM d, yyyy", java.util.Locale.US)) + (if (s.length >= 16 && s[10] == 'T') " " + s.substring(11, 16) else "")
    }.getOrDefault(s)

    /** The verification bundle: originals, sums, the case manifest, the custody log and the packet itself. */
    fun bundle(input: Input, packet: Built, ledgerBytes: ByteArray?, maxExhibits: Int = Int.MAX_VALUE): ByteArray {
        val case = input.case.copy(exhibits = input.case.exhibits.take(maxExhibits))
        val files = ArrayList<Pair<String, ByteArray>>()
        val sums = StringBuilder()
        for ((i, e) in case.exhibits.withIndex()) {
            val bytes = input.original(e)
            check(sha256Hex(bytes) == e.sha256) { "${label(i)} no longer matches its fingerprint" }
            val name = bundleName(i, e)
            files += name to bytes
            sums.append(e.sha256).append("  ").append(name).append('\n')
        }
        sums.append(packet.sha256).append("  exhibit-packet.pdf\n")
        val manifest = Json.obj(
            "tool" to input.tool, "created_utc" to DateTimeFormatter.ISO_INSTANT.format(input.now.truncatedTo(java.time.temporal.ChronoUnit.SECONDS)),
            "case" to case.toJson(), "packet_sha256" to packet.sha256, "packet_pages" to packet.pages,
            "ledger_head" to input.ledgerHead, "ledger_entries" to input.ledgerEntries,
        )
        val readme = """
            |VERIFICATION BUNDLE - ${case.displayTitle}${if (case.number.isNotBlank()) " (Case No. ${case.number})" else ""}
            |
            |exhibit-packet.pdf   The printable packet: index, chronology, every exhibit, declaration.
            |exhibits/            The original files, byte-for-byte as they were added.
            |SHA256SUMS.txt       The SHA-256 fingerprint of every file above.
            |case.json            The case, its exhibits and what each file's metadata showed.
            |custody-log.jsonl    The hash-chained custody log (each line's "prev" is the hash of the line before).
            |
            |To check every file at once on Mac or Linux, open a terminal in this folder and run:
            |    shasum -a 256 -c SHA256SUMS.txt
            |On Windows, check one file at a time:
            |    certutil -hashfile "exhibits\file name" SHA256
            |
            |Made with ${input.tool}. It reports what the files say about themselves and does not certify evidence.
            |""".trimMargin()
        val out = ArrayList<Pair<String, ByteArray>>()
        out += "README.txt" to readme.toByteArray(Charsets.UTF_8)
        out += "exhibit-packet.pdf" to packet.pdf
        out += "SHA256SUMS.txt" to sums.toString().toByteArray(Charsets.UTF_8)
        out += "case.json" to manifest.canonicalBytes()
        ledgerBytes?.let { out += "custody-log.jsonl" to it }
        out += files
        return Zip.write(out)
    }
}
