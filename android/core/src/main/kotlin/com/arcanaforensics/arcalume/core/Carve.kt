package com.arcanaforensics.arcalume.core

/**
 * File identification by content, not by name, using header signatures in the style of
 * Scalpel's carving configuration. Two jobs:
 *
 *  - [identify]: what a file really is, so a renamed file (a ".jpg" that is really a PDF,
 *    a ".txt" that is really a ZIP) is flagged before it goes into an exhibit packet.
 *  - [carveJpegs]: JPEG images embedded inside another file, such as the thumbnail in a
 *    photo's EXIF block or pictures inside a PDF or Word file. A thumbnail that does not
 *    match the main picture is a classic sign that a photo was cropped or edited.
 */
object Carve {
    enum class Kind(val label: String, val mime: String, val ext: String) {
        JPEG("JPEG image", "image/jpeg", "jpg"),
        PNG("PNG image", "image/png", "png"),
        GIF("GIF image", "image/gif", "gif"),
        WEBP("WebP image", "image/webp", "webp"),
        HEIC("HEIC image", "image/heic", "heic"),
        BMP("BMP image", "image/bmp", "bmp"),
        TIFF("TIFF image", "image/tiff", "tif"),
        PDF("PDF document", "application/pdf", "pdf"),
        DOCX("Word document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
        XLSX("Excel workbook", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"),
        PPTX("PowerPoint deck", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx"),
        ODF("OpenDocument file", "application/vnd.oasis.opendocument.text", "odt"),
        ZIP("ZIP archive", "application/zip", "zip"),
        OLE("Legacy Office document", "application/msword", "doc"),
        RTF("Rich text document", "application/rtf", "rtf"),
        MP4("MP4 video", "video/mp4", "mp4"),
        MOV("QuickTime video", "video/quicktime", "mov"),
        THREE_GP("3GP video", "video/3gpp", "3gp"),
        M4A("M4A audio", "audio/mp4", "m4a"),
        MP3("MP3 audio", "audio/mpeg", "mp3"),
        WAV("WAV audio", "audio/wav", "wav"),
        OGG("Ogg audio", "audio/ogg", "ogg"),
        AMR("AMR voice recording", "audio/amr", "amr"),
        SQLITE("SQLite database", "application/vnd.sqlite3", "db"),
        SEVEN_Z("7-Zip archive", "application/x-7z-compressed", "7z"),
        RAR("RAR archive", "application/vnd.rar", "rar"),
        ARCR("Arcalume vault", "application/octet-stream", "arcr"),
        EML("Email message", "message/rfc822", "eml"),
        HTML("Web page", "text/html", "html"),
        XML("XML document", "application/xml", "xml"),
        TEXT("Text file", "text/plain", "txt"),
        UNKNOWN("Unknown binary file", "application/octet-stream", "bin");

        val isImage get() = mime.startsWith("image/")
        val isOfficeZip get() = this == DOCX || this == XLSX || this == PPTX || this == ODF
    }

    /** Names a file may carry for each kind without being called a mismatch. */
    private val ALIASES: Map<Kind, Set<String>> = mapOf(
        Kind.JPEG to setOf("jpg", "jpeg", "jpe", "jfif"),
        Kind.TIFF to setOf("tif", "tiff", "dng"),
        Kind.HEIC to setOf("heic", "heif", "avif"),
        Kind.MP4 to setOf("mp4", "m4v"),
        Kind.MOV to setOf("mov", "qt"),
        Kind.THREE_GP to setOf("3gp", "3gpp", "3g2"),
        Kind.M4A to setOf("m4a", "aac", "m4b"),
        Kind.OGG to setOf("ogg", "oga", "opus"),
        Kind.OLE to setOf("doc", "xls", "ppt", "msg"),
        Kind.ODF to setOf("odt", "ods", "odp"),
        Kind.SQLITE to setOf("db", "sqlite", "sqlite3"),
        Kind.HTML to setOf("html", "htm"),
        Kind.TEXT to setOf("txt", "text", "csv", "log", "md", "json", "vcf"),
        Kind.XML to setOf("xml"),
        Kind.EML to setOf("eml", "txt"),
        Kind.ZIP to setOf("zip"),
    )

    private fun at(b: ByteArray, off: Int, vararg sig: Int): Boolean {
        if (off < 0 || b.size < off + sig.size) return false
        for (i in sig.indices) if ((b[off + i].toInt() and 0xff) != sig[i]) return false
        return true
    }

    private fun ascii(b: ByteArray, off: Int, s: String): Boolean =
        b.size >= off + s.length && s.indices.all { (b[off + it].toInt() and 0xff) == s[it].code }

    /** What [data] is, judged from its bytes alone. [zipNames] lists entries when it is a ZIP. */
    fun identify(data: ByteArray, zipNames: () -> List<String> = { Zip.names(data) }): Kind {
        val b = data
        return when {
            at(b, 0, 0xFF, 0xD8, 0xFF) -> Kind.JPEG
            at(b, 0, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) -> Kind.PNG
            ascii(b, 0, "GIF87a") || ascii(b, 0, "GIF89a") -> Kind.GIF
            ascii(b, 0, "RIFF") && ascii(b, 8, "WEBP") -> Kind.WEBP
            ascii(b, 0, "RIFF") && ascii(b, 8, "WAVE") -> Kind.WAV
            ascii(b, 0, "%PDF-") -> Kind.PDF
            ascii(b, 0, "ARCR") -> Kind.ARCR
            at(b, 0, 0x50, 0x4B, 0x03, 0x04) -> zipKind(zipNames())
            at(b, 0, 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1) -> Kind.OLE
            ascii(b, 0, "{\\rtf") -> Kind.RTF
            ascii(b, 4, "ftyp") -> ftypKind(if (b.size >= 12) String(b, 8, 4, Charsets.ISO_8859_1) else "")
            ascii(b, 0, "ID3") || at(b, 0, 0xFF, 0xFB) || at(b, 0, 0xFF, 0xF3) || at(b, 0, 0xFF, 0xF2) -> Kind.MP3
            ascii(b, 0, "OggS") -> Kind.OGG
            ascii(b, 0, "#!AMR") -> Kind.AMR
            ascii(b, 0, "SQLite format 3\u0000") -> Kind.SQLITE
            at(b, 0, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C) -> Kind.SEVEN_Z
            ascii(b, 0, "Rar!") -> Kind.RAR
            ascii(b, 0, "BM") && b.size > 26 && at(b, 6, 0, 0, 0, 0) -> Kind.BMP
            at(b, 0, 0x49, 0x49, 0x2A, 0x00) || at(b, 0, 0x4D, 0x4D, 0x00, 0x2A) -> Kind.TIFF
            else -> textKind(b)
        }
    }

    private fun zipKind(names: List<String>): Kind = when {
        names.any { it.startsWith("word/") } -> Kind.DOCX
        names.any { it.startsWith("xl/") } -> Kind.XLSX
        names.any { it.startsWith("ppt/") } -> Kind.PPTX
        names.contains("content.xml") && names.contains("mimetype") -> Kind.ODF
        else -> Kind.ZIP
    }

    private fun ftypKind(brand: String): Kind = when (brand.trim().lowercase()) {
        "heic", "heix", "hevc", "heim", "heis", "mif1", "msf1", "avif" -> Kind.HEIC
        "qt" -> Kind.MOV
        "m4a", "m4b", "m4p" -> Kind.M4A
        "3gp4", "3gp5", "3gp6", "3g2a", "3gs7" -> Kind.THREE_GP
        else -> if (brand.startsWith("3g")) Kind.THREE_GP else Kind.MP4
    }

    private fun textKind(b: ByteArray): Kind {
        if (b.isEmpty()) return Kind.TEXT
        val n = minOf(b.size, 4096)
        var bad = 0
        for (i in 0 until n) {
            val c = b[i].toInt() and 0xff
            if (c == 0) return Kind.UNKNOWN
            if (c < 9 || (c in 14..31)) bad++
        }
        if (bad * 50 > n) return Kind.UNKNOWN
        val head = String(b, 0, n, Charsets.UTF_8).trimStart('\uFEFF', ' ', '\n', '\r', '\t').lowercase()
        return when {
            head.startsWith("<!doctype html") || head.startsWith("<html") -> Kind.HTML
            head.startsWith("<?xml") || head.startsWith("<smses") -> Kind.XML
            Regex("^(received|return-path|from|message-id|date|mime-version|delivered-to):", RegexOption.MULTILINE).containsMatchIn(head.take(1500)) &&
                head.contains("subject:") -> Kind.EML
            else -> Kind.TEXT
        }
    }

    /** True when the file name's extension disagrees with what the bytes say. */
    fun extensionMismatch(name: String, kind: Kind): Boolean {
        if (kind == Kind.UNKNOWN) return false
        val ext = name.substringAfterLast('.', "").lowercase()
        if (ext.isEmpty() || ext.length > 6) return false
        val ok = ALIASES[kind] ?: setOf(kind.ext)
        // Office files are ZIPs; a plain ZIP named .docx is the suspicious direction, not the reverse.
        if (kind == Kind.ZIP && ext in setOf("apk", "jar", "epub", "kmz", "ipa", "aar", "crx", "xpi")) return false
        if (kind == Kind.TEXT && ext in setOf("xml", "html", "htm", "eml", "srt", "vtt", "ics", "rtf")) return false
        if (kind == Kind.XML && ext in setOf("svg", "plist", "kml", "gpx", "rss", "xhtml")) return false
        return ext !in ok && ext != kind.ext
    }

    data class Carved(val offset: Int, val length: Int, val bytes: ByteArray)

    /**
     * JPEG streams found inside [data] after its first byte (so a JPEG's own body is not
     * returned as a carve of itself). Each runs from an SOI marker followed by a valid
     * segment to the first EOI after it. At most [limit] images of at least [minBytes].
     */
    fun carveJpegs(data: ByteArray, limit: Int = 12, minBytes: Int = 600, maxBytes: Int = 8 shl 20): List<Carved> {
        val out = ArrayList<Carved>()
        var i = 1
        while (i < data.size - 4 && out.size < limit) {
            if (at(data, i, 0xFF, 0xD8, 0xFF) && validSegment(data[i + 3].toInt() and 0xff)) {
                val end = findEoi(data, i + 2, minOf(data.size, i + maxBytes))
                if (end > 0) {
                    val len = end - i
                    if (len >= minBytes) out += Carved(i, len, data.copyOfRange(i, end))
                    i = end
                    continue
                }
            }
            i++
        }
        return out
    }

    private fun validSegment(m: Int) = m == 0xE0 || m == 0xE1 || m == 0xDB || m == 0xC0 || m == 0xC2 || m == 0xC4 || m == 0xEE || m == 0xFE

    /** Walks marker segments so 0xFFD9 inside an embedded thumbnail does not end the outer image early. */
    private fun findEoi(b: ByteArray, from: Int, limit: Int): Int {
        var p = from
        while (p + 4 <= limit) {
            if ((b[p].toInt() and 0xff) != 0xFF) return scanEoi(b, p, limit)
            val m = b[p + 1].toInt() and 0xff
            when {
                m == 0xD9 -> return p + 2
                m == 0xDA -> return scanEoi(b, p + 2, limit)
                m == 0x01 || m in 0xD0..0xD7 || m == 0xFF -> p += if (m == 0xFF) 1 else 2
                else -> {
                    val len = ((b[p + 2].toInt() and 0xff) shl 8) or (b[p + 3].toInt() and 0xff)
                    if (len < 2) return -1
                    p += 2 + len
                }
            }
        }
        return -1
    }

    private fun scanEoi(b: ByteArray, from: Int, limit: Int): Int {
        var p = from
        while (p + 1 < limit) {
            if ((b[p].toInt() and 0xff) == 0xFF && (b[p + 1].toInt() and 0xff) == 0xD9) return p + 2
            p++
        }
        return -1
    }
}
