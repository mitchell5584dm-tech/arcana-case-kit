package com.arcanaforensics.arcalume.core

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Reads the metadata a file carries about itself (camera EXIF, PDF and Office document
 * properties, video creation times) and turns it into plain-language findings: when and
 * with what it was made, whether editing software touched it, whether it was changed
 * after it was first saved, and what it would reveal (such as GPS) if handed over.
 *
 * Nothing here decides whether a file is genuine. It reports what the file says, so a
 * person can spot what needs explaining before someone else does.
 */
object Meta {
    data class Field(val label: String, val value: String)

    data class Result(
        val kind: Carve.Kind,
        val fields: List<Field>,
        val findings: List<Finding>,
        /** Best "made at" time, ISO-8601 (offset when known), for ordering a timeline. */
        val created: String?,
        /** The EXIF preview image, when the photo carries one. */
        val thumbnail: ByteArray? = null,
        /** EXIF orientation (1 = upright); used when drawing the image in a packet. */
        val orientation: Int = 1,
        val gps: Pair<Double, Double>? = null,
    ) {
        fun toJson(): Json.Obj = Json.obj(
            "kind" to kind.name.lowercase(),
            "created" to created,
            "fields" to fields.map { Json.obj("label" to it.label, "value" to it.value) },
            "findings" to findings.map { Json.obj("level" to it.level.name.lowercase(), "text" to it.text) },
        )
    }

    private val EDITORS = listOf(
        "photoshop", "lightroom", "gimp", "snapseed", "picsart", "canva", "pixelmator", "affinity", "facetune",
        "photopea", "paint.net", "luminar", "fotor", "polarr", "vsco", "remini", "photoroom", "inshot", "capcut",
        "illustrator", "acrobat", "pdfelement", "smallpdf", "ilovepdf", "sejda", "foxit phantom", "nitro",
    )

    fun read(name: String, data: ByteArray): Result {
        val kind = Carve.identify(data)
        val r = when (kind) {
            Carve.Kind.JPEG -> jpeg(data)
            Carve.Kind.PNG -> png(data)
            Carve.Kind.PDF -> pdf(data)
            Carve.Kind.DOCX, Carve.Kind.XLSX, Carve.Kind.PPTX -> ooxml(kind, data)
            Carve.Kind.MP4, Carve.Kind.MOV, Carve.Kind.THREE_GP, Carve.Kind.M4A, Carve.Kind.HEIC -> isoMedia(kind, data)
            else -> Result(kind, emptyList(), emptyList(), null)
        }
        val extra = ArrayList<Finding>()
        if (Carve.extensionMismatch(name, kind)) {
            extra += Finding(Finding.Level.WARN, "The name ends in .${name.substringAfterLast('.').lowercase()} but the contents are a ${kind.label}. " +
                "The file was renamed or saved with the wrong type; expect to be asked why.")
        }
        val fields = listOf(Field("Type (from contents)", kind.label), Field("Size", "${data.size} bytes")) + r.fields
        return r.copy(kind = kind, fields = fields, findings = extra + r.findings)
    }

    // ---- JPEG / EXIF ----------------------------------------------------------------

    private class Tiff(val b: ByteArray, val base: Int) {
        val le = b[base].toInt() == 0x49
        fun u16(o: Int): Int { val p = base + o; return if (le) (b[p].u() or (b[p + 1].u() shl 8)) else ((b[p].u() shl 8) or b[p + 1].u()) }
        fun u32(o: Int): Long { val p = base + o
            return if (le) (b[p].u().toLong() or (b[p + 1].u().toLong() shl 8) or (b[p + 2].u().toLong() shl 16) or (b[p + 3].u().toLong() shl 24))
            else ((b[p].u().toLong() shl 24) or (b[p + 1].u().toLong() shl 16) or (b[p + 2].u().toLong() shl 8) or b[p + 3].u().toLong()) }
        fun ok(o: Int, n: Int) = o >= 0 && base + o + n <= b.size

        data class Entry(val tag: Int, val type: Int, val count: Long, val valueOff: Int)

        fun ifd(off: Int): Pair<List<Entry>, Int> {
            if (!ok(off, 2)) return emptyList<Entry>() to 0
            val n = u16(off).coerceAtMost(512)
            val out = ArrayList<Entry>()
            for (i in 0 until n) {
                val e = off + 2 + i * 12
                if (!ok(e, 12)) break
                val type = u16(e + 2)
                val count = u32(e + 4)
                val size = count * (TYPE_SIZE.getOrElse(type) { 1 })
                val vo = if (size <= 4) e + 8 else u32(e + 8).toInt()
                out += Entry(u16(e), type, count, vo)
            }
            val nextAt = off + 2 + n * 12
            val next = if (ok(nextAt, 4)) u32(nextAt).toInt() else 0
            return out to next
        }

        fun ascii(e: Entry): String? {
            if (e.count <= 0 || e.count > 4096 || !ok(e.valueOff, e.count.toInt())) return null
            return String(b, base + e.valueOff, e.count.toInt(), Charsets.UTF_8).trimEnd('\u0000', ' ').takeIf { it.isNotBlank() }
        }

        fun uint(e: Entry): Long? = when (e.type) { 3 -> if (ok(e.valueOff, 2)) u16(e.valueOff).toLong() else null; 4 -> if (ok(e.valueOff, 4)) u32(e.valueOff) else null; else -> null }

        fun rationals(e: Entry): List<Double> {
            if (e.type != 5 || e.count > 16 || !ok(e.valueOff, e.count.toInt() * 8)) return emptyList()
            return (0 until e.count.toInt()).map { i -> val n = u32(e.valueOff + i * 8); val d = u32(e.valueOff + i * 8 + 4); if (d == 0L) 0.0 else n.toDouble() / d }
        }

        companion object { val TYPE_SIZE = mapOf(1 to 1, 2 to 1, 3 to 2, 4 to 4, 5 to 8, 7 to 1, 9 to 4, 10 to 8) }
    }

    private fun Byte.u() = toInt() and 0xff

    /** Finds the EXIF APP1 segment and returns the offset of its TIFF header. */
    private fun exifBase(b: ByteArray): Int? {
        var p = 2
        while (p + 4 <= b.size) {
            if (b[p].u() != 0xFF) return null
            val m = b[p + 1].u()
            if (m == 0xDA || m == 0xD9) return null
            val len = (b[p + 2].u() shl 8) or b[p + 3].u()
            if (len < 2) return null
            if (m == 0xE1 && p + 10 <= b.size && String(b, p + 4, 6, Charsets.ISO_8859_1) == "Exif\u0000\u0000") return p + 10
            p += 2 + len
        }
        return null
    }

    private fun jpeg(b: ByteArray): Result {
        val fields = ArrayList<Field>()
        val findings = ArrayList<Finding>()
        var created: String? = null
        var thumb: ByteArray? = null
        var orientation = 1
        var gps: Pair<Double, Double>? = null
        var software: String? = null
        val base = exifBase(b)
        if (base != null && base + 8 <= b.size) {
            val t = Tiff(b, base)
            val (ifd0, next) = t.ifd(t.u32(4).toInt())
            val tags = ifd0.associateBy { it.tag }
            val make = tags[0x010F]?.let(t::ascii)
            val model = tags[0x0110]?.let(t::ascii)
            software = tags[0x0131]?.let(t::ascii)
            val modified = tags[0x0132]?.let(t::ascii)
            tags[0x0112]?.let(t::uint)?.let { orientation = it.toInt().coerceIn(1, 8) }
            var original: String? = null
            var digitized: String? = null
            var offset: String? = null
            tags[0x8769]?.let(t::uint)?.let { exifOff ->
                val ex = t.ifd(exifOff.toInt()).first.associateBy { it.tag }
                original = ex[0x9003]?.let(t::ascii)
                digitized = ex[0x9004]?.let(t::ascii)
                offset = (ex[0x9011] ?: ex[0x9010])?.let(t::ascii)
                ex[0xA434]?.let(t::ascii)?.let { fields += Field("Lens", it) }
            }
            tags[0x8825]?.let(t::uint)?.let { gpsOff ->
                val g = t.ifd(gpsOff.toInt()).first.associateBy { it.tag }
                val lat = g[2]?.let(t::rationals)
                val lon = g[4]?.let(t::rationals)
                if (lat != null && lat.size == 3 && lon != null && lon.size == 3) {
                    var la = lat[0] + lat[1] / 60 + lat[2] / 3600
                    var lo = lon[0] + lon[1] / 60 + lon[2] / 3600
                    if (g[1]?.let(t::ascii)?.startsWith("S") == true) la = -la
                    if (g[3]?.let(t::ascii)?.startsWith("W") == true) lo = -lo
                    if (la != 0.0 || lo != 0.0) gps = la to lo
                }
            }
            if (next > 0) {
                val ifd1 = t.ifd(next).first.associateBy { it.tag }
                val to = ifd1[0x0201]?.let(t::uint)?.toInt()
                val tl = ifd1[0x0202]?.let(t::uint)?.toInt()
                if (to != null && tl != null && tl in 100..(1 shl 20) && t.ok(to, tl)) {
                    val cand = b.copyOfRange(base + to, base + to + tl)
                    if (cand.size > 3 && cand[0].u() == 0xFF && cand[1].u() == 0xD8) thumb = cand
                }
            }
            val device = listOfNotNull(make, model?.removePrefix(make ?: "")?.trim()).joinToString(" ").trim()
            if (device.isNotEmpty()) fields += Field("Camera", device)
            original?.let { fields += Field("Taken", exifDate(it, offset) ?: it) }
            modified?.let { fields += Field("Last saved", exifDate(it, offset) ?: it) }
            software?.let { fields += Field("Software", it) }
            gps?.let { fields += Field("GPS", String.format(java.util.Locale.ROOT, "%.6f, %.6f", it.first, it.second)) }
            created = (original ?: digitized)?.let { exifDate(it, offset) }

            if (device.isNotEmpty() && original != null) findings += Finding(Finding.Level.OK, "Camera metadata is present: taken ${fieldsValue(fields, "Taken")} on a $device.")
            if (original != null && modified != null) {
                val a = exifDate(original, null); val m = exifDate(modified, null)
                if (a != null && m != null && secondsBetween(a, m)?.let { it > 60 } == true) {
                    findings += Finding(Finding.Level.WARN, "The photo was saved again after it was taken (taken ${exifDate(original, offset)}, last saved ${exifDate(modified, offset)}). " +
                        "Be ready to explain what changed, such as a crop or rotation.")
                }
            }
            if (thumb != null) findings += Finding(Finding.Level.INFO, "An embedded preview image was found (${thumb.size / 1024} KB). " +
                "If the preview shows something the main picture does not, the photo was edited after it was taken.")
        }
        val xmp = String(b, 0, minOf(b.size, 256 shl 10), Charsets.ISO_8859_1)
        val creatorTool = Regex("CreatorTool(?:=\"|>)([^\"<]{1,120})").find(xmp)?.groupValues?.get(1)
        if (creatorTool != null && creatorTool != software) fields += Field("Created with", creatorTool)
        editor(listOfNotNull(software, creatorTool))?.let { findings += Finding(Finding.Level.WARN, "Editing software saved this file ($it). The image may not be exactly what the camera recorded.") }
        if (base == null) findings += Finding(Finding.Level.INFO, "No camera metadata. This is normal for screenshots and for photos sent through messaging apps, which strip it. " +
            "If the original is still on the phone that took it, add that copy too.")
        gps?.let { findings += Finding(Finding.Level.INFO, "The photo records where it was taken (GPS). Anyone given the original file can see that location.") }
        val carved = Carve.carveJpegs(b).filter { thumb == null || !it.bytes.contentEquals(thumb) }
        if (carved.isNotEmpty()) findings += Finding(Finding.Level.INFO, "${carved.size} more embedded image${if (carved.size != 1) "s" else ""} found inside the file.")
        return Result(Carve.Kind.JPEG, fields, findings, created, thumb, orientation, gps)
    }

    private fun fieldsValue(f: List<Field>, label: String) = f.firstOrNull { it.label == label }?.value ?: ""

    private fun editor(names: List<String>): String? = names.firstOrNull { n -> EDITORS.any { n.lowercase().contains(it) } }

    /** "2024:05:01 13:22:10" (+ "-04:00") to "2024-05-01T13:22:10-04:00". */
    fun exifDate(s: String, offset: String?): String? {
        val m = Regex("^(\\d{4}):(\\d{2}):(\\d{2})[ T](\\d{2}):(\\d{2}):(\\d{2})").find(s.trim()) ?: return null
        val (y, mo, d, h, mi, se) = m.destructured
        if (y == "0000") return null
        val off = offset?.trim()?.takeIf { Regex("^[+-]\\d{2}:\\d{2}$").matches(it) } ?: ""
        return "$y-$mo-${d}T$h:$mi:$se$off"
    }

    private fun secondsBetween(a: String, b: String): Long? = runCatching {
        val p = java.time.LocalDateTime.parse(a.take(19)); val q = java.time.LocalDateTime.parse(b.take(19))
        kotlin.math.abs(java.time.Duration.between(p, q).seconds)
    }.getOrNull()

    // ---- PNG ------------------------------------------------------------------------

    private fun png(b: ByteArray): Result {
        val fields = ArrayList<Field>()
        val findings = ArrayList<Finding>()
        var created: String? = null
        var p = 8
        var hasExif = false
        val texts = ArrayList<String>()
        while (p + 12 <= b.size) {
            val len = ((b[p].u() shl 24) or (b[p + 1].u() shl 16) or (b[p + 2].u() shl 8) or b[p + 3].u())
            if (len < 0 || p + 12 + len > b.size) break
            val type = String(b, p + 4, 4, Charsets.ISO_8859_1)
            val d = p + 8
            when (type) {
                "tIME" -> if (len == 7) {
                    val y = (b[d].u() shl 8) or b[d + 1].u()
                    created = String.format(java.util.Locale.ROOT, "%04d-%02d-%02dT%02d:%02d:%02dZ", y, b[d + 2].u(), b[d + 3].u(), b[d + 4].u(), b[d + 5].u(), b[d + 6].u())
                    fields += Field("Last saved", created!!)
                }
                "tEXt", "iTXt" -> {
                    val s = String(b, d, minOf(len, 2048), Charsets.ISO_8859_1)
                    val key = s.substringBefore('\u0000')
                    val value = s.substringAfterLast('\u0000').trim()
                    if (key in setOf("Software", "Author", "Description", "Title", "Creation Time", "Comment") && value.isNotEmpty()) {
                        fields += Field(key, value.take(200)); texts += value
                    }
                    if (key == "XML:com.adobe.xmp") texts += s
                }
                "eXIf" -> hasExif = true
                "IEND" -> break
            }
            p += 12 + len
        }
        editor(texts)?.let { findings += Finding(Finding.Level.WARN, "Editing software saved this image ($it).") }
        if (!hasExif) findings += Finding(Finding.Level.INFO, "No camera metadata, as is normal for screenshots. A screenshot shows what was on the screen; keep the phone or account it came from in case the other side disputes it.")
        return Result(Carve.Kind.PNG, fields, findings, created)
    }

    // ---- PDF ------------------------------------------------------------------------

    private fun pdf(b: ByteArray): Result {
        val s = String(b, Charsets.ISO_8859_1)
        val fields = ArrayList<Field>()
        val findings = ArrayList<Finding>()
        fun info(key: String): String? = Regex("/$key\\s*\\((.{0,300}?)(?<!\\\\)\\)", RegexOption.DOT_MATCHES_ALL).findAll(s).lastOrNull()?.groupValues?.get(1)
            ?.let(::pdfString)?.takeIf { it.isNotBlank() }
        val producer = info("Producer")
        val creator = info("Creator")
        val author = info("Author")
        val title = info("Title")
        val createdRaw = info("CreationDate")
        val modRaw = info("ModDate")
        val created = createdRaw?.let(::pdfDate) ?: Regex("<xmp:CreateDate>([^<]{10,40})</xmp:CreateDate>").find(s)?.groupValues?.get(1)
        val modified = modRaw?.let(::pdfDate) ?: Regex("<xmp:ModifyDate>([^<]{10,40})</xmp:ModifyDate>").find(s)?.groupValues?.get(1)
        title?.let { fields += Field("Title", it) }
        author?.let { fields += Field("Author", it) }
        creator?.let { fields += Field("Made with", it) }
        producer?.let { fields += Field("Saved by", it) }
        created?.let { fields += Field("Created", it) }
        modified?.let { fields += Field("Modified", it) }
        val pages = Regex("/Type\\s*/Page[^s]").findAll(s).count()
        if (pages > 0) fields += Field("Pages", pages.toString())
        val saves = Regex("%%EOF").findAll(s).count()
        if (saves > 1) findings += Finding(Finding.Level.WARN, "This PDF was saved ${saves} times: ${saves - 1} later change${if (saves > 2) "s were" else " was"} added on top of the first version. " +
            "Earlier versions may still be inside the file, and the content may differ from what was first made.")
        if (created != null && modified != null && created != modified) findings += Finding(Finding.Level.INFO, "Created $created, last modified $modified.")
        editor(listOfNotNull(producer, creator))?.let { findings += Finding(Finding.Level.INFO, "Last saved with $it, which can edit PDFs.") }
        if (s.contains("/Annot")) findings += Finding(Finding.Level.INFO, "Contains annotations (comments, highlights, form fields or stamps).")
        if (s.contains("/JavaScript") || s.contains("/JS ")) findings += Finding(Finding.Level.WARN, "Contains JavaScript. Court e-filing systems often reject PDFs with scripts.")
        if (s.contains("/Encrypt")) findings += Finding(Finding.Level.WARN, "The PDF is password-protected or restricted. Many clerks cannot accept it until the restriction is removed.")
        val imgs = Carve.carveJpegs(b).size
        if (imgs > 0) findings += Finding(Finding.Level.INFO, "$imgs embedded picture${if (imgs != 1) "s" else ""} found inside the PDF.")
        return Result(Carve.Kind.PDF, fields, findings, created)
    }

    private fun pdfString(raw: String): String {
        if (raw.startsWith("\u00fe\u00ff")) {
            val bytes = raw.substring(2).toByteArray(Charsets.ISO_8859_1)
            return String(bytes, Charsets.UTF_16BE)
        }
        return raw.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")
    }

    /** "D:20240501132210-04'00'" to "2024-05-01T13:22:10-04:00". */
    fun pdfDate(s: String): String? {
        val m = Regex("D?:?(\\d{4})(\\d{2})?(\\d{2})?(\\d{2})?(\\d{2})?(\\d{2})?([Zz+-])?(\\d{2})?'?(\\d{2})?").find(s.trim()) ?: return null
        val g = m.groupValues
        fun two(i: Int, d: String) = g[i].ifEmpty { d }
        val tz = when (g[7]) { "Z", "z" -> "Z"; "+", "-" -> if (g[8].isNotEmpty()) "${g[7]}${g[8]}:${g[9].ifEmpty { "00" }}" else ""; else -> "" }
        return "${g[1]}-${two(2, "01")}-${two(3, "01")}T${two(4, "00")}:${two(5, "00")}:${two(6, "00")}$tz"
    }

    // ---- Word, Excel, PowerPoint ----------------------------------------------------

    private fun ooxml(kind: Carve.Kind, b: ByteArray): Result {
        val parts = Zip.entries(b) { it == "docProps/core.xml" || it == "docProps/app.xml" || it == "word/document.xml" || it == "word/comments.xml" }
        val core = parts["docProps/core.xml"]?.toString(Charsets.UTF_8) ?: ""
        val app = parts["docProps/app.xml"]?.toString(Charsets.UTF_8) ?: ""
        fun tag(x: String, t: String) = Regex("<$t[^>]*>([^<]{1,300})</$t>").find(x)?.groupValues?.get(1)?.let(::unXml)?.trim()?.takeIf { it.isNotEmpty() }
        val fields = ArrayList<Field>()
        val findings = ArrayList<Finding>()
        val creator = tag(core, "dc:creator")
        val lastBy = tag(core, "cp:lastModifiedBy")
        val created = tag(core, "dcterms:created")
        val modified = tag(core, "dcterms:modified")
        val revision = tag(core, "cp:revision")
        val printed = tag(core, "cp:lastPrinted")
        val application = tag(app, "Application")
        val company = tag(app, "Company")
        val minutes = tag(app, "TotalTime")
        tag(core, "dc:title")?.let { fields += Field("Title", it) }
        creator?.let { fields += Field("Created by", it) }
        lastBy?.let { fields += Field("Last edited by", it) }
        created?.let { fields += Field("Created", it) }
        modified?.let { fields += Field("Modified", it) }
        printed?.let { fields += Field("Last printed", it) }
        revision?.let { fields += Field("Revision", it) }
        minutes?.let { fields += Field("Editing time", "$it minutes") }
        application?.let { fields += Field("Application", it) }
        company?.let { fields += Field("Company", it) }
        if (creator != null && lastBy != null && creator != lastBy) findings += Finding(Finding.Level.INFO, "Created by \"$creator\" but last edited by \"$lastBy\".")
        if (created != null && modified != null && created != modified) findings += Finding(Finding.Level.INFO, "Created $created, last modified $modified" + (revision?.let { ", revision $it" } ?: "") + ".")
        val doc = parts["word/document.xml"]?.toString(Charsets.UTF_8) ?: ""
        val ins = Regex("<w:ins ").findAll(doc).count()
        val del = Regex("<w:del ").findAll(doc).count()
        if (ins + del > 0) findings += Finding(Finding.Level.WARN, "Contains tracked changes ($ins insertion${if (ins != 1) "s" else ""}, $del deletion${if (del != 1) "s" else ""}). " +
            "Deleted text is still inside the file even when it does not show on the page.")
        if (parts.containsKey("word/comments.xml")) findings += Finding(Finding.Level.INFO, "Contains reviewer comments that may not print.")
        if (company != null || creator != null) findings += Finding(Finding.Level.INFO, "Names stored in the file travel with it. Check them before you share the original.")
        return Result(kind, fields, findings, created)
    }

    private fun unXml(s: String) = s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")

    // ---- MP4, MOV, 3GP, M4A, HEIC ---------------------------------------------------

    private fun isoMedia(kind: Carve.Kind, b: ByteArray): Result {
        val fields = ArrayList<Field>()
        val findings = ArrayList<Finding>()
        var created: String? = null
        val mvhd = indexOf(b, "mvhd".toByteArray(Charsets.ISO_8859_1))
        if (mvhd >= 4 && mvhd + 24 <= b.size) {
            val v = b[mvhd + 4].u()
            val (c, m, scaleAt) = if (v == 1 && mvhd + 32 <= b.size) Triple(u64(b, mvhd + 8), u64(b, mvhd + 16), mvhd + 24) else Triple(u32(b, mvhd + 8), u32(b, mvhd + 12), mvhd + 16)
            fun mac(sec: Long) = if (sec <= 0) null else Instant.ofEpochSecond(sec - 2082844800L).takeIf { it.isAfter(Instant.parse("1995-01-01T00:00:00Z")) }
                ?.let { DateTimeFormatter.ISO_INSTANT.format(it.atZone(ZoneOffset.UTC)) }
            created = mac(c)
            val mod = mac(m)
            created?.let { fields += Field("Recorded (UTC)", it) }
            if (mod != null && mod != created) fields += Field("Modified (UTC)", mod)
            if (scaleAt + 8 <= b.size) {
                val scale = u32(b, scaleAt)
                val dur = if (v == 1) u64(b, scaleAt + 4) else u32(b, scaleAt + 4)
                if (scale > 0 && dur > 0) fields += Field("Length", "${dur / scale} seconds")
            }
            if (mod != null && created != null && mod != created) findings += Finding(Finding.Level.INFO, "The file's modified time differs from its recorded time, which happens when a clip is trimmed or re-exported.")
        }
        val head = String(b, 0, minOf(b.size, 1 shl 20), Charsets.ISO_8859_1)
        Regex("\u00a9xyz.{0,4}([+-]\\d{1,3}\\.\\d+[+-]\\d{1,3}\\.\\d+)").find(head)?.let {
            fields += Field("GPS", it.groupValues[1]); findings += Finding(Finding.Level.INFO, "The recording stores where it was made (GPS).")
        }
        if (created == null) findings += Finding(Finding.Level.INFO, "No recording time inside the file. Messaging apps often remove it.")
        return Result(kind, fields, findings, created)
    }

    private fun u32(b: ByteArray, p: Int): Long = (b[p].u().toLong() shl 24) or (b[p + 1].u().toLong() shl 16) or (b[p + 2].u().toLong() shl 8) or b[p + 3].u().toLong()
    private fun u64(b: ByteArray, p: Int): Long = (u32(b, p) shl 32) or u32(b, p + 4)

    private fun indexOf(b: ByteArray, pat: ByteArray, limit: Int = minOf(b.size, 64 shl 20)): Int {
        outer@ for (i in 0..limit - pat.size) {
            for (j in pat.indices) if (b[i + j] != pat[j]) continue@outer
            return i
        }
        return -1
    }
}
