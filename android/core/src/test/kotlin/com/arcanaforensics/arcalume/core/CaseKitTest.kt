package com.arcanaforensics.arcalume.core

import java.awt.Color
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.time.Instant
import java.time.ZoneId
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The case kit: identification, metadata, chat exports, the packet and the bundle. */
class CaseKitTest {
    private val zone = ZoneId.of("America/New_York")
    private fun tmp(): File = Files.createTempDirectory("casekit").toFile()

    // ---- fixtures -----------------------------------------------------------------

    private fun plainJpeg(w: Int = 320, h: Int = 200, color: Color = Color(40, 90, 160)): ByteArray {
        val img = BufferedImage(w, h, BufferedImage.TYPE_INT_RGB)
        val g = img.createGraphics(); g.color = color; g.fillRect(0, 0, w, h); g.color = Color.WHITE; g.drawString("Exhibit test", 20, 40); g.dispose()
        return ByteArrayOutputStream().also { ImageIO.write(img, "jpg", it) }.toByteArray()
    }

    private fun png(): ByteArray {
        val img = BufferedImage(64, 64, BufferedImage.TYPE_INT_RGB)
        return ByteArrayOutputStream().also { ImageIO.write(img, "png", it) }.toByteArray()
    }

    /** Little-endian TIFF/EXIF block with IFD0 (make, model, software, datetime), an EXIF IFD, a GPS IFD and an IFD1 thumbnail. */
    private fun exif(software: String?, taken: String, saved: String, thumb: ByteArray?): ByteArray {
        class E(val tag: Int, val type: Int, val count: Int, val data: ByteArray)
        fun ascii(tag: Int, s: String) = (s + "\u0000").toByteArray(Charsets.US_ASCII).let { E(tag, 2, it.size, it) }
        fun long(tag: Int, v: Int) = E(tag, 4, 1, ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array())
        fun rat(tag: Int, vararg v: Pair<Int, Int>) = E(tag, 5, v.size, ByteBuffer.allocate(8 * v.size).order(ByteOrder.LITTLE_ENDIAN).also { b -> v.forEach { b.putInt(it.first); b.putInt(it.second) } }.array())
        val buf = ByteBuffer.allocate(8192).order(ByteOrder.LITTLE_ENDIAN)
        buf.put("II".toByteArray()); buf.putShort(42); buf.putInt(8)
        // Layout: each IFD is written with its out-of-line data right after it.
        fun writeIfd(at: Int, entries: List<E>, next: Int): Int {
            buf.position(at)
            buf.putShort(entries.size.toShort())
            var dataAt = at + 2 + entries.size * 12 + 4
            for (e in entries) {
                buf.putShort(e.tag.toShort()); buf.putShort(e.type.toShort()); buf.putInt(e.count)
                if (e.data.size <= 4) { buf.put(e.data); repeat(4 - e.data.size) { buf.put(0) } } else { buf.putInt(dataAt); dataAt += e.data.size + (e.data.size and 1) }
            }
            buf.putInt(next)
            var p = at + 2 + entries.size * 12 + 4
            for (e in entries) if (e.data.size > 4) { buf.position(p); buf.put(e.data); p += e.data.size + (e.data.size and 1) }
            return p
        }
        val exifAt = 1000; val gpsAt = 1400; val ifd1At = 1800; val thumbAt = 2000
        val ifd0 = listOfNotNull(ascii(0x010F, "Google"), ascii(0x0110, "Pixel 8"), software?.let { ascii(0x0131, it) }, ascii(0x0132, saved),
            long(0x8769, exifAt), long(0x8825, gpsAt))
        writeIfd(8, ifd0, if (thumb != null) ifd1At else 0)
        writeIfd(exifAt, listOf(ascii(0x9003, taken), ascii(0x9011, "-04:00")), 0)
        writeIfd(gpsAt, listOf(ascii(1, "N"), rat(2, 28 to 1, 4 to 1, 48 to 1), ascii(3, "W"), rat(4, 80 to 1, 36 to 1, 36 to 1)), 0)
        if (thumb != null) {
            writeIfd(ifd1At, listOf(long(0x0201, thumbAt), long(0x0202, thumb.size)), 0)
            buf.position(thumbAt); buf.put(thumb)
        }
        val end = if (thumb != null) thumbAt + thumb.size else 2000
        return buf.array().copyOf(end)
    }

    private fun withExif(jpeg: ByteArray, tiff: ByteArray): ByteArray {
        val payload = "Exif\u0000\u0000".toByteArray(Charsets.ISO_8859_1) + tiff
        val len = payload.size + 2
        val app1 = byteArrayOf(0xFF.toByte(), 0xE1.toByte(), (len shr 8).toByte(), len.toByte()) + payload
        return jpeg.copyOfRange(0, 2) + app1 + jpeg.copyOfRange(2, jpeg.size)
    }

    private fun docx(): ByteArray = Zip.write(listOf(
        "[Content_Types].xml" to "<Types/>".toByteArray(),
        "word/document.xml" to "<w:document><w:body><w:p><w:ins w:id=\"1\"><w:r><w:t>added</w:t></w:r></w:ins><w:del w:id=\"2\"><w:r><w:delText>removed</w:delText></w:r></w:del></w:p></w:body></w:document>".toByteArray(),
        "docProps/core.xml" to ("<cp:coreProperties><dc:creator>Jordan H.</dc:creator><cp:lastModifiedBy>Attorney Office</cp:lastModifiedBy>" +
            "<cp:revision>7</cp:revision><dcterms:created xsi:type=\"dcterms:W3CDTF\">2024-05-23T14:02:00Z</dcterms:created>" +
            "<dcterms:modified xsi:type=\"dcterms:W3CDTF\">2024-06-02T09:10:00Z</dcterms:modified></cp:coreProperties>").toByteArray(),
        "docProps/app.xml" to "<Properties><Application>Microsoft Office Word</Application><TotalTime>94</TotalTime></Properties>".toByteArray(),
    ))

    private val whatsappUs = """
        |1/14/24, 9:02 PM - Messages and calls are end-to-end encrypted. No one outside of this chat, not even WhatsApp, can read or listen to them.
        |1/14/24, 9:03 PM - Jordan: You are not picking them up this weekend.
        |1/14/24, 9:05 PM - Sam: The order says I have them Saturday at 10.
        |It is on page 3.
        |1/15/24, 7:41 AM - Jordan: <Media omitted>
        |1/15/24, 12:00 PM - Sam: I will be there at 10 😀
        |""".trimMargin()

    private val whatsappIos = """
        |[31/01/2024, 21:15:03] Jordan: Don't come to the house
        |[01/02/2024, 08:01:10] Sam: Noted. Exchange at the police station then.
        |[01/02/2024, 08:30:00] Jordan: Fine
        |""".trimMargin()

    private val smsXml = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
        |<smses count="3">
        |  <sms protocol="0" address="+13215550100" date="1705284180000" type="1" body="Where are you?" contact_name="Landlord" />
        |  <sms protocol="0" address="+13215550100" date="1705284240000" type="2" body="The heat is still broken &amp; it is 40 degrees" contact_name="Landlord" />
        |  <mms date="1705284300000" msg_box="1" address="+13215550100" contact_name="Landlord"><parts><part ct="text/plain" text="Will fix Monday" /><part ct="image/jpeg" name="a.jpg" /></parts></mms>
        |</smses>""".trimMargin()

    // ---- identification -------------------------------------------------------------

    @Test fun `identifies by contents and flags renamed files`() {
        assertEquals(Carve.Kind.PNG, Carve.identify(png()))
        assertTrue(Carve.extensionMismatch("receipt.jpg", Carve.Kind.PNG))
        assertEquals(Carve.Kind.DOCX, Carve.identify(docx()))
        assertTrue(Carve.extensionMismatch("notes.txt", Carve.Kind.DOCX))
        assertTrue(!Carve.extensionMismatch("photo.JPEG", Carve.Kind.JPEG))
        assertEquals(Carve.Kind.TEXT, Carve.identify(whatsappUs.toByteArray()))
        assertEquals(Carve.Kind.XML, Carve.identify(smsXml.toByteArray()))
        assertEquals(Carve.Kind.PDF, Carve.identify("%PDF-1.7\n".toByteArray()))
        assertEquals(Carve.Kind.MP4, Carve.identify(byteArrayOf(0, 0, 0, 0x18) + "ftypmp42".toByteArray() + ByteArray(16)))
        assertEquals(Carve.Kind.HEIC, Carve.identify(byteArrayOf(0, 0, 0, 0x18) + "ftypheic".toByteArray() + ByteArray(16)))
        val finding = Meta.read("receipt.jpg", png()).findings.first()
        assertEquals(Finding.Level.WARN, finding.level)
        assertTrue(finding.text.contains("renamed"))
    }

    @Test fun `carves jpegs hidden inside other bytes`() {
        val a = plainJpeg(100, 80); val b = plainJpeg(60, 60, Color.RED)
        val blob = ByteArray(500) { 7 } + a + ByteArray(300) { 1 } + b + ByteArray(50)
        val found = Carve.carveJpegs(blob)
        assertEquals(2, found.size)
        assertTrue(found[0].bytes.contentEquals(a))
        assertEquals(500, found[0].offset)
        assertTrue(found[1].bytes.contentEquals(b))
    }

    // ---- metadata -------------------------------------------------------------------

    @Test fun `reads camera exif, editing, gps and the embedded preview`() {
        val thumb = plainJpeg(80, 50, Color.GREEN)
        val jpg = withExif(plainJpeg(), exif("Adobe Photoshop 25.0 (Windows)", "2024:05:01 13:22:10", "2024:05:03 08:00:00", thumb))
        val m = Meta.read("IMG_0001.jpg", jpg)
        assertEquals("2024-05-01T13:22:10-04:00", m.created)
        val f = m.fields.associate { it.label to it.value }
        assertEquals("Google Pixel 8", f["Camera"])
        assertEquals("28.080000, -80.610000", f["GPS"])
        assertNotNull(m.thumbnail); assertTrue(m.thumbnail!!.contentEquals(thumb))
        val text = m.findings.joinToString("\n") { "${it.level} ${it.text}" }
        assertTrue(text.contains("WARN Editing software saved this file (Adobe Photoshop"), text)
        assertTrue(text.contains("WARN The photo was saved again after it was taken"), text)
        assertTrue(text.contains("GPS"), text)
        assertTrue(text.contains("embedded preview"), text)
    }

    @Test fun `screenshots and stripped photos say so plainly`() {
        val m = Meta.read("Screenshot_20240114.png", png())
        assertTrue(m.findings.any { it.text.contains("screenshots") })
        val j = Meta.read("IMG-20240114-WA0003.jpg", plainJpeg())
        assertTrue(j.findings.any { it.text.contains("messaging apps") })
        assertNull(j.created)
    }

    @Test fun `office documents reveal authors, revisions and tracked changes`() {
        val m = Meta.read("Proposed Order.docx", docx())
        assertEquals(Carve.Kind.DOCX, m.kind)
        val f = m.fields.associate { it.label to it.value }
        assertEquals("Jordan H.", f["Created by"]); assertEquals("Attorney Office", f["Last edited by"]); assertEquals("94 minutes", f["Editing time"])
        assertEquals("2024-05-23T14:02:00Z", m.created)
        val text = m.findings.joinToString("\n") { it.text }
        assertTrue(text.contains("tracked changes (1 insertion, 1 deletion)"), text)
        assertTrue(text.contains("last edited by \"Attorney Office\""), text)
    }

    @Test fun `pdf properties and later saves are reported`() {
        val pdf = Pdf("Lease", "Test Producer").also { it.newPage().text(72.0, 700.0, "Lease agreement") }.bytes("D:20240301120000-05'00'")
        val once = Meta.read("lease.pdf", pdf)
        assertEquals("Test Producer", once.fields.first { it.label == "Saved by" }.value)
        assertEquals("2024-03-01T12:00:00-05:00", once.created)
        assertTrue(once.findings.none { it.text.contains("saved 2 times") })
        val updated = pdf + "\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\nstartxref\n0\n%%EOF\n".toByteArray()
        assertTrue(Meta.read("lease.pdf", updated).findings.any { it.level == Finding.Level.WARN && it.text.contains("saved 2 times") })
    }

    // ---- chats ----------------------------------------------------------------------

    @Test fun `whatsapp android export, month first, 12 hour, multi-line`() {
        val t = assertNotNull(Chats.parse("WhatsApp Chat with Jordan.txt", whatsappUs.toByteArray(), zone))
        assertEquals(listOf("Jordan", "Sam"), t.participants)
        assertEquals(5, t.messages.size)
        assertEquals("2024-01-14T21:05:00", t.messages[2].time)
        assertEquals("The order says I have them Saturday at 10.\nIt is on page 3.", t.messages[2].text)
        assertEquals("2024-01-15T12:00:00", t.messages.last().time)
        assertEquals("(WhatsApp notice)", t.messages[0].sender)
    }

    @Test fun `whatsapp iphone export, day first, 24 hour, inside a zip`() {
        val t = assertNotNull(Chats.parse("chat.zip", Zip.write(listOf("_chat.txt" to whatsappIos.toByteArray(), "IMG-1.jpg" to plainJpeg())), zone))
        assertEquals(true, t.dayFirst)
        assertEquals("2024-01-31T21:15:03", t.messages[0].time)
        assertEquals("2024-02-01T08:01:10", t.messages[1].time)
    }

    @Test fun `sms backup and restore xml, texts and picture messages`() {
        val t = assertNotNull(Chats.parse("sms-20240115.xml", smsXml.toByteArray(), zone))
        assertEquals(3, t.messages.size)
        assertEquals("2024-01-14T21:03:00", t.messages[0].time)
        assertEquals("Landlord", t.messages[0].sender)
        assertEquals("Me", t.messages[1].sender); assertEquals(true, t.messages[1].outgoing)
        assertEquals("The heat is still broken & it is 40 degrees", t.messages[1].text)
        assertEquals("Will fix Monday [1 attachment]", t.messages[2].text)
    }

    @Test fun `plain text that is not a chat is not parsed as one`() {
        assertNull(Chats.parse("notes.txt", "Called the school on Monday.\nThey said she was absent.".toByteArray(), zone))
    }

    // ---- pdf writer -----------------------------------------------------------------

    @Test fun `pdf writer produces a valid cross-reference table`() {
        val doc = Pdf("T", "P")
        doc.newPage().text(72.0, 720.0, "Héllo “quoted” — dash (paren) \\ emoji 😀")
        val img = assertNotNull(doc.jpeg(plainJpeg()))
        doc.newPage().image(img, 72.0, 300.0, 320.0, 200.0)
        val bytes = doc.bytes("D:20240101000000Z")
        val s = String(bytes, Charsets.ISO_8859_1)
        assertTrue(s.startsWith("%PDF-1.4"))
        val start = s.substringAfterLast("startxref\n").substringBefore('\n').trim().toInt()
        assertTrue(s.substring(start).startsWith("xref"))
        // Every xref offset points at "N 0 obj".
        val rows = s.substring(start).lines().drop(3).takeWhile { it.endsWith(" n ") }
        rows.forEachIndexed { i, r -> assertTrue(s.substring(r.take(10).toInt()).startsWith("${i + 1} 0 obj"), "object ${i + 1}") }
        assertEquals("/Count 2", Regex("/Count \\d+").find(s)!!.value)
        assertTrue(Pdf.wrap("one two three four five six seven", Pdf.Font.REGULAR, 10.0, 60.0).size > 2)
    }

    // ---- the whole case -------------------------------------------------------------

    @Test fun `case store, packet and bundle agree with each other and with the custody log`() {
        val dir = tmp()
        val ledger = Ledger(File(dir, "vault/ledger.jsonl"))
        var heads = 0
        val store = CaseStore(File(dir, "case"), ledger) { heads++ }
        store.updateDetails("Rivera v. Hale", "2024-DR-000123", "In the Circuit Court for Sample County", "Sam Rivera", "")
        val photo = withExif(plainJpeg(640, 420), exif(null, "2024:01:13 10:02:00", "2024:01:13 10:02:00", null))
        store.add("IMG_20240113_100200.jpg", photo, "Photo of the front door at the 10:00 exchange", zone)
        store.add("WhatsApp Chat with Jordan.txt", whatsappUs.toByteArray(), "WhatsApp messages with Jordan, Jan 14-15", zone)
        store.add("sms-20240115.xml", smsXml.toByteArray(), "Texts with landlord about heat", zone)
        store.add("Proposed Order.docx", docx(), "Proposed order received by email", zone)
        val (c0, screenshot) = store.add("Screenshot_20240116.png", png(), "Screenshot of call log", zone)
        store.edit(screenshot.id, screenshot.title, "Shows 14 missed calls between 9 and 11 PM.", "2024-01-16T21:00")
        val c = store.sortByDate()
        assertEquals(5, c.exhibits.size)
        assertEquals("Photo of the front door at the 10:00 exchange", c.exhibits.first().title)
        assertEquals("Proposed order received by email", c.exhibits.last().title)
        assertEquals("Screenshot of call log", c.exhibits[3].title)
        assertEquals(5, c0.exhibits.size)

        val v = ledger.verify()
        assertTrue(v.ok, v.message)
        assertEquals(heads, v.entries)

        val input = Packet.Input(c, store::original, { e -> store.original(e).takeIf { e.kind == Carve.Kind.JPEG } }, v.head, v.entries,
            "Arcalume test", Instant.parse("2026-10-10T16:00:00Z"), zone)
        val packet = Packet.build(input)
        assertTrue(packet.pages >= 8, "pages: ${packet.pages}")
        val s = String(packet.pdf, Charsets.ISO_8859_1)
        assertEquals("/Count ${packet.pages}", Regex("/Count \\d+").find(s)!!.value)
        System.getenv("ARCALUME_PACKET_OUT")?.let { File(it).writeBytes(packet.pdf) }

        val free = Packet.build(input, Entitlements.FREE_PACKET_EXHIBITS)
        assertTrue(free.pages < packet.pages)

        val zip = Packet.bundle(input, packet, ledger.file.readBytes())
        val files = Zip.entries(zip) { true }
        val sums = files.getValue("SHA256SUMS.txt").toString(Charsets.UTF_8).trim().lines()
        assertEquals(6, sums.size)
        for (line in sums) {
            val (hash, name) = line.split("  ", limit = 2)
            assertEquals(hash, sha256Hex(files.getValue(name)), name)
        }
        assertTrue(files.containsKey("custody-log.jsonl"))
        assertEquals(c.exhibits.size, (Json.parse(files.getValue("case.json")).obj()["case"]!!.obj()["exhibits"] as Json.Arr).items.size)
        assertTrue(Zip.write(listOf("a.txt" to "x".toByteArray())).contentEquals(Zip.write(listOf("a.txt" to "x".toByteArray()))), "bundles are reproducible")

        store.recordExport("packet_exported", packet.sha256, c.exhibits.size)
        val removed = store.remove(c.exhibits.first().id)
        assertEquals(4, removed.exhibits.size)
        assertTrue(ledger.verify().ok)
        assertEquals("exhibit_removed", Json.parse(ledger.file.readLines().last()).obj()["event"]!!.str())
        assertEquals(removed, store.load())
    }
}
