package com.arcanaforensics.arcalume.core

import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Turns message exports into a chronological transcript:
 *
 *  - WhatsApp "Export chat" text files (Android and iPhone layouts, 12- and 24-hour clocks,
 *    month-first or day-first dates, multi-line messages, attachment lines).
 *  - "SMS Backup & Restore" XML files (texts and picture messages).
 *
 * Every message keeps the exact line or record it came from, so the transcript can be
 * checked against the original export, which is kept byte-for-byte.
 */
object Chats {
    data class Message(val time: String, val sender: String, val text: String, val outgoing: Boolean? = null) {
        fun toJson() = Json.obj("time" to time, "sender" to sender, "text" to text, "outgoing" to outgoing)
    }

    data class Transcript(val source: String, val messages: List<Message>, val participants: List<String>, val dayFirst: Boolean? = null) {
        val first get() = messages.firstOrNull()?.time
        val last get() = messages.lastOrNull()?.time
    }

    /** Parses [data] when it is a chat export this knows; otherwise null. */
    fun parse(name: String, data: ByteArray, zone: ZoneId = ZoneId.systemDefault()): Transcript? {
        val kind = Carve.identify(data)
        if (kind == Carve.Kind.ZIP) {
            // WhatsApp "Export chat > Include media" shares a ZIP holding _chat.txt or "WhatsApp Chat with X.txt".
            val txt = Zip.entries(data) { it.endsWith(".txt") && !it.contains("/") }.entries.firstOrNull() ?: return null
            return whatsapp(txt.value.toString(Charsets.UTF_8))
        }
        if (kind != Carve.Kind.TEXT && kind != Carve.Kind.XML) return null
        val text = data.toString(Charsets.UTF_8).removePrefix("\uFEFF")
        if (text.trimStart().startsWith("<?xml") || text.contains("<smses")) return smsBackup(text, zone)
        return whatsapp(text)
    }

    // ---- WhatsApp -------------------------------------------------------------------

    // Android: "12/31/23, 9:15 PM - Name: text"   iPhone: "[12/31/23, 9:15:03 PM] Name: text"
    private val LINE = Regex(
        "^\\u200E?\\[?(\\d{1,4})[./-](\\d{1,2})[./-](\\d{1,4}),?\\s+(\\d{1,2})[:.](\\d{2})(?:[:.](\\d{2}))?\\s*([AaPp]\\.?\\s?[Mm]\\.?)?\\]?\\s*(?:-|–)?\\s*([^:]{1,80}?):\\s?(.*)$"
    )
    private val SYSTEM = Regex(
        "^\\u200E?\\[?(\\d{1,4})[./-](\\d{1,2})[./-](\\d{1,4}),?\\s+(\\d{1,2})[:.](\\d{2})(?:[:.](\\d{2}))?\\s*([AaPp]\\.?\\s?[Mm]\\.?)?\\]?\\s*(?:-|–)\\s*(.*)$"
    )

    private data class Raw(val a: Int, val b: Int, val y: Int, val h: Int, val mi: Int, val s: Int, val ampm: String?, val sender: String, val text: String, val yearFirst: Boolean)

    fun whatsapp(text: String): Transcript? {
        val raws = ArrayList<Raw>()
        for (line0 in text.lines()) {
            val line = line0.replace('\u202F', ' ').replace('\u00A0', ' ')
            val m = LINE.find(line)
            val sys = if (m == null) SYSTEM.find(line) else null
            val g = (m ?: sys)?.groupValues
            if (g != null) {
                val p1 = g[1].toInt(); val p2 = g[2].toInt(); val p3 = g[3].toInt()
                val yearFirst = g[1].length == 4
                val (a, b, y) = if (yearFirst) Triple(p2, p3, p1) else Triple(p1, p2, if (p3 < 100) 2000 + p3 else p3)
                val sender = if (m != null) g[8].trim().trimStart('\u200E') else ""
                val body = if (m != null) g[9] else g[8]
                raws += Raw(a, b, y, g[4].toInt(), g[5].toInt(), g[6].ifEmpty { "0" }.toInt(), g[7].ifEmpty { null }, sender, body.trimStart('\u200E'), yearFirst)
            } else if (raws.isNotEmpty() && line.isNotEmpty()) {
                val last = raws.removeAt(raws.size - 1)
                raws += last.copy(text = last.text + "\n" + line)
            }
        }
        if (raws.size < 2) return null
        // Decide month-first or day-first from the whole file: any first number over 12 means day-first.
        val dayFirst = when {
            raws.all { it.yearFirst } -> false
            raws.any { !it.yearFirst && it.a > 12 } -> true
            raws.any { !it.yearFirst && it.b > 12 } -> false
            else -> !raws.any { it.ampm != null } // 24-hour exports are usually day-first locales
        }
        val msgs = raws.mapNotNull { r ->
            val (month, day) = if (r.yearFirst) r.a to r.b else if (dayFirst) r.b to r.a else r.a to r.b
            var h = r.h
            r.ampm?.lowercase()?.let { ap -> if (ap.startsWith("p") && h < 12) h += 12; if (ap.startsWith("a") && h == 12) h = 0 }
            val t = runCatching { LocalDateTime.of(r.y, month, day, h, r.mi, r.s) }.getOrNull() ?: return@mapNotNull null
            Message(t.format(LOCAL), r.sender.ifEmpty { "(WhatsApp notice)" }, r.text.trim())
        }
        if (msgs.size < 2) return null
        val people = msgs.map { it.sender }.filter { it != "(WhatsApp notice)" }.distinct()
        return Transcript("WhatsApp export", msgs.sortedBy { it.time }, people, dayFirst)
    }

    private val LOCAL = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")

    // ---- SMS Backup & Restore -------------------------------------------------------

    private val ATTR = Regex("([A-Za-z_]+)=\"([^\"]*)\"")

    fun smsBackup(xml: String, zone: ZoneId = ZoneId.systemDefault()): Transcript? {
        val out = ArrayList<Message>()
        for (m in Regex("<(sms|mms)\\s([^>]*?)/?>").findAll(xml)) {
            val attrs = ATTR.findAll(m.groupValues[2]).associate { it.groupValues[1] to unXml(it.groupValues[2]) }
            val ms = attrs["date"]?.toLongOrNull() ?: continue
            val time = LocalDateTime.ofInstant(Instant.ofEpochMilli(ms), zone).format(LOCAL)
            val contact = attrs["contact_name"]?.takeIf { it.isNotBlank() && it != "(Unknown)" } ?: attrs["address"] ?: "Unknown"
            if (m.groupValues[1] == "sms") {
                val outgoing = attrs["type"] == "2"
                out += Message(time, if (outgoing) "Me" else contact, attrs["body"] ?: "", outgoing)
            } else {
                val outgoing = attrs["msg_box"] == "2"
                // Picture-message text lives in a <part ct="text/plain" text="..."/> after the opening tag.
                val tail = xml.substring(m.range.last + 1, minOf(xml.length, m.range.last + 1 + 200_000)).substringBefore("</mms>")
                val body = Regex("<part\\s[^>]*ct=\"text/plain\"[^>]*text=\"([^\"]*)\"").findAll(tail).joinToString("\n") { unXml(it.groupValues[1]) }
                val media = Regex("<part\\s[^>]*ct=\"(image|video|audio)/[^\"]*\"").findAll(tail).count()
                val text = listOfNotNull(body.ifBlank { null }, if (media > 0) "[$media attachment${if (media != 1) "s" else ""}]" else null).joinToString(" ")
                out += Message(time, if (outgoing) "Me" else contact, text, outgoing)
            }
        }
        if (out.isEmpty()) return null
        return Transcript("SMS Backup & Restore export", out.sortedBy { it.time }, out.map { it.sender }.distinct())
    }

    private fun unXml(s: String) = s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'")
        .replace("&#10;", "\n").replace("&#13;", "").replace("&amp;", "&")
}
