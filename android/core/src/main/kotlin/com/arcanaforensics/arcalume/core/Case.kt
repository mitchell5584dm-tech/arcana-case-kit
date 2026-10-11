package com.arcanaforensics.arcalume.core

import java.io.File

/**
 * One case: its details and its numbered exhibits. Originals are stored byte-for-byte
 * under `files/<sha256>`; adding, removing and re-numbering exhibits is written to the
 * same hash-chained custody ledger the vault uses, so the log tells the whole story.
 */
data class Case(
    val title: String = "",
    val number: String = "",
    val court: String = "",
    val party: String = "",
    /** Prefix for page stamps, such as "SMITH" in SMITH-000012. */
    val stampPrefix: String = "",
    val exhibits: List<Exhibit> = emptyList(),
) {
    val displayTitle get() = title.ifBlank { "Untitled case" }
    val prefix get() = stampPrefix.ifBlank {
        title.uppercase().filter { it.isLetterOrDigit() || it == ' ' }.split(' ').filter { it.length > 2 && it != "VS" && it != "THE" }.take(3).joinToString("") { it.take(3) }.ifEmpty { "EXH" }
    }.uppercase().filter { it.isLetterOrDigit() }.take(12)

    fun toJson(): Json.Obj = Json.obj(
        "version" to 1, "title" to title, "number" to number, "court" to court, "party" to party, "stamp_prefix" to stampPrefix,
        "exhibits" to exhibits.map { it.toJson() },
    )

    companion object {
        fun fromJson(o: Json.Obj): Case = Case(
            title = o.s("title"), number = o.s("number"), court = o.s("court"), party = o.s("party"), stampPrefix = o.s("stamp_prefix"),
            exhibits = (o["exhibits"] as? Json.Arr)?.items?.map { Exhibit.fromJson(it.obj()) } ?: emptyList(),
        )
    }
}

data class Exhibit(
    val id: String,
    val title: String,
    val description: String,
    val fileName: String,
    val sha256: String,
    val size: Long,
    val addedUtc: String,
    val kind: Carve.Kind,
    /** When the file says it was made, if it says. */
    val created: String?,
    /** The date the person says the event happened, overriding [created] in the timeline. */
    val eventDate: String = "",
    val fields: List<Meta.Field> = emptyList(),
    val findings: List<Finding> = emptyList(),
    /** Set when the file is a chat export: the participants and the message count. */
    val chat: ChatSummary? = null,
) {
    data class ChatSummary(val source: String, val participants: List<String>, val messages: Int, val first: String?, val last: String?)

    val when_ get() = eventDate.ifBlank { created ?: "" }

    fun toJson(): Json.Obj = Json.obj(
        "id" to id, "title" to title, "description" to description, "file_name" to fileName, "sha256" to sha256, "size" to size,
        "added_utc" to addedUtc, "kind" to kind.name, "created" to created, "event_date" to eventDate,
        "fields" to fields.map { Json.obj("label" to it.label, "value" to it.value) },
        "findings" to findings.map { Json.obj("level" to it.level.name, "text" to it.text) },
        "chat" to chat?.let { Json.obj("source" to it.source, "participants" to it.participants, "messages" to it.messages, "first" to it.first, "last" to it.last) },
    )

    companion object {
        fun fromJson(o: Json.Obj): Exhibit = Exhibit(
            id = o.s("id"), title = o.s("title"), description = o.s("description"), fileName = o.s("file_name"), sha256 = o.s("sha256"),
            size = (o["size"] as? Json.Num)?.long ?: 0, addedUtc = o.s("added_utc"),
            kind = runCatching { Carve.Kind.valueOf(o.s("kind")) }.getOrDefault(Carve.Kind.UNKNOWN),
            created = (o["created"] as? Json.Str)?.value, eventDate = o.s("event_date"),
            fields = (o["fields"] as? Json.Arr)?.items?.map { Meta.Field(it.obj().s("label"), it.obj().s("value")) } ?: emptyList(),
            findings = (o["findings"] as? Json.Arr)?.items?.map {
                Finding(runCatching { Finding.Level.valueOf(it.obj().s("level")) }.getOrDefault(Finding.Level.INFO), it.obj().s("text"))
            } ?: emptyList(),
            chat = (o["chat"] as? Json.Obj)?.let { c ->
                ChatSummary(c.s("source"), (c["participants"] as? Json.Arr)?.items?.map { it.str() } ?: emptyList(),
                    (c["messages"] as? Json.Num)?.long?.toInt() ?: 0, (c["first"] as? Json.Str)?.value, (c["last"] as? Json.Str)?.value)
            },
        )
    }
}

internal fun Json.Obj.s(key: String): String = (this[key] as? Json.Str)?.value ?: ""

/** Keeps one case on disk: `case.json`, `files/<sha256>`, and events in [ledger]. */
class CaseStore(val dir: File, private val ledger: Ledger, private val onLedger: (Json.Obj) -> Unit = {}) {
    private val caseFile = File(dir, "case.json")
    private val files = File(dir, "files")
    private val rng = java.security.SecureRandom()

    @Synchronized
    fun load(): Case = if (caseFile.exists()) runCatching { Case.fromJson(Json.parse(caseFile.readBytes()).obj()) }.getOrDefault(Case()) else Case()

    @Synchronized
    private fun save(c: Case) {
        dir.mkdirs()
        val tmp = File(dir, "case.json.tmp")
        tmp.writeBytes(c.toJson().canonicalBytes())
        if (!tmp.renameTo(caseFile)) { caseFile.delete(); tmp.renameTo(caseFile) }
    }

    fun original(e: Exhibit): ByteArray = File(files, e.sha256).readBytes()
    fun originalFile(e: Exhibit): File = File(files, e.sha256)

    @Synchronized
    fun updateDetails(title: String, number: String, court: String, party: String, stampPrefix: String): Case {
        val c = load().copy(title = title.take(200), number = number.take(80), court = court.take(200), party = party.take(120), stampPrefix = stampPrefix.take(12))
        save(c)
        return c
    }

    /** Adds [data] as the next exhibit; the same bytes twice are allowed (separate exhibits). */
    @Synchronized
    fun add(name: String, data: ByteArray, title: String? = null, zone: java.time.ZoneId = java.time.ZoneId.systemDefault()): Pair<Case, Exhibit> {
        val sha = sha256Hex(data)
        files.mkdirs()
        val f = File(files, sha)
        if (!f.exists()) Evidence.writeNew(f, data)
        val meta = Meta.read(name, data)
        val transcript = runCatching { Chats.parse(name, data, zone) }.getOrNull()
        val findings = meta.findings.toMutableList()
        if (transcript != null) {
            findings.add(0, Finding(Finding.Level.OK, "Read as a ${transcript.source}: ${transcript.messages.size} messages between " +
                "${transcript.participants.take(4).joinToString(", ")}${if (transcript.participants.size > 4) " and others" else ""}, " +
                "${transcript.first?.take(10)} to ${transcript.last?.take(10)}. The packet prints them in time order."))
        }
        val e = Exhibit(
            id = sha.take(12) + hex(ByteArray(2).also(rng::nextBytes)),
            title = (title ?: name.substringBeforeLast('.')).take(160),
            description = "",
            fileName = name.take(200),
            sha256 = sha,
            size = data.size.toLong(),
            addedUtc = Ledger.now(),
            kind = meta.kind,
            created = meta.created ?: transcript?.first,
            fields = meta.fields,
            findings = findings,
            chat = transcript?.let { Exhibit.ChatSummary(it.source, it.participants, it.messages.size, it.first, it.last) },
        )
        val c = load().let { it.copy(exhibits = it.exhibits + e) }
        save(c)
        onLedger(ledger.append("exhibit_added", Json.obj(
            "exhibit" to c.exhibits.size, "exhibit_id" to e.id, "source_sha256" to sha, "size" to data.size, "kind" to meta.kind.name.lowercase(),
        )))
        return c to e
    }

    @Synchronized
    fun edit(id: String, title: String, description: String, eventDate: String): Case {
        val c = load().let { c -> c.copy(exhibits = c.exhibits.map { if (it.id == id) it.copy(title = title.take(160), description = description.take(2000), eventDate = eventDate.take(40)) else it }) }
        save(c)
        return c
    }

    @Synchronized
    fun move(id: String, delta: Int): Case {
        val c = load()
        val i = c.exhibits.indexOfFirst { it.id == id }
        val j = i + delta
        if (i < 0 || j !in c.exhibits.indices) return c
        val list = c.exhibits.toMutableList().also { java.util.Collections.swap(it, i, j) }
        val next = c.copy(exhibits = list)
        save(next)
        onLedger(ledger.append("exhibits_renumbered", Json.obj("order" to list.map { it.id })))
        return next
    }

    /** Sorts exhibits by date (undated last), the usual order for a chronology. */
    @Synchronized
    fun sortByDate(): Case {
        val c = load()
        val list = c.exhibits.sortedWith(compareBy<Exhibit> { it.when_.isEmpty() }.thenBy { it.when_ })
        if (list == c.exhibits) return c
        val next = c.copy(exhibits = list)
        save(next)
        onLedger(ledger.append("exhibits_renumbered", Json.obj("order" to list.map { it.id })))
        return next
    }

    @Synchronized
    fun remove(id: String): Case {
        val c = load()
        val e = c.exhibits.firstOrNull { it.id == id } ?: return c
        val next = c.copy(exhibits = c.exhibits.filterNot { it.id == id })
        save(next)
        if (next.exhibits.none { it.sha256 == e.sha256 }) File(files, e.sha256).delete()
        onLedger(ledger.append("exhibit_removed", Json.obj("exhibit_id" to e.id, "source_sha256" to e.sha256)))
        return next
    }

    /** Records that a packet or bundle was produced, with the fingerprint of what was handed out. */
    fun recordExport(event: String, sha256: String, exhibits: Int) {
        onLedger(ledger.append(event, Json.obj("sha256" to sha256, "exhibits" to exhibits)))
    }
}
