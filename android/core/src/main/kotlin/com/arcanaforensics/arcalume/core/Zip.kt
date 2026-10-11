package com.arcanaforensics.arcalume.core

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

/** Small, bounded ZIP helpers. Reading never inflates more than [MAX_ENTRY] bytes per entry. */
object Zip {
    const val MAX_ENTRY = 16 shl 20
    const val MAX_ENTRIES = 4000

    fun names(data: ByteArray): List<String> = try {
        val out = ArrayList<String>()
        ZipInputStream(ByteArrayInputStream(data)).use { z ->
            while (out.size < MAX_ENTRIES) {
                val e = z.nextEntry ?: break
                out += e.name
            }
        }
        out
    } catch (e: Exception) {
        emptyList()
    }

    /** The bytes of the first entry named [name], or null. */
    fun read(data: ByteArray, name: String): ByteArray? = entries(data) { it == name }[name]

    /** Entries whose names pass [want], read up to [MAX_ENTRY] bytes each. */
    fun entries(data: ByteArray, want: (String) -> Boolean): Map<String, ByteArray> = try {
        val out = LinkedHashMap<String, ByteArray>()
        ZipInputStream(ByteArrayInputStream(data)).use { z ->
            var n = 0
            while (n++ < MAX_ENTRIES) {
                val e = z.nextEntry ?: break
                if (e.isDirectory || !want(e.name) || out.containsKey(e.name)) continue
                val buf = ByteArrayOutputStream()
                val chunk = ByteArray(1 shl 14)
                var total = 0
                while (true) {
                    val r = z.read(chunk)
                    if (r < 0) break
                    total += r
                    if (total > MAX_ENTRY) break
                    buf.write(chunk, 0, r)
                }
                if (total <= MAX_ENTRY) out[e.name] = buf.toByteArray()
            }
        }
        out
    } catch (e: Exception) {
        emptyMap()
    }

    /**
     * Writes a ZIP whose bytes depend only on the inputs: fixed timestamps, entries in the
     * given order. Already-compressed media is stored, everything else deflated.
     */
    fun write(files: List<Pair<String, ByteArray>>): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { z ->
            for ((name, bytes) in files) {
                val e = ZipEntry(name)
                e.time = FIXED_TIME
                if (storedExt(name)) {
                    e.method = ZipEntry.STORED
                    e.size = bytes.size.toLong()
                    e.compressedSize = bytes.size.toLong()
                    e.crc = CRC32().also { it.update(bytes) }.value
                }
                z.putNextEntry(e)
                z.write(bytes)
                z.closeEntry()
            }
        }
        return bos.toByteArray()
    }

    private const val FIXED_TIME = 315532800000L + 86_400_000L // 1980-01-02, the ZIP epoch plus a day

    private fun storedExt(name: String) = name.substringAfterLast('.', "").lowercase() in
        setOf("jpg", "jpeg", "png", "gif", "webp", "heic", "mp4", "mov", "m4a", "mp3", "ogg", "zip", "docx", "xlsx", "pptx", "arcr", "3gp", "amr", "opus")
}
