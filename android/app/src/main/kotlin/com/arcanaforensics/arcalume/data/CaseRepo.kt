package com.arcanaforensics.arcalume.data

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import com.arcanaforensics.arcalume.Brand
import com.arcanaforensics.arcalume.core.Carve
import com.arcanaforensics.arcalume.core.CaseStore
import com.arcanaforensics.arcalume.core.Exhibit
import com.arcanaforensics.arcalume.core.Meta
import com.arcanaforensics.arcalume.core.Packet
import java.io.ByteArrayOutputStream
import java.io.File
import java.time.ZoneId

/**
 * The case kept on this phone, in app-private storage next to the vault. Every change is
 * written to the vault's custody log, and the log head is remembered the same way sealing
 * does, so the Vault tab's check covers case changes too.
 */
class CaseRepo(context: Context, private val evidence: EvidenceRepo) {
    val store = CaseStore(File(context.filesDir, "case"), evidence.ledger) { evidence.remember(it) }

    fun packetInput(zone: ZoneId = ZoneId.systemDefault()): Packet.Input {
        val c = store.load()
        val head = evidence.ledger.verify()
        return Packet.Input(c, store::original, ::printable, head.head, head.entries, Brand.TOOL, zone = zone)
    }

    /**
     * A JPEG the packet can print: decoded, turned upright from its EXIF orientation, scaled
     * to at most [Brand.PACKET_IMAGE_MAX_SIDE] and re-encoded. The original is untouched.
     */
    fun printable(e: Exhibit): ByteArray? {
        val bytes = store.original(e)
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        var sample = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / (sample * 2) >= Brand.PACKET_IMAGE_MAX_SIDE) sample *= 2
        val bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample }) ?: return null
        val orientation = if (e.kind == Carve.Kind.JPEG) Meta.read(e.fileName, bytes).orientation else 1
        val upright = rotate(bmp, orientation)
        val long = maxOf(upright.width, upright.height)
        val scaled = if (long > Brand.PACKET_IMAGE_MAX_SIDE) {
            val f = Brand.PACKET_IMAGE_MAX_SIDE.toFloat() / long
            Bitmap.createScaledBitmap(upright, (upright.width * f).toInt().coerceAtLeast(1), (upright.height * f).toInt().coerceAtLeast(1), true)
        } else upright
        // JPEG has no alpha: draw onto white so transparent screenshots stay readable.
        val opaque = Bitmap.createBitmap(scaled.width, scaled.height, Bitmap.Config.ARGB_8888).also {
            val canvas = android.graphics.Canvas(it)
            canvas.drawColor(android.graphics.Color.WHITE)
            canvas.drawBitmap(scaled, 0f, 0f, null)
        }
        return ByteArrayOutputStream().also { opaque.compress(Bitmap.CompressFormat.JPEG, 88, it) }.toByteArray()
    }

    private fun rotate(b: Bitmap, orientation: Int): Bitmap {
        val m = Matrix()
        when (orientation) {
            2 -> m.postScale(-1f, 1f)
            3 -> m.postRotate(180f)
            4 -> m.postScale(1f, -1f)
            5 -> { m.postRotate(90f); m.postScale(-1f, 1f) }
            6 -> m.postRotate(90f)
            7 -> { m.postRotate(-90f); m.postScale(-1f, 1f) }
            8 -> m.postRotate(-90f)
            else -> return b
        }
        return Bitmap.createBitmap(b, 0, 0, b.width, b.height, m, true)
    }
}
