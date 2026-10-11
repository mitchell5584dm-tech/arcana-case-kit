package com.arcanaforensics.arcalume.ui

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Log
import androidx.annotation.StringRes
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.arcanaforensics.arcalume.ArcalumeApp
import com.arcanaforensics.arcalume.Brand
import com.arcanaforensics.arcalume.R
import com.arcanaforensics.arcalume.core.Case
import com.arcanaforensics.arcalume.core.Entitlements
import com.arcanaforensics.arcalume.core.Evidence
import com.arcanaforensics.arcalume.core.Exhibit
import com.arcanaforensics.arcalume.core.Packet
import com.arcanaforensics.arcalume.core.sha256Hex
import com.arcanaforensics.arcalume.data.CaseRepo
import com.arcanaforensics.arcalume.core.Json
import com.arcanaforensics.arcalume.core.RepairConfig
import com.arcanaforensics.arcalume.core.Vault
import com.arcanaforensics.arcalume.data.EvidenceRepo
import com.arcanaforensics.arcalume.data.Page
import com.arcanaforensics.arcalume.data.Processor
import com.arcanaforensics.arcalume.data.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File

enum class Tab { CASE, RECOVER, VAULT, PLAN }

data class SealOutcome(val names: List<String>, val head: String, val vaults: List<File>)

data class OpenedVault(val manifest: Json.Obj, val entries: Map<String, ByteArray>) {
    val sourceName get() = (manifest["source_name"] as? Json.Str)?.value ?: "evidence"
    val created get() = (manifest["created_utc"] as? Json.Str)?.value ?: ""
    val tool get() = (manifest["tool"] as? Json.Str)?.value ?: ""
    val status get() = (manifest["report"] as? Json.Obj)?.get("status")?.let { (it as? Json.Str)?.value } ?: ""
}

data class UiState(
    val tab: Tab = Tab.CASE,
    val case: Case = Case(),
    val pages: List<Page> = emptyList(),
    val currentId: Long? = null,
    val busy: String? = null,
    val sealed: SealOutcome? = null,
    val opened: OpenedVault? = null,
    val vaults: List<EvidenceRepo.VaultFile> = emptyList(),
    val log: List<EvidenceRepo.LogEntry> = emptyList(),
    val check: EvidenceRepo.Check? = null,
    val head: String? = null,
) {
    val current: Page? get() = pages.firstOrNull { it.id == currentId } ?: pages.lastOrNull()
}

/** All state for the app's three tabs. Heavy work runs on Dispatchers.Default, one job at a time. */
class AppViewModel(app: Application) : AndroidViewModel(app) {
    val pro = (app as ArcalumeApp).pro
    val repo = EvidenceRepo(app)
    val cases = CaseRepo(app, repo)
    private val state = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = state
    private val messages = MutableStateFlow<String?>(null)
    /** One-shot messages shown in a snackbar (and so announced by TalkBack). */
    val message: StateFlow<String?> = messages
    private val work = Mutex()

    init { refreshVault(); refreshCase() }

    private fun str(@StringRes id: Int, vararg args: Any) = getApplication<Application>().getString(id, *args)
    fun say(text: String) { messages.value = text }
    fun said() { messages.value = null }
    fun select(tab: Tab) { state.update { it.copy(tab = tab) }; if (tab == Tab.VAULT) refreshVault() }
    fun show(page: Page) = state.update { it.copy(currentId = page.id) }

    private fun job(busy: String, block: suspend () -> Unit) {
        viewModelScope.launch {
            work.withLock {
                state.update { it.copy(busy = busy) }
                try { block() } finally { state.update { it.copy(busy = null) } }
            }
        }
    }

    // ---- acquire ------------------------------------------------------------------

    fun importUris(uris: List<Uri>) {
        for (uri in uris) {
            val name = displayName(uri)
            job(str(R.string.working_reading, name)) {
                val bytes = try { withContext(Dispatchers.IO) { readCapped(uri) } } catch (e: Exception) {
                    say(str(R.string.read_failed, name, e.message ?: e.javaClass.simpleName)); return@job
                }
                if (bytes == null) { say(str(R.string.too_large, name)); return@job }
                add(name, Source.IMPORT, bytes)
            }
        }
    }

    fun captured(file: File) {
        val name = "Photo " + java.text.SimpleDateFormat("yyyy-MM-dd HH.mm.ss", java.util.Locale.ROOT).format(java.util.Date()) + ".jpg"
        job(str(R.string.working_reading, name)) {
            val bytes = withContext(Dispatchers.IO) { file.readBytes().also { file.delete() } }
            add(name, Source.CAMERA, bytes)
        }
    }

    fun loadSample() = job(str(R.string.working_reading, "sample")) {
        val bytes = withContext(Dispatchers.IO) { getApplication<Application>().assets.open("sample_page.jpg").use { it.readBytes() } }
        add("Sample - two-column ledger.jpg", Source.SAMPLE, bytes)
    }

    private suspend fun add(name: String, source: Source, bytes: ByteArray) {
        state.update { it.copy(busy = str(R.string.working_recovering, name)) }
        try {
            val page = withContext(Dispatchers.Default) { Processor.process(name, source, bytes, RepairConfig()) }
            state.update { it.copy(pages = it.pages + page, currentId = page.id, tab = Tab.RECOVER) }
        } catch (e: Exception) {
            Log.w("Arcalume", "recovery failed", e)   // local logcat only; carries no file name
            say(str(R.string.read_failed, name, e.message ?: e.javaClass.simpleName))
        }
    }

    fun reprocess(page: Page, cfg: RepairConfig) = job(str(R.string.working_recovering, page.name)) {
        val next = withContext(Dispatchers.Default) { Processor.reprocess(page, cfg) }
        state.update { s -> s.copy(pages = s.pages.map { if (it.id == page.id) next else it }) }
    }

    fun remove(page: Page) = state.update { s -> s.copy(pages = s.pages.filterNot { it.id == page.id }, currentId = null) }

    private fun displayName(uri: Uri): String {
        val cr = getApplication<Application>().contentResolver
        return runCatching {
            cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            }
        }.getOrNull() ?: uri.lastPathSegment?.substringAfterLast('/') ?: "image"
    }

    /** Reads at most the size limit; returns null when the file is larger. */
    private fun readCapped(uri: Uri): ByteArray? {
        getApplication<Application>().contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "no data" }
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(1 shl 16)
            var total = 0L
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                total += n
                if (total > Brand.MAX_INPUT_BYTES) return null
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }
    }

    // ---- case ---------------------------------------------------------------------

    fun refreshCase() {
        viewModelScope.launch {
            val c = withContext(Dispatchers.IO) { cases.store.load() }
            state.update { it.copy(case = c) }
        }
    }

    private suspend fun caseChange(block: () -> Case) {
        val c = withContext(Dispatchers.IO) { block() }
        state.update { it.copy(case = c, tab = Tab.CASE) }
        refreshVault()
    }

    /** Adds files as exhibits, in the order given. Any type is accepted; nothing is changed. */
    fun addToCase(uris: List<Uri>) {
        for (uri in uris) {
            val name = displayName(uri)
            job(str(R.string.working_adding, name)) {
                val bytes = try { withContext(Dispatchers.IO) { readCapped(uri) } } catch (e: Exception) {
                    say(str(R.string.read_failed, name, e.message ?: e.javaClass.simpleName)); return@job
                }
                if (bytes == null) { say(str(R.string.too_large, name)); return@job }
                try {
                    caseChange { cases.store.add(name, bytes).first }
                    say(str(R.string.case_added, name))
                } catch (e: Exception) {
                    Log.w("Arcalume", "add to case failed", e)
                    say(str(R.string.read_failed, name, e.message ?: e.javaClass.simpleName))
                }
            }
        }
    }

    /** Adds a recovered page: the untouched original, then the lighting-corrected copy. */
    fun addPageToCase(page: Page) = job(str(R.string.working_adding, page.name)) {
        caseChange {
            val (_, orig) = cases.store.add(page.name, page.original, page.name.substringBeforeLast('.'))
            val base = page.name.substringBeforeLast('.')
            val (c, copy) = cases.store.add("$base-recovered.png", page.restoredPng, str(R.string.case_recovered_title, base))
            val n = c.exhibits.indexOfFirst { it.id == orig.id } + 1
            cases.store.edit(copy.id, copy.title, str(R.string.case_recovered_note, n), "")
        }
        say(str(R.string.case_added_page))
    }

    fun saveCaseDetails(title: String, number: String, court: String, party: String, prefix: String) = job(str(R.string.case_saving)) {
        caseChange { cases.store.updateDetails(title, number, court, party, prefix) }
        say(str(R.string.case_saved))
    }

    fun editExhibit(e: Exhibit, title: String, description: String, date: String) = job(str(R.string.case_saving)) {
        caseChange { cases.store.edit(e.id, title, description, date) }
    }

    fun moveExhibit(e: Exhibit, delta: Int) = job(str(R.string.case_saving)) { caseChange { cases.store.move(e.id, delta) } }

    fun sortExhibits() = job(str(R.string.case_saving)) { caseChange { cases.store.sortByDate() }; say(str(R.string.case_sorted)) }

    fun removeExhibit(e: Exhibit) = job(str(R.string.delete)) { caseChange { cases.store.remove(e.id) }; say(str(R.string.case_removed)) }

    private val packetLimit get() = if (pro.entitlements.value.packet) Int.MAX_VALUE else Entitlements.FREE_PACKET_EXHIBITS

    fun exportPacket(uri: Uri) = job(str(R.string.working_packet)) {
        try {
            val built = withContext(Dispatchers.Default) { Packet.build(cases.packetInput(), packetLimit) }
            withContext(Dispatchers.IO) { write(uri, built.pdf); cases.store.recordExport("packet_exported", built.sha256, minOf(state.value.case.exhibits.size, packetLimit)) }
            refreshVault()
            say(str(R.string.packet_saved, built.pages))
        } catch (e: Exception) {
            Log.w("Arcalume", "packet failed", e)
            say(str(R.string.save_failed, e.message ?: e.javaClass.simpleName))
        }
    }

    /** Pro only: the ZIP of originals, sums, manifest, log and packet. */
    fun exportBundle(uri: Uri) = job(str(R.string.working_bundle)) {
        if (!pro.entitlements.value.packet) return@job
        try {
            val zip = withContext(Dispatchers.Default) {
                val input = cases.packetInput()
                val built = Packet.build(input)
                Packet.bundle(input, built, repo.ledgerFile.takeIf { it.exists() }?.readBytes())
            }
            withContext(Dispatchers.IO) { write(uri, zip); cases.store.recordExport("bundle_exported", sha256Hex(zip), state.value.case.exhibits.size) }
            refreshVault()
            say(str(R.string.bundle_saved))
        } catch (e: Exception) {
            Log.w("Arcalume", "bundle failed", e)
            say(str(R.string.save_failed, e.message ?: e.javaClass.simpleName))
        }
    }

    // ---- export -------------------------------------------------------------------

    fun saveCopy(page: Page, uri: Uri) = job(str(R.string.save_copy)) {
        val free = !pro.entitlements.value.cleanExport
        try {
            val png = withContext(Dispatchers.Default) { Processor.exportPng(page, watermark = free) }
            withContext(Dispatchers.IO) { write(uri, png) }
            say(str(if (free) R.string.saved_copy_watermarked else R.string.saved_copy))
        } catch (e: Exception) {
            say(str(R.string.save_failed, e.message ?: e.javaClass.simpleName))
        }
    }

    fun exportFile(file: File, uri: Uri) = job(str(R.string.export)) {
        try {
            withContext(Dispatchers.IO) { write(uri, file.readBytes()) }
            say(str(R.string.exported))
        } catch (e: Exception) {
            say(str(R.string.save_failed, e.message ?: e.javaClass.simpleName))
        }
    }

    fun exportBytes(bytes: ByteArray, uri: Uri) = job(str(R.string.export)) {
        try {
            withContext(Dispatchers.IO) { write(uri, bytes) }
            say(str(R.string.exported))
        } catch (e: Exception) {
            say(str(R.string.save_failed, e.message ?: e.javaClass.simpleName))
        }
    }

    private fun write(uri: Uri, bytes: ByteArray) {
        getApplication<Application>().contentResolver.openOutputStream(uri, "wt").use { out ->
            requireNotNull(out) { "cannot write there" }
            out.write(bytes)
        }
    }

    // ---- seal and open ------------------------------------------------------------

    /** Seals [pages] with one passphrase. Pro only; the UI offers the upgrade instead otherwise. */
    fun seal(pages: List<Page>, passphrase: String) = job(str(R.string.working_sealing)) {
        if (!pro.entitlements.value.seal) return@job
        try {
            val done = withContext(Dispatchers.Default) { pages.map { repo.seal(it, passphrase) } }
            val head = done.last().ledgerEntry["hash"]!!.str()
            state.update { it.copy(sealed = SealOutcome(pages.map { p -> p.name }, head, done.map { d -> d.vault })) }
            refreshVault()
        } catch (e: java.nio.file.FileAlreadyExistsException) {
            say(e.reason ?: e.message ?: "already sealed")
        } catch (e: Vault.VaultError) {
            say(e.message ?: "could not seal")
        }
    }

    fun dismissSealed() = state.update { it.copy(sealed = null) }

    fun openVault(bytes: ByteArray, passphrase: String, onWrong: () -> Unit) = job(str(R.string.working_opening)) {
        try {
            val (manifest, entries) = withContext(Dispatchers.Default) { Evidence.open(bytes, passphrase) }
            state.update { it.copy(opened = OpenedVault(manifest, entries)) }
        } catch (e: Vault.AuthError) {
            onWrong()
        } catch (e: Exception) {
            say(e.message ?: "not a vault")
        }
    }

    fun readUri(uri: Uri): ByteArray? = try { readCapped(uri) } catch (e: Exception) { null }

    fun closeOpened() = state.update { it.copy(opened = null) }

    fun deleteVault(v: EvidenceRepo.VaultFile) = job(str(R.string.delete)) {
        withContext(Dispatchers.IO) { repo.delete(v) }
        refreshVault()
        say(str(R.string.deleted))
    }

    fun verify(expected: String?) = job(str(R.string.working_verifying)) {
        val check = withContext(Dispatchers.IO) { repo.verify(expected) }
        state.update { it.copy(check = check, head = check.result.head) }
    }

    fun refreshVault() {
        viewModelScope.launch {
            val (v, log) = withContext(Dispatchers.IO) { repo.vaults() to repo.entries() }
            state.update { it.copy(vaults = v, log = log, head = log.firstOrNull()?.hash, check = null) }
        }
    }
}
