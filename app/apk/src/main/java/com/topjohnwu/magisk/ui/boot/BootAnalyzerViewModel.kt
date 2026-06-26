package com.topjohnwu.magisk.ui.boot

import android.net.Uri
import androidx.databinding.Bindable
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.topjohnwu.magisk.BR
import com.topjohnwu.magisk.R
import com.topjohnwu.magisk.arch.ActivityExecutor
import com.topjohnwu.magisk.arch.BaseViewModel
import com.topjohnwu.magisk.arch.UIActivity
import com.topjohnwu.magisk.arch.ViewEvent
import com.topjohnwu.magisk.core.AppContext
import com.topjohnwu.magisk.core.Config
import com.topjohnwu.magisk.core.Info
import com.topjohnwu.magisk.databinding.DiffItem
import com.topjohnwu.magisk.databinding.ObservableRvItem
import com.topjohnwu.magisk.databinding.set
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.launch
import timber.log.Timber
import java.io.File

class BootAnalyzerViewModel : BaseViewModel() {

    data class BootAnalysis(
        val headerVersion: String,
        val isVendor: Boolean,
        val pageSize: Int,
        val osVersion: String,
        val osPatchLevel: String,
        val name: String,
        val cmdline: String,
        val id: String,
        val isSha256: Boolean,
        val sections: List<SectionInfo>,
        val oemFlags: List<String>,
        val avbSigned: Boolean,
        val avbFooter: Boolean,
        val ramdiskStatus: String,
        val ramdiskFiles: List<RamdiskFileEntry>?,
        val dtbFstabs: List<FstabEntry>?,
        val patchPreview: PatchPreview?
    )

    data class SectionInfo(
        val name: String,
        val size: Long,
        val format: String
    ) : ObservableRvItem(), DiffItem<SectionInfo> {
        override val layoutRes get() = R.layout.item_boot_section

        val sizeFormatted: String get() = when {
            size >= 1024 * 1024 -> "${"%.2f".format(size / 1048576.0)} MB"
            size >= 1024 -> "${"%.2f".format(size / 1024.0)} KB"
            else -> "$size B"
        }

        override fun itemSameAs(other: SectionInfo) = name == other.name
        override fun contentSameAs(other: SectionInfo) = size == other.size && format == other.format
    }

    data class RamdiskFileEntry(
        val path: String,
        val mode: String,
        val uid: Int,
        val gid: Int,
        val size: Long
    ) : ObservableRvItem(), DiffItem<RamdiskFileEntry> {
        override val layoutRes get() = R.layout.item_ramdisk_file

        override fun itemSameAs(other: RamdiskFileEntry) = path == other.path
        override fun contentSameAs(other: RamdiskFileEntry) = size == other.size
    }

    data class FstabEntry(
        val source: String,
        val mountPoint: String,
        val fsType: String,
        val flags: List<String>
    )

    data class PatchPreview(
        val willPatchVerity: Boolean,
        val willPatchEncryption: Boolean,
        val willPatchLegacySAR: Boolean,
        val kernelPatches: List<String>,
        val willPatchVbmeta: Boolean,
        val ramdiskHasMagisk: Boolean
    )

    @get:Bindable
    var analysis: BootAnalysis? = null
        set(value) = set(value, field, { field = it }, BR.analysis)

    @get:Bindable
    var loading = false
        set(value) = set(value, field, { field = it }, BR.loading)

    @get:Bindable
    var selectedFileName: String = ""
        set(value) = set(value, field, { field = it }, BR.selectedFileName)

    val hasFile get() = selectedFileName.isNotEmpty()

    fun onSelectFilePressed() = object : ViewEvent(), ActivityExecutor {
        override fun invoke(activity: UIActivity<*>) {
            // Handled by Fragment via viewEvents
        }
    }.publish()

    fun analyzeBootImage(uri: Uri) {
        loading = true
        analysis = null

        viewModelScope.launch {
            try {
                val tmpDir = File(AppContext.cacheDir, "boot_analysis")
                tmpDir.mkdirs()
                val tmpFile = File(tmpDir, "boot.img")

                // Copy file from URI
                AppContext.contentResolver.openInputStream(uri)?.use { input ->
                    tmpFile.outputStream().use { output -> input.copyTo(output) }
                }

                selectedFileName = uri.lastPathSegment ?: "boot.img"

                val shell = Shell.getShell()

                // 1. Unpack and capture output
                val unpackResult = shell.newJob()
                    .add("cd $tmpDir && magiskboot unpack -h boot.img 2>&1")
                    .to(ArrayList<String>())
                    .exec()

                val headerInfo = parseUnpackOutput(unpackResult.out)

                // 2. Check ramdisk status
                val ramdiskTest = shell.newJob()
                    .add("cd $tmpDir && magiskboot cpio ramdisk.cpio test 2>&1")
                    .exec()
                val ramdiskStatus = when (ramdiskTest.code) {
                    0 -> "stock"
                    1 -> "magisk"
                    2 -> "unsupported"
                    else -> "unknown"
                }

                // 3. List ramdisk files
                val ramdiskList = shell.newJob()
                    .add("cd $tmpDir && magiskboot cpio ramdisk.cpio ls 2>&1")
                    .to(ArrayList<String>())
                    .exec()
                val ramdiskFiles = parseCpioListing(ramdiskList.out)

                // 4. Build analysis result
                val sections = mutableListOf<SectionInfo>()
                headerInfo["kernel_size"]?.toLongOrNull()?.let {
                    sections.add(SectionInfo("Kernel", it, headerInfo["kernel_format"] ?: "raw"))
                }
                headerInfo["ramdisk_size"]?.toLongOrNull()?.let {
                    sections.add(SectionInfo("Ramdisk", it, headerInfo["ramdisk_format"] ?: "raw"))
                }
                headerInfo["second_size"]?.toLongOrNull()?.let {
                    if (it > 0) sections.add(SectionInfo("Second", it, "raw"))
                }
                headerInfo["dtb_size"]?.toLongOrNull()?.let {
                    if (it > 0) sections.add(SectionInfo("DTB", it, "raw"))
                }

                val oemFlags = mutableListOf<String>()
                if (headerInfo.containsKey("chromeos")) oemFlags.add("ChromeOS")
                if (headerInfo.containsKey("dhtb")) oemFlags.add("Samsung DHTB")
                if (headerInfo.containsKey("tegra")) oemFlags.add("Tegra BLOB")
                if (headerInfo.containsKey("mtk")) oemFlags.add("MTK")
                if (headerInfo.containsKey("zimage")) oemFlags.add("zImage")

                val preview = PatchPreview(
                    willPatchVerity = !Config.keepVerity,
                    willPatchEncryption = !Config.keepEnc,
                    willPatchLegacySAR = Info.legacySAR,
                    kernelPatches = emptyList(),
                    willPatchVbmeta = Info.patchBootVbmeta,
                    ramdiskHasMagisk = ramdiskStatus == "magisk"
                )

                analysis = BootAnalysis(
                    headerVersion = headerInfo["version"] ?: "unknown",
                    isVendor = headerInfo["is_vendor"]?.toBoolean() ?: false,
                    pageSize = headerInfo["page_size"]?.toIntOrNull() ?: 4096,
                    osVersion = headerInfo["os_version"] ?: "",
                    osPatchLevel = headerInfo["os_patch_level"] ?: "",
                    name = headerInfo["name"] ?: "",
                    cmdline = headerInfo["cmdline"] ?: "",
                    id = headerInfo["id"] ?: "",
                    isSha256 = headerInfo["sha256"]?.toBoolean() ?: false,
                    sections = sections,
                    oemFlags = oemFlags,
                    avbSigned = headerInfo.containsKey("avb_signed"),
                    avbFooter = headerInfo.containsKey("avb_footer"),
                    ramdiskStatus = ramdiskStatus,
                    ramdiskFiles = ramdiskFiles,
                    dtbFstabs = null,
                    patchPreview = preview
                )

                // Cleanup
                shell.newJob().add("cd $tmpDir && magiskboot cleanup 2>/dev/null; rm -rf $tmpDir").exec()

            } catch (e: Exception) {
                Timber.e(e, "Boot analysis failed")
            } finally {
                loading = false
            }
        }
    }

    private fun parseUnpackOutput(lines: List<String>): Map<String, String> {
        val map = mutableMapOf<String, String>()
        lines.forEach { line ->
            val idx = line.indexOf(": ")
            if (idx > 0) {
                val key = line.substring(0, idx).trim().lowercase().replace(" ", "_")
                val value = line.substring(idx + 2).trim()
                map[key] = value
            }
        }
        return map
    }

    private fun parseCpioListing(lines: List<String>): List<RamdiskFileEntry> {
        return lines.mapNotNull { line ->
            // Format: mode uid gid size path
            val parts = line.trim().split(Regex("\\s+"), limit = 5)
            if (parts.size >= 5) {
                try {
                    RamdiskFileEntry(
                        path = parts[4],
                        mode = parts[0],
                        uid = parts[1].toInt(),
                        gid = parts[2].toInt(),
                        size = parts[3].toLong()
                    )
                } catch (_: Exception) { null }
            } else null
        }
    }
}
