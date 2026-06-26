package com.topjohnwu.magisk.core.security

import android.content.Context
import com.topjohnwu.magisk.core.Config
import com.topjohnwu.magisk.core.Const
import com.topjohnwu.magisk.core.Info
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.ShellUtils.fastCmd
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

object SecurityAudit {

    data class AuditReport(
        val magiskStatus: MagiskStatus,
        val selinuxStatus: SelinuxStatus,
        val encryptionStatus: EncryptionStatus,
        val bootLayout: BootLayout,
        val zygiskStatus: ZygiskStatus,
        val denyListStatus: DenyListStatus,
        val suStatistics: SuStatistics,
        val riskAssessment: List<RiskItem>
    )

    data class MagiskStatus(
        val version: String,
        val versionCode: Int,
        val isActive: Boolean,
        val isDebug: Boolean,
        val isUnsupported: Boolean,
        val magiskPath: String
    )

    data class SelinuxStatus(
        val mode: SelinuxMode,
        val context: String,
        val isMagiskDomain: Boolean
    )

    enum class SelinuxMode { ENFORCING, PERMISSIVE, DISABLED }

    data class EncryptionStatus(
        val type: EncryptionType,
        val cryptoType: String
    )

    enum class EncryptionType { FDE, FBE, NONE }

    data class BootLayout(
        val isSAR: Boolean,
        val isLegacySAR: Boolean,
        val isAB: Boolean,
        val slot: String,
        val hasRamdisk: Boolean,
        val isVendorBoot: Boolean,
        val patchBootVbmeta: Boolean
    )

    data class ZygiskStatus(
        val enabled: Boolean,
        val loadedModuleCount: Int,
        val moduleNames: List<String>
    )

    data class DenyListStatus(
        val enforced: Boolean,
        val targetCount: Int,
        val enforcementMode: String
    )

    data class SuStatistics(
        val rootAccessMode: Int,
        val allowedApps: Int,
        val deniedApps: Int,
        val totalRequests: Int,
        val multiuserMode: Int,
        val namespaceMode: Int,
        val biometricEnabled: Boolean,
        val reauthEnabled: Boolean
    )

    data class RiskItem(
        val level: RiskLevel,
        val title: String,
        val description: String,
        val action: String?
    )

    enum class RiskLevel { HIGH, MEDIUM, LOW }

    suspend fun collect(shell: Shell, context: Context): AuditReport = withContext(Dispatchers.IO) {
        val magiskStatus = collectMagiskStatus(shell)
        val selinuxStatus = collectSelinuxStatus(shell)
        val encryptionStatus = collectEncryptionStatus()
        val bootLayout = collectBootLayout()
        val zygiskStatus = collectZygiskStatus(shell)
        val denyListStatus = collectDenyListStatus(shell)
        val suStatistics = collectSuStatistics(shell)
        val riskAssessment = assessRisks(
            magiskStatus, selinuxStatus, encryptionStatus,
            bootLayout, zygiskStatus, denyListStatus, suStatistics
        )

        AuditReport(
            magiskStatus, selinuxStatus, encryptionStatus,
            bootLayout, zygiskStatus, denyListStatus, suStatistics,
            riskAssessment
        )
    }

    private fun collectMagiskStatus(shell: Shell): MagiskStatus {
        val magiskPath = try {
            fastCmd(shell, "magisk --path").trim()
        } catch (_: Exception) { "" }

        return MagiskStatus(
            version = Info.env.versionString,
            versionCode = Info.env.versionCode,
            isActive = Info.env.isActive,
            isDebug = Info.env.isDebug,
            isUnsupported = Info.env.isUnsupported,
            magiskPath = magiskPath
        )
    }

    private fun collectSelinuxStatus(shell: Shell): SelinuxStatus {
        val enforce = try {
            fastCmd(shell, "cat /sys/fs/selinux/enforce").trim()
        } catch (_: Exception) { "" }

        val mode = when (enforce) {
            "1" -> SelinuxMode.ENFORCING
            "0" -> SelinuxMode.PERMISSIVE
            else -> SelinuxMode.DISABLED
        }

        val context = try {
            fastCmd(shell, "cat /proc/self/attr/current").trim()
        } catch (_: Exception) { "" }

        val magiskCon = try {
            fastCmd(shell, "cat /proc/\$(pidof magiskd)/attr/current 2>/dev/null").trim()
        } catch (_: Exception) { "" }
        val isMagiskDomain = magiskCon.contains("magisk")

        return SelinuxStatus(mode, context, isMagiskDomain)
    }

    private fun collectEncryptionStatus(): EncryptionStatus {
        return EncryptionStatus(
            type = when {
                Info.isFDE -> EncryptionType.FDE
                Info.crypto.isNotEmpty() -> EncryptionType.FBE
                else -> EncryptionType.NONE
            },
            cryptoType = Info.crypto
        )
    }

    private fun collectBootLayout(): BootLayout {
        return BootLayout(
            isSAR = Info.isSAR,
            isLegacySAR = Info.legacySAR,
            isAB = Info.isAB,
            slot = Info.slot,
            hasRamdisk = Info.ramdisk,
            isVendorBoot = Info.isVendorBoot,
            patchBootVbmeta = Info.patchBootVbmeta
        )
    }

    private fun collectZygiskStatus(shell: Shell): ZygiskStatus {
        val enabled = Info.isZygiskEnabled

        val modules = if (enabled) {
            try {
                val moduleDir = File(Const.MODULE_PATH)
                moduleDir.listFiles()
                    ?.filter { it.isDirectory && File(it, "zygisk").isDirectory }
                    ?.mapNotNull { dir ->
                        val prop = File(dir, "module.prop")
                        if (prop.exists()) {
                            prop.readLines()
                                .firstOrNull { it.startsWith("name=") }
                                ?.removePrefix("name=")
                        } else null
                    } ?: emptyList()
            } catch (_: Exception) { emptyList() }
        } else emptyList()

        return ZygiskStatus(enabled, modules.size, modules)
    }

    private fun collectDenyListStatus(shell: Shell): DenyListStatus {
        val enforced = Config.denyList
        val count = try {
            val result = Shell.cmd("magisk --denylist ls").exec()
            result.out.size
        } catch (_: Exception) { 0 }

        val mode = if (Info.isZygiskEnabled) "zygisk" else "logcat"

        return DenyListStatus(enforced, count, mode)
    }

    private fun collectSuStatistics(shell: Shell): SuStatistics {
        var allowed = 0
        var denied = 0
        try {
            val result = Shell.cmd("magisk --sqlite \"SELECT policy, COUNT(*) FROM su GROUP BY policy\"").exec()
            result.out.forEach { line ->
                val parts = line.split("|")
                val policy = parts.firstOrNull { it.startsWith("policy=") }
                    ?.removePrefix("policy=")?.toIntOrNull()
                val count = parts.firstOrNull { it.startsWith("count=") }
                    ?.removePrefix("count=")?.toIntOrNull() ?: 0
                when (policy) {
                    Config.Value.SU_AUTO_ALLOW -> allowed = count
                    Config.Value.SU_AUTO_DENY -> denied = count
                }
            }
        } catch (_: Exception) {}

        return SuStatistics(
            rootAccessMode = Config.rootMode,
            allowedApps = allowed,
            deniedApps = denied,
            totalRequests = allowed + denied,
            multiuserMode = Config.suMultiuserMode,
            namespaceMode = Config.suMntNamespaceMode,
            biometricEnabled = Config.suAuth,
            reauthEnabled = Config.suReAuth
        )
    }

    fun assessRisks(
        magisk: MagiskStatus,
        selinux: SelinuxStatus,
        encryption: EncryptionStatus,
        boot: BootLayout,
        zygisk: ZygiskStatus,
        denyList: DenyListStatus,
        su: SuStatistics
    ): List<RiskItem> {
        val risks = mutableListOf<RiskItem>()

        // Risk 1: SELinux Permissive
        if (selinux.mode == SelinuxMode.PERMISSIVE) {
            risks.add(RiskItem(
                RiskLevel.HIGH,
                "SELinux Permissive",
                "SELinux is in permissive mode, system security enforcement is weakened",
                "Restore SELinux to Enforcing mode"
            ))
        }

        // Risk 2: SELinux Disabled
        if (selinux.mode == SelinuxMode.DISABLED) {
            risks.add(RiskItem(
                RiskLevel.HIGH,
                "SELinux Disabled",
                "SELinux has been completely disabled, extremely dangerous",
                null
            ))
        }

        // Risk 3: Outdated Magisk
        if (magisk.isUnsupported) {
            risks.add(RiskItem(
                RiskLevel.HIGH,
                "Outdated Magisk",
                "Current Magisk version is too old, potential security vulnerabilities exist",
                "Update to the latest version"
            ))
        }

        // Risk 4: Root without authentication
        if (su.rootAccessMode == Config.Value.ROOT_ACCESS_APPS_AND_ADB &&
            !su.biometricEnabled && !su.reauthEnabled
        ) {
            risks.add(RiskItem(
                RiskLevel.MEDIUM,
                "Root Access Without Authentication",
                "Root access is open to all apps without biometric authentication",
                "Enable SU biometric auth or restrict root access scope"
            ))
        }

        // Risk 5: Emulator environment
        if (Info.isEmulator) {
            risks.add(RiskItem(
                RiskLevel.LOW,
                "Emulator Environment",
                "Emulator environment detected, some features may be limited",
                null
            ))
        }

        // Risk 6: Zygisk without DenyList
        if (zygisk.enabled && !denyList.enforced) {
            risks.add(RiskItem(
                RiskLevel.MEDIUM,
                "Zygisk Without DenyList",
                "Zygisk is enabled but DenyList is not enforced, Magisk may be detected",
                "Enable DenyList enforcement"
            ))
        }

        // Risk 7: No screen lock
        if (!Info.isDeviceSecure) {
            risks.add(RiskItem(
                RiskLevel.MEDIUM,
                "No Screen Lock",
                "Device has no screen lock set, root access has no physical protection",
                "Set up screen lock"
            ))
        }

        // Risk 8: Bootloop counter
        if (Config.bootloop > 2) {
            risks.add(RiskItem(
                RiskLevel.MEDIUM,
                "Bootloop Detected",
                "Multiple boot failures detected (${Config.bootloop} times), possibly caused by modules",
                "Check recently installed modules or enter safe mode"
            ))
        }

        return risks.sortedBy { it.level.ordinal }
    }
}
