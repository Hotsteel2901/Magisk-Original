package com.topjohnwu.magisk.core.deny

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object DenyListAutoDetector {

    private val bankingPatterns = listOf(
        "bank", "pay", "wallet", "finance", "chase", "wells", "fargo",
        "credit", "invest", "stock", "trade", "broker", "money"
    )

    private val safetyNetPermission = "com.google.android.gms.permission.SAFETY_NET"
    private val nfcServicePermission = "android.permission.BIND_NFC_SERVICE"

    fun detectRiskLevel(info: ApplicationInfo, pm: PackageManager): Double {
        var score = 0.0

        // Rule 1: Apps using SafetyNet/Play Integrity
        if (hasPermission(info, pm, safetyNetPermission)) {
            score += 0.4
        }

        // Rule 2: NFC payment related
        if (hasPermission(info, pm, nfcServicePermission)) {
            score += 0.3
        }

        // Rule 3: App category (API 26+)
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            when (info.category) {
                ApplicationInfo.CATEGORY_FINANCE -> score += 0.3
                ApplicationInfo.CATEGORY_PRODUCTIVITY -> score += 0.1
            }
        }

        // Rule 4: Package name matching known banking/payment patterns
        val pkg = info.packageName.lowercase()
        if (bankingPatterns.any { pkg.contains(it) }) {
            score += 0.2
        }

        // Rule 5: DRM related metadata
        try {
            val appInfo = pm.getApplicationInfo(
                info.packageName,
                PackageManager.GET_META_DATA
            )
            if (appInfo.metaData?.containsKey("com.google.android.gms.car.application") == true) {
                score += 0.1
            }
        } catch (_: Exception) {}

        return score.coerceIn(0.0, 1.0)
    }

    private fun hasPermission(
        info: ApplicationInfo,
        pm: PackageManager,
        permission: String
    ): Boolean {
        return try {
            val pi = pm.getPackageInfo(info.packageName, PackageManager.GET_PERMISSIONS)
            pi.requestedPermissions?.contains(permission) == true
        } catch (_: Exception) {
            false
        }
    }

    suspend fun scanInstalledApps(
        pm: PackageManager,
        threshold: Double = 0.5
    ): List<Pair<ApplicationInfo, Double>> = withContext(Dispatchers.IO) {
        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        apps.asSequence()
            .filter { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 }
            .map { it to detectRiskLevel(it, pm) }
            .filter { it.second >= threshold }
            .sortedByDescending { it.second }
            .toList()
    }
}
