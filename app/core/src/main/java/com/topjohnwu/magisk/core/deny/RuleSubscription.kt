package com.topjohnwu.magisk.core.deny

import com.topjohnwu.magisk.core.AppContext
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

class RuleSubscription {

    var subscriptionUrls: MutableSet<String> = mutableSetOf(
        DenyListPresets.DEFAULT_SUBSCRIPTION_URL
    )

    var lastUpdate: Long = 0L

    suspend fun fetchAndMerge(): Map<DenyListPresets.Category, List<DenyListPresets.PresetEntry>> =
        withContext(Dispatchers.IO) {
            val allRules = mutableMapOf<DenyListPresets.Category, MutableList<DenyListPresets.PresetEntry>>()

            // Merge built-in rules
            DenyListPresets.builtin.forEach { (cat, entries) ->
                allRules.getOrPut(cat) { mutableListOf() }
                    .addAll(entries.map { (pkg, procs) -> DenyListPresets.PresetEntry(pkg, procs) })
            }

            // Fetch remote subscriptions via shell (curl)
            for (url in subscriptionUrls) {
                try {
                    val result = Shell.cmd("curl -sL '$url'").exec()
                    if (result.isSuccess && result.out.isNotEmpty()) {
                        val json = result.out.joinToString("\n")
                        val parsed = parsePresetsJson(json)
                        parsed.forEach { (cat, entries) ->
                            allRules.getOrPut(cat) { mutableListOf() }.addAll(entries)
                        }
                    }
                } catch (_: Exception) {
                    // Log failure but continue with other subscriptions
                }
            }

            lastUpdate = System.currentTimeMillis()
            allRules
        }

    suspend fun applyRules(
        rules: Map<DenyListPresets.Category, List<DenyListPresets.PresetEntry>>
    ) = withContext(Dispatchers.IO) {
        val pm = AppContext.packageManager
        val installedApps = pm.getInstalledApplications(0)
            .map { it.packageName }.toSet()

        val toAdd = mutableListOf<Pair<String, String>>()
        rules.values.flatten().forEach { entry ->
            if (entry.pkg in installedApps) {
                if (entry.procs.isEmpty()) {
                    toAdd.add(entry.pkg to entry.pkg)
                } else {
                    entry.procs.forEach { proc ->
                        toAdd.add(entry.pkg to proc)
                    }
                }
            }
        }

        if (toAdd.isNotEmpty()) {
            val pairs = toAdd.joinToString(" ") { "${it.first}|${it.second}" }
            Shell.cmd("magisk --denylist add_batch ${toAdd.size} $pairs").exec()
        }
    }

    suspend fun clearAndReapply(
        rules: Map<DenyListPresets.Category, List<DenyListPresets.PresetEntry>>
    ) = withContext(Dispatchers.IO) {
        Shell.cmd("magisk --denylist clear_all").exec()
        applyRules(rules)
    }

    companion object {
        fun parsePresetsJson(json: String): Map<DenyListPresets.Category, List<DenyListPresets.PresetEntry>> {
            val result = mutableMapOf<DenyListPresets.Category, MutableList<DenyListPresets.PresetEntry>>()
            try {
                val root = JSONObject(json)
                val categories = root.optJSONObject("categories") ?: return result

                for (catName in categories.keys()) {
                    val category = try {
                        DenyListPresets.Category.valueOf(catName.uppercase())
                    } catch (_: Exception) {
                        continue
                    }
                    val arr = categories.getJSONArray(catName)
                    val entries = mutableListOf<DenyListPresets.PresetEntry>()
                    for (i in 0 until arr.length()) {
                        val obj = arr.getJSONObject(i)
                        val pkg = obj.getString("pkg")
                        val procsArr = obj.optJSONArray("procs")
                        val procs = if (procsArr != null) {
                            (0 until procsArr.length()).map { procsArr.getString(it) }
                        } else {
                            emptyList()
                        }
                        entries.add(DenyListPresets.PresetEntry(pkg, procs))
                    }
                    result[category] = entries
                }
            } catch (_: Exception) {}
            return result
        }
    }
}
