package com.topjohnwu.magisk.core.deny

import com.topjohnwu.magisk.core.R

object DenyListPresets {

    enum class Category(val displayRes: Int) {
        BANKING(R.string.deny_preset_banking),
        PAYMENT(R.string.deny_preset_payment),
        ENTERPRISE(R.string.deny_preset_enterprise),
        STREAMING(R.string.deny_preset_streaming),
        GAMING(R.string.deny_preset_gaming),
        SOCIAL(R.string.deny_preset_social)
    }

    data class PresetEntry(
        val pkg: String,
        val procs: List<String> = emptyList()
    )

    val builtin: Map<Category, Map<String, List<String>>> = mapOf(
        Category.BANKING to mapOf(
            "com.chase.sig.android" to listOf(),
            "com.bankofamerica.mobilebanking" to listOf(),
            "com.wf.wellsfargo" to listOf(),
            "com.usaa.mobile.android" to listOf(),
            "com.capitalone.mobile" to listOf(),
            "com.citi.citimobile" to listOf(),
            "com.td" to listOf(),
            "com.pnc.ecommerce.mobile" to listOf(),
            "com.usbank.mobilebanking" to listOf(),
            "com.schwab.mobile" to listOf()
        ),
        Category.PAYMENT to mapOf(
            "com.google.android.apps.nbu.paisa.user" to listOf(),
            "com.samsung.android.spay" to listOf(),
            "com.paypal.android.p2pmobile" to listOf(),
            "com.venmo" to listOf(),
            "com.cash.app" to listOf()
        ),
        Category.ENTERPRISE to mapOf(
            "com.microsoft.office.outlook" to listOf(),
            "com.microsoft.teams" to listOf(),
            "com.google.android.apps.work.oobconfig" to listOf(),
            "com.airwatch.androidagent" to listOf(),
            "com.mobileiron" to listOf()
        ),
        Category.STREAMING to mapOf(
            "com.netflix.mediaclient" to listOf(),
            "com.disney.disneyplus" to listOf(),
            "com.hbo.hbonow" to listOf(),
            "com.amazon.avod" to listOf(),
            "com.spotify.music" to listOf()
        ),
        Category.GAMING to mapOf(
            "com.supercell.clashofclans" to listOf(),
            "com.supercell.clashroyale" to listOf(),
            "com.epicgames.fortnite" to listOf(),
            "com.activision.callofduty.shooter" to listOf(),
            "com.garena.game.codm" to listOf()
        ),
        Category.SOCIAL to mapOf(
            "com.snapchat.android" to listOf(),
            "com.instagram.android" to listOf(),
            "com.twitter.android" to listOf(),
            "com.whatsapp" to listOf(),
            "com.zhiliaoapp.musically" to listOf()
        )
    )

    const val DEFAULT_SUBSCRIPTION_URL =
        "https://raw.githubusercontent.com/topjohnwu/magisk-denylist-presets/main/presets.json"

    fun getInstalledPresets(
        category: Category,
        installedApps: Set<String>
    ): List<PresetEntry> {
        val rules = builtin[category] ?: return emptyList()
        return rules
            .filter { (pkg, _) -> pkg in installedApps }
            .map { (pkg, procs) -> PresetEntry(pkg, procs) }
    }

    fun getAllInstalledPresets(installedApps: Set<String>): Map<Category, List<PresetEntry>> {
        return Category.entries.associateWith { getInstalledPresets(it, installedApps) }
            .filter { it.value.isNotEmpty() }
    }
}
