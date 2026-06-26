package com.topjohnwu.magisk.ui.security

import com.topjohnwu.magisk.R
import com.topjohnwu.magisk.core.security.SecurityAudit
import com.topjohnwu.magisk.databinding.DiffItem
import com.topjohnwu.magisk.databinding.RvItem

class RiskRvItem(
    val risk: SecurityAudit.RiskItem
) : RvItem(), DiffItem<RiskRvItem> {

    override val layoutRes get() = R.layout.item_risk

    val levelText: String get() = when (risk.level) {
        SecurityAudit.RiskLevel.HIGH -> "HIGH"
        SecurityAudit.RiskLevel.MEDIUM -> "MEDIUM"
        SecurityAudit.RiskLevel.LOW -> "LOW"
    }

    val levelColor: Int get() = when (risk.level) {
        SecurityAudit.RiskLevel.HIGH -> R.color.status_error
        SecurityAudit.RiskLevel.MEDIUM -> R.color.status_warning
        SecurityAudit.RiskLevel.LOW -> R.color.status_ok
    }

    override fun itemSameAs(other: RiskRvItem) = risk.title == other.risk.title
    override fun contentSameAs(other: RiskRvItem) = risk == other.risk
}
