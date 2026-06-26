package com.topjohnwu.magisk.ui.security

import com.topjohnwu.magisk.R
import com.topjohnwu.magisk.core.security.SecurityAudit
import com.topjohnwu.magisk.databinding.RvItem

class SecurityStatusItem(
    val title: String,
    val value: String,
    val statusColor: Int
) : RvItem() {
    override val layoutRes get() = R.layout.item_security_status
}
