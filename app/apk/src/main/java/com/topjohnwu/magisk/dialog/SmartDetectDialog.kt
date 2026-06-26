package com.topjohnwu.magisk.dialog

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.topjohnwu.magisk.R
import com.topjohnwu.magisk.core.AppContext
import androidx.databinding.Bindable
import com.topjohnwu.magisk.BR
import com.topjohnwu.magisk.core.deny.DenyListAutoDetector
import com.topjohnwu.magisk.databinding.DiffItem
import com.topjohnwu.magisk.databinding.ObservableRvItem
import com.topjohnwu.magisk.databinding.set
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.launch

class SmartDetectDialog(
    private val lifecycleOwner: LifecycleOwner
) {
    fun show() {
        val context = AppContext
        val pm = context.packageManager

        lifecycleOwner.lifecycleScope.launch {
            val detected = DenyListAutoDetector.scanInstalledApps(pm, 0.3)

            if (detected.isEmpty()) {
                MaterialAlertDialogBuilder(context)
                    .setTitle(R.string.deny_smart_detect)
                    .setMessage(R.string.deny_smart_detect_empty)
                    .setPositiveButton(R.string.ok, null)
                    .show()
                return@launch
            }

            val items = detected.map { (appInfo, score) ->
                SmartDetectItem(appInfo, score, pm)
            }

            val recyclerView = RecyclerView(context).apply {
                layoutManager = LinearLayoutManager(context)
                adapter = SmartDetectAdapter(items)
                setPadding(48, 16, 48, 0)
            }

            MaterialAlertDialogBuilder(context)
                .setTitle(R.string.deny_smart_detect)
                .setView(recyclerView)
                .setPositiveButton(R.string.deny_apply_selected) { _, _ ->
                    applySelected(items)
                }
                .setNegativeButton(R.string.cancel, null)
                .show()
        }
    }

    private fun applySelected(items: List<SmartDetectItem>) {
        val selected = items.filter { it.isSelected }
        if (selected.isEmpty()) return

        val pairs = selected.joinToString(" ") { "${it.packageName}|${it.packageName}" }
        Shell.cmd("magisk --denylist add_batch ${selected.size} $pairs").submit()
    }
}

class SmartDetectItem(
    val appInfo: ApplicationInfo,
    val riskScore: Double,
    private val pm: PackageManager
) : ObservableRvItem(), DiffItem<SmartDetectItem> {

    override val layoutRes get() = R.layout.item_smart_detect

    val appName: String = pm.getApplicationLabel(appInfo).toString()
    val packageName: String = appInfo.packageName
    val riskPercent: Int = (riskScore * 100).toInt()
    val riskLevel: String = when {
        riskScore >= 0.7 -> "HIGH"
        riskScore >= 0.5 -> "MEDIUM"
        else -> "LOW"
    }

    @get:Bindable
    var isSelected = riskScore >= 0.5
        set(value) = set(value, field, { field = it }, BR.selected)

    fun toggleSelected() {
        isSelected = !isSelected
    }

    override fun itemSameAs(other: SmartDetectItem) = packageName == other.packageName
    override fun contentSameAs(other: SmartDetectItem) = isSelected == other.isSelected
}

class SmartDetectAdapter(
    private val items: List<SmartDetectItem>
) : RecyclerView.Adapter<SmartDetectAdapter.ViewHolder>() {

    class ViewHolder(val itemView: android.view.View) : RecyclerView.ViewHolder(itemView)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = com.topjohnwu.magisk.databinding.ItemSmartDetectBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return ViewHolder(binding.root)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val binding = com.topjohnwu.magisk.databinding.ItemSmartDetectBinding.bind(holder.itemView)
        binding.item = items[position]
        binding.executePendingBindings()
    }

    override fun getItemCount() = items.size
}
