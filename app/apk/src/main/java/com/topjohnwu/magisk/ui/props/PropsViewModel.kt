package com.topjohnwu.magisk.ui.props

import android.content.Context
import androidx.databinding.Bindable
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.topjohnwu.magisk.BR
import com.topjohnwu.magisk.R
import com.topjohnwu.magisk.arch.AsyncLoadViewModel
import com.topjohnwu.magisk.core.AppContext
import com.topjohnwu.magisk.databinding.DiffItem
import com.topjohnwu.magisk.databinding.ObservableRvItem
import com.topjohnwu.magisk.databinding.filterList
import com.topjohnwu.magisk.databinding.set
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class PropsViewModel : AsyncLoadViewModel() {

    data class PropItem(
        val key: String,
        val value: String,
        val context: String,
        val isPersistent: Boolean,
        val isReadOnly: Boolean,
        var isFavorite: Boolean
    ) : ObservableRvItem(), DiffItem<PropItem> {
        override val layoutRes get() = R.layout.item_prop

        val category: String get() = key.substringBefore(".", key)
        val displayValue: String get() =
            if (value.length > 100) value.take(97) + "..." else value

        @get:Bindable
        var expanded = false
            set(value) = set(value, field, { field = it }, BR.expanded)

        fun toggleExpand() {
            expanded = !expanded
        }

        override fun itemSameAs(other: PropItem) = key == other.key
        override fun contentSameAs(other: PropItem) =
            value == other.value && isFavorite == other.isFavorite
    }

    val items = filterList<PropItem>(viewModelScope)
    val query = MutableLiveData("")

    @get:Bindable
    var categories: List<String> = emptyList()
        private set(value) = set(value, field, { field = it }, BR.categories)

    @get:Bindable
    var selectedCategory: String? = null
        set(value) = set(value, field, { field = it }, BR.selectedCategory) {
            doFilter()
        }

    private val favorites: MutableSet<String>
        get() = AppContext.getSharedPreferences("prop_favorites", Context.MODE_PRIVATE)
            .getStringSet("keys", emptySet())?.toMutableSet() ?: mutableSetOf()

    @get:Bindable
    var loading = true
        private set(value) = set(value, field, { field = it }, BR.loading)

    private var allProps: List<PropItem> = emptyList()

    override suspend fun doLoadWork() {
        loading = true
        val shell = Shell.getShell()

        val props = withContext(Dispatchers.IO) {
            // Use getprop to list all properties (works without modifying native)
            val result = shell.newJob()
                .add("getprop")
                .to(ArrayList<String>())
                .exec()

            val favs = favorites
            result.out.mapNotNull { line ->
                val match = Regex("""^\[(.+?)\]:\s*\[(.*)\]$""").find(line)
                match?.let {
                    PropItem(
                        key = it.groupValues[1],
                        value = it.groupValues[2],
                        context = "",
                        isPersistent = it.groupValues[1].startsWith("persist."),
                        isReadOnly = it.groupValues[1].startsWith("ro."),
                        isFavorite = it.groupValues[1] in favs
                    )
                }
            }
        }

        allProps = props
        categories = props.map { it.category }.distinct().sorted()
        items.set(props)
        loading = false
    }

    fun search(queryText: String) {
        query.value = queryText
        doFilter()
    }

    private fun doFilter() {
        val q = query.value ?: ""
        val cat = selectedCategory
        items.filter { item ->
            val matchesQuery = q.isEmpty() ||
                item.key.contains(q, true) ||
                item.value.contains(q, true)
            val matchesCategory = cat == null || item.category == cat
            matchesQuery && matchesCategory
        }
    }

    fun modifyProp(key: String, newValue: String, bypassSvc: Boolean) {
        val cmd = buildString {
            append("magisk --resetprop")
            if (bypassSvc) append(" -n")
            append(" \"$key\" \"$newValue\"")
        }
        Shell.cmd(cmd).submit {
            if (it.isSuccess) startLoading()
        }
    }

    fun deleteProp(key: String) {
        Shell.cmd("magisk --resetprop -d \"$key\"").submit {
            if (it.isSuccess) startLoading()
        }
    }

    fun toggleFavorite(key: String) {
        val favs = favorites
        if (key in favs) favs.remove(key) else favs.add(key)
        AppContext.getSharedPreferences("prop_favorites", Context.MODE_PRIVATE)
            .edit().putStringSet("keys", favs).apply()
        // Update the item's favorite state
        allProps.find { it.key == key }?.isFavorite = key in favs
        doFilter()
    }
}
