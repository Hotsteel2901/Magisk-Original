package com.topjohnwu.magisk.ui.props

import android.os.Bundle
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.widget.LinearLayout
import androidx.appcompat.widget.SearchView
import androidx.core.view.MenuProvider
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.topjohnwu.magisk.R
import com.topjohnwu.magisk.arch.BaseFragment
import com.topjohnwu.magisk.arch.viewModel
import com.topjohnwu.magisk.databinding.FragmentPropsMd2Binding
import com.topjohnwu.magisk.core.R as CoreR

class PropsFragment : BaseFragment<FragmentPropsMd2Binding>(), MenuProvider {

    override val layoutRes = R.layout.fragment_props_md2
    override val viewModel by viewModel<PropsViewModel>()

    override fun onStart() {
        super.onStart()
        activity?.setTitle(CoreR.string.props_browser)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.lifecycleOwner = viewLifecycleOwner
    }

    override fun onPreBind(binding: FragmentPropsMd2Binding) = Unit

    override fun onCreateMenu(menu: Menu, inflater: MenuInflater) {
        inflater.inflate(R.menu.menu_props, menu)
        val searchView = menu.findItem(R.id.action_search_props).actionView as SearchView
        searchView.queryHint = getString(CoreR.string.props_search_hint)
        searchView.setOnQueryTextListener(object : SearchView.OnQueryTextListener {
            override fun onQueryTextSubmit(query: String?) = true
            override fun onQueryTextChange(newText: String?): Boolean {
                viewModel.search(newText ?: "")
                return true
            }
        })
    }

    override fun onMenuItemSelected(item: MenuItem): Boolean {
        return false
    }

    fun showModifyDialog(item: PropsViewModel.PropItem) {
        val context = requireContext()
        val input = TextInputEditText(context).apply {
            setText(item.value)
            setSelectAllOnFocus(true)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(48, 16, 48, 0)
            }
        }

        MaterialAlertDialogBuilder(context)
            .setTitle(CoreR.string.props_modify_title)
            .setMessage("${item.key}")
            .setView(input)
            .setPositiveButton(CoreR.string.ok) { _, _ ->
                val newValue = input.text.toString()
                if (newValue.isNotEmpty()) {
                    viewModel.modifyProp(item.key, newValue, item.isReadOnly)
                }
            }
            .setNegativeButton(CoreR.string.cancel, null)
            .show()
    }

    fun showDeleteDialog(item: PropsViewModel.PropItem) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(CoreR.string.props_delete_title)
            .setMessage(item.key)
            .setPositiveButton(CoreR.string.yes) { _, _ ->
                viewModel.deleteProp(item.key)
            }
            .setNegativeButton(CoreR.string.no, null)
            .show()
    }
}
