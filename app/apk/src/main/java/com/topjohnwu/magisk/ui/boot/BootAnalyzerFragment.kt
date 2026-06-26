package com.topjohnwu.magisk.ui.boot

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import com.topjohnwu.magisk.R
import com.topjohnwu.magisk.arch.BaseFragment
import com.topjohnwu.magisk.arch.viewModel
import com.topjohnwu.magisk.databinding.FragmentBootAnalyzerMd2Binding
import com.topjohnwu.magisk.core.R as CoreR

class BootAnalyzerFragment : BaseFragment<FragmentBootAnalyzerMd2Binding>() {

    override val layoutRes = R.layout.fragment_boot_analyzer_md2
    override val viewModel by viewModel<BootAnalyzerViewModel>()

    private val filePicker = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                viewModel.analyzeBootImage(uri)
            }
        }
    }

    override fun onStart() {
        super.onStart()
        activity?.setTitle(CoreR.string.boot_analyzer)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.lifecycleOwner = viewLifecycleOwner
        binding.selectFileButton.setOnClickListener { launchFilePicker() }
    }

    override fun onPreBind(binding: FragmentBootAnalyzerMd2Binding) = Unit

    private fun launchFilePicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        filePicker.launch(intent)
    }
}
