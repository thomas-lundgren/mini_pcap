package dev.minipcap.ui

import android.app.Activity
import android.content.Intent
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.ListView
import android.widget.TextView
import dev.minipcap.R
import dev.minipcap.capture.CaptureConfig
import java.util.Locale

/** Searchable picker of launchable apps (minimum package visibility, no QUERY_ALL_PACKAGES). */
class AppPickerActivity : Activity() {
    private data class AppRow(val pkg: String, val label: String, val uid: Int, var icon: Drawable? = null)

    private val selected = HashSet<String>()
    private var all: List<AppRow> = emptyList()
    private var shown: List<AppRow> = emptyList()
    private lateinit var adapter: BaseAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_picker)
        selected += CaptureConfig.load(this).selectedPackages
        val list = findViewById<ListView>(R.id.list)
        val search = findViewById<EditText>(R.id.search)
        val info = findViewById<TextView>(R.id.info)
        adapter = object : BaseAdapter() {
            override fun getCount() = shown.size
            override fun getItem(i: Int) = shown[i]
            override fun getItemId(i: Int) = i.toLong()
            override fun getView(i: Int, convert: View?, parent: ViewGroup): View {
                val v = convert ?: layoutInflater.inflate(R.layout.row_app, parent, false)
                val r = shown[i]
                if (r.icon == null) r.icon = runCatching { packageManager.getApplicationIcon(r.pkg) }.getOrNull()
                v.findViewById<ImageView>(R.id.icon).setImageDrawable(r.icon)
                v.findViewById<TextView>(R.id.label).text = r.label
                v.findViewById<TextView>(R.id.pkg).text = "${r.pkg} • uid ${r.uid}"
                val cb = v.findViewById<CheckBox>(R.id.check)
                cb.setOnCheckedChangeListener(null)
                cb.isChecked = r.pkg in selected
                cb.setOnCheckedChangeListener { _, on -> if (on) selected += r.pkg else selected -= r.pkg }
                v.setOnClickListener { cb.isChecked = !cb.isChecked }
                return v
            }
        }
        list.adapter = adapter
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: Editable?) = filter(s.toString())
        })
        findViewById<Button>(R.id.done).setOnClickListener { finish() }
        Thread {
            val pm = packageManager
            val launch = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val rows = pm.queryIntentActivities(launch, 0)
                .map { it.activityInfo.applicationInfo }
                .distinctBy { it.packageName }
                .filter { it.packageName != packageName }
                .map { AppRow(it.packageName, pm.getApplicationLabel(it).toString(), it.uid) }
                .sortedBy { it.label.lowercase(Locale.ROOT) }
            val missing = selected.filter { s -> rows.none { it.pkg == s } }
            runOnUiThread {
                all = rows + missing.map { AppRow(it, getString(R.string.not_installed), -1) }
                info.text = getString(R.string.picker_info, rows.size)
                filter(search.text.toString())
            }
        }.start()
    }

    private fun filter(q: String) {
        val s = q.trim().lowercase(Locale.ROOT)
        shown = if (s.isEmpty()) all else all.filter { s in it.label.lowercase(Locale.ROOT) || s in it.pkg }
        adapter.notifyDataSetChanged()
    }

    override fun onPause() {
        super.onPause()
        val c = CaptureConfig.load(this)
        CaptureConfig.save(this, c.copy(selectedPackages = selected.toSet()))
    }
}
