// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Typeface
import android.text.InputType
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.siros.sdk.wallet.TransactionConsentEntry
import org.siros.sdk.wallet.TransactionConsentRequest
import kotlin.coroutines.resume

/**
 * Shows a payment confirmation (EC TS12) in [activity] and returns whether the
 * user confirmed. A plain Android dialog: the DC API activity has no Compose
 * and the app's own screens are not in front of the user.
 *
 * Level 1 fields are prominent, 2 and 3 follow, 4 is omitted; the disclosed
 * attributes are listed per credential (TS12 3.3.1); an unsigned request shows
 * a warning and the confirm button stays disabled until it is acknowledged
 * (TS12 3.1). Dismissing the dialog is a decline.
 */
internal suspend fun showTransactionConsentDialog(activity: Activity, request: TransactionConsentRequest): Boolean =
    withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { cont ->
            val unsigned = request.requestSigned == false
            val ack = CheckBox(activity)
            val first = request.entries.firstOrNull()
            val dialog = AlertDialog.Builder(activity)
                .setTitle(first?.title ?: "Confirm transaction")
                .setView(ScrollView(activity).apply { addView(buildContent(activity, request, ack)) })
                .setPositiveButton(first?.affirmativeLabel ?: "Confirm") { _, _ -> if (cont.isActive) cont.resume(true) }
                .setNegativeButton(first?.denialLabel ?: "Cancel") { _, _ -> if (cont.isActive) cont.resume(false) }
                .setOnCancelListener { if (cont.isActive) cont.resume(false) }
                .create()
            dialog.setOnShowListener {
                val confirm = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                confirm.isEnabled = !unsigned
                ack.setOnCheckedChangeListener { _, checked -> confirm.isEnabled = checked }
            }
            cont.invokeOnCancellation { activity.runOnUiThread { dialog.dismiss() } }
            dialog.show()
        }
    }

private fun text(activity: Activity, s: String, bold: Boolean = false, size: Float = 14f) = TextView(activity).apply {
    this.text = s
    textSize = size
    if (bold) setTypeface(typeface, Typeface.BOLD)
    inputType = InputType.TYPE_NULL
}

private fun buildContent(activity: Activity, request: TransactionConsentRequest, ack: CheckBox): LinearLayout {
    val pad = { v: Int -> (v * activity.resources.displayMetrics.density).toInt() }
    val column = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(pad(20), pad(8), pad(20), pad(8))
    }
    request.verifier?.let { column.addView(text(activity, it)) }
    request.credentialName?.let { column.addView(text(activity, it)) }
    if (request.requestSigned == false) {
        column.addView(text(activity, "This request is not signed, so its sender could not be verified. Only continue if you started this yourself."))
        ack.text = "I started this request and want to continue"
        column.addView(ack)
    }
    request.entries.forEach { addEntry(activity, column, it) }
    request.disclosures.forEach { d ->
        val claims = d.claims?.takeIf { it.isNotEmpty() }?.joinToString(", ") ?: "all"
        column.addView(text(activity, "${d.credentialName ?: ""}: $claims", size = 12f))
    }
    return column
}

private fun addEntry(activity: Activity, column: LinearLayout, entry: TransactionConsentEntry) {
    entry.fields.filter { it.level == 1 }.forEach {
        column.addView(text(activity, it.label, size = 12f))
        column.addView(text(activity, it.value, bold = true, size = 22f))
    }
    entry.fields.filter { it.level == 2 || it.level == 3 }.forEach { column.addView(text(activity, "${it.label}: ${it.value}")) }
    entry.securityHint?.let { column.addView(text(activity, it, size = 12f)) }
}
