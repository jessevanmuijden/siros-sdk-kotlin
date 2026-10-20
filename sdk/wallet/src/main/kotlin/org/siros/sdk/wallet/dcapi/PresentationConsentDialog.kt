// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Typeface
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlin.coroutines.resume
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.siros.sdk.credentials.PresentationConsentRequest
import org.siros.sdk.wallet.ConsentScreen
import org.siros.sdk.wallet.PresentationConsentText

/**
 * Shows the consent for a `circuit_zk` presentation in [activity] and returns whether the user agreed. A plain
 * Android dialog, like [showTransactionConsentDialog]: the DC API activity has no Compose and the app's own
 * screens are not in front of the user. The wording is the SDK's ([PresentationConsentText]); this renders it.
 *
 * The verifier id value is shown verbatim on a detail line (long ones shortened in the middle for display;
 * tap or long-press shows the whole value). Dismissing the dialog is a decline. Nothing here is logged.
 */
internal suspend fun showPresentationConsentDialog(activity: Activity, request: PresentationConsentRequest): Boolean =
    withContext(Dispatchers.Main) {
        val screen = PresentationConsentText.forContext(activity).render(request)
        suspendCancellableCoroutine { cont ->
            val dialog = AlertDialog.Builder(activity)
                .setTitle(screen.title)
                .setView(ScrollView(activity).apply { addView(buildContent(activity, screen)) })
                .setPositiveButton(screen.shareLabel) { _, _ -> if (cont.isActive) cont.resume(true) }
                .setNegativeButton(screen.cancelLabel) { _, _ -> if (cont.isActive) cont.resume(false) }
                .setOnCancelListener { if (cont.isActive) cont.resume(false) }
                .create()
            dialog.show()
            // Registered after show(): a continuation that is already cancelled dismisses the visible dialog at once.
            cont.invokeOnCancellation { activity.runOnUiThread { dialog.dismiss() } }
        }
    }

private fun text(activity: Activity, s: String, bold: Boolean = false, size: Float = 14f, topDp: Int = 0) = TextView(activity).apply {
    this.text = s
    textSize = size
    if (bold) setTypeface(typeface, Typeface.BOLD)
    setPadding(0, (topDp * activity.resources.displayMetrics.density).toInt(), 0, 0)
}

private fun buildContent(activity: Activity, screen: ConsentScreen): LinearLayout {
    val pad = { v: Int -> (v * activity.resources.displayMetrics.density).toInt() }
    val column = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(pad(20), pad(8), pad(20), pad(8))
    }
    column.addView(text(activity, screen.header))
    screen.verifierDetail?.let { detail ->
        var expanded = false
        val line = text(activity, detail.shortened, size = 12f)
        val toggle = {
            expanded = !expanded
            line.text = if (expanded) detail.full else detail.shortened
        }
        line.setOnClickListener { toggle() }
        line.setOnLongClickListener { toggle(); true }
        column.addView(line)
    }
    screen.entries.forEach { entry ->
        entry.credentialName?.let { column.addView(text(activity, it, bold = true, topDp = 12)) }
        entry.issuerName?.let { column.addView(text(activity, it, size = 12f)) }
        entry.lines.forEach { column.addView(text(activity, it, topDp = 6)) }
    }
    column.addView(text(activity, screen.footer, size = 12f, topDp = 12))
    return column
}
