package com.ghostdeveloper.spdecode

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostdeveloper.spdecode.cloud.AppAnalysisClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// Same AMOLED palette as the QA screen (SpDecodeAmoledTheme): black
// background, #242424 cards, #F7F7F7 text, white buttons with black text.
// Green (#38A36D) only for states, never for buttons.
private val AA_WHITE = Color(0xFFF7F7F7)
private val AA_MUTED = Color(0xFFB1B1B1)
private val AA_CARD = Color(0xFF242424)
private val AA_BORDER = Color(0xFF383838)
private val AA_RED = Color(0xFFFF8585)
private val AA_GREEN = Color(0xFF38A36D)

private fun activityLabel(job: AppAnalysisClient.JobView?): Int = when (job?.phaseCode) {
    "UPLOAD_STARTED" -> R.string.app_analysis_activity_uploading
    "UPLOAD_RECEIVED", "PACKAGE_VALIDATION", "PACKAGE_VALIDATED" ->
        R.string.app_analysis_activity_validating
    "ANALYSIS_STARTED" -> R.string.app_analysis_activity_started
    "BINARY_ANALYSIS" -> R.string.app_analysis_activity_binary
    "METHOD_DECODING" -> R.string.app_analysis_activity_decoding
    "CATALOG_BUILDING", "CATALOG_CANDIDATE_FOUND" -> R.string.app_analysis_activity_catalog
    "RESULT_PREPARATION", "REPORT_READY" -> R.string.app_analysis_activity_preparing
    "ANALYSIS_FAILED" -> R.string.app_analysis_activity_failed
    else -> when (job?.status) {
        "UPLOADING" -> R.string.app_analysis_activity_uploading
        "QUEUED_FOR_ANALYSIS" -> R.string.app_analysis_activity_queued
        "ANALYZING", "AWAITING_HUMAN" -> R.string.app_analysis_activity_analyzing
        "COMPLETED", "COMPLETED_PARTIAL" -> R.string.app_analysis_activity_ready
        "FAILED", "REJECTED", "EXPIRED" -> R.string.app_analysis_activity_failed
        else -> R.string.app_analysis_activity_idle
    }
}

private fun statusLabel(status: String): Int = when (status) {
    "COMPLETED" -> R.string.app_analysis_status_completed
    "COMPLETED_PARTIAL" -> R.string.app_analysis_status_partial
    "FAILED" -> R.string.app_analysis_status_failed
    "REJECTED" -> R.string.app_analysis_status_rejected
    "EXPIRED" -> R.string.app_analysis_status_expired
    "UPLOADING" -> R.string.app_analysis_status_uploading
    "QUEUED_FOR_ANALYSIS", "ANALYZING", "AWAITING_HUMAN" ->
        R.string.app_analysis_status_analyzing
    else -> R.string.app_analysis_status_queued
}

private fun errorLabel(code: String?): Int = when (code) {
    "METHOD_UNAVAILABLE" -> R.string.app_analysis_error_method_unavailable
    "NOT_VPN_APP" -> R.string.app_analysis_error_not_vpn
    "INSUFFICIENT_CREDITS" -> R.string.app_analysis_error_no_credits
    "SIGN_IN_REQUIRED" -> R.string.app_analysis_error_sign_in
    "APP_ANALYSIS_SHA_MISMATCH", "INVALID_APK" -> R.string.app_analysis_error_invalid_apk
    "INPUT_TOO_LARGE", "APP_ANALYSIS_INPUT_TOO_LARGE" -> R.string.app_analysis_error_too_large
    "APP_ANALYSIS_BUSY" -> R.string.app_analysis_error_busy
    else -> R.string.app_analysis_error_generic
}

/**
 * App-analysis tab (replaces the "Próximamente" placeholder, not the QA
 * screen). One "Importar aplicación" button, enabled only when the server
 * confirms credits; no checkboxes. Progress is ONE status card that updates
 * in place (SP-DECODE Arnés + current activity + progress bar) — the server
 * events are never rendered as a list or timeline, and nothing about the
 * analysis ever appears in the support chat.
 */
@Composable
internal fun AppAnalysisScreen(
    preflight: AppAnalysisClient.Preflight?,
    preflightLoading: Boolean,
    job: AppAnalysisClient.JobView?,
    running: Boolean,
    error: String?,
    history: List<AppAnalysisClient.JobView>,
    onPick: () -> Unit,
    onRefresh: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val client = remember(context) { AppAnalysisClient(context) }
    var exportJob by remember { mutableStateOf<AppAnalysisClient.JobView?>(null) }
    var exportStatus by remember { mutableStateOf<String?>(null) }
    val downloadLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/zip")
    ) { uri ->
        val target = exportJob
        exportJob = null
        if (uri != null && target != null) {
            scope.launch {
                exportStatus = try {
                    // Local copy first; otherwise download from the server
                    // (Bearer session) and keep the local copy for re-export.
                    val ok = withContext(Dispatchers.IO) {
                        client.exportResult(target.jobId, uri) ||
                            client.downloadResult(target, uri)
                    }
                    if (ok) context.getString(R.string.app_analysis_export_success)
                    else context.getString(R.string.app_analysis_export_failure)
                } catch (_: Exception) {
                    context.getString(R.string.app_analysis_export_failure)
                }
            }
        }
    }
    val priceText = preflight?.let {
        val dollars = it.creditPriceCents / 100
        val cents = it.creditPriceCents % 100
        "$" + dollars + "." + cents.toString().padStart(2, '0') + " " + it.currency
    }
    val canImport = !running && preflight != null && preflight.creditsAvailable >= 1
    Column(
        Modifier.fillMaxSize().testTag("app_analysis_screen")
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(stringResource(R.string.app_analysis_title), color = AA_WHITE,
            fontSize = 23.sp, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.app_analysis_intro), color = AA_MUTED,
            fontSize = 13.sp, lineHeight = 20.sp)

        Surface(color = AA_CARD, shape = RoundedCornerShape(16.dp),
            border = BorderStroke(1.dp, AA_BORDER), modifier = Modifier.fillMaxWidth()
                .testTag("app_analysis_import_card")) {
            Column(Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.app_analysis_cost), color = AA_MUTED, fontSize = 13.sp)
                    Text(stringResource(R.string.app_analysis_cost_value), color = AA_WHITE,
                        fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.app_analysis_balance), color = AA_MUTED, fontSize = 13.sp)
                    Text(
                        if (preflightLoading) stringResource(R.string.app_analysis_loading)
                        else if (preflight != null) stringResource(
                            R.string.app_analysis_credits_available, preflight.creditsAvailable)
                        else stringResource(R.string.app_analysis_balance_unknown),
                        color = AA_WHITE, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                }
                if (priceText != null) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(stringResource(R.string.app_analysis_price), color = AA_MUTED, fontSize = 13.sp)
                        Text(priceText, color = AA_WHITE, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
                Text(stringResource(R.string.app_analysis_formats), color = AA_MUTED, fontSize = 12.sp)
                Text(stringResource(R.string.app_analysis_reserve_note), color = AA_MUTED, fontSize = 12.sp)
                Button(
                    onClick = onPick, enabled = canImport,
                    modifier = Modifier.fillMaxWidth().testTag("app_analysis_import"),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = AA_WHITE, contentColor = Color.Black,
                        disabledContainerColor = AA_WHITE.copy(alpha = 0.45f),
                        disabledContentColor = Color.Black.copy(alpha = 0.45f)),
                ) {
                    Text(stringResource(R.string.app_analysis_import_button),
                        fontWeight = FontWeight.Bold, fontSize = 15.sp)
                }
                if (preflight != null && preflight.creditsAvailable < 1 && !running) {
                    Text(stringResource(R.string.app_analysis_no_credits), color = AA_RED, fontSize = 12.sp)
                }
            }
        }

        if (job != null) {
            Surface(color = AA_CARD, shape = RoundedCornerShape(16.dp),
                border = BorderStroke(1.dp, AA_BORDER), modifier = Modifier.fillMaxWidth()
                    .testTag("app_analysis_status_card")) {
                Column(Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Image(painterResource(R.drawable.arnes),
                            contentDescription = stringResource(R.string.app_analysis_arnes_name),
                            contentScale = ContentScale.Crop,
                            modifier = Modifier.size(44.dp).clip(CircleShape))
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(stringResource(R.string.app_analysis_arnes_name),
                                color = AA_WHITE, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                            Text(job.appName ?: job.packageName ?: job.filename,
                                color = AA_MUTED, fontSize = 12.sp)
                        }
                        if (job.terminal && job.status in setOf("COMPLETED", "COMPLETED_PARTIAL")) {
                            Text(stringResource(R.string.app_analysis_status_completed),
                                color = AA_GREEN, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }
                    Text(stringResource(activityLabel(job)), color = AA_MUTED, fontSize = 13.sp)
                    if (job.status == "UPLOADING") {
                        LinearProgressIndicator(
                            progress = { (job.receivedBytes.toFloat() / job.totalBytes.coerceAtLeast(1).toFloat())
                                .coerceIn(0f, 1f) },
                            modifier = Modifier.fillMaxWidth(),
                            color = AA_WHITE, trackColor = AA_BORDER)
                        Text(
                            stringResource(R.string.app_analysis_upload_progress,
                                job.receivedBytes / 1_000_000, job.totalBytes / 1_000_000),
                            color = AA_MUTED, fontSize = 12.sp)
                    } else if (job.progressPercent != null) {
                        LinearProgressIndicator(
                            progress = { (job.progressPercent / 100f).coerceIn(0f, 1f) },
                            modifier = Modifier.fillMaxWidth(),
                            color = AA_WHITE, trackColor = AA_BORDER)
                        Text(job.progressPercent.toString() + "%", color = AA_MUTED, fontSize = 12.sp)
                    } else if (running) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth(),
                            color = AA_WHITE, trackColor = AA_BORDER)
                    }
                    if (job.status in setOf("FAILED", "REJECTED", "EXPIRED")) {
                        Text(stringResource(errorLabel(job.errorCode ?: error)),
                            color = AA_RED, fontSize = 13.sp)
                        Text(stringResource(R.string.app_analysis_credit_returned),
                            color = AA_MUTED, fontSize = 12.sp)
                    }
                    if (job.terminal && job.status in setOf("COMPLETED", "COMPLETED_PARTIAL")) {
                        if (job.needsToken) {
                            Text(stringResource(R.string.app_analysis_token_notice),
                                color = AA_WHITE, fontSize = 13.sp)
                        }
                        Button(
                            onClick = {
                                exportJob = job
                                val name = (job.packageName ?: "app-analysis") +
                                    "-analysis-" + job.jobId.take(8) + ".zip"
                                downloadLauncher.launch(name)
                            },
                            modifier = Modifier.fillMaxWidth().testTag("app_analysis_download"),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = AA_WHITE, contentColor = Color.Black),
                        ) {
                            Text(stringResource(R.string.app_analysis_download_button),
                                fontWeight = FontWeight.Bold, fontSize = 15.sp)
                        }
                    }
                }
            }
        }

        if (error != null && job == null) {
            Text(stringResource(errorLabel(error)), color = AA_RED, fontSize = 13.sp)
            OutlinedButton(onClick = onRefresh, modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = AA_WHITE)) {
                Text(stringResource(R.string.app_analysis_retry))
            }
        }
        exportStatus?.let { Text(it, color = AA_MUTED, fontSize = 12.sp) }

        Surface(color = AA_CARD, shape = RoundedCornerShape(16.dp),
            border = BorderStroke(1.dp, AA_BORDER), modifier = Modifier.fillMaxWidth()
                .testTag("app_analysis_history")) {
            Column(Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.app_analysis_history_title), color = AA_WHITE,
                    fontWeight = FontWeight.Bold, fontSize = 16.sp)
                if (history.isEmpty()) {
                    Text(stringResource(R.string.app_analysis_history_empty),
                        color = AA_MUTED, fontSize = 13.sp)
                } else {
                    history.forEach { item ->
                        Column(Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Row(Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically) {
                                Column(Modifier.weight(1f)) {
                                    Text(item.appName ?: item.packageName ?: item.filename,
                                        color = AA_WHITE, fontSize = 14.sp,
                                        fontWeight = FontWeight.SemiBold)
                                    Text(
                                        (item.createdAt ?: "").take(10) + " · " +
                                            stringResource(statusLabel(item.status)),
                                        color = AA_MUTED, fontSize = 12.sp)
                                }
                                if (item.status in setOf("COMPLETED", "COMPLETED_PARTIAL")) {
                                    OutlinedButton(
                                        onClick = {
                                            exportJob = item
                                            val name = (item.packageName ?: "app-analysis") +
                                                "-analysis-" + item.jobId.take(8) + ".zip"
                                            downloadLauncher.launch(name)
                                        },
                                        shape = RoundedCornerShape(12.dp),
                                        colors = ButtonDefaults.outlinedButtonColors(
                                            contentColor = AA_WHITE),
                                    ) {
                                        Text(stringResource(R.string.app_analysis_download_button),
                                            fontSize = 13.sp)
                                    }
                                }
                            }
                            HorizontalDivider(color = AA_BORDER)
                        }
                    }
                }
            }
        }
    }
}
