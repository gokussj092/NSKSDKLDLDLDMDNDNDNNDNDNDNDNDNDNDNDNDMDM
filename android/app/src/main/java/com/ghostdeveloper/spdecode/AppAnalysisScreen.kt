package com.ghostdeveloper.spdecode

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.FileUpload
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Refresh
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostdeveloper.spdecode.cloud.AppAnalysisClient
import com.ghostdeveloper.spdecode.cloud.HarnessPresentation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.time.Instant
import java.util.Date
import java.util.Locale

private val AA_WHITE = Color(0xFFF7F7F7)
private val AA_MUTED = Color(0xFFB1B1B1)
private val AA_CARD = Color(0xFF171717)
private val AA_BORDER = Color(0xFF303030)
private val AA_RED = Color(0xFFFF8585)
private val AA_GREEN = Color(0xFF75D9A3)

private fun statusLabel(status: String?): Int = when (status) {
    "COMPLETED" -> R.string.app_analysis_status_completed
    "COMPLETED_PARTIAL" -> R.string.app_analysis_status_partial
    "FAILED" -> R.string.app_analysis_status_failed
    "REJECTED" -> R.string.app_analysis_status_rejected
    "EXPIRED" -> R.string.app_analysis_status_expired
    "UPLOADING" -> R.string.app_analysis_status_uploading
    "ANALYZING" -> R.string.app_analysis_status_analyzing
    "AWAITING_HUMAN" -> R.string.harness_review
    "UPLOADED" -> R.string.app_analysis_activity_validating
    "QUEUED_FOR_ANALYSIS" -> R.string.app_analysis_status_queued
    else -> R.string.harness_preparing
}
private fun activityLabel(job: AppAnalysisClient.JobView?): Int = when (
    HarnessPresentation.stage(job?.status, job?.phaseCode)) {
    "COMPLETED", "COMPLETED_PARTIAL" -> R.string.app_analysis_activity_ready
    "FAILED", "REJECTED", "EXPIRED" -> R.string.app_analysis_activity_failed
    "UPLOADING" -> R.string.app_analysis_activity_uploading
    "QUEUED" -> R.string.harness_queued_hint
    "REVIEW" -> R.string.harness_review_hint
    "METADATA" -> R.string.harness_metadata
    "CODE" -> R.string.harness_code
    "NATIVE" -> R.string.app_analysis_activity_binary
    "METHODS" -> R.string.app_analysis_activity_decoding
    "CATALOG" -> R.string.app_analysis_activity_catalog
    "RESULTS" -> R.string.app_analysis_activity_preparing
    "VALIDATING" -> R.string.app_analysis_activity_validating
    "ANALYZING" -> R.string.app_analysis_activity_analyzing
    else -> R.string.harness_preparing
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
private fun sizeLabel(bytes: Long): String = if (bytes >= 1_000_000)
    String.format(Locale.getDefault(), "%.1f MB", bytes / 1_000_000.0)
    else String.format(Locale.getDefault(), "%.0f KB", bytes / 1_000.0)
private fun dateLabel(raw: String?): String? = raw?.let {
    runCatching { DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
        .format(Date.from(Instant.parse(it))) }.getOrNull()
}

@Composable
private fun HarnessCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Surface(color = AA_CARD, shape = RoundedCornerShape(22.dp),
        border = BorderStroke(1.dp, AA_BORDER), modifier = modifier.fillMaxWidth()) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp), content = content)
    }
}
@Composable
private fun HarnessBadge(text: String, success: Boolean = false) {
    Surface(color = if (success) AA_GREEN.copy(alpha = .10f) else Color(0xFF292929),
        shape = RoundedCornerShape(9.dp)) {
        Text(text, Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            color = if (success) AA_GREEN else AA_WHITE, fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold)
    }
}

/** One live status card. Results and the analysis/support engines remain independent. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun AppAnalysisScreen(
    preflight: AppAnalysisClient.Preflight?, preflightLoading: Boolean,
    job: AppAnalysisClient.JobView?, running: Boolean, error: String?,
    history: List<AppAnalysisClient.JobView>, onPick: () -> Unit, onRefresh: () -> Unit,
    pending: AppAnalysisClient.Snapshot? = null, chunked: Boolean = false,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val client = remember(context) { AppAnalysisClient(context) }
    var exportJob by remember { mutableStateOf<AppAnalysisClient.JobView?>(null) }
    var detailId by remember { mutableStateOf<String?>(null) }
    var exporting by remember { mutableStateOf(false) }
    var exportStatus by remember { mutableStateOf<String?>(null) }
    val rows = remember(history, job) {
        (listOfNotNull(job) + history).distinctBy { it.jobId }
            .sortedByDescending { it.createdAt ?: it.updatedAt.orEmpty() }
    }
    val detail = rows.find { it.jobId == detailId }
    val downloadLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/zip")) { uri ->
        val target = exportJob
        if (uri != null && target != null) scope.launch {
            exporting = true
            exportStatus = try {
                val ok = withContext(Dispatchers.IO) {
                    client.exportResult(target.jobId, uri) || client.downloadResult(target, uri)
                }
                context.getString(if (ok) R.string.app_analysis_export_success else R.string.app_analysis_export_failure)
            } catch (_: Exception) { context.getString(R.string.app_analysis_export_failure) }
            finally { exporting = false }
        }
    }
    val export: (AppAnalysisClient.JobView) -> Unit = { target ->
        exportJob = target
        val name = target.displayName.replace(Regex("[^\\p{L}\\p{N}_. -]"), "_").take(80)
        downloadLauncher.launch("$name-analysis-${target.jobId.take(8)}.zip")
    }
    val canImport = !running && preflight != null && preflight.creditsAvailable >= 1
    Column(Modifier.fillMaxSize().testTag("app_analysis_screen")
        .verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            Image(painterResource(R.drawable.arnes), null, contentScale = ContentScale.Crop,
                modifier = Modifier.size(58.dp).clip(CircleShape))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.app_analysis_arnes_name), color = AA_WHITE,
                    fontSize = 21.sp, fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.app_analysis_title), color = AA_MUTED, fontSize = 13.sp)
            }
        }
        HarnessCard(Modifier.testTag("app_analysis_import_card")) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Text(stringResource(R.string.app_analysis_balance), color = AA_MUTED, fontSize = 12.sp)
                    Text(if (preflight != null) stringResource(R.string.app_analysis_credits_available, preflight.creditsAvailable)
                        else stringResource(if (preflightLoading) R.string.app_analysis_loading else R.string.app_analysis_balance_unknown),
                        color = AA_WHITE, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                }
                IconButton(onClick = onRefresh, enabled = !preflightLoading) {
                    Icon(Icons.Outlined.Refresh, stringResource(R.string.app_analysis_retry), tint = AA_WHITE)
                }
            }
            HorizontalDivider(color = AA_BORDER)
            Text(stringResource(R.string.app_analysis_formats), color = AA_MUTED, fontSize = 12.sp, lineHeight = 18.sp)
            Button(onClick = onPick, enabled = canImport,
                modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp).testTag("app_analysis_import"),
                shape = RoundedCornerShape(14.dp), colors = ButtonDefaults.buttonColors(
                    containerColor = AA_WHITE, contentColor = Color.Black,
                    disabledContainerColor = Color(0xFF343434), disabledContentColor = AA_MUTED)) {
                Icon(Icons.Outlined.FileUpload, null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.app_analysis_import_button), fontWeight = FontWeight.SemiBold)
            }
            Text(stringResource(if (chunked) R.string.harness_chunks else R.string.harness_normal),
                color = AA_MUTED, fontSize = 11.sp)
            if (preflight != null && preflight.creditsAvailable < 1 && !running)
                Text(stringResource(R.string.app_analysis_no_credits), color = AA_RED, fontSize = 12.sp)
        }
        if (job != null || running) {
            HarnessCard(Modifier.testTag("app_analysis_status_card")) {
                val bytes = job?.totalBytes ?: pending?.totalBytes ?: 0L
                val filename = HarnessPresentation.text(job?.filename) ?: pending?.filename.orEmpty()
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                        Text(job?.displayName ?: HarnessPresentation.name(null, filename, null),
                            color = AA_WHITE, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                        Text(if (bytes > 0) sizeLabel(bytes) else stringResource(R.string.harness_unknown_size),
                            color = AA_MUTED, fontSize = 12.sp)
                    }
                    HarnessBadge(stringResource(statusLabel(job?.status)), job?.status in setOf("COMPLETED", "COMPLETED_PARTIAL"))
                }
                Text(filename, color = AA_MUTED, fontSize = 12.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
                HorizontalDivider(color = AA_BORDER)
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    CommerceAvatar(preflight?.agentAvatar, Modifier.size(38.dp))
                    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text("Yamada", color = AA_WHITE, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                        Text(stringResource(R.string.harness_support_ai), color = AA_MUTED, fontSize = 11.sp)
                    }
                }
                Text(stringResource(activityLabel(job)), color = AA_WHITE, fontSize = 14.sp, lineHeight = 21.sp)
                when {
                    job?.status == "UPLOADING" -> {
                        LinearProgressIndicator(progress = { (job.receivedBytes.toFloat() / job.totalBytes.coerceAtLeast(1)).coerceIn(0f, 1f) },
                            modifier = Modifier.fillMaxWidth(), color = AA_GREEN, trackColor = AA_BORDER)
                        Text("${sizeLabel(job.receivedBytes)} / ${sizeLabel(job.totalBytes)} · " +
                            stringResource(if (pending?.chunked == true) R.string.harness_chunks else R.string.harness_normal),
                            color = AA_MUTED, fontSize = 11.sp)
                    }
                    job?.status == "ANALYZING" && job.progressPercent != null -> {
                        LinearProgressIndicator(progress = { (job.progressPercent / 100f).coerceIn(0f, 1f) },
                            modifier = Modifier.fillMaxWidth(), color = AA_GREEN, trackColor = AA_BORDER)
                        Text("${job.progressPercent}%", color = AA_MUTED, fontSize = 12.sp)
                    }
                }
                dateLabel(job?.updatedAt)?.let {
                    Text(stringResource(R.string.harness_updated, it), color = AA_MUTED, fontSize = 11.sp)
                }
                if (job?.status in setOf("FAILED", "REJECTED", "EXPIRED")) {
                    Text(stringResource(errorLabel(job?.errorCode ?: error)), color = AA_RED, fontSize = 13.sp)
                    if (job?.creditState == "released") Text(stringResource(R.string.app_analysis_credit_returned), color = AA_MUTED, fontSize = 12.sp)
                }
                if (job?.status in setOf("COMPLETED", "COMPLETED_PARTIAL")) {
                    if (job?.needsToken == true) Text(stringResource(R.string.app_analysis_token_notice), color = AA_MUTED, fontSize = 12.sp)
                    OutlinedButton(onClick = { detailId = job?.jobId }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.harness_details), color = AA_WHITE)
                    }
                }
            }
        }
        if (error != null) {
            Text(stringResource(errorLabel(error)), color = AA_RED, fontSize = 13.sp)
            OutlinedButton(onClick = onRefresh, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.app_analysis_retry), color = AA_WHITE)
            }
        }
        exportStatus?.let { Text(it, color = AA_MUTED, fontSize = 12.sp) }
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(Icons.Outlined.History, null, tint = AA_MUTED, modifier = Modifier.size(19.dp))
                Text(stringResource(R.string.app_analysis_history_title), color = AA_WHITE, fontSize = 17.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.weight(1f))
                Text(rows.size.toString(), color = AA_MUTED, fontSize = 12.sp)
            }
            Text(stringResource(R.string.harness_history_hint), color = AA_MUTED, fontSize = 12.sp)
        }
        HarnessCard(Modifier.testTag("app_analysis_history")) {
            if (rows.isEmpty()) Text(stringResource(R.string.app_analysis_history_empty), color = AA_MUTED, fontSize = 13.sp)
            rows.forEachIndexed { index, item ->
                if (index > 0) HorizontalDivider(color = AA_BORDER)
                Row(Modifier.fillMaxWidth().clickable { detailId = item.jobId }.padding(vertical = 7.dp),
                    verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(item.displayName, color = AA_WHITE, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                        Text(listOfNotNull(if (item.totalBytes > 0) sizeLabel(item.totalBytes) else null,
                            dateLabel(item.createdAt)).joinToString(" · "), color = AA_MUTED, fontSize = 11.sp)
                        Text(stringResource(statusLabel(item.status)), color = if (item.status in setOf("COMPLETED", "COMPLETED_PARTIAL")) AA_GREEN else AA_MUTED, fontSize = 12.sp)
                    }
                    Icon(Icons.Outlined.ChevronRight, stringResource(R.string.harness_details), tint = AA_MUTED)
                }
            }
        }
        Spacer(Modifier.height(8.dp))
    }
    if (detail != null) ModalBottomSheet(onDismissRequest = { detailId = null }, containerColor = AA_CARD) {
        Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = 22.dp).padding(bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(detail.displayName, color = AA_WHITE, fontWeight = FontWeight.Bold, fontSize = 23.sp)
            HarnessBadge(stringResource(statusLabel(detail.status)), detail.status in setOf("COMPLETED", "COMPLETED_PARTIAL"))
            Text(stringResource(R.string.harness_filename) + "\n" + detail.filename, color = AA_MUTED, fontSize = 13.sp)
            Text(stringResource(R.string.harness_size) + " · " + if (detail.totalBytes > 0) sizeLabel(detail.totalBytes) else stringResource(R.string.harness_unknown_size), color = AA_MUTED, fontSize = 13.sp)
            detail.packageName?.let { Text(it, color = AA_MUTED, fontSize = 12.sp) }
            Text(stringResource(activityLabel(detail)), color = AA_WHITE, fontSize = 14.sp)
            dateLabel(detail.updatedAt ?: detail.createdAt)?.let { Text(stringResource(R.string.harness_updated, it), color = AA_MUTED, fontSize = 12.sp) }
            if (detail.needsToken) Text(stringResource(R.string.app_analysis_token_notice), color = AA_MUTED, fontSize = 13.sp)
            val local = client.hasLocalResult(detail.jobId)
            if (local) Text(stringResource(R.string.harness_local_copy), color = AA_GREEN, fontSize = 12.sp)
            if (local || detail.status in setOf("COMPLETED", "COMPLETED_PARTIAL")) Button(
                onClick = { export(detail) }, enabled = !exporting,
                modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("app_analysis_download"),
                shape = RoundedCornerShape(14.dp), colors = ButtonDefaults.buttonColors(containerColor = AA_WHITE, contentColor = Color.Black)) {
                Icon(Icons.Outlined.Download, null, modifier = Modifier.size(19.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.app_analysis_download_button), fontWeight = FontWeight.SemiBold)
            }
            exportStatus?.let { Text(it, color = AA_MUTED, fontSize = 12.sp) }
        }
    }
}
