package com.ghostdeveloper.spdecode

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.time.Instant
import java.util.Date
import java.util.Locale

// SP-DECODE Arnes history only: no credits, no Import button, no progress
// box. Same AMOLED palette as AppAnalysisScreen: black background,
// #242424 cards, #F7F7F7 text, white buttons with black text. Green
// (#38A36D) only for the completed state, never for buttons.
private val AH_WHITE = Color(0xFFF7F7F7)
private val AH_MUTED = Color(0xFFABABAB)
private val AH_CARD = Color(0xFF242424)
private val AH_BORDER = Color(0xFF383838)
private val AH_RED = Color(0xFFFF8585)
private val AH_GREEN = Color(0xFF38A36D)

private fun historyStatusLabel(status: String): Int = when (status) {
    "COMPLETED" -> R.string.app_analysis_status_completed
    "COMPLETED_PARTIAL" -> R.string.app_analysis_status_partial
    "FAILED" -> R.string.app_analysis_status_failed
    "REJECTED" -> R.string.app_analysis_status_rejected
    "EXPIRED" -> R.string.app_analysis_status_expired
    "UPLOADING" -> R.string.app_analysis_status_uploading
    "QUEUED_FOR_ANALYSIS" -> R.string.app_analysis_status_queued
    else -> R.string.app_analysis_status_analyzing
}

private fun historyStatusColor(status: String): Color = when (status) {
    "COMPLETED", "COMPLETED_PARTIAL" -> AH_GREEN
    "FAILED", "REJECTED", "EXPIRED" -> AH_RED
    else -> AH_MUTED
}

private fun historyErrorLabel(code: String?): Int = when (code) {
    "METHOD_UNAVAILABLE" -> R.string.app_analysis_error_method_unavailable
    "NOT_VPN_APP" -> R.string.app_analysis_error_not_vpn
    "INSUFFICIENT_CREDITS" -> R.string.app_analysis_error_no_credits
    "SIGN_IN_REQUIRED" -> R.string.app_analysis_error_sign_in
    "APP_ANALYSIS_SHA_MISMATCH", "INVALID_APK" -> R.string.app_analysis_error_invalid_apk
    "INPUT_TOO_LARGE", "APP_ANALYSIS_INPUT_TOO_LARGE" -> R.string.app_analysis_error_too_large
    "APP_ANALYSIS_BUSY" -> R.string.app_analysis_error_busy
    else -> R.string.app_analysis_error_generic
}

private fun historyDate(value: String?, language: String): String {
    if (value.isNullOrBlank()) return ""
    return runCatching {
        DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.forLanguageTag(language))
            .format(Date.from(Instant.parse(value)))
    }.getOrDefault(value.take(10))
}

/**
 * Own "Historial de análisis APK" screen (route "analysis-history").
 * Only the user's history, from AppAnalysisClient.refreshHistory()
 * (V2 op 30). Each row expands for details; completed jobs can download
 * the saved result ZIP again via downloadResult(). The servers/networks
 * line comes from JobView.resultSummary and is shown only when the server
 * sent it; older jobs without it show no such line, never invented zeros.
 */
@Composable
internal fun AppAnalysisHistoryScreen(language: String, auth: NativeCommerceAuth,
    onSignIn: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val client = remember(context) { AppAnalysisClient(context) }
    val tr: (String, String) -> String =
        { es, en -> CommerceI18n.translate(language, es, en) }
    var jobs by remember { mutableStateOf<List<AppAnalysisClient.JobView>>(emptyList()) }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf(false) }
    var expandedJobId by remember { mutableStateOf<String?>(null) }
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
    fun reload() {
        if (loading) return
        scope.launch {
            loading = true; error = false
            try {
                jobs = client.refreshHistory()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                error = true
            } finally {
                loading = false
            }
        }
    }
    LaunchedEffect(Unit) { reload() }
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(13.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Image(painterResource(R.drawable.arnes),
                contentDescription = stringResource(R.string.app_analysis_arnes_name),
                contentScale = ContentScale.Crop,
                modifier = Modifier.size(44.dp).clip(CircleShape))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.apk_analysis_title), color = AH_WHITE,
                    fontSize = 24.sp, fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.app_analysis_arnes_name),
                    color = AH_MUTED, fontSize = 12.sp)
            }
            IconButton(onClick = { reload() }, enabled = !loading) {
                Icon(Icons.Outlined.Refresh, tr("Actualizar", "Refresh"), tint = AH_WHITE)
            }
        }
        if (loading) LinearProgressIndicator(Modifier.fillMaxWidth(), color = AH_WHITE)
        if (error) Text(tr("No se pudo cargar el historial. Inténtalo de nuevo.",
            "Could not load the history. Try again."), color = AH_RED, fontSize = 13.sp)
        if (auth.sessionToken() == null) {
            Button(onClick = onSignIn, modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = AH_WHITE, contentColor = Color.Black)) {
                Text(tr("Iniciar sesión", "Sign in"), fontWeight = FontWeight.Bold)
            }
        } else if (!loading && jobs.isEmpty() && !error) {
            Column(Modifier.fillMaxWidth().padding(top = 60.dp),
                horizontalAlignment = Alignment.CenterHorizontally) {
                Image(painterResource(R.drawable.arnes),
                    contentDescription = null, contentScale = ContentScale.Crop,
                    modifier = Modifier.size(64.dp).clip(CircleShape))
                Spacer(Modifier.height(14.dp))
                Text(stringResource(R.string.app_analysis_history_empty),
                    color = AH_MUTED, fontSize = 14.sp)
            }
        } else {
            LazyColumn(Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(9.dp)) {
                items(jobs, key = { it.jobId }) { job ->
                    val expanded = expandedJobId == job.jobId
                    Surface(color = AH_CARD, shape = RoundedCornerShape(16.dp),
                        border = BorderStroke(1.dp, AH_BORDER),
                        modifier = Modifier.fillMaxWidth()
                            .testTag("app_analysis_history_row")) {
                        Column(Modifier.fillMaxWidth()
                            .clickable { expandedJobId = if (expanded) null else job.jobId }
                            .padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                Image(painterResource(R.drawable.arnes),
                                    contentDescription = null,
                                    contentScale = ContentScale.Crop,
                                    modifier = Modifier.size(44.dp).clip(CircleShape))
                                Column(Modifier.weight(1f),
                                    verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                    Text(job.appName ?: job.packageName ?: job.filename,
                                        color = AH_WHITE, fontSize = 15.sp,
                                        fontWeight = FontWeight.SemiBold)
                                    Text((job.packageName ?: job.filename),
                                        color = AH_MUTED, fontSize = 12.sp)
                                    Text(
                                        historyDate(job.createdAt ?: job.updatedAt, language) +
                                            " · " + stringResource(historyStatusLabel(job.status)),
                                        color = historyStatusColor(job.status), fontSize = 12.sp)
                                    // Servers/networks only when the server
                                    // sent resultSummary; never invented.
                                    job.resultSummary?.let { summary ->
                                        Text(stringResource(
                                            R.string.app_analysis_result_summary,
                                            summary.servers, summary.networks),
                                            color = AH_MUTED, fontSize = 12.sp)
                                    }
                                }
                                Icon(if (expanded) Icons.Outlined.ExpandLess
                                    else Icons.Outlined.ExpandMore, null, tint = AH_MUTED)
                            }
                            if (expanded) {
                                HorizontalDivider(color = AH_BORDER)
                                Text(tr("Archivo", "File") + ": " + job.filename,
                                    color = AH_MUTED, fontSize = 12.sp)
                                Text(tr("Estado", "Status") + ": " +
                                    stringResource(historyStatusLabel(job.status)),
                                    color = AH_WHITE, fontSize = 12.sp)
                                if (job.errorCode != null)
                                    Text(stringResource(historyErrorLabel(job.errorCode)),
                                        color = AH_RED, fontSize = 12.sp)
                                if (job.updatedAt != null)
                                    Text(tr("Actualizado", "Updated") + ": " +
                                        historyDate(job.updatedAt, language),
                                        color = AH_MUTED, fontSize = 12.sp)
                                if (job.status in setOf("COMPLETED", "COMPLETED_PARTIAL")) {
                                    Button(onClick = {
                                        exportJob = job
                                        val name = (job.packageName ?: "app-analysis") +
                                            "-analysis-" + job.jobId.take(8) + ".zip"
                                        downloadLauncher.launch(name)
                                    }, modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(12.dp),
                                        colors = ButtonDefaults.buttonColors(
                                            containerColor = AH_WHITE,
                                            contentColor = Color.Black)) {
                                        Text(stringResource(
                                            R.string.app_analysis_download_button),
                                            fontWeight = FontWeight.Bold, fontSize = 14.sp)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        exportStatus?.let { Text(it, color = AH_MUTED, fontSize = 12.sp) }
    }
}
