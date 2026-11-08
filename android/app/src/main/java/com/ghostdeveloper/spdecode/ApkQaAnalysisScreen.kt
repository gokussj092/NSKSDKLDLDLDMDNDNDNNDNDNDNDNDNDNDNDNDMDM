package com.ghostdeveloper.spdecode

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Android
import com.ghostdeveloper.spdecode.cloud.CloudApkQaClient
import com.ghostdeveloper.spdecode.cloud.ApkQaHistoryStore
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.text.DateFormat
import java.util.Date
import java.io.OutputStreamWriter


private data class PublicStage(val id:String,val label:Int,val status:String)
private fun publicStages(events:List<CloudApkQaClient.ActivityEvent>):List<PublicStage> {
    val stages=linkedMapOf<String,PublicStage>()
    events.sortedBy { it.sequence }.forEach { event ->
        val code=event.code
        val key=when(code) {
            "UPLOAD_STARTED","UPLOAD_RECEIVED","UPLOAD_REJECTED"->"upload"
            "PACKAGE_VALIDATION","PACKAGE_VALIDATED"->"validate"
            "COMPONENT_INSPECTION","COMPONENTS_INSPECTED"->"components"
            "ADVANCED_ANALYSIS","ADVANCED_ANALYSIS_COMPLETE",
                "ADVANCED_ANALYSIS_PARTIAL","ADVANCED_ANALYSIS_SKIPPED"->"advanced"
            "REPORT_PREPARATION","REPORT_READY"->"report"
            "ANALYSIS_FAILED"->"failure"
            else->return@forEach
        }
        val final=code in setOf("UPLOAD_RECEIVED","PACKAGE_VALIDATED",
            "COMPONENTS_INSPECTED","ADVANCED_ANALYSIS_COMPLETE","REPORT_READY")
        val failed=code in setOf("UPLOAD_REJECTED","ANALYSIS_FAILED")
        val partial=code in setOf("ADVANCED_ANALYSIS_PARTIAL","ADVANCED_ANALYSIS_SKIPPED")
        val status=when {
            failed->"FAILED"
            partial->"PARTIAL"
            final->"DONE"
            else->"RUNNING" // Never display a green tick for stage-start events.
        }
        val label=when(key) {
            "upload"->if(final)R.string.apk_qa_event_upload_received else R.string.apk_qa_event_upload_started
            "validate"->if(final)R.string.apk_qa_event_package_validated else R.string.apk_qa_event_package_validation
            "components"->if(final)R.string.apk_qa_event_components_inspected else R.string.apk_qa_event_component_inspection
            "advanced"->R.string.apk_qa_advanced_stage
            "report"->if(final)R.string.apk_qa_event_report_ready else R.string.apk_qa_event_report_preparation
            else->R.string.apk_qa_event_analysis_failed
        }
        if(key=="failure") {
            val open=stages.entries.lastOrNull { it.value.status=="RUNNING" }?.key
            if(open!=null)stages[open]=stages.getValue(open).copy(status="FAILED")
        }
        stages[key]=PublicStage(key,label,status)
    }
    return stages.values.toList()
}
private fun storedEvents(raw:String):List<CloudApkQaClient.ActivityEvent> =
    runCatching {
        val array=JSONArray(raw)
        (0 until minOf(array.length(),64)).mapNotNull { n ->
            val item=array.optJSONObject(n)?:return@mapNotNull null
            CloudApkQaClient.ActivityEvent(item.optInt("sequence"),item.optString("code"),
                item.optString("status"))
        }
    }.getOrDefault(emptyList())

private val QA_WHITE=Color(0xFFF7F7F7)
private val QA_MUTED=Color(0xFFB1B1B1)
private val QA_CARD=Color(0xFF242424)
private val QA_BORDER=Color(0xFF383838)

@Composable
internal fun ApkQaAnalysisScreen(
    active:Boolean,phase:String,received:Long,total:Long,
    report:String?,error:String?,
    onPick:()->Unit,onCancel:()->Unit,
    events:List<CloudApkQaClient.ActivityEvent> = emptyList(),
    onRetry:()->Unit = {},
) {
    var authorized by rememberSaveable { mutableStateOf(false) }
    val clipboard=LocalClipboardManager.current
    val context=LocalContext.current
    val scope=rememberCoroutineScope()
    val historyStore=remember(context) { ApkQaHistoryStore(context) }
    var historyVersion by remember { mutableIntStateOf(0) }
    val savedItems by produceState<List<ApkQaHistoryStore.Item>>(
        emptyList(),report,phase,historyVersion) {
        value=runCatching { withContext(Dispatchers.IO){historyStore.list()} }
            .getOrDefault(emptyList())
    }
    var historyExpanded by rememberSaveable { mutableStateOf(false) }
    var selectedRecord by remember { mutableStateOf<ApkQaHistoryStore.Record?>(null) }
    var exportText by remember { mutableStateOf<String?>(null) }
    var exportStatus by remember { mutableStateOf<String?>(null) }
    var deleteCandidate by remember { mutableStateOf<ApkQaHistoryStore.Item?>(null) }
    val launcher=rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        val snapshot=exportText
        exportText=null
        if(uri!=null && snapshot!=null) {
            scope.launch {
                exportStatus=try {
                    withContext(Dispatchers.IO) {
                        val output=context.contentResolver.openOutputStream(uri,"w")
                            ?:throw java.io.IOException("WRITE_UNAVAILABLE")
                        OutputStreamWriter(output,Charsets.UTF_8).use { it.write(snapshot) }
                    }
                    context.getString(R.string.apk_qa_export_success)
                }catch(_:Exception){context.getString(R.string.apk_qa_export_failure)}
            }
        }
    }
    val displayReport=selectedRecord?.report ?: report
    val displayEvents=remember(selectedRecord,events) {
        selectedRecord?.let{storedEvents(it.events)} ?: events
    }
    val sections=remember(displayReport) {
        displayReport?.let(ApkReportMarkdown::blocks).orEmpty()
    }
    Column(Modifier.fillMaxSize().testTag("apk_qa_screen")
        .verticalScroll(rememberScrollState())
        .padding(horizontal=20.dp,vertical=16.dp),
        verticalArrangement=Arrangement.spacedBy(14.dp)) {
        Text(stringResource(R.string.apk_qa_title),color=QA_WHITE,
            fontSize=23.sp,fontWeight=FontWeight.Bold)
        Text(stringResource(R.string.apk_qa_description),color=QA_MUTED,
            fontSize=13.sp,lineHeight=20.sp)

        Surface(color=QA_CARD,shape=RoundedCornerShape(16.dp),
            border=BorderStroke(1.dp,QA_BORDER),modifier=Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp),
                verticalArrangement=Arrangement.spacedBy(12.dp)) {
                Row(verticalAlignment=Alignment.CenterVertically) {
                    Icon(Icons.Outlined.Android,contentDescription=null,tint=QA_WHITE)
                    Spacer(Modifier.width(9.dp))
                    Text(stringResource(R.string.apk_qa_limit),color=QA_WHITE,
                        fontSize=13.sp)
                }
                Row(verticalAlignment=Alignment.CenterVertically) {
                    Checkbox(checked=authorized,enabled=!active,
                        onCheckedChange={authorized=it},modifier=Modifier.testTag("apk_qa_consent"),
                        colors=CheckboxDefaults.colors(checkedColor=Color(0xFF438A74)))
                    Text(stringResource(R.string.apk_qa_consent),color=QA_WHITE,
                        fontSize=13.sp,lineHeight=19.sp)
                }
                Button(onClick=onPick,enabled=authorized&&!active,
                    modifier=Modifier.fillMaxWidth().testTag("apk_qa_import"),
                    shape=RoundedCornerShape(12.dp)) {
                    Text(stringResource(R.string.apk_qa_pick))
                }
                Text(stringResource(R.string.apk_qa_no_charge),color=QA_MUTED,fontSize=12.sp)
                Text(stringResource(R.string.apk_qa_retention_notice),
                    color=QA_MUTED,fontSize=12.sp,lineHeight=18.sp)
            }
        }

        if(active) {
            Surface(color=QA_CARD,shape=RoundedCornerShape(14.dp),
                border=BorderStroke(1.dp,QA_BORDER),modifier=Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp),
                    verticalArrangement=Arrangement.spacedBy(10.dp)) {
                    val label=when(phase) {
                        "QUEUED","READING"->R.string.apk_qa_reading
                        "UPLOADING","SENDING"->R.string.apk_qa_uploading
                        else->R.string.apk_qa_processing
                    }
                    Text(stringResource(label),color=QA_WHITE,fontSize=14.sp)
                    val fraction=if(total>0L) (received.toDouble()/total)
                        .toFloat().coerceIn(0f,1f) else 0f
                    if(phase in setOf("QUEUED","UPLOADING","SENDING","READING"))
                        LinearProgressIndicator(progress={fraction},
                            modifier=Modifier.fillMaxWidth().testTag("apk_qa_progress"))
                    else
                        LinearProgressIndicator(
                            modifier=Modifier.fillMaxWidth().testTag("apk_qa_progress"))
                    if(total>0L) Text(String.format("%d / %d MiB",
                        received/1024L/1024L,total/1024L/1024L),
                        color=QA_MUTED,fontSize=12.sp)
                    Text(stringResource(R.string.apk_qa_one_at_time),
                        color=QA_MUTED,fontSize=12.sp,lineHeight=18.sp)
                    if(error!=null) {
                        OutlinedButton(onClick=onRetry,
                            modifier=Modifier.fillMaxWidth().testTag("apk_qa_reconnect")) {
                            Text(stringResource(R.string.apk_qa_retry_connection))
                        }
                    }
                }
            }
        }
        val timeline=remember(displayEvents){publicStages(displayEvents)}
        if(timeline.isNotEmpty()) {
            Surface(color=QA_CARD,shape=RoundedCornerShape(14.dp),
                border=BorderStroke(1.dp,QA_BORDER),modifier=Modifier.fillMaxWidth()
                    .testTag("apk_qa_activity")) {
                Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.apk_qa_activity_title),color=QA_WHITE,
                        fontWeight=FontWeight.SemiBold,fontSize=16.sp)
                    timeline.forEach { stage ->
                        Row(verticalAlignment=Alignment.CenterVertically) {
                            when(stage.status) {
                                "RUNNING"->CircularProgressIndicator(
                                    modifier=Modifier.size(17.dp),strokeWidth=2.dp,
                                    color=Color(0xFF84B8EA))
                                "DONE"->Text("✓",color=Color(0xFF66B99A),fontSize=18.sp)
                                "FAILED"->Text("✕",color=Color(0xFFFF9999),fontSize=18.sp)
                                else->Text("!",color=Color(0xFFFFCF75),fontSize=18.sp)
                            }
                            Spacer(Modifier.width(12.dp))
                            Column {
                                Text(stringResource(stage.label),color=QA_WHITE,fontSize=13.sp)
                                Text(stringResource(when(stage.status) {
                                    "RUNNING"->R.string.apk_qa_running_stage
                                    "DONE"->R.string.apk_qa_done_stage
                                    "FAILED"->R.string.apk_qa_failed_stage
                                    else->R.string.apk_qa_partial_stage
                                }),color=when(stage.status) {
                                    "RUNNING"->Color(0xFF84B8EA)
                                    "DONE"->Color(0xFF66B99A)
                                    "FAILED"->Color(0xFFFF9999)
                                    else->Color(0xFFFFCF75)
                                },fontSize=11.sp)
                            }
                        }
                    }
                }
            }
        }
        if(error!=null) {
            Surface(color=QA_CARD,shape=RoundedCornerShape(14.dp),
                border=BorderStroke(1.dp,QA_BORDER),modifier=Modifier.fillMaxWidth()) {
                Text(error,color=Color(0xFFFF9999),modifier=Modifier.padding(16.dp),
                    fontSize=13.sp)
            }
        }
        // History is distinct from the one active upload; old reports survive new jobs.
        Surface(color=QA_CARD,shape=RoundedCornerShape(14.dp),
            border=BorderStroke(1.dp,QA_BORDER),modifier=Modifier.fillMaxWidth()
                .testTag("apk_qa_history")) {
            Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(8.dp)) {
                TextButton(onClick={historyExpanded=!historyExpanded}) {
                    Text(stringResource(R.string.apk_qa_history_title),color=QA_WHITE)
                    Spacer(Modifier.width(7.dp))
                    Text("(${savedItems.size})",color=QA_MUTED)
                }
                if(historyExpanded) {
                    if(savedItems.isEmpty()) Text(
                        stringResource(R.string.apk_qa_history_empty),color=QA_MUTED,fontSize=12.sp)
                    else LazyColumn(modifier=Modifier.fillMaxWidth().height(240.dp)) {
                        items(savedItems,key={it.id}){ item ->
                            Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically) {
                                TextButton(onClick={
                                    scope.launch {
                                        selectedRecord=runCatching {
                                            withContext(Dispatchers.IO){historyStore.read(item.id)}
                                        }.getOrNull()
                                    }
                                },modifier=Modifier.weight(1f)) {
                                    Column {
                                        Text(item.filename,color=QA_WHITE,maxLines=1,fontSize=12.sp)
                                        Text(
                                            DateFormat.getDateTimeInstance().format(Date(item.createdAt))+
                                                " · "+item.phase,
                                            color=QA_MUTED,fontSize=10.sp)
                                    }
                                }
                                TextButton(onClick={deleteCandidate=item}) {
                                    Text(stringResource(R.string.apk_qa_history_delete),
                                        color=Color(0xFFFF9999),fontSize=11.sp)
                                }
                            }
                            HorizontalDivider(color=QA_BORDER)
                        }
                    }
                    if(selectedRecord!=null) {
                        OutlinedButton(onClick={selectedRecord=null}) {
                            Text(stringResource(R.string.apk_qa_history_back))
                        }
                    }
                }
            }
        }
        if(displayReport!=null) {
            Surface(color=QA_CARD,shape=RoundedCornerShape(14.dp),
                border=BorderStroke(1.dp,QA_BORDER),modifier=Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(9.dp)) {
                    Text(stringResource(if(selectedRecord!=null)
                        R.string.apk_qa_history_title else R.string.apk_qa_report),color=QA_WHITE,
                        fontWeight=FontWeight.SemiBold,fontSize=17.sp)
                    Row(verticalAlignment=Alignment.CenterVertically) {
                        Button(onClick={
                            val original=displayReport
                            if(original!=null) {
                                exportText=original
                                val base=(selectedRecord?.item?.filename
                                    ?: "SP-DECODE_APK_Analysis").substringBeforeLast('.')
                                    .replace(Regex("[^A-Za-z0-9_.-]"),"_").take(72)
                                launcher.launch("${base}_analysis.json")
                            }
                        },modifier=Modifier.testTag("apk_qa_export_json")) {
                            Text(stringResource(R.string.apk_qa_export_json))
                        }
                        if(exportStatus!=null) Text(exportStatus.orEmpty(),
                            color=QA_MUTED,fontSize=11.sp)
                    }
                    sections.forEachIndexed { index, block ->
                        Text(block.title,color=QA_WHITE,fontWeight=FontWeight.Medium,
                            fontSize=13.sp)
                        Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                            TextButton(onClick={
                                if(block.markdown.length<700_000)
                                    clipboard.setText(AnnotatedString(block.markdown))
                                else exportStatus=context.getString(R.string.result_copy_too_large)
                            }) { Text(stringResource(R.string.apk_qa_copy_markdown)) }
                            TextButton(onClick={
                                if(block.content.length<700_000)
                                    clipboard.setText(AnnotatedString(block.content))
                                else exportStatus=context.getString(R.string.result_copy_too_large)
                            }) { Text(stringResource(R.string.copy)) }
                        }
                        if (block.language=="json") {
                            Text("```json",color=QA_MUTED,fontFamily=FontFamily.Monospace,
                                fontSize=12.sp)
                            Box(Modifier.testTag("apk_qa_report_json")) {
                                LargeResultViewer(
                                raw=block.content,mask=false,
                                identity="apk-qa-$index-${block.content.length}",
                                suffix="json",
                                )
                            }
                            Text("```",color=QA_MUTED,fontFamily=FontFamily.Monospace,
                                fontSize=12.sp)
                        } else {
                            SelectionContainer {
                                Text(block.markdown,color=QA_WHITE,
                                    fontFamily=FontFamily.Monospace,fontSize=12.sp,
                                    lineHeight=18.sp,modifier=Modifier.testTag("apk_qa_report_json"))
                            }
                        }
                    }
                }
            }
        }
        if(deleteCandidate!=null) {
            AlertDialog(
                onDismissRequest={deleteCandidate=null},
                title={Text(stringResource(R.string.apk_qa_history_delete))},
                text={Text(stringResource(R.string.apk_qa_history_confirm))},
                confirmButton={
                    TextButton(onClick={
                        val item=deleteCandidate
                        deleteCandidate=null
                        if(item!=null)scope.launch {
                            runCatching {
                                withContext(Dispatchers.IO){historyStore.delete(item.id)}
                            }.onSuccess {
                                if(selectedRecord?.item?.id==item.id)selectedRecord=null
                                historyVersion++
                            }.onFailure {
                                exportStatus=context.getString(R.string.apk_qa_export_failure)
                            }
                        }
                    }) {Text(stringResource(R.string.apk_qa_history_delete))}
                },
                dismissButton={
                    TextButton(onClick={deleteCandidate=null}) {
                        Text(stringResource(R.string.cancel))
                    }
                },
            )
        }
    }
}
