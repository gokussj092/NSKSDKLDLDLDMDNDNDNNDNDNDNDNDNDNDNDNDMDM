package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Android
import com.ghostdeveloper.spdecode.cloud.CloudApkQaClient
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val QA_WHITE=Color(0xFFF7F7F7)
private val QA_MUTED=Color(0xFFB1B1B1)
private val QA_CARD=Color(0xFF242424)
private val QA_BORDER=Color(0xFF383838)

@Composable
internal fun ApkQaAnalysisScreen(
    active:Boolean,phase:String,received:Long,total:Long,
    report:String?,error:String?,
    onPick:()->Unit,onCancel:()->Unit,onCopyDeviceId:()->Unit,
    events:List<CloudApkQaClient.ActivityEvent> = emptyList(),
) {
    var authorized by rememberSaveable { mutableStateOf(false) }
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
                TextButton(onClick=onCopyDeviceId,enabled=!active,
                    modifier=Modifier.fillMaxWidth().testTag("apk_qa_copy_device_id")) {
                    Text(stringResource(R.string.apk_qa_copy_device_id),color=QA_WHITE)
                }
            }
        }

        if(active) {
            Surface(color=QA_CARD,shape=RoundedCornerShape(14.dp),
                border=BorderStroke(1.dp,QA_BORDER),modifier=Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp),
                    verticalArrangement=Arrangement.spacedBy(10.dp)) {
                    val label=when(phase) {
                        "READING"->R.string.apk_qa_reading
                        "SENDING"->R.string.apk_qa_uploading
                        else->R.string.apk_qa_processing
                    }
                    Text(stringResource(label),color=QA_WHITE,fontSize=14.sp)
                    val fraction=if(total>0L) (received.toDouble()/total)
                        .toFloat().coerceIn(0f,1f) else 0f
                    LinearProgressIndicator(progress={fraction},
                        modifier=Modifier.fillMaxWidth().testTag("apk_qa_progress"))
                    if(total>0L) Text(String.format("%d / %d MiB",
                        received/1024L/1024L,total/1024L/1024L),
                        color=QA_MUTED,fontSize=12.sp)
                    OutlinedButton(onClick=onCancel,modifier=Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.cancel))
                    }
                }
            }
        }
        if(events.isNotEmpty()) {
            Surface(color=QA_CARD,shape=RoundedCornerShape(14.dp),
                border=BorderStroke(1.dp,QA_BORDER),modifier=Modifier.fillMaxWidth()
                    .testTag("apk_qa_activity")) {
                Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)) {
                    Text(stringResource(R.string.apk_qa_activity_title),color=QA_WHITE,
                        fontWeight=FontWeight.SemiBold,fontSize=16.sp)
                    events.sortedBy { it.sequence }.forEach { entry ->
                        val label=when(entry.code) {
                            "UPLOAD_STARTED"->R.string.apk_qa_event_upload_started
                            "UPLOAD_RECEIVED"->R.string.apk_qa_event_upload_received
                            "UPLOAD_REJECTED"->R.string.apk_qa_event_upload_rejected
                            "PACKAGE_VALIDATION"->R.string.apk_qa_event_package_validation
                            "PACKAGE_VALIDATED"->R.string.apk_qa_event_package_validated
                            "COMPONENT_INSPECTION"->R.string.apk_qa_event_component_inspection
                            "COMPONENTS_INSPECTED"->R.string.apk_qa_event_components_inspected
                            "REPORT_PREPARATION"->R.string.apk_qa_event_report_preparation
                            "REPORT_READY"->R.string.apk_qa_event_report_ready
                            "ANALYSIS_FAILED"->R.string.apk_qa_event_analysis_failed
                            else->null
                        }
                        if(label!=null) Row(verticalAlignment=Alignment.CenterVertically) {
                            val tint=when(entry.status) {
                                "DONE"->Color(0xFF66B99A)
                                "FAILED"->Color(0xFFFF9999)
                                else->Color(0xFF84B8EA)
                            }
                            Text(when(entry.status) {
                                "DONE"->"✓"
                                "FAILED"->"!"
                                else->"•"
                            },color=tint,fontSize=18.sp)
                            Spacer(Modifier.width(10.dp))
                            Text(stringResource(label),color=QA_WHITE,
                                fontSize=13.sp,lineHeight=18.sp)
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
        if(report!=null) {
            Surface(color=QA_CARD,shape=RoundedCornerShape(14.dp),
                border=BorderStroke(1.dp,QA_BORDER),modifier=Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(9.dp)) {
                    Text(stringResource(R.string.apk_qa_report),color=QA_WHITE,
                        fontWeight=FontWeight.SemiBold,fontSize=17.sp)
                    SelectionContainer {
                        Text(report,color=QA_WHITE,fontSize=12.sp,lineHeight=18.sp,
                            modifier=Modifier.testTag("apk_qa_report_json"))
                    }
                }
            }
        }
    }
}
