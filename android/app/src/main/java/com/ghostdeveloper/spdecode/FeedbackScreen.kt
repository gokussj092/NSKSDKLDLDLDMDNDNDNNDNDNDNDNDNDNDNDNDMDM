package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import java.util.UUID

data class FeedbackDraft(
    val category:String,
    val appLink:String,
    val description:String,
    val issues:List<String>,
    val submissionId:String,
)
private val feedbackIssues=listOf(
    "decode_failed" to R.string.feedback_issue_decode,
    "catalog_download" to R.string.feedback_issue_catalog,
    "import_failed" to R.string.feedback_issue_import,
    "export_failed" to R.string.feedback_issue_export,
    "app_crash" to R.string.feedback_issue_crash,
    "cloud_access" to R.string.feedback_issue_cloud,
    "other" to R.string.feedback_issue_other,
)
private val fg=Color(0xFFF7F7F7)
private val muted=Color(0xFFB6B6B6)
private val panel=Color(0xFF242424)

@Composable
internal fun FeedbackScreen(
    onBack:()->Unit,
    onSend:suspend (FeedbackDraft)->String,
) {
    // No category is selected automatically: details remain hidden until chosen.
    var category by rememberSaveable { mutableStateOf<String?>(null) }
    var appLink by rememberSaveable { mutableStateOf("") }
    var description by rememberSaveable { mutableStateOf("") }
    var extra by rememberSaveable { mutableStateOf("") }
    var issueIds by rememberSaveable { mutableStateOf("") }
    var submissionId by rememberSaveable { mutableStateOf(UUID.randomUUID().toString()) }
    var receipt by rememberSaveable { mutableStateOf<String?>(null) }
    var failed by rememberSaveable { mutableStateOf(false) }
    var sending by remember { mutableStateOf(false) }
    val scope=rememberCoroutineScope()
    val selected=issueIds.split(",").filter { it.isNotBlank() }.toSet()
    val combinedText=listOf(description.trim(),extra.trim().takeIf { it.isNotBlank() }
        ?.let { stringResource(R.string.feedback_extra_title)+": "+it }.orEmpty())
        .filter { it.isNotBlank() }.joinToString("\n\n")
    fun invalidateReceipt() {
        if(receipt!=null)submissionId=UUID.randomUUID().toString()
        receipt=null
        failed=false
    }
    val valid=combinedText.length<=2000 && when(category) {
        "method"->{
            val uri=android.net.Uri.parse(appLink.trim())
            (uri.scheme=="https"||uri.scheme=="http") &&
                !uri.host.isNullOrBlank() && description.trim().length>=10
        }
        "bug"->selected.isNotEmpty()
        "suggestion"->description.trim().length>=10
        else->false
    }
    Column(
        Modifier.fillMaxSize().testTag("feedback_screen")
            .verticalScroll(rememberScrollState())
            .padding(horizontal=20.dp,vertical=12.dp),
        verticalArrangement=Arrangement.spacedBy(14.dp),
    ) {
        Row(verticalAlignment=Alignment.CenterVertically) {
            IconButton(onClick=onBack,enabled=!sending,modifier=Modifier.testTag("feedback_back")) {
                Icon(Icons.Outlined.ArrowBack,stringResource(R.string.settings),tint=fg)
            }
            Text(stringResource(R.string.feedback_title),
                fontWeight=FontWeight.Bold,fontSize=22.sp,color=fg)
        }
        Text(stringResource(R.string.feedback_intro),
            color=muted,fontSize=13.sp,lineHeight=19.sp)
        Surface(color=panel,shape=RoundedCornerShape(18.dp),
            border=BorderStroke(1.dp,Color(0xFF383838)),
            modifier=Modifier.fillMaxWidth().testTag("feedback_type_card")) {
            Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.feedback_category),color=fg,
                    fontWeight=FontWeight.SemiBold,fontSize=17.sp)
                listOf(
                    Triple("method",R.string.feedback_category_method,Icons.Outlined.Extension),
                    Triple("bug",R.string.feedback_category_bug,Icons.Outlined.BugReport),
                    Triple("suggestion",R.string.feedback_category_suggestion,Icons.Outlined.Lightbulb),
                ).forEach { (value,title,icon) ->
                    val subtitle=when(value) {
                        "method"->R.string.feedback_method_description
                        "bug"->R.string.feedback_bug_description
                        else->R.string.feedback_suggestion_description
                    }
                    val chosen=category==value
                    Surface(
                        color=if(chosen) Color(0xFF353535) else panel,
                        shape=RoundedCornerShape(13.dp),
                        border=BorderStroke(1.dp,if(chosen)fg.copy(alpha=.55f)
                            else Color(0xFF383838)),
                        modifier=Modifier.fillMaxWidth()
                            .testTag("feedback_category_"+value)
                            .clickable(enabled=!sending) {
                                if(category!=value) {
                                    category=value
                                    invalidateReceipt()
                                }
                            },
                    ) {
                        Row(Modifier.padding(horizontal=11.dp,vertical=13.dp),
                            verticalAlignment=Alignment.CenterVertically) {
                            RadioButton(selected=chosen,onClick={
                                if(category!=value && !sending) {
                                    category=value
                                    invalidateReceipt()
                                }
                            },enabled=!sending,
                                colors=RadioButtonDefaults.colors(selectedColor=fg,
                                    unselectedColor=muted))
                            Spacer(Modifier.width(6.dp))
                            Icon(icon,null,tint=fg,modifier=Modifier.size(22.dp))
                            Spacer(Modifier.width(11.dp))
                            Column(Modifier.weight(1f),
                                verticalArrangement=Arrangement.spacedBy(3.dp)) {
                                Text(stringResource(title),color=fg,fontSize=14.sp,
                                    fontWeight=FontWeight.SemiBold)
                                Text(stringResource(subtitle),color=muted,
                                    fontSize=12.sp,lineHeight=17.sp)
                            }
                        }
                    }
                }
            }
        }

        if(category!=null) {
            Surface(color=panel,shape=RoundedCornerShape(18.dp),
                border=BorderStroke(1.dp,Color(0xFF383838)),
                modifier=Modifier.fillMaxWidth().testTag("feedback_details")) {
                Column(Modifier.padding(17.dp),
                    verticalArrangement=Arrangement.spacedBy(13.dp)) {
                    Text(stringResource(R.string.feedback_details_title),
                        color=fg,fontWeight=FontWeight.SemiBold,fontSize=17.sp)
                    if(category=="method") {
                        Text(stringResource(R.string.feedback_method_help),
                            color=muted,fontSize=12.sp,lineHeight=18.sp)
                        OutlinedTextField(
                            value=appLink,onValueChange={
                                if(it.length<=1500){appLink=it;invalidateReceipt()}
                            },label={Text(stringResource(R.string.feedback_app_link))},
                            placeholder={Text(stringResource(R.string.feedback_app_link_hint))},
                            modifier=Modifier.fillMaxWidth().testTag("feedback_app_link"),
                            singleLine=true,enabled=!sending,
                            shape=RoundedCornerShape(12.dp),
                            colors=OutlinedTextFieldDefaults.colors(
                                focusedTextColor=fg,unfocusedTextColor=fg,
                                focusedBorderColor=fg,unfocusedBorderColor=muted,
                                focusedLabelColor=fg,unfocusedLabelColor=muted),
                        )
                    }
                    if(category=="bug") {
                        Text(stringResource(R.string.feedback_bug_instruction),
                            color=fg,fontSize=13.sp,fontWeight=FontWeight.SemiBold)
                        Column(verticalArrangement=Arrangement.spacedBy(2.dp)) {
                            feedbackIssues.forEach { (id,label) ->
                                Row(
                                    Modifier.fillMaxWidth()
                                        .testTag("feedback_issue_"+id)
                                        .clickable(enabled=!sending) {
                                            val next=selected.toMutableSet()
                                            if(!next.add(id))next.remove(id)
                                            issueIds=feedbackIssues.map { it.first }
                                                .filter{it in next}.joinToString(",")
                                            invalidateReceipt()
                                        },
                                    verticalAlignment=Alignment.CenterVertically,
                                ) {
                                    Checkbox(checked=id in selected,onCheckedChange={checked->
                                        val next=selected.toMutableSet()
                                        if(checked)next.add(id)else next.remove(id)
                                        issueIds=feedbackIssues.map{it.first}
                                            .filter{it in next}.joinToString(",")
                                        invalidateReceipt()
                                    },enabled=!sending)
                                    Text(stringResource(label),color=fg,fontSize=13.sp)
                                }
                            }
                        }
                    }
                    Text(stringResource(if(category=="bug")
                        R.string.feedback_optional_report
                        else R.string.feedback_description_required),
                        color=fg,fontSize=14.sp,fontWeight=FontWeight.SemiBold)
                    OutlinedTextField(
                        value=description,onValueChange={
                            if(it.length<=2000){description=it;invalidateReceipt()}
                        },modifier=Modifier.fillMaxWidth().testTag("feedback_description"),
                        minLines=3,maxLines=6,enabled=!sending,
                        placeholder={Text(stringResource(if(category=="bug")
                            R.string.feedback_report_hint else R.string.feedback_description_hint))},
                        shape=RoundedCornerShape(12.dp),
                        colors=OutlinedTextFieldDefaults.colors(
                            focusedTextColor=fg,unfocusedTextColor=fg,
                            focusedBorderColor=fg,unfocusedBorderColor=muted,
                            focusedPlaceholderColor=muted,unfocusedPlaceholderColor=muted),
                    )
                    Text(stringResource(R.string.feedback_extra_title),color=fg,
                        fontSize=13.sp,fontWeight=FontWeight.SemiBold)
                    OutlinedTextField(
                        value=extra,onValueChange={
                            if(it.length<=350){extra=it;invalidateReceipt()}
                        },modifier=Modifier.fillMaxWidth().testTag("feedback_extra"),
                        singleLine=false,maxLines=3,enabled=!sending,
                        placeholder={Text(stringResource(R.string.feedback_extra_hint))},
                        shape=RoundedCornerShape(12.dp),
                        colors=OutlinedTextFieldDefaults.colors(
                            focusedTextColor=fg,unfocusedTextColor=fg,
                            focusedBorderColor=fg,unfocusedBorderColor=muted,
                            focusedPlaceholderColor=muted,unfocusedPlaceholderColor=muted),
                    )
                }
            }
            Row(Modifier.fillMaxWidth().padding(horizontal=4.dp),
                verticalAlignment=Alignment.Top,
                horizontalArrangement=Arrangement.spacedBy(10.dp)) {
                Icon(Icons.Outlined.Shield,null,tint=muted,modifier=Modifier.size(20.dp))
                Text(stringResource(R.string.feedback_privacy_note),
                    color=muted,fontSize=12.sp,lineHeight=18.sp,
                    modifier=Modifier.weight(1f))
            }
        }
        if(failed) Text(stringResource(R.string.feedback_error),
            color=Color(0xFFFFABAB),fontSize=13.sp,
            modifier=Modifier.testTag("feedback_send_error"))
        receipt?.let {
            Text(stringResource(R.string.feedback_received,it),color=fg,fontSize=13.sp,
                modifier=Modifier.testTag("feedback_send_received"))
        }
        Button(
            enabled=valid&&!sending&&receipt==null,
            onClick={
                if(!sending && valid) {
                    sending=true
                    failed=false
                    val draft=FeedbackDraft(category!!,
                        if(category=="method")appLink.trim() else "",
                        combinedText,
                        if(category=="bug")selected.toList() else emptyList(),
                        submissionId)
                    scope.launch {
                        try {
                            val id=onSend(draft)
                            if(!id.matches(Regex("[0-9a-fA-F-]{36}")))
                                throw IllegalStateException("INVALID_RECEIPT")
                            receipt=id
                        }catch(e:CancellationException){throw e}
                        catch(_:Exception){failed=true}
                        finally{sending=false}
                    }
                }
            },
            modifier=Modifier.fillMaxWidth().testTag("feedback_submit"),
            shape=RoundedCornerShape(13.dp),
            colors=ButtonDefaults.buttonColors(containerColor=fg,contentColor=Color.Black),
        ) {
            if(sending) CircularProgressIndicator(Modifier.size(18.dp),strokeWidth=2.dp)
            else Icon(Icons.Outlined.Send,null)
            Spacer(Modifier.width(8.dp))
            Text(stringResource(if(sending)R.string.feedback_sending
                else R.string.feedback_send))
        }
        Spacer(Modifier.height(12.dp))
    }
}
