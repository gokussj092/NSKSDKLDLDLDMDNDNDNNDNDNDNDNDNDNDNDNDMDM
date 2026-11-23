package com.ghostdeveloper.spdecode

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import java.util.Locale

private val helpText=Color(0xFFF7F7F7)
private val helpMuted=Color(0xFFABABAB)
private val helpGreen=Color(0xFF38A36D)
private val helpError=Color(0xFFFF8585)

private const val reportCategory="technical"
private val unsupportedReportCharacters=Regex("[\u0000-\u0008\u000B\u000C\u000E-\u001F]")

private fun defaultLanguageName(language:String,locale:Locale):String {
    val tag=if(language=="system") locale.toLanguageTag() else language
    val code=if(locale.language=="fil") "tl" else locale.language
    return (SupportedLanguages.options.firstOrNull{it.tag==tag}
        ?:SupportedLanguages.options.firstOrNull{it.tag.substringBefore('-')==code})
        ?.nativeName ?: locale.getDisplayName(locale)
}

/**
 * Translation-error report inside Settings. Reuses the existing support
 * thread flow: same account session (NativeCommerceAuth) and the existing
 * "technical" category. No new server endpoint, no new V2 operation.
 * The "[Error de traducción]" marker lives only in the message text so
 * support can tell these reports apart; nothing internal is ever shown.
 */
@Composable
internal fun LanguageHelpScreen(
    language:String,
    onBack:()->Unit,
    onSignIn:()->Unit,
){
    val context=LocalContext.current
    val auth=remember(context){NativeCommerceAuth(context)}
    // Read fresh on every composition: returning from the sign-in flow must
    // show the form without reopening this page.
    val signedIn=auth.sessionToken()!=null
    val locked=NativeDeviceAccountGuard.enabled(context) && !NativeDeviceAccountGuard.unlocked
    val locale=LocalConfiguration.current.locales[0]
    val initialLanguage=defaultLanguageName(language,locale)
    val scope=rememberCoroutineScope()
    var languageField by rememberSaveable(initialLanguage){
        mutableStateOf(initialLanguage)
    }
    var where by rememberSaveable{mutableStateOf("")}
    var wrong by rememberSaveable{mutableStateOf("")}
    var correct by rememberSaveable{mutableStateOf("")}
    var comment by rememberSaveable{mutableStateOf("")}
    var busy by remember{mutableStateOf(false)}
    var sent by remember{mutableStateOf(false)}
    var sendError by remember{mutableStateOf(false)}

    val complete=languageField.isNotBlank() && wrong.isNotBlank() && correct.isNotBlank()
    val subject=("Error de traducción: "+languageField.trim()).take(60).trim()
    val body=buildString {
        appendLine("[Error de traducción]")
        appendLine("Idioma: "+languageField.trim())
        appendLine("Dónde: "+where.trim())
        appendLine("Texto actual: "+wrong.trim())
        appendLine("Corrección sugerida: "+correct.trim())
        append("Comentarios: "+comment.trim())
    }
    val invalidReport=body.toByteArray(Charsets.UTF_8).size>4096 ||
        unsupportedReportCharacters.containsMatchIn(body) ||
        supportThreadPayload(subject,reportCategory,body).toString().toByteArray(Charsets.UTF_8).size>6200
    val canSend=signedIn && !locked && !busy && complete && !invalidReport

    fun send(){
        if(!canSend || NativeDeviceAccountGuard.enabled(context) && !NativeDeviceAccountGuard.unlocked)return
        busy=true
        sendError=false
        sent=false
        scope.launch{
            try{
                auth.openSupportThread(subject,reportCategory,body)
                languageField=initialLanguage
                where=""
                wrong=""
                correct=""
                comment=""
                sent=true
            }catch(e:CancellationException){throw e}
            catch(_:Exception){
                // Generic message on purpose: suspension included, nothing
                // internal (server, panel, API, deploys) is ever exposed.
                sendError=true
            }finally{busy=false}
        }
    }

    Column(
        Modifier.fillMaxSize().background(Color.Black)
            .testTag("settings_language_help_screen")
            .padding(horizontal=20.dp,vertical=12.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement=Arrangement.spacedBy(12.dp),
    ){
        Row(verticalAlignment=Alignment.CenterVertically){
            IconButton(onClick=onBack,modifier=Modifier.size(44.dp)
                .testTag("settings_language_help_back")){
                Icon(Icons.Outlined.ArrowBack,
                    contentDescription=stringResource(R.string.close),
                    tint=helpText,modifier=Modifier.size(25.dp))
            }
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.language_help_title),
                color=helpText,fontSize=24.sp,fontWeight=FontWeight.Bold,
                modifier=Modifier.weight(1f))
        }
        if(!signedIn){
            Text(stringResource(R.string.language_help_signin_title),
                color=helpText,fontSize=18.sp,fontWeight=FontWeight.SemiBold)
            Text(stringResource(R.string.language_help_signin_detail),
                color=helpMuted,fontSize=13.sp,lineHeight=19.sp)
            Button(onClick=onSignIn,modifier=Modifier.fillMaxWidth(),
                colors=ButtonDefaults.buttonColors(containerColor=helpText,
                    contentColor=Color.Black)){
                Text(stringResource(R.string.language_help_signin_button))
            }
        }else if(locked) {
            CommerceAccountUnlockPage(locale.language)
        }else{
            Text(stringResource(R.string.language_help_form_title),
                color=helpText,fontSize=18.sp,fontWeight=FontWeight.SemiBold)
            OutlinedTextField(
                enabled=!busy,
                value=languageField,
                onValueChange={languageField=it.take(60);sent=false},
                label={Text(stringResource(R.string.language_help_language_label))},
                singleLine=true,
                modifier=Modifier.fillMaxWidth()
                    .testTag("language_help_language")
            )
            OutlinedTextField(
                enabled=!busy,
                value=where,
                onValueChange={where=it.take(200);sent=false},
                label={Text(stringResource(R.string.language_help_where_label))},
                singleLine=true,
                modifier=Modifier.fillMaxWidth()
                    .testTag("language_help_where")
            )
            OutlinedTextField(
                enabled=!busy,
                value=wrong,
                onValueChange={wrong=it.take(2000);sent=false},
                label={Text(stringResource(R.string.language_help_wrong_label))},
                minLines=3,
                modifier=Modifier.fillMaxWidth()
                    .testTag("language_help_wrong")
            )
            OutlinedTextField(
                enabled=!busy,
                value=correct,
                onValueChange={correct=it.take(2000);sent=false},
                label={Text(stringResource(R.string.language_help_correct_label))},
                minLines=3,
                modifier=Modifier.fillMaxWidth()
                    .testTag("language_help_correct")
            )
            OutlinedTextField(
                enabled=!busy,
                value=comment,
                onValueChange={comment=it.take(2000);sent=false},
                label={Text(stringResource(R.string.language_help_comment_label))},
                minLines=3,
                modifier=Modifier.fillMaxWidth()
                    .testTag("language_help_comment")
            )
            if(!complete)Text(stringResource(R.string.language_help_required),
                color=helpMuted,fontSize=12.sp,lineHeight=17.sp)
            if(invalidReport)Text(stringResource(R.string.language_help_invalid_input),
                color=helpError,fontSize=13.sp,lineHeight=19.sp)
            Button(onClick={send()},enabled=canSend,
                modifier=Modifier.fillMaxWidth()
                    .testTag("language_help_send"),
                colors=ButtonDefaults.buttonColors(containerColor=helpText,
                    contentColor=Color.Black)){
                if(busy)CircularProgressIndicator(color=Color.Black,
                    strokeWidth=2.dp,modifier=Modifier.size(18.dp))
                else Text(stringResource(R.string.language_help_send))
            }
            if(sent)Text(stringResource(R.string.language_help_sent),
                color=helpGreen,fontSize=13.sp,lineHeight=19.sp)
            if(sendError)Text(stringResource(R.string.language_help_error),
                color=helpError,fontSize=13.sp,lineHeight=19.sp)
        }
    }
}
