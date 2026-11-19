package com.ghostdeveloper.spdecode.offline

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date

/**
 * Offline UI with the online app's AMOLED look: one theme, brand header on
 * top, Home and History as separate screens, Settings opened from the header
 * or the 3-tab bottom bar (Home, History, Settings) like the online app's
 * BottomTabs. All offline function is preserved; only the visual and
 * navigation structure changed.
 */
internal class OfflineUiState {
    var tab by mutableIntStateOf(0)
    var language by mutableStateOf("system")
    var fileName by mutableStateOf<String?>(null)
    var extension by mutableStateOf("")
    var result by mutableStateOf<String?>(null)
    var busy by mutableStateOf(false)
    var message by mutableStateOf<String?>(null)
    var error by mutableStateOf<OfflineUiError?>(null)
    var history by mutableStateOf<List<OfflineRecord>>(emptyList())
    var identity by mutableStateOf<String?>(null)
    var pendingPrompt by mutableStateOf<OfflinePrompt?>(null)
    var showTextDecoder by mutableStateOf(false)
    var settingsOpen by mutableStateOf(false)
    var aboutOpen by mutableStateOf(false)
}

internal data class OfflinePrompt(
    val requirePassword: Boolean = false,
    val requireHwid: Boolean = false,
    val requireIdentity: Boolean = false,
    val errorMessage: String = "",
)

internal data class OfflineActions(
    val importFile: () -> Unit,
    val copyResult: () -> Unit,
    val exportResult: () -> Unit,
    val clearResult: () -> Unit,
    val decodeText: (String) -> Unit,
    val retryWithCredentials: (String, String, String) -> Unit,
    val dismissPrompt: () -> Unit,
    val selectHistory: (OfflineRecord) -> Unit,
    val deleteHistory: (OfflineRecord) -> Unit,
    val deleteSelected: (Set<String>) -> Unit,
    val clearHistory: () -> Unit,
    val favoriteHistory: (OfflineRecord) -> Unit,
    val createIdentity: () -> Unit,
    val importIdentity: () -> Unit,
    val exportIdentity: () -> Unit,
    val deleteIdentity: () -> Unit,
    val copyValue: (String) -> Unit,
    val setLanguage: (String) -> Unit,
    val openUrl: (String) -> Unit,
)

private data class OfflinePalette(
    val bg: Color, val panel: Color, val raised: Color,
    val line: Color, val primary: Color, val ink: Color,
    val subdued: Color, val onPrimary: Color,
    val edge: Color, val amber: Color,
)

/** Single AMOLED palette, same values as the online app (SpDecodeApp.kt). */
private fun palette() = OfflinePalette(
    bg=Color(0xFF000000), panel=Color(0xFF242424), raised=Color(0xFF2A2A2A),
    line=Color(0xFF525252), primary=Color(0xFFF7F7F7), ink=Color(0xFFF7F7F7),
    subdued=Color(0xFFABABAB), onPrimary=Color(0xFF000000),
    edge=Color(0xFF292929), amber=Color(0xFFE0B563),
)

@Composable
internal fun OfflineScreen(state: OfflineUiState, action: OfflineActions) {
    val theme = palette()
    val scheme = darkColorScheme(
        primary=theme.primary,onPrimary=theme.onPrimary,
        primaryContainer=theme.panel,onPrimaryContainer=theme.ink,
        secondary=theme.ink,onSecondary=theme.onPrimary,
        tertiary=theme.ink,onTertiary=theme.onPrimary,
        background=theme.bg,onBackground=theme.ink,
        surface=theme.bg,onSurface=theme.ink,
        surfaceVariant=theme.panel,onSurfaceVariant=theme.subdued,
        outline=theme.line,
    )
    MaterialTheme(colorScheme=scheme) {
        BackHandler(enabled=state.aboutOpen||state.settingsOpen||state.tab==1){
            when {
                state.aboutOpen -> state.aboutOpen=false
                state.settingsOpen -> state.settingsOpen=false
                else -> state.tab=0
            }
        }
        Scaffold(
            containerColor=theme.bg,
            bottomBar={
                BottomTabs(when {
                    state.settingsOpen -> 2
                    state.tab==1 -> 1
                    else -> 0
                },{
                    when(it) {
                        0 -> {state.settingsOpen=false;state.aboutOpen=false;state.tab=0}
                        1 -> {state.settingsOpen=false;state.aboutOpen=false;state.tab=1}
                        else -> {state.aboutOpen=false;state.settingsOpen=true}
                    }
                },state.language,theme)
            },
        ) { insets ->
            Column(Modifier.fillMaxSize().padding(insets)) {
                BrandHeader(state.language,{state.settingsOpen=true},theme)
                Box(Modifier.weight(1f)) {
                    when {
                        state.settingsOpen -> if(state.aboutOpen) About(state,action,theme) else Settings(state,action,theme)
                        state.tab==1 -> History(state,action,theme)
                        else -> Home(state,action,theme)
                    }
                }
            }
        }

        var confirmClear by remember { mutableStateOf(false) }
        var confirmHistory by remember { mutableStateOf<OfflineRecord?>(null) }
        var confirmAll by remember { mutableStateOf(false) }
        var confirmIdentity by remember { mutableStateOf(false) }
        if(confirmClear) Confirmation(
            txt("delete_result",state.language),txt("remove_visible_only",state.language),
            theme,onDismiss={confirmClear=false},onConfirm={
                confirmClear=false;action.clearResult()
            },state.language)
        if(confirmHistory!=null) Confirmation(
            txt("delete_history",state.language),txt("delete_history_warning",state.language),
            theme,onDismiss={confirmHistory=null},onConfirm={
                val target=confirmHistory; confirmHistory=null
                if(target!=null) action.deleteHistory(target)
            },state.language)
        if(confirmAll) Confirmation(
            txt("clear_history",state.language),txt("clear_history_warning",state.language),
            theme,onDismiss={confirmAll=false},onConfirm={
                confirmAll=false; action.clearHistory()
            },state.language)
        if(confirmIdentity) Confirmation(
            txt("delete_identity",state.language),txt("delete_identity_warning",state.language),
            theme,onDismiss={confirmIdentity=false},onConfirm={
                confirmIdentity=false;action.deleteIdentity()
            },state.language)
        state.error?.let { problem ->
            AlertDialog(onDismissRequest={state.error=null},
                title={Text(problem.title)},text={Text(problem.description)},
                confirmButton={TextButton(onClick={state.error=null}) {
                    Text(txt("confirm",state.language))
                }},containerColor=theme.panel)
        }
        state.pendingPrompt?.let { prompt ->
            CredentialDialog(prompt,state.language,theme,
                onDismiss=action.dismissPrompt,onRetry=action.retryWithCredentials,
                identityAvailable=state.identity!=null)
        }
        // These actions are elevated to the screen instead of keeping large
        // confirmations or private identity material in the main activity.
        OfflineConfirmBus.current = OfflineConfirmCallbacks(
            clearResult={confirmClear=true},
            deleteHistory={confirmHistory=it},
            clearHistory={confirmAll=true},
            deleteIdentity={confirmIdentity=true},
        )
    }
}

/** Bottom bar in the online app's BottomTabs style, 3 tabs only: the
 * offline app has no Formatos or Server VPN. Selected tab in white,
 * unselected in muted, divider in Outline, black background. */
@Composable
private fun BottomTabs(active:Int,onTab:(Int)->Unit,language:String,p:OfflinePalette) {
    val tabs=listOf(
        Triple("home",Icons.Outlined.Home,0),
        Triple("history",Icons.Outlined.History,1),
        Triple("settings",Icons.Outlined.Settings,2),
    )
    // Edge-to-edge (targetSdk 36): the Scaffold bottomBar sits at the window
    // edge, under the system navigation bar. Lift it above the phone's own
    // bar, like the online app does with safeDrawingPadding().
    Column(Modifier.navigationBarsPadding()) {
        HorizontalDivider(color=p.line)
        Row(Modifier.fillMaxWidth().heightIn(min=65.dp).padding(bottom=2.dp),
            verticalAlignment=Alignment.CenterVertically){
            tabs.forEach{(key,icon,index)->
                val selected=active==index
                Column(Modifier.weight(1f).clickable{onTab(index)}
                        .padding(vertical=9.dp),
                    horizontalAlignment=Alignment.CenterHorizontally,
                    verticalArrangement=Arrangement.spacedBy(4.dp)){
                    Icon(icon,txt(key,language),
                        tint=if(selected)p.ink else p.subdued,modifier=Modifier.size(21.dp))
                    Text(txt(key,language),fontSize=11.sp,
                        color=if(selected)p.ink else p.subdued,
                        maxLines=1,overflow=TextOverflow.Ellipsis)
                }
            }
        }
    }
}

private data class OfflineConfirmCallbacks(
    val clearResult:()->Unit,
    val deleteHistory:(OfflineRecord)->Unit,
    val clearHistory:()->Unit,
    val deleteIdentity:()->Unit,
)
/** No persistent global results: ephemeral UI callbacks only. */
private object OfflineConfirmBus {
    var current: OfflineConfirmCallbacks?=null
}

/** Same brand header as the online app: white shield in a panel tile. */
@Composable
private fun BrandHeader(language:String,onSettings:()->Unit,p:OfflinePalette) {
    Row(
        modifier=Modifier.fillMaxWidth().padding(start=20.dp,end=12.dp,top=14.dp,bottom=11.dp),
        verticalAlignment=Alignment.CenterVertically,
    ){
        Box(
            Modifier.size(45.dp).background(p.panel,RoundedCornerShape(13.dp)),
            contentAlignment=Alignment.Center,
        ){
            Icon(Icons.Outlined.Shield,null,tint=p.ink,modifier=Modifier.size(26.dp))
        }
        Spacer(Modifier.width(11.dp))
        Column(Modifier.weight(1f)){
            Text("SP-DECODE",color=p.ink,fontSize=23.sp,fontWeight=FontWeight.Bold,
                maxLines=1)
            Text(txt("splash_subtitle",language),color=p.subdued,fontSize=14.sp,
                maxLines=1,overflow=TextOverflow.Ellipsis)
        }
        IconButton(onClick=onSettings){
            Icon(Icons.Outlined.Tune,txt("settings",language),tint=p.subdued)
        }
    }
}

@Composable
private fun OfflineCard(p:OfflinePalette,body:@Composable ColumnScope.()->Unit) {
    Surface(
        color=p.panel,shape=RoundedCornerShape(17.dp),
        border=BorderStroke(1.dp,p.line),
        modifier=Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(15.dp),verticalArrangement=Arrangement.spacedBy(12.dp),content=body)
    }
}
@Composable
private fun Section(title:String,p:OfflinePalette) {
    Text(title,fontSize=16.sp,fontWeight=FontWeight.SemiBold,color=p.ink)
}
@Composable
private fun SmallCaption(text:String,p:OfflinePalette) {
    Text(text,color=p.subdued,fontSize=12.sp,lineHeight=17.sp)
}
@Composable
private fun PrimaryButton(label:String,p:OfflinePalette,enabled:Boolean=true,onClick:()->Unit) {
    Button(onClick=onClick,enabled=enabled,modifier=Modifier.fillMaxWidth().heightIn(min=47.dp),
        shape=RoundedCornerShape(13.dp),
        colors=ButtonDefaults.buttonColors(containerColor=p.primary,contentColor=p.onPrimary)) {
        Text(label,fontWeight=FontWeight.SemiBold)
    }
}

@Composable
private fun Home(state:OfflineUiState,action:OfflineActions,p:OfflinePalette) {
    var showImportFormats by remember { mutableStateOf(false) }
    Column(
        modifier=Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal=20.dp,vertical=11.dp),
        verticalArrangement=Arrangement.spacedBy(19.dp),
    ) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement=Arrangement.spacedBy(10.dp),
            verticalAlignment=Alignment.CenterVertically,
        ) {
            Button(
                onClick={showImportFormats=true},
                enabled=!state.busy,
                modifier=Modifier.weight(1f).heightIn(min=52.dp),
                shape=RoundedCornerShape(14.dp),
                contentPadding=PaddingValues(horizontal=8.dp,vertical=12.dp),
                colors=ButtonDefaults.buttonColors(
                    containerColor=p.panel,contentColor=p.ink,
                    disabledContainerColor=p.panel,disabledContentColor=p.subdued),
            ) {
                Icon(Icons.Outlined.FileUpload,null,modifier=Modifier.size(20.dp))
                Spacer(Modifier.width(6.dp))
                Text(txt("import_file",state.language),
                    fontSize=13.sp,maxLines=2,lineHeight=16.sp,
                    textAlign=TextAlign.Center)
            }
            Button(
                onClick={state.showTextDecoder=!state.showTextDecoder},
                enabled=!state.busy,
                modifier=Modifier.weight(1f).heightIn(min=52.dp),
                shape=RoundedCornerShape(14.dp),
                contentPadding=PaddingValues(horizontal=8.dp,vertical=12.dp),
                colors=ButtonDefaults.buttonColors(
                    containerColor=if(state.showTextDecoder)p.raised else p.panel,
                    contentColor=p.ink,disabledContainerColor=p.panel,
                    disabledContentColor=p.subdued),
            ) {
                Icon(Icons.Outlined.DataObject,null,modifier=Modifier.size(20.dp))
                Spacer(Modifier.width(6.dp))
                Text(txt("decode_text",state.language),
                    fontSize=13.sp,maxLines=2,lineHeight=16.sp,
                    textAlign=TextAlign.Center)
            }
        }
        if(state.showTextDecoder) {
            var input by remember { mutableStateOf("") }
            Surface(
                modifier=Modifier.fillMaxWidth(),
                shape=RoundedCornerShape(15.dp),
                color=p.panel,
                border=BorderStroke(1.dp,Color(0xFF303030)),
            ) {
                Column(
                    modifier=Modifier.padding(12.dp),
                    verticalArrangement=Arrangement.spacedBy(9.dp),
                ) {
                    OutlinedTextField(value=input,
                        onValueChange={if(it.length<=250_000)input=it},
                        label={Text(txt("paste_text",state.language))},
                        modifier=Modifier.fillMaxWidth(),
                        minLines=3,maxLines=7,
                        enabled=!state.busy,
                        shape=RoundedCornerShape(12.dp))
                    Button(
                        enabled=input.isNotBlank()&&!state.busy,
                        onClick={if(input.isNotBlank())action.decodeText(input)},
                        modifier=Modifier.fillMaxWidth().heightIn(min=44.dp),
                        shape=RoundedCornerShape(12.dp),
                        colors=ButtonDefaults.buttonColors(
                            containerColor=Color(0xFFF1F1F1),
                            contentColor=Color(0xFF111111)),
                    ) {
                        Icon(Icons.Outlined.DataObject,null,modifier=Modifier.size(17.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(txt("decode_text",state.language),fontSize=14.sp)
                    }
                    SmallCaption(txt("text_support",state.language),p)
                }
            }
        }
        if(showImportFormats) AlertDialog(
            onDismissRequest={showImportFormats=false},
            title={Text(txt("import_config",state.language))},
            text={Text(txt("import_description",state.language)+
                "\n\n.hc · .ehi · .nm · .npv · .npvs · .npvt · .npv4* · .dark · .dt · .hat")},
            confirmButton={TextButton(onClick={showImportFormats=false;action.importFile()}){
                Text(txt("import_file",state.language))
            }},
            dismissButton={TextButton(onClick={showImportFormats=false}){
                Text(txt("cancel",state.language))
            }},
            containerColor=p.panel,
        )
        Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically){
            Text(txt("result",state.language),color=p.ink,fontWeight=FontWeight.Bold,
                fontSize=18.sp,modifier=Modifier.weight(1f))
            if(state.result!=null) {
                IconButton(onClick={OfflineConfirmBus.current?.clearResult?.invoke()},enabled=!state.busy,
                    modifier=Modifier.size(42.dp)) {
                    Icon(Icons.Outlined.DeleteOutline,
                        contentDescription=txt("delete",state.language),
                        tint=if(state.busy)p.subdued else p.ink,modifier=Modifier.size(21.dp))
                }
            }
        }
        ResultCard(state,action,p)
        Row(verticalAlignment=Alignment.CenterVertically){
            Icon(Icons.Outlined.Lock,null,tint=p.subdued,modifier=Modifier.size(15.dp))
            Spacer(Modifier.width(8.dp))
            Text(txt("offline_footer",state.language),fontSize=12.sp,color=p.subdued)
        }
        if(!state.message.isNullOrEmpty()) {
            SmallCaption(state.message.orEmpty(),p)
        }
        val recent=remember(state.history,state.result) {
            val current=state.result
            (if(current==null) state.history
                else state.history.filter{it.json!=current}).take(3)
        }
        if(recent.isNotEmpty()){
            Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically){
                Text(txt("recent",state.language),fontWeight=FontWeight.SemiBold,color=p.ink,
                    modifier=Modifier.weight(1f))
                TextButton(onClick={state.tab=1}){ Text(txt("history",state.language)) }
            }
            recent.forEach{item->
                Row(
                    modifier=Modifier.fillMaxWidth().clickable{action.selectHistory(item)}
                        .padding(vertical=8.dp),
                    verticalAlignment=Alignment.CenterVertically,
                ){
                    Icon(Icons.Outlined.InsertDriveFile,null,tint=p.subdued)
                    Spacer(Modifier.width(10.dp))
                    Text(item.filename,color=p.ink,modifier=Modifier.weight(1f),
                        maxLines=1,overflow=TextOverflow.Ellipsis)
                    Icon(Icons.Outlined.KeyboardArrowRight,null,tint=p.subdued)
                }
            }
        }
    }
}

/** Result card shaped like the online CompleteResultCard. */
@Composable
private fun ResultCard(state:OfflineUiState,action:OfflineActions,p:OfflinePalette) {
    Surface(
        modifier=Modifier.fillMaxWidth(),
        shape=RoundedCornerShape(17.dp),
        color=Color.Black,
        border=BorderStroke(1.dp,p.edge),
    ) {
        Column(modifier=Modifier.padding(16.dp),
            verticalArrangement=Arrangement.spacedBy(14.dp)) {
            if(state.busy) {
                LinearProgressIndicator(modifier=Modifier.fillMaxWidth(),color=p.ink)
                SmallCaption(txt("decrypting",state.language),p)
            } else if(state.result==null) {
                Column(Modifier.fillMaxWidth().padding(vertical=18.dp),horizontalAlignment=Alignment.CenterHorizontally) {
                    Icon(Icons.Outlined.DataObject,null,tint=p.subdued,modifier=Modifier.size(30.dp))
                    Spacer(Modifier.height(8.dp))
                    SmallCaption(txt("no_result",state.language),p)
                }
            } else {
                Row(verticalAlignment=Alignment.CenterVertically) {
                    Icon(Icons.Outlined.DataObject,null,tint=p.subdued,
                        modifier=Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Column(Modifier.weight(1f)) {
                        Text(state.fileName?:txt("result",state.language),
                            color=p.ink,fontSize=14.sp,fontWeight=FontWeight.SemiBold,
                            maxLines=1,overflow=TextOverflow.Ellipsis)
                        Text(state.extension.uppercase()+" · JSON",
                            color=p.subdued,fontSize=12.sp)
                    }
                }
                Column(verticalArrangement=Arrangement.spacedBy(4.dp)) {
                    Text("// "+txt("decode_success",state.language)+" · SP-DECODE",
                        color=p.subdued,fontSize=12.sp,lineHeight=17.sp,
                        style=TextStyle(textDirection=TextDirection.Ltr))
                    Text("// "+txt("splash_powered_by",state.language),
                        color=p.subdued,fontSize=12.sp,lineHeight=17.sp,
                        style=TextStyle(textDirection=TextDirection.Ltr))
                }
                HorizontalDivider(color=p.edge)
                CompleteJsonViewer(state.result.orEmpty(),p,state.language)
                Row(horizontalArrangement=Arrangement.spacedBy(10.dp)) {
                    val buttons=ButtonDefaults.buttonColors(
                        containerColor=p.panel,contentColor=p.ink,
                        disabledContainerColor=p.panel,disabledContentColor=p.subdued)
                    Button(onClick=action.copyResult,enabled=!state.busy,
                        modifier=Modifier.weight(1f),colors=buttons,
                        shape=RoundedCornerShape(11.dp)) {
                        Icon(Icons.Outlined.ContentCopy,null,tint=p.ink,
                            modifier=Modifier.size(17.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(txt("copy",state.language),color=p.ink,fontSize=13.sp)
                    }
                    Button(onClick=action.exportResult,enabled=!state.busy,
                        modifier=Modifier.weight(1f),colors=buttons,
                        shape=RoundedCornerShape(11.dp)) {
                        Icon(Icons.Outlined.FileDownload,null,tint=p.ink,
                            modifier=Modifier.size(17.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(txt("export",state.language),color=p.ink,fontSize=13.sp)
                    }
                }
            }
        }
    }
}

/** JSON syntax colors, same as the online result view (ContinuousJsonView):
 * keys blue, strings green, numbers orange, booleans purple, null pink,
 * punctuation white. The document is pretty-printed, so each value sits on
 * its own line: one cheap pass per line, no full-document parse. */
private fun highlightJson(content:String,ink:Color):AnnotatedString {
    val key=Color(0xFF7CB7F9)
    val str=Color(0xFF98D9A0)
    val num=Color(0xFFE8B66D)
    val bool=Color(0xFFC9A0F3)
    val nul=Color(0xFFE7A5B4)
    return buildAnnotatedString {
        content.split('\n').forEachIndexed { index,line ->
            if(index>0) append("\n")
            highlightJsonLine(line,ink,key,str,num,bool,nul)
        }
    }
}

private fun AnnotatedString.Builder.highlightJsonLine(line:String,ink:Color,
    key:Color,str:Color,num:Color,bool:Color,nul:Color) {
    var i=0
    while(i<line.length && line[i]==' ') i++
    if(i>0) withStyle(SpanStyle(color=ink)) { append(line.substring(0,i)) }
    if(i>=line.length) return
    val rest=line.substring(i)
    if(rest.startsWith('"')) {
        val end=jsonStringEnd(rest,0)
        var j=end
        while(j<rest.length && rest[j]==' ') j++
        if(j<rest.length && rest[j]==':') {
            withStyle(SpanStyle(color=key)) { append(rest.substring(0,end)) }
            var k=j+1
            while(k<rest.length && rest[k]==' ') k++
            withStyle(SpanStyle(color=ink)) { append(rest.substring(end,k)) }
            appendJsonValue(rest.substring(k),ink,str,num,bool,nul)
            return
        }
    }
    appendJsonValue(rest,ink,str,num,bool,nul)
}

private fun AnnotatedString.Builder.appendJsonValue(value:String,ink:Color,
    str:Color,num:Color,bool:Color,nul:Color) {
    if(value.isEmpty()) return
    when {
        value.startsWith('"') -> {
            val end=jsonStringEnd(value,0).coerceAtLeast(1)
            withStyle(SpanStyle(color=str)) { append(value.substring(0,end)) }
            if(end<value.length) withStyle(SpanStyle(color=ink)) { append(value.substring(end)) }
        }
        value.startsWith("true") -> {
            withStyle(SpanStyle(color=bool)) { append("true") }
            if(value.length>4) withStyle(SpanStyle(color=ink)) { append(value.substring(4)) }
        }
        value.startsWith("false") -> {
            withStyle(SpanStyle(color=bool)) { append("false") }
            if(value.length>5) withStyle(SpanStyle(color=ink)) { append(value.substring(5)) }
        }
        value.startsWith("null") -> {
            withStyle(SpanStyle(color=nul)) { append("null") }
            if(value.length>4) withStyle(SpanStyle(color=ink)) { append(value.substring(4)) }
        }
        value[0].isDigit() || value[0]=='-' -> {
            var e=0
            while(e<value.length && (value[e].isDigit() || value[e] in ".eE+-")) e++
            withStyle(SpanStyle(color=num)) { append(value.substring(0,e)) }
            if(e<value.length) withStyle(SpanStyle(color=ink)) { append(value.substring(e)) }
        }
        else -> withStyle(SpanStyle(color=ink)) { append(value) }
    }
}

/** Index just past the closing quote of the JSON string starting at [from]
 * (honors backslash escapes); the string length if unterminated. */
private fun jsonStringEnd(s:String,from:Int):Int {
    var i=from+1
    while(i<s.length) {
        when(s[i]) {
            '\\' -> i+=2
            '"' -> return i+1
            else -> i++
        }
    }
    return s.length
}

@Composable
private fun CompleteJsonViewer(content:String,p:OfflinePalette,language:String) {
    val numberCount=remember(content) { content.count { it=='\n' } + 1 }
    val highlighted=remember(content) { highlightJson(content,p.ink) }
    val gutter=remember(numberCount) { (1..numberCount).joinToString("\n") }
    val rowScroll=rememberScrollState()
    // Height is measured from actual font scale. Up to 150 rows fit without
    // blank padding; the original, complete document remains vertically scrollable.
    val maxRows=numberCount.coerceAtMost(150)
    val viewportHeight=with(LocalDensity.current) {
        (18.sp.toPx()*maxRows + 14.dp.toPx()).toDp()
    }
    Box(Modifier.fillMaxWidth().heightIn(max=viewportHeight)
        .verticalScroll(rememberScrollState())) {
        Row(Modifier.horizontalScroll(rowScroll)) {
            Text(gutter,color=p.subdued,modifier=Modifier.background(p.raised)
                .padding(start=7.dp,end=9.dp,top=7.dp,bottom=7.dp),
                fontFamily=FontFamily.Monospace,fontSize=11.sp,lineHeight=18.sp,
                softWrap=false)
            SelectionContainer {
                Text(highlighted,modifier=Modifier.padding(7.dp),
                    fontFamily=FontFamily.Monospace,fontSize=11.sp,
                    lineHeight=18.sp,softWrap=false)
            }
        }
    }
    SmallCaption(txt("json_selectable",language),p)
}

@Composable
private fun History(state:OfflineUiState,action:OfflineActions,p:OfflinePalette) {
    var selecting by remember { mutableStateOf(false) }
    val selected = remember { mutableStateListOf<String>() }
    var deletion by remember { mutableStateOf<Set<String>?>(null) }
    var query by rememberSaveable { mutableStateOf("") }
    var format by rememberSaveable { mutableStateOf<String?>(null) }
    var favoritesOnly by rememberSaveable { mutableStateOf(false) }
    var sort by rememberSaveable { mutableStateOf("newest") }
    var formatMenu by remember { mutableStateOf(false) }
    var sortMenu by remember { mutableStateOf(false) }
    val formats = state.history.map { it.extension }.distinct().sorted()
    val filtered = state.history.filter {
        (!favoritesOnly||it.favorite) &&
        (format==null||it.extension==format) &&
        (query.isBlank()||it.filename.contains(query,true)||
            it.extension.contains(query,true))
    }
    val visible = when(sort){
        "oldest" -> filtered.sortedBy{it.created}
        "name" -> filtered.sortedBy{it.filename.lowercase()}
        else -> filtered.sortedByDescending{it.created}
    }
    val visibleIds = visible.map { it.id }.toSet()
    LaunchedEffect(state.history.map { it.id }) {
        selected.retainAll(state.history.map { it.id }.toSet())
        if (state.history.isEmpty()) selecting = false
    }
    LazyColumn(
        modifier=Modifier.fillMaxSize(),
        verticalArrangement=Arrangement.spacedBy(12.dp),
        contentPadding=PaddingValues(horizontal=20.dp,vertical=16.dp),
    ) {
        item {
            Row(verticalAlignment=Alignment.CenterVertically) {
                IconButton(onClick={state.tab=0},modifier=Modifier.size(42.dp)) {
                    Icon(Icons.Outlined.ArrowBack,txt("home",state.language),tint=p.ink,
                        modifier=Modifier.size(21.dp))
                }
                Text(txt("history",state.language),color=p.ink,
                    fontSize=24.sp,fontWeight=FontWeight.Bold,
                    modifier=Modifier.weight(1f))
                if(state.history.isNotEmpty()) TextButton(onClick={
                    selecting=!selecting;selected.clear()
                }) { Text(txt(if(selecting)"cancel" else "select",state.language)) }
            }
        }
        item { Text(txt("history_subtitle",state.language),color=p.subdued,fontSize=13.sp) }
        if(state.history.isNotEmpty()) {
            item {
                OutlinedTextField(
                    value=query,onValueChange={query=it},
                    modifier=Modifier.fillMaxWidth(),
                    singleLine=true,shape=RoundedCornerShape(14.dp),
                    label={Text(txt("search",state.language))},
                    leadingIcon={Icon(Icons.Outlined.Search,null)},
                    trailingIcon={
                        if(query.isNotEmpty()) IconButton(onClick={query=""}) {
                            Icon(Icons.Outlined.Close,txt("cancel",state.language))
                        }
                    },
                )
            }
            item {
                FlowRow(
                    horizontalArrangement=Arrangement.spacedBy(7.dp),
                    verticalArrangement=Arrangement.spacedBy(5.dp),
                    modifier=Modifier.fillMaxWidth()) {
                    FilterChip(selected=favoritesOnly,onClick={favoritesOnly=!favoritesOnly},
                        label={Text(txt("favorites",state.language))},
                        leadingIcon={Icon(Icons.Outlined.StarBorder,null,
                            modifier=Modifier.size(16.dp))})
                    Box {
                        OutlinedButton(onClick={formatMenu=true},
                            contentPadding=PaddingValues(horizontal=10.dp)) {
                            Text(format?.let{"." + it}?:txt("all_formats",state.language),
                                fontSize=12.sp)
                            Icon(Icons.Outlined.ArrowDropDown,null)
                        }
                        DropdownMenu(expanded=formatMenu,onDismissRequest={formatMenu=false},
                            containerColor=p.panel) {
                            DropdownMenuItem(
                                text={Text(txt("all_formats",state.language))},
                                onClick={format=null;formatMenu=false})
                            formats.forEach { extension ->
                                DropdownMenuItem(text={Text("." + extension)},
                                    onClick={format=extension;formatMenu=false})
                            }
                        }
                    }
                    Box {
                        OutlinedButton(onClick={sortMenu=true},
                            contentPadding=PaddingValues(horizontal=10.dp)) {
                            Icon(Icons.Outlined.Sort,null,modifier=Modifier.size(15.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(txt("sort",state.language),fontSize=12.sp)
                        }
                        DropdownMenu(expanded=sortMenu,onDismissRequest={sortMenu=false},
                            containerColor=p.panel) {
                            listOf(
                                "newest" to "sort_newest",
                                "oldest" to "sort_oldest",
                                "name" to "sort_name",
                            ).forEach { (value,key) ->
                                DropdownMenuItem(text={Text(txt(key,state.language))},
                                    onClick={sort=value;sortMenu=false})
                            }
                        }
                    }
                }
            }
            item {
                Text(txt("history_matches",state.language).format(visible.size),
                    color=p.subdued,fontSize=12.sp)
            }
        }
        if(state.history.isEmpty()) {
            item { OfflineCard(p) { SmallCaption(txt("history_empty",state.language),p) } }
        } else {
            if(selecting) item {
                Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically) {
                    TextButton(onClick={
                        if(visibleIds.isNotEmpty() &&
                            visibleIds.all{it in selected}) {
                            selected.removeAll(visibleIds)
                        } else selected.addAll(visibleIds.filterNot{it in selected})
                    }) {
                        Text(txt(if(visibleIds.isNotEmpty() &&
                            visibleIds.all{it in selected})"deselect_all" else "select_all",
                            state.language))
                    }
                    Spacer(Modifier.weight(1f))
                    Text(txt("selected_count",state.language).format(selected.size),
                        color=p.subdued,fontSize=12.sp)
                }
            }
            items(visible,key={it.id}) { item ->
                val checked=item.id in selected
                Surface(color=p.panel,shape=RoundedCornerShape(14.dp),
                    modifier=Modifier.fillMaxWidth().clickable {
                        if(selecting) {
                            if(checked) selected.remove(item.id) else selected.add(item.id)
                        } else action.selectHistory(item)
                    }) {
                    Row(Modifier.padding(horizontal=12.dp,vertical=12.dp),
                        verticalAlignment=Alignment.CenterVertically) {
                        if(selecting) Checkbox(checked=checked,onCheckedChange={
                            if(it && !checked)selected.add(item.id)
                            else if(!it)selected.remove(item.id)
                        }) else Icon(Icons.Outlined.InsertDriveFile,null,tint=p.ink)
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(item.filename,color=p.ink,maxLines=1,
                                overflow=TextOverflow.Ellipsis)
                            Text(".${item.extension} · "+DateFormat.getDateTimeInstance(
                                DateFormat.SHORT,DateFormat.SHORT).format(Date(item.created)),
                                color=p.subdued,fontSize=12.sp)
                        }
                        if(!selecting) {
                            IconButton(onClick={action.favoriteHistory(item)}) {
                                Icon(if(item.favorite)Icons.Outlined.Star else Icons.Outlined.StarBorder,
                                    txt("favorites",state.language),
                                    tint=if(item.favorite)p.amber else p.subdued)
                            }
                            IconButton(onClick={
                                OfflineConfirmBus.current?.deleteHistory?.invoke(item)
                            }) {
                                Icon(Icons.Outlined.DeleteOutline,
                                    txt("delete",state.language),tint=p.subdued)
                            }
                        }
                    }
                }
            }
            item {
                if(selecting) Button(
                    onClick={deletion=selected.toSet()},
                    enabled=selected.isNotEmpty(),modifier=Modifier.fillMaxWidth()) {
                    Icon(Icons.Outlined.DeleteOutline,null)
                    Spacer(Modifier.width(8.dp))
                    Text(txt("delete_selected",state.language))
                } else OutlinedButton(onClick={
                    OfflineConfirmBus.current?.clearHistory?.invoke()
                },modifier=Modifier.fillMaxWidth()) {
                    Icon(Icons.Outlined.DeleteOutline,null)
                    Spacer(Modifier.width(8.dp))
                    Text(txt("clear_history",state.language))
                }
            }
        }
    }
    if(deletion!=null) AlertDialog(
        onDismissRequest={deletion=null},
        title={Text(txt("delete_history",state.language))},
        text={Text(if(deletion!!.size==1) txt("delete_history_warning",state.language)
            else txt("delete_selected_confirm",state.language).format(deletion!!.size))},
        confirmButton={TextButton(onClick={
            val ids=deletion.orEmpty()
            deletion=null;selected.clear();selecting=false
            if(ids.isNotEmpty()) action.deleteSelected(ids)
        }){ Text(txt(if(deletion!!.size==1)"delete" else "delete_selected",state.language)) }},
        dismissButton={TextButton(onClick={deletion=null}){
            Text(txt("cancel",state.language))
        }},
        containerColor=p.panel,
    )
}

@Composable
private fun Settings(state:OfflineUiState,action:OfflineActions,p:OfflinePalette) {
    Column(
        modifier=Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal=20.dp,vertical=11.dp),
        verticalArrangement=Arrangement.spacedBy(14.dp),
    ) {
        Row(verticalAlignment=Alignment.CenterVertically) {
            IconButton(onClick={state.settingsOpen=false}) {
                Icon(Icons.Outlined.ArrowBack,txt("settings",state.language),tint=p.ink)
            }
            Text(txt("settings",state.language),color=p.ink,fontWeight=FontWeight.SemiBold,fontSize=21.sp)
        }
        OfflineCard(p) {
            Section(txt("language",state.language),p)
            var expanded by remember { mutableStateOf(false) }
            OutlinedButton(onClick={expanded=true},modifier=Modifier.fillMaxWidth()) {
                Text(languageLabel(state.language),modifier=Modifier.weight(1f))
                Icon(Icons.Outlined.ArrowDropDown,null)
            }
            DropdownMenu(expanded=expanded,onDismissRequest={expanded=false}) {
                supportedOfflineLanguages.forEach { (value,name) ->
                    DropdownMenuItem(text={Text(name)},onClick={
                        action.setLanguage(value);expanded=false
                    })
                }
            }
        }
        OfflineCard(p) {
            Section(txt("npv_identity",state.language),p)
            val identity=remember(state.identity) {
                try { state.identity?.let(::JSONObject) } catch (_:Exception) { null }
            }
            if(identity==null) {
                SmallCaption(txt("identity_missing",state.language),p)
            } else {
                val publicKey=identity.optString("publicKey")
                val privateKey=identity.optString("privateKey")
                val fingerprint=identity.optString("fingerprint")
                SmallCaption(txt("identity_saved",state.language),p)
                Text("Public Key",color=p.ink,fontWeight=FontWeight.SemiBold)
                SelectionContainer {
                    Text(publicKey,color=p.subdued,fontSize=11.sp,
                        fontFamily=FontFamily.Monospace)
                }
                TextButton(onClick={action.copyValue(publicKey)}) {
                    Text(txt("copy_public",state.language))
                }
                var reveal by remember(state.identity) { mutableStateOf(false) }
                Row(verticalAlignment=Alignment.CenterVertically) {
                    Text("Private Key",modifier=Modifier.weight(1f),color=p.ink,
                        fontWeight=FontWeight.SemiBold)
                    IconButton(onClick={reveal=!reveal}) {
                        Icon(if(reveal)Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                            txt("reveal",state.language),tint=p.subdued)
                    }
                }
                if(reveal) {
                    SelectionContainer {
                        Text(privateKey,color=p.subdued,fontSize=11.sp,
                            fontFamily=FontFamily.Monospace)
                    }
                    TextButton(onClick={action.copyValue(privateKey)}) {
                        Text(txt("copy_private",state.language))
                    }
                } else SmallCaption("••••••••••••••••••••••••••",p)
                Text("Fingerprint",fontWeight=FontWeight.SemiBold,color=p.ink)
                SelectionContainer { Text(fingerprint,color=p.subdued,fontSize=11.sp) }
            }
            PrimaryButton(txt("generate_identity",state.language),p,!state.busy,action.createIdentity)
            Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick=action.importIdentity,modifier=Modifier.weight(1f)) {
                    Text(txt("import",state.language))
                }
                OutlinedButton(onClick=action.exportIdentity,
                    enabled=identity!=null,modifier=Modifier.weight(1f)) {
                    Text(txt("export",state.language))
                }
            }
            if(identity!=null) TextButton(onClick={
                OfflineConfirmBus.current?.deleteIdentity?.invoke()
            }) { Text(txt("delete_identity",state.language)) }
            SmallCaption(txt("identity_warning",state.language),p)
        }
        OfflineCard(p) {
            Section(txt("security",state.language),p)
            SmallCaption(txt("security_info",state.language),p)
        }
        OutlinedButton(onClick={state.aboutOpen=true},modifier=Modifier.fillMaxWidth()) {
            Icon(Icons.Outlined.Info,null)
            Spacer(Modifier.width(9.dp))
            Text(txt("about",state.language),modifier=Modifier.weight(1f))
            Icon(Icons.Outlined.ChevronRight,null)
        }
        if(!state.message.isNullOrBlank()) SmallCaption(state.message.orEmpty(),p)
    }
}

@Composable
private fun About(state:OfflineUiState,action:OfflineActions,p:OfflinePalette) {
    Column(
        modifier=Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal=20.dp,vertical=11.dp),
        verticalArrangement=Arrangement.spacedBy(14.dp),
    ) {
        Row(verticalAlignment=Alignment.CenterVertically) {
            IconButton(onClick={state.aboutOpen=false}) {
                Icon(Icons.Outlined.ArrowBack,txt("settings",state.language),tint=p.ink)
            }
            Text(txt("about",state.language),color=p.ink,fontWeight=FontWeight.SemiBold,fontSize=21.sp)
        }
        OfflineCard(p) {
            Column(Modifier.fillMaxWidth(),horizontalAlignment=Alignment.CenterHorizontally) {
                Image(painter=painterResource(com.ghostdeveloper.spdecode.R.drawable.offline_launcher_foreground),
                    contentDescription="SP-DECODE Offline",modifier=Modifier.size(72.dp))
                Text("SP-DECODE Offline",color=p.ink,fontSize=23.sp,fontWeight=FontWeight.Bold)
                SmallCaption(txt("native_edition",state.language),p)
                Text(com.ghostdeveloper.spdecode.BuildConfig.VERSION_NAME,color=p.subdued,fontSize=12.sp)
            }
        }
        OfflineCard(p) {
            Section(txt("developer",state.language),p)
            Text("Ghost Developer · @Gh0stDeveloper",color=p.ink,
                fontSize=16.sp,fontWeight=FontWeight.SemiBold)
            Text("Ghost Nexora Studio",color=p.subdued,fontSize=13.sp)
            SmallCaption(txt("developer_credit",state.language),p)
        }
        OfflineCard(p) {
            Section(txt("community",state.language),p)
            OutlinedButton(onClick={action.openUrl("https://t.me/GhostDeve")},
                modifier=Modifier.fillMaxWidth()) {
                Icon(Icons.Outlined.Send,null)
                Spacer(Modifier.width(8.dp))
                Text(txt("telegram_channel",state.language))
            }
            OutlinedButton(onClick={action.openUrl("https://t.me/+Ntu6EJMirrAwMzgx")},
                modifier=Modifier.fillMaxWidth()) {
                Icon(Icons.Outlined.PeopleOutline,null)
                Spacer(Modifier.width(8.dp))
                Text(txt("telegram_group",state.language))
            }
        }
        OfflineCard(p) {
            Section(txt("capabilities",state.language),p)
            SmallCaption("HTTP Custom · HTTP Injector · NetMod Syna · NPV Tunnel · Dark Tunnel · Hat Tunnel",p)
            SmallCaption(txt("offline_footer",state.language),p)
        }
    }
}

@Composable
private fun Confirmation(title:String,body:String,p:OfflinePalette,
    onDismiss:()->Unit,onConfirm:()->Unit,language:String) {
    AlertDialog(onDismissRequest=onDismiss,title={Text(title)},
        text={Text(body)},confirmButton={
            TextButton(onClick=onConfirm){Text(txt("confirm",language))}
        },dismissButton={
            TextButton(onClick=onDismiss){Text(txt("cancel",language))}
        },containerColor=p.panel)
}

@Composable
private fun CredentialDialog(prompt:OfflinePrompt,language:String,p:OfflinePalette,
    identityAvailable:Boolean,onDismiss:()->Unit,onRetry:(String,String,String)->Unit) {
    var password by remember(prompt) { mutableStateOf("") }
    var hwid by remember(prompt) { mutableStateOf("") }
    var identity by remember(prompt) { mutableStateOf("") }
    AlertDialog(
        onDismissRequest=onDismiss,
        containerColor=p.panel,
        title={Text(txt("required_details",language))},
        text={
            Column(verticalArrangement=Arrangement.spacedBy(12.dp)) {
                SmallCaption(txt("protected_config",language),p)
                if(prompt.requirePassword) OutlinedTextField(
                    value=password,onValueChange={password=it.take(4096)},
                    modifier=Modifier.fillMaxWidth(),
                    label={Text(txt("password",language))},
                    visualTransformation=PasswordVisualTransformation(),singleLine=true)
                if(prompt.requireHwid) OutlinedTextField(
                    value=hwid,onValueChange={hwid=it.take(128)},
                    modifier=Modifier.fillMaxWidth(),
                    label={Text("HWID")},singleLine=true)
                if(prompt.requireIdentity) {
                    val wrongIdentity=prompt.errorMessage in setOf("RECIPIENT_MISMATCH","NPV_RECIPIENT_MISMATCH")
                    SmallCaption(if(wrongIdentity)txt("recipient_mismatch_help",language)
                        else txt("identity_original_help",language),p)
                    OutlinedTextField(value=identity,
                        onValueChange={identity=it.take(16000)},
                        label={Text(txt("identity_manual",language))},
                        modifier=Modifier.fillMaxWidth(),
                        minLines=2,maxLines=4)
                }
            }
        },
        confirmButton={
            TextButton(
                enabled=(!prompt.requirePassword||password.isNotEmpty())&&
                    (!prompt.requireHwid||hwid.isNotEmpty())&&
                    (!prompt.requireIdentity||identity.isNotBlank()||
                        (identityAvailable && prompt.errorMessage=="PRIVATE_KEY_REQUIRED")),
                onClick={onRetry(password,hwid,identity)}
            ){ Text(txt("retry",language)) }
        },
        dismissButton={TextButton(onClick=onDismiss){Text(txt("cancel",language))}}
    )
}
