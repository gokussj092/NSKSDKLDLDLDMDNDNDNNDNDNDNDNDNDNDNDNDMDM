package com.ghostdeveloper.spdecode.offline

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date

internal class OfflineUiState {
    var tab by mutableIntStateOf(0)
    var theme by mutableStateOf("amoled")
    var language by mutableStateOf("system")
    var fileName by mutableStateOf<String?>(null)
    var extension by mutableStateOf("")
    var result by mutableStateOf<String?>(null)
    var busy by mutableStateOf(false)
    var message by mutableStateOf<String?>(null)
    var history by mutableStateOf<List<OfflineRecord>>(emptyList())
    var identity by mutableStateOf<String?>(null)
    var pendingPrompt by mutableStateOf<OfflinePrompt?>(null)
    var showTextDecoder by mutableStateOf(false)
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
    val clearHistory: () -> Unit,
    val favoriteHistory: (OfflineRecord) -> Unit,
    val createIdentity: () -> Unit,
    val importIdentity: () -> Unit,
    val exportIdentity: () -> Unit,
    val deleteIdentity: () -> Unit,
    val copyValue: (String) -> Unit,
    val setTheme: (String) -> Unit,
    val setLanguage: (String) -> Unit,
    val openUrl: (String) -> Unit,
)

private data class OfflinePalette(
    val bg: Color, val panel: Color, val raised: Color,
    val line: Color, val primary: Color, val ink: Color,
    val subdued: Color, val onPrimary: Color
)

private fun palette(mode: String) = when (mode) {
    "dark" -> OfflinePalette(Color(0xFF111316), Color(0xFF1C2026),
        Color(0xFF292F36), Color(0xFF39414A), Color(0xFF80BBFF),
        Color(0xFFF3F6FB), Color(0xFFADB8C5), Color(0xFF071B34))
    "light" -> OfflinePalette(Color(0xFFF8F9FB), Color.White,
        Color(0xFFF0F3F8), Color(0xFFD9DEE8), Color(0xFF176F8B),
        Color(0xFF17232E), Color(0xFF667585), Color.White)
    else -> OfflinePalette(Color.Black, Color(0xFF10191B),
        Color(0xFF1B2C2F), Color(0xFF283A3D), Color(0xFF38DCC3),
        Color(0xFFF5FFFD), Color(0xFF9BAFB0), Color(0xFF061415))
}

@Composable
internal fun OfflineScreen(state: OfflineUiState, action: OfflineActions) {
    val theme = palette(state.theme)
    val scheme = if (state.theme == "light") lightColorScheme(
        primary=theme.primary,onPrimary=theme.onPrimary,
        background=theme.bg,onBackground=theme.ink,
        surface=theme.panel,onSurface=theme.ink,
        surfaceVariant=theme.raised,onSurfaceVariant=theme.subdued,
        outline=theme.line,
    ) else darkColorScheme(
        primary=theme.primary,onPrimary=theme.onPrimary,
        background=theme.bg,onBackground=theme.ink,
        surface=theme.panel,onSurface=theme.ink,
        surfaceVariant=theme.raised,onSurfaceVariant=theme.subdued,
        outline=theme.line,
    )
    MaterialTheme(colorScheme=scheme) {
        Scaffold(
            containerColor=theme.bg,
            bottomBar={
                NavigationBar(containerColor=theme.panel,
                    contentColor=theme.ink) {
                    val titles=listOf("home","history","settings","about")
                    val icons=listOf(
                        Icons.Outlined.Home,Icons.Outlined.History,
                        Icons.Outlined.Settings,Icons.Outlined.Info,
                    )
                    titles.forEachIndexed { index,key ->
                        NavigationBarItem(
                            selected=state.tab==index,
                            onClick={state.tab=index},
                            icon={Icon(icons[index],contentDescription=txt(key,state.language))},
                            label={Text(txt(key,state.language),fontSize=10.sp)},
                            colors=NavigationBarItemDefaults.colors(
                                selectedIconColor=theme.onPrimary,
                                selectedTextColor=theme.primary,
                                indicatorColor=theme.primary,
                                unselectedIconColor=theme.subdued,
                                unselectedTextColor=theme.subdued,
                            )
                        )
                    }
                }
            },
        ) { insets ->
            Column(
                modifier=Modifier.fillMaxSize()
                    .padding(insets)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal=17.dp,vertical=15.dp),
                verticalArrangement=Arrangement.spacedBy(14.dp)
            ) {
                when(state.tab) {
                    0 -> Home(state,action,theme)
                    1 -> History(state,action,theme)
                    2 -> Settings(state,action,theme)
                    else -> About(state,action,theme)
                }
                Spacer(Modifier.height(6.dp))
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

@Composable
private fun Header(title:String,caption:String?,p:OfflinePalette) {
    Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically) {
        Icon(Icons.Outlined.Shield,prefixA11y(),tint=p.primary,modifier=Modifier.size(26.dp))
        Spacer(Modifier.width(9.dp))
        Column(Modifier.weight(1f)) {
            Text(title,fontSize=22.sp,fontWeight=FontWeight.Bold,color=p.ink)
            if(caption!=null) Text(caption,fontSize=12.sp,color=p.subdued)
        }
    }
}
private fun prefixA11y() = "SP-DECODE"

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
    Header("SP-DECODE Offline",txt("subtitle",state.language),p)
    OfflineCard(p) {
        Row(verticalAlignment=Alignment.CenterVertically) {
            Icon(Icons.Outlined.FolderOpen,null,tint=p.primary)
            Spacer(Modifier.width(8.dp))
            Section(txt("import_config",state.language),p)
        }
        SmallCaption(txt("import_description",state.language),p)
        PrimaryButton(txt("import_file",state.language),p,!state.busy,action.importFile)
        SmallCaption(".hc · .ehi · .nm · .npv · .npvs · .npvt · .npv4*",p)
        OutlinedButton(onClick={state.showTextDecoder=!state.showTextDecoder},
            enabled=!state.busy,modifier=Modifier.fillMaxWidth(),
            shape=RoundedCornerShape(13.dp),
            border=BorderStroke(1.dp,p.line)) {
            Icon(Icons.Outlined.Code,null)
            Spacer(Modifier.width(8.dp))
            Text(txt("decode_text",state.language))
        }
        if(state.showTextDecoder) {
            var input by remember { mutableStateOf("") }
            OutlinedTextField(value=input,
                onValueChange={if(it.length<=250_000)input=it},
                label={Text(txt("paste_text",state.language))},
                modifier=Modifier.fillMaxWidth(),
                minLines=3,maxLines=7,
                enabled=!state.busy,
                shape=RoundedCornerShape(12.dp))
            PrimaryButton(txt("decode_text",state.language),p,
                enabled=input.isNotBlank()&&!state.busy) {
                action.decodeText(input)
            }
            SmallCaption(txt("text_support",state.language),p)
        }
    }
    Row(verticalAlignment=Alignment.CenterVertically) {
        Section(txt("result",state.language),p)
        Spacer(Modifier.weight(1f))
        if(state.result!=null) {
            IconButton(onClick=action.copyResult,enabled=!state.busy) {
                Icon(Icons.Outlined.ContentCopy,txt("copy",state.language),tint=p.primary)
            }
            IconButton(onClick=action.exportResult,enabled=!state.busy) {
                Icon(Icons.Outlined.SaveAlt,txt("export",state.language),tint=p.ink)
            }
            IconButton(onClick={OfflineConfirmBus.current?.clearResult?.invoke()},enabled=!state.busy) {
                Icon(Icons.Outlined.DeleteOutline,txt("delete",state.language),tint=p.ink)
            }
        }
    }
    OfflineCard(p) {
        if(state.busy) {
            LinearProgressIndicator(modifier=Modifier.fillMaxWidth(),color=p.primary)
            SmallCaption(txt("decrypting",state.language),p)
        } else if(state.result==null) {
            Column(Modifier.fillMaxWidth().padding(vertical=18.dp),horizontalAlignment=Alignment.CenterHorizontally) {
                Icon(Icons.Outlined.DataObject,null,tint=p.subdued,modifier=Modifier.size(30.dp))
                Spacer(Modifier.height(8.dp))
                SmallCaption(txt("no_result",state.language),p)
            }
        } else {
            Row(verticalAlignment=Alignment.CenterVertically) {
                Icon(Icons.Outlined.Description,null,tint=p.primary)
                Spacer(Modifier.width(8.dp))
                Column {
                    Text(state.fileName?:txt("result",state.language),
                        color=p.ink,fontWeight=FontWeight.Medium,maxLines=1,
                        overflow=TextOverflow.Ellipsis)
                    SmallCaption(state.extension.uppercase()+" · JSON",p)
                }
            }
            HorizontalDivider(color=p.line)
            // Complete source is selectable across lines, with separate aligned
            // line-number gutter. Nothing is truncated or paginated.
            CompleteJsonViewer(state.result.orEmpty(),p)
            Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick=action.copyResult,modifier=Modifier.weight(1f)) {
                    Icon(Icons.Outlined.ContentCopy,null,modifier=Modifier.size(16.dp))
                    Spacer(Modifier.width(5.dp))
                    Text(txt("copy_all",state.language),fontSize=12.sp)
                }
                OutlinedButton(onClick=action.exportResult,modifier=Modifier.weight(1f)) {
                    Icon(Icons.Outlined.SaveAlt,null,modifier=Modifier.size(16.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("JSON",fontSize=12.sp)
                }
            }
        }
    }
    if(!state.message.isNullOrEmpty()) {
        SmallCaption(state.message.orEmpty(),p)
    }
    SmallCaption(txt("offline_footer",state.language),p)
}

@Composable
private fun CompleteJsonViewer(content:String,p:OfflinePalette) {
    val numberCount=remember(content) { content.count { it=='\n' } + 1 }
    val gutter=remember(numberCount) { (1..numberCount).joinToString("\n") }
    val rowScroll=rememberScrollState()
    Box(Modifier.fillMaxWidth().heightIn(max=440.dp)
        .verticalScroll(rememberScrollState())) {
        Row(Modifier.horizontalScroll(rowScroll)) {
            Text(gutter,color=p.subdued,modifier=Modifier.background(p.raised)
                .padding(start=7.dp,end=9.dp,top=7.dp,bottom=7.dp),
                fontFamily=FontFamily.Monospace,fontSize=11.sp,lineHeight=18.sp,
                softWrap=false)
            SelectionContainer {
                Text(content,color=p.ink,modifier=Modifier.padding(7.dp),
                    fontFamily=FontFamily.Monospace,fontSize=11.sp,
                    lineHeight=18.sp,softWrap=false)
            }
        }
    }
    SmallCaption(txt("json_selectable",if(p.bg==Color.White)"es" else "system"),p)
}

@Composable
private fun History(state:OfflineUiState,action:OfflineActions,p:OfflinePalette) {
    Header(txt("history",state.language),txt("history_subtitle",state.language),p)
    var search by remember { mutableStateOf("") }
    var onlyFavorites by remember { mutableStateOf(false) }
    OutlinedTextField(value=search,onValueChange={search=it},
        modifier=Modifier.fillMaxWidth(),singleLine=true,
        label={Text(txt("search",state.language))},
        leadingIcon={Icon(Icons.Outlined.Search,null)})
    Row(verticalAlignment=Alignment.CenterVertically) {
        FilterChip(selected=onlyFavorites,onClick={onlyFavorites=!onlyFavorites},
            label={Text(txt("favorites",state.language))},
            leadingIcon={Icon(Icons.Outlined.StarBorder,null)})
        Spacer(Modifier.weight(1f))
        if(state.history.isNotEmpty()) TextButton(onClick={
            OfflineConfirmBus.current?.clearHistory?.invoke()
        }) { Text(txt("clear_history",state.language)) }
    }
    val visible=state.history.filter {
        (!onlyFavorites||it.favorite) &&
        (search.isBlank()||it.filename.contains(search,true)||
            it.extension.contains(search,true))
    }
    if(visible.isEmpty()) {
        OfflineCard(p) { SmallCaption(txt("history_empty",state.language),p) }
    }
    visible.forEach { item ->
        OfflineCard(p) {
            Row(verticalAlignment=Alignment.CenterVertically) {
                Icon(Icons.Outlined.InsertDriveFile,null,tint=p.primary)
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(item.filename,color=p.ink,maxLines=1,overflow=TextOverflow.Ellipsis,
                        fontWeight=FontWeight.Medium)
                    SmallCaption(".${item.extension} · "+DateFormat.getDateTimeInstance(
                        DateFormat.SHORT,DateFormat.SHORT).format(Date(item.created)),p)
                }
                IconButton(onClick={action.favoriteHistory(item)}) {
                    Icon(if(item.favorite) Icons.Outlined.Star else Icons.Outlined.StarBorder,
                        txt("favorites",state.language),tint=if(item.favorite)p.primary else p.subdued)
                }
                IconButton(onClick={OfflineConfirmBus.current?.deleteHistory?.invoke(item)}) {
                    Icon(Icons.Outlined.DeleteOutline,txt("delete",state.language),tint=p.subdued)
                }
            }
            OutlinedButton(onClick={action.selectHistory(item)},
                modifier=Modifier.fillMaxWidth()) {
                Text(txt("open_result",state.language))
            }
        }
    }
}

@Composable
private fun Settings(state:OfflineUiState,action:OfflineActions,p:OfflinePalette) {
    Header(txt("settings",state.language),null,p)
    OfflineCard(p) {
        Section(txt("appearance",state.language),p)
        val themes=listOf("amoled" to "theme_amoled","dark" to "theme_dark","light" to "theme_light")
        themes.forEach { (value,key) ->
            Row(verticalAlignment=Alignment.CenterVertically) {
                RadioButton(selected=state.theme==value,onClick={action.setTheme(value)})
                Text(txt(key,state.language),color=p.ink)
            }
        }
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
    if(!state.message.isNullOrBlank()) SmallCaption(state.message.orEmpty(),p)
}

@Composable
private fun About(state:OfflineUiState,action:OfflineActions,p:OfflinePalette) {
    Header(txt("about",state.language),null,p)
    OfflineCard(p) {
        Column(Modifier.fillMaxWidth(),horizontalAlignment=Alignment.CenterHorizontally) {
            Icon(Icons.Outlined.Shield,null,tint=p.primary,modifier=Modifier.size(58.dp))
            Text("SP-DECODE Offline",color=p.ink,fontSize=23.sp,fontWeight=FontWeight.Bold)
            SmallCaption(txt("native_edition",state.language),p)
            Text("1.1.25-offline.alpha1",color=p.subdued,fontSize=12.sp)
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
        SmallCaption("HTTP Custom · HTTP Injector · NetMod Syna · NPV Tunnel",p)
        SmallCaption(txt("offline_footer",state.language),p)
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
                    SmallCaption(if(identityAvailable)
                        txt("identity_retry",language) else txt("identity_missing",language),p)
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
                    (!prompt.requireIdentity||identity.isNotBlank()||identityAvailable),
                onClick={onRetry(password,hwid,identity)}
            ){ Text(txt("retry",language)) }
        },
        dismissButton={TextButton(onClick=onDismiss){Text(txt("cancel",language))}}
    )
}
