package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.activity.compose.BackHandler
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.testTag
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import com.ghostdeveloper.spdecode.cloud.CloudTextRoute
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val Pane=Color(0xFF242424)
private val MutedText=Color(0xFFABABAB)
private val TitleText=Color(0xFFF7F7F7)
private val SurfaceLine=Color(0xFF343434)

/** Offline preferences, release information and Telegram-only developer contact. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FunctionalSettingsPanel(
    language:String,
    maskCredentials:Boolean,
    onLanguage:(String)->Unit,
    onMaskCredentials:(Boolean)->Unit,
    onClear:()->Unit,
    onExternalLink:(String)->Unit,
    retentionDays:Int,
    onRetention:(Int)->Unit,
    onShowGuide:()->Unit={},
    onLegalLink:(String)->Unit={},
    onWithdrawConsent:()->Unit={},
    catalogUpdatesEnabled:Boolean=false,
    onCatalogUpdates:(Boolean)->Unit={},
    usageAnalyticsEnabled:Boolean=false,
    onUsageAnalytics:(Boolean)->Unit={},
    supportedFormats:List<AndroidDecoderCatalog.Format> = emptyList(),
    supportedTextFormats:List<CloudTextRoute> = emptyList(),
    catalogLoading:Boolean=false,
    catalogProgress:Int?=null,
){
    var clearDialog by remember { mutableStateOf(false) }
    var languagePage by rememberSaveable { mutableStateOf(false) }
    var formatsPage by rememberSaveable { mutableStateOf(false) }
    var retentionDialog by remember { mutableStateOf(false) }
    var withdrawDialog by remember { mutableStateOf(false) }
    BackHandler(enabled=languagePage || formatsPage) {
        if(formatsPage) formatsPage=false else languagePage=false
    }
    if(languagePage) {
        LanguageSelectionScreen(
            selectedLanguage=language,
            onBack={languagePage=false},
            onSelect={tag->if(language!=tag)onLanguage(tag)},
        )
        return
    }
    if(formatsPage) {
        FormatsScreen(supportedFormats,supportedTextFormats,catalogLoading,catalogProgress,
            onBack={formatsPage=false})
        return
    }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal=20.dp,vertical=12.dp),
        verticalArrangement=Arrangement.spacedBy(14.dp),
    ){
        Text(stringResource(R.string.settings_title),fontSize=24.sp,
            fontWeight=FontWeight.Bold,color=TitleText)

        // One compact row instead of a permanently expanded radio list.
        SettingsCard {
            Row(
                modifier=Modifier.fillMaxWidth().clickable{languagePage=true}
                    .padding(vertical=5.dp),
                verticalAlignment=Alignment.CenterVertically,
            ) {
                Icon(Icons.Outlined.Language,null,tint=TitleText,
                    modifier=Modifier.size(25.dp))
                Spacer(Modifier.width(13.dp))
                Column(modifier=Modifier.weight(1f),
                    verticalArrangement=Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(R.string.language_title),color=TitleText,
                        fontWeight=FontWeight.SemiBold,fontSize=16.sp)
                    val languageName=SupportedLanguages.options
                        .firstOrNull{it.tag==language}?.nativeName.orEmpty()
                    Text(if(language=="system")stringResource(R.string.language_system)
                        else languageName.ifBlank{stringResource(R.string.language_system)},
                        color=MutedText,fontSize=13.sp)
                }
                Icon(Icons.Outlined.ChevronRight,
                    stringResource(R.string.language_title),tint=MutedText)
            }
        }
        SettingsCard {
            Row(
                modifier=Modifier.fillMaxWidth().testTag("settings_formats_entry")
                    .clickable{formatsPage=true}.padding(vertical=5.dp),
                verticalAlignment=Alignment.CenterVertically,
            ) {
                Icon(Icons.Outlined.Code,null,tint=TitleText,modifier=Modifier.size(25.dp))
                Spacer(Modifier.width(13.dp))
                Column(modifier=Modifier.weight(1f),
                    verticalArrangement=Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(R.string.settings_formats_title),
                        color=TitleText,fontWeight=FontWeight.SemiBold,fontSize=16.sp)
                    Text(stringResource(R.string.settings_formats_detail),
                        color=MutedText,fontSize=13.sp)
                }
                Icon(Icons.Outlined.ChevronRight,
                    stringResource(R.string.settings_formats_title),tint=MutedText)
            }
        }
        SettingsCard{
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.Visibility,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.result_preferences_title),
                    color=TitleText,fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            }
            Row(verticalAlignment=Alignment.CenterVertically){
                Column(modifier=Modifier.weight(1f)){
                    Text(stringResource(R.string.mask_passwords_title),color=TitleText)
                    Text(stringResource(R.string.mask_passwords_detail),
                        color=MutedText,fontSize=12.sp,lineHeight=18.sp)
                }
                Switch(
                    checked=maskCredentials,onCheckedChange=onMaskCredentials,
                    colors=SwitchDefaults.colors(checkedThumbColor=Color.Black,
                        checkedTrackColor=TitleText)
                )
            }
            Text(stringResource(R.string.export_security_note),
                color=MutedText,fontSize=12.sp,lineHeight=17.sp)
        }
        SettingsCard{
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.Lock,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.privacy_title),color=TitleText,
                    fontWeight=FontWeight.SemiBold)
            }
            Text(stringResource(R.string.privacy_text),color=MutedText,
                fontSize=13.sp,lineHeight=19.sp)
            Row(
                modifier=Modifier.fillMaxWidth().clickable{retentionDialog=true}
                    .padding(vertical=5.dp),
                verticalAlignment=Alignment.CenterVertically,
            ) {
                Icon(Icons.Outlined.History,null,tint=MutedText,
                    modifier=Modifier.size(21.dp))
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.history_retention),
                        color=TitleText,fontSize=14.sp)
                    Text(if(retentionDays==0)stringResource(R.string.history_keep_forever)
                        else stringResource(R.string.history_keep_days,retentionDays),
                        color=MutedText,fontSize=12.sp)
                }
                Icon(Icons.Outlined.ChevronRight,null,tint=MutedText)
            }
            Text(stringResource(R.string.history_retention_note),
                color=MutedText,fontSize=12.sp,lineHeight=17.sp)
            OutlinedButton(onClick={clearDialog=true},modifier=Modifier.fillMaxWidth()){
                Icon(Icons.Outlined.DeleteOutline,null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.delete_session))
            }
        }
        if(BuildConfig.SPDECODE_CLOUD_ENABLED) SettingsCard {
            Row(verticalAlignment=Alignment.CenterVertically) {
                Icon(Icons.Outlined.Lock,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.cloud_legal_title),color=TitleText,
                    fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            }
            OutlinedButton(onClick={onLegalLink("terms")},
                modifier=Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.cloud_legal_terms))
            }
            OutlinedButton(onClick={onLegalLink("privacy")},
                modifier=Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.cloud_legal_privacy))
            }
            OutlinedButton(onClick={withdrawDialog=true},
                modifier=Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.cloud_legal_withdraw))
            }
        }
        if(BuildConfig.SPDECODE_CLOUD_ENABLED) SettingsCard {
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.Insights,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.cloud_usage_title),color=TitleText,
                    fontWeight=FontWeight.SemiBold,fontSize=16.sp)
            }
            // Information only: minimum Cloud capacity metrics are explained
            // before acceptance of Cloud terms; never use a misleading opt-out.
            Text(stringResource(R.string.cloud_usage_detail),color=MutedText,
                fontSize=12.sp,lineHeight=18.sp)
            Text(stringResource(R.string.cloud_usage_footnote),color=MutedText,fontSize=11.sp)
        }
        if(BuildConfig.SPDECODE_CLOUD_ENABLED) SettingsCard {
            Row(verticalAlignment=Alignment.CenterVertically) {
                Icon(Icons.Outlined.Sync,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.catalog_auto_title),
                    color=TitleText,fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            }
            Text(stringResource(R.string.catalog_auto_detail),
                color=MutedText,fontSize=12.sp,lineHeight=18.sp)
            Row(verticalAlignment=Alignment.CenterVertically) {
                Text(stringResource(R.string.catalog_auto_switch),
                    color=TitleText,modifier=Modifier.weight(1f),fontSize=14.sp)
                Switch(checked=catalogUpdatesEnabled,
                    onCheckedChange=onCatalogUpdates,
                    colors=SwitchDefaults.colors(checkedThumbColor=Color.Black,
                        checkedTrackColor=TitleText))
            }
        }
        // Settings additions injected here by the Android Gradle task.
        SettingsCard {
            Row(verticalAlignment=Alignment.CenterVertically) {
                Icon(Icons.Outlined.HelpOutline,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.guide_settings_title),
                    color=TitleText,fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            }
            Text(stringResource(R.string.guide_settings_detail),
                color=MutedText,fontSize=13.sp,lineHeight=19.sp)
            OutlinedButton(onClick=onShowGuide,modifier=Modifier.fillMaxWidth()) {
                Icon(Icons.Outlined.PlayCircleOutline,null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.guide_replay))
            }
        }
        SettingsCard {
            Row(verticalAlignment=Alignment.CenterVertically) {
                Icon(Icons.Outlined.Info,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.about_title),color=TitleText,
                    fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            }
            Text(stringResource(R.string.settings_version,BuildConfig.VERSION_NAME),
                color=TitleText,fontSize=15.sp)
            Text(stringResource(R.string.settings_build_code,BuildConfig.VERSION_CODE),
                color=MutedText,fontSize=12.sp)
            Text(stringResource(R.string.settings_security_offline),
                color=MutedText,fontSize=13.sp,lineHeight=19.sp)
            Text(stringResource(R.string.about_text),color=MutedText,
                fontSize=12.sp,lineHeight=18.sp)
        }
        SettingsCard{
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.PersonOutline,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.developer_credits),color=TitleText,
                    fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            }
            Text("Ghost Developer",color=TitleText,fontSize=16.sp,
                fontWeight=FontWeight.SemiBold)
            Text(stringResource(R.string.contribute_invitation),
                color=MutedText,fontSize=13.sp,lineHeight=19.sp)
            LinkRow(Icons.Outlined.AccountCircle,
                stringResource(R.string.contact_developer),
                "https://t.me/Gh0stDeveloper",onExternalLink)
            LinkRow(Icons.Outlined.Groups,
                stringResource(R.string.telegram_group),
                "https://t.me/CodeBreakersHub",onExternalLink)
            LinkRow(Icons.Outlined.Campaign,
                stringResource(R.string.telegram_channel),
                "https://t.me/GhostDeve",onExternalLink)
        }
        Spacer(Modifier.height(6.dp))
    }
    if(withdrawDialog) AlertDialog(
        onDismissRequest={withdrawDialog=false},
        title={Text(stringResource(R.string.cloud_legal_withdraw))},
        text={Text(stringResource(R.string.cloud_legal_withdraw_detail))},
        confirmButton={TextButton(onClick={withdrawDialog=false;onWithdrawConsent()}) {
            Text(stringResource(R.string.cloud_legal_withdraw))
        }},
        dismissButton={TextButton(onClick={withdrawDialog=false}) {
            Text(stringResource(R.string.cancel))
        }},
        containerColor=Color.Black,
        titleContentColor=TitleText,
        textContentColor=TitleText,
        tonalElevation=0.dp,
    )
    if(retentionDialog) AlertDialog(
        onDismissRequest={retentionDialog=false},
        title={Text(stringResource(R.string.history_retention),color=TitleText)},
        text={
            Column(verticalArrangement=Arrangement.spacedBy(5.dp)) {
                listOf(0,7,30,90,365).forEach { days ->
                    Row(
                        modifier=Modifier.fillMaxWidth()
                            .clickable{
                                retentionDialog=false
                                if(days!=retentionDays) onRetention(days)
                            }.padding(vertical=4.dp),
                        verticalAlignment=Alignment.CenterVertically
                    ) {
                        RadioButton(selected=retentionDays==days,
                            onClick={
                                retentionDialog=false
                                if(days!=retentionDays) onRetention(days)
                            })
                        Spacer(Modifier.width(8.dp))
                        Text(if(days==0)stringResource(R.string.history_keep_forever)
                            else stringResource(R.string.history_keep_days,days),
                            color=TitleText)
                    }
                }
            }
        },
        confirmButton={TextButton(onClick={retentionDialog=false}) {
            Text(stringResource(R.string.close))
        }},
        containerColor=Color.Black,
        titleContentColor=TitleText,
        textContentColor=TitleText,
        tonalElevation=0.dp,
    )
    if(clearDialog) AlertDialog(
        onDismissRequest={clearDialog=false},
        title={Text(stringResource(R.string.clear_confirm_title))},
        text={Text(stringResource(R.string.clear_confirm_detail))},
        confirmButton={
            TextButton(onClick={clearDialog=false;onClear()}){
                Text(stringResource(R.string.delete_session))
            }
        },
        dismissButton={TextButton(onClick={clearDialog=false}){
            Text(stringResource(R.string.cancel))
        }},
        containerColor=Color.Black,
        titleContentColor=TitleText,
        textContentColor=TitleText,
        tonalElevation=0.dp,
    )
}

@Composable private fun SettingsCard(content:@Composable ColumnScope.()->Unit){
    Surface(
        color=Pane,shape=RoundedCornerShape(16.dp),
        modifier=Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(12.dp),
            content=content)
    }
}
@Composable private fun LinkRow(
    icon:androidx.compose.ui.graphics.vector.ImageVector,
    text:String,url:String,onExternalLink:(String)->Unit
){
    Surface(
        modifier=Modifier.fillMaxWidth().clickable{onExternalLink(url)},
        color=Pane,shape=RoundedCornerShape(8.dp)
    ){
        Row(Modifier.fillMaxWidth().padding(vertical=9.dp),
            verticalAlignment=Alignment.CenterVertically){
            Icon(icon,null,tint=MutedText,modifier=Modifier.size(20.dp))
            Spacer(Modifier.width(12.dp))
            Text(text,color=TitleText,modifier=Modifier.weight(1f),fontSize=13.sp)
            Icon(Icons.Outlined.OpenInNew,null,tint=MutedText,
                modifier=Modifier.size(18.dp))
        }
    }
}
