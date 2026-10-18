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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
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
){
    var clearDialog by remember { mutableStateOf(false) }
    var languageSheet by remember { mutableStateOf(false) }
    var retentionDialog by remember { mutableStateOf(false) }
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
                modifier=Modifier.fillMaxWidth().clickable{languageSheet=true}
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
        DeviceCredentialSettingsSection()
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
    if(languageSheet) ModalBottomSheet(
        onDismissRequest={languageSheet=false},
        containerColor=Pane,
        contentColor=TitleText,
        scrimColor=Color.Black.copy(alpha=0.72f),
    ) {
        Column(
            Modifier.fillMaxWidth().heightIn(max=550.dp)
                .verticalScroll(rememberScrollState())
                .padding(start=22.dp,end=22.dp,bottom=25.dp),
            verticalArrangement=Arrangement.spacedBy(8.dp),
        ) {
            Text(stringResource(R.string.language_title),color=TitleText,
                fontWeight=FontWeight.Bold,fontSize=21.sp)
            Text(stringResource(R.string.language_pick_description),
                color=MutedText,fontSize=13.sp,lineHeight=19.sp)
            Spacer(Modifier.height(7.dp))
            SupportedLanguages.options.forEach { option ->
                Row(
                    modifier=Modifier.fillMaxWidth()
                        .clickable {
                            languageSheet=false
                            if(language!=option.tag) onLanguage(option.tag)
                        }
                        .padding(vertical=8.dp),
                    verticalAlignment=Alignment.CenterVertically,
                ) {
                    RadioButton(
                        selected=language==option.tag,
                        onClick={
                            languageSheet=false
                            if(language!=option.tag) onLanguage(option.tag)
                        },
                        colors=RadioButtonDefaults.colors(
                            selectedColor=TitleText,unselectedColor=MutedText,
                        ),
                    )
                    Spacer(Modifier.width(11.dp))
                    Text(if(option.tag=="system")stringResource(R.string.language_system)
                        else option.nativeName,
                        color=TitleText,fontSize=15.sp)
                }
            }
        }
    }
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
        containerColor=Pane,
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
        containerColor=Pane,
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
