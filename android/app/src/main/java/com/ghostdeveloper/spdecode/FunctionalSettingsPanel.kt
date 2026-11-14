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
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
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
    telegramCreditUsername:String="",
    onSaveTelegramCredit:(String)->Boolean={false},
    onLanguage:(String)->Unit,
    onMaskCredentials:(Boolean)->Unit,
    onClear:()->Unit,
    onExternalLink:(String)->Unit,
    retentionDays:Int,
    onRetention:(Int)->Unit,
    onShowGuide:()->Unit={},
    onLegalLink:(String)->Unit={},
    onWithdrawConsent:()->Unit={},
    onAdsPrivacyOptions:()->Unit={},
    catalogDownloadChunks:Boolean=false,
    onCatalogDownloadChunks:(Boolean)->Unit={},
    catalogUpdatesEnabled:Boolean=false,
    onCatalogUpdates:(Boolean)->Unit={},
    usageAnalyticsEnabled:Boolean=false,
    onUsageAnalytics:(Boolean)->Unit={},
    supportedFormats:List<AndroidDecoderCatalog.Format> = emptyList(),
    supportedTextFormats:List<CloudTextRoute> = emptyList(),
    catalogLoading:Boolean=false,
    catalogProgress:Int?=null,
    onFeedbackSubmit:suspend (FeedbackDraft)->String={throw IllegalStateException("FEEDBACK_UNAVAILABLE")},
){
    var clearDialog by remember { mutableStateOf(false) }
    var creditDraft by rememberSaveable(telegramCreditUsername) {
        mutableStateOf(telegramCreditUsername.trimStart('@'))
    }
    var editingCredit by rememberSaveable { mutableStateOf(false) }
    var deleteCreditDialog by remember { mutableStateOf(false) }
    val hasSavedCredit=telegramCreditUsername.isNotBlank()
    val normalizedCredit=TelegramResultCopy.normalizeUsername(creditDraft)
    var languagePage by rememberSaveable { mutableStateOf(false) }
    var formatsPage by rememberSaveable { mutableStateOf(false) }
    var feedbackPage by rememberSaveable { mutableStateOf(false) }
    var aboutPage by rememberSaveable { mutableStateOf(false) }
    val pageState=rememberSaveableStateHolder()
    var retentionDialog by remember { mutableStateOf(false) }
    var withdrawDialog by remember { mutableStateOf(false) }
    BackHandler(enabled=languagePage || formatsPage || feedbackPage || aboutPage) {
        when { aboutPage -> aboutPage=false
            feedbackPage -> feedbackPage=false
            formatsPage -> formatsPage=false
            else -> languagePage=false }
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
    if(feedbackPage){
        pageState.SaveableStateProvider("feedback-form") {
            FeedbackScreen(onBack={feedbackPage=false},onSend=onFeedbackSubmit)
        }
        return
    }
    if(aboutPage){
        AboutScreen(onBack={aboutPage=false},onExternalLink=onExternalLink,
            onLegalLink=onLegalLink)
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
        if(BuildConfig.SPDECODE_CLOUD_ENABLED) SettingsCard {
            Row(Modifier.fillMaxWidth().testTag("settings_feedback_entry")
                    .clickable{feedbackPage=true}.padding(vertical=5.dp),
                verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.Feedback,null,tint=TitleText,modifier=Modifier.size(25.dp))
                Spacer(Modifier.width(13.dp))
                Column(Modifier.weight(1f)){
                    Text(stringResource(R.string.feedback_title),color=TitleText,
                        fontWeight=FontWeight.SemiBold,fontSize=16.sp)
                    Text(stringResource(R.string.feedback_settings_detail),
                        color=MutedText,fontSize=13.sp)
                }
                Icon(Icons.Outlined.ChevronRight,null,tint=MutedText)
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
        if(BuildConfig.SPDECODE_CLOUD_ENABLED) SettingsCard {
            Row(verticalAlignment=Alignment.CenterVertically) {
                Icon(Icons.Outlined.AlternateEmail,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.decrypt_credits_title),
                    color=TitleText,fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            }
            Text(stringResource(R.string.decrypt_credits_description),
                color=MutedText,fontSize=12.sp,lineHeight=18.sp)
            if(hasSavedCredit && !editingCredit) {
                Text(stringResource(R.string.decrypt_credits_saved),
                    color=MutedText,fontSize=12.sp)
                Text(telegramCreditUsername,color=TitleText,
                    fontSize=17.sp,fontWeight=FontWeight.SemiBold,
                    modifier=Modifier.testTag("telegram_decrypt_credit_saved"))
                Row(horizontalArrangement=Arrangement.spacedBy(10.dp),
                    modifier=Modifier.fillMaxWidth()) {
                    OutlinedButton(
                        onClick={
                            creditDraft=telegramCreditUsername.trimStart('@')
                            editingCredit=true
                        },
                        modifier=Modifier.weight(1f).testTag("telegram_decrypt_credit_edit")
                    ) { Text(stringResource(R.string.decrypt_credits_edit)) }
                    OutlinedButton(
                        onClick={deleteCreditDialog=true},
                        modifier=Modifier.weight(1f).testTag("telegram_decrypt_credit_delete")
                    ) { Text(stringResource(R.string.decrypt_credits_delete)) }
                }
            } else {
                OutlinedTextField(
                    value=creditDraft,
                    onValueChange={creditDraft=it.trimStart('@').take(40)},
                    label={Text(stringResource(R.string.decrypt_credits_handle))},
                    prefix={Text("@")},
                    singleLine=true,
                    isError=normalizedCredit==null,
                    modifier=Modifier.fillMaxWidth().testTag("telegram_decrypt_credit")
                )
                if(normalizedCredit==null)
                    Text(stringResource(R.string.decrypt_credits_invalid),
                        color=Color(0xFFFF9696),fontSize=12.sp)
                Button(onClick={
                    normalizedCredit?.takeIf{it.isNotEmpty()}?.let{normalized->
                        if(onSaveTelegramCredit(normalized))editingCredit=false
                    }
                },enabled=normalizedCredit?.isNotEmpty()==true,
                    modifier=Modifier.fillMaxWidth().testTag("telegram_decrypt_credit_save")) {
                    Text(stringResource(R.string.decrypt_credits_save))
                }
                if(hasSavedCredit) TextButton(
                    onClick={
                        creditDraft=telegramCreditUsername.trimStart('@')
                        editingCredit=false
                    },modifier=Modifier.fillMaxWidth()
                ) { Text(stringResource(R.string.cancel)) }
            }
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
            if(BuildConfig.SPDECODE_UNITY_ADS_ENABLED) OutlinedButton(
                onClick=onAdsPrivacyOptions,modifier=Modifier.fillMaxWidth()
            ) { Text(stringResource(R.string.ads_privacy_options)) }
            // Consent withdrawal remains accessible without duplicating legal links.
            if(BuildConfig.SPDECODE_CLOUD_ENABLED) OutlinedButton(
                onClick={withdrawDialog=true},modifier=Modifier.fillMaxWidth()
            ) {
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
        if(BuildConfig.SPDECODE_CLOUD_ENABLED) SettingsCard {
            val labels=when(language.substringBefore('-')){
                "es"->listOf("Modo de descarga del catálogo","Descarga completa","Conexión estable · descarga normal","Por partes (chunks)","Conexión lenta o inestable · permite reanudar","Se aplicará en la próxima descarga.")
                "pt"->listOf("Modo de download do catálogo","Download completo","Conexão estável · download normal","Por partes (chunks)","Conexão lenta ou instável · permite retomar","Aplica-se ao próximo download.")
                "fr"->listOf("Mode de téléchargement du catalogue","Téléchargement complet","Connexion stable · téléchargement normal","Par fragments","Connexion lente ou instable · reprise possible","Appliqué au prochain téléchargement.")
                "de"->listOf("Katalog-Downloadmodus","Vollständiger Download","Stabile Verbindung · normaler Download","In Teilen (Chunks)","Langsame oder instabile Verbindung · fortsetzbar","Gilt für den nächsten Download.")
                "it"->listOf("Modalità download catalogo","Download completo","Connessione stabile · download normale","A blocchi","Connessione lenta o instabile · riprendibile","Si applica al prossimo download.")
                "ru"->listOf("Режим загрузки каталога","Полная загрузка","Стабильное соединение · обычная загрузка","По частям","Медленное или нестабильное соединение · с возобновлением","Применится при следующей загрузке.")
                "ar"->listOf("وضع تنزيل الكتالوج","تنزيل كامل","اتصال مستقر · تنزيل عادي","تنزيل على أجزاء","اتصال بطيء أو غير مستقر · قابل للاستئناف","يطبق عند التنزيل التالي.")
                "fa"->listOf("روش دانلود کاتالوگ","دانلود کامل","اتصال پایدار · دانلود عادی","دانلود بخش‌بخش","اتصال کند یا ناپایدار · قابل ادامه","در دانلود بعدی اعمال می‌شود.")
                "hi"->listOf("कैटलॉग डाउनलोड मोड","पूरा डाउनलोड","स्थिर कनेक्शन · सामान्य डाउनलोड","भागों में (chunks)","धीमा या अस्थिर कनेक्शन · फिर शुरू कर सकते हैं","अगले डाउनलोड पर लागू होगा।")
                "id","in"->listOf("Mode unduhan katalog","Unduhan penuh","Koneksi stabil · unduhan normal","Per bagian (chunks)","Koneksi lambat atau tidak stabil · dapat dilanjutkan","Berlaku untuk unduhan berikutnya.")
                "ja"->listOf("カタログのダウンロード方式","一括ダウンロード","安定した接続 · 通常のダウンロード","分割ダウンロード","低速・不安定な接続 · 再開可能","次回のダウンロードから適用されます。")
                "tr"->listOf("Katalog indirme modu","Tam indirme","Kararlı bağlantı · normal indirme","Parçalı indirme","Yavaş veya kararsız bağlantı · devam edilebilir","Sonraki indirmede uygulanır.")
                "vi"->listOf("Chế độ tải danh mục","Tải đầy đủ","Kết nối ổn định · tải thông thường","Tải theo phần","Kết nối chậm hoặc không ổn định · có thể tiếp tục","Áp dụng cho lần tải tiếp theo.")
                else->listOf("Catalog download mode","Full download","Stable connection · normal download","Chunked download","Slow or unstable connection · resumable","Applies to the next download.")
            }
            Text(labels[0],color=TitleText,fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            listOf(false,true).forEachIndexed { index,value->
                Row(Modifier.fillMaxWidth().clickable(enabled=!catalogLoading){onCatalogDownloadChunks(value)}
                    .padding(vertical=6.dp),verticalAlignment=Alignment.CenterVertically){
                    RadioButton(selected=catalogDownloadChunks==value,onClick={onCatalogDownloadChunks(value)},enabled=!catalogLoading)
                    Column(Modifier.weight(1f)){
                        Text(labels[1+index*2],color=TitleText,fontSize=14.sp)
                        Text(labels[2+index*2],color=MutedText,fontSize=12.sp)
                    }
                }
            }
            Text(labels[5],color=MutedText,fontSize=11.sp)
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
        // One entry only: version and developer credits live in AboutScreen.
        SettingsCard {
            Row(
                modifier=Modifier.fillMaxWidth().testTag("settings_about_entry")
                    .clickable{aboutPage=true}.padding(vertical=5.dp),
                verticalAlignment=Alignment.CenterVertically,
            ){
                Icon(Icons.Outlined.Info,null,tint=TitleText,
                    modifier=Modifier.size(25.dp))
                Spacer(Modifier.width(13.dp))
                Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(4.dp)){
                    Text(stringResource(R.string.about_title),color=TitleText,
                        fontWeight=FontWeight.SemiBold,fontSize=16.sp)
                    Text(stringResource(R.string.about_screen_entry_detail),
                        color=MutedText,fontSize=13.sp)
                }
                Icon(Icons.Outlined.ChevronRight,null,tint=MutedText)
            }
        }
        Spacer(Modifier.height(6.dp))
    }
    if(deleteCreditDialog) AlertDialog(
        onDismissRequest={deleteCreditDialog=false},
        title={Text(stringResource(R.string.decrypt_credits_delete),color=TitleText)},
        text={Text(stringResource(R.string.decrypt_credits_delete_confirm),color=MutedText)},
        confirmButton={TextButton(onClick={
            if(onSaveTelegramCredit("")) {
                creditDraft=""
                editingCredit=false
                deleteCreditDialog=false
            }
        }) { Text(stringResource(R.string.decrypt_credits_delete)) }},
        dismissButton={TextButton(onClick={deleteCreditDialog=false}) {
            Text(stringResource(R.string.cancel))
        }},
        containerColor=Color.Black,
        titleContentColor=TitleText,
        textContentColor=TitleText
    )
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
