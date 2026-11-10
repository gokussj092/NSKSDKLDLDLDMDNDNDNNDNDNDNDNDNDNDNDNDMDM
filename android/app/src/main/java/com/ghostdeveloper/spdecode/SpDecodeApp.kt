package com.ghostdeveloper.spdecode

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.boundsInWindow
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import com.ghostdeveloper.spdecode.cloud.CloudNewsNotice
import com.ghostdeveloper.spdecode.cloud.ServerVpnApp
import com.ghostdeveloper.spdecode.cloud.CloudTextRoute
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog

/** Authoritative reference is the USER-PROVIDED 2026-10-08 ChatGPT capture:
 * true black, #242424 centered import hero, thin result border and white text,
 * four monochrome bottom tabs, compact title with rounded shield icon.
 * This replaces mismatched older SVG illustrations for the functional UI.
 */
private val Background=Color(0xFF000000)
private val Panel=Color(0xFF242424)
private val Raised=Color(0xFF2A2A2A)
private val Outline=Color(0xFF202020)
private val White=Color(0xFFF7F7F7)
private val Secondary=Color(0xFFABABAB)
private val Green=Color(0xFF38A36D)
private val Amber=Color(0xFFE0B563)

@Composable
internal fun SpDecodeApp(
    activeTab:Int,
    current:DecodeView?,
    session:List<DecodeView>,
    busy:Boolean,
    error:String?,
    progressStage:Int,
    cloudProgressPhase:Int?=null,
    progressFilename:String?,
    progressPosition:Int,
    progressTotal:Int,
    reveal:Boolean,
    onTab:(Int)->Unit,
    onImport:()->Unit,
    onImportMultiple:()->Unit,
    onCancel:()->Unit,
    onReveal:(Boolean)->Unit,
    onCopy:(ResultExport)->Unit,
    onExport:(ResultExport)->Unit,
    selectedLanguage:String,
    hideCredentials:Boolean,
    onLanguage:(String)->Unit,
    onMaskCredentials:(Boolean)->Unit,
    onExternalLink:(String)->Unit,
    onSelect:(DecodeView)->Unit,
    onClear:()->Unit,
    onClearResult:()->Unit,
    onDeleteSelected:(Set<String>)->Unit,
    onFavorite:(String,Boolean)->Unit,
    retentionDays:Int,
    onRetention:(Int)->Unit,
    onDismissError:()->Unit,
    errorTitle:Int=R.string.decode_notice_title,
    canReportError:Boolean=false,
    onReportError:()->Unit={},
    onDecodeText:(String)->Unit={},
    onDecodeCloud:(String)->Unit={},
    onDecodeServerCatalog:()->Unit={},
    onDecodeServerApp:(String)->Unit={}, 
    serverVpnApps:List<ServerVpnApp> = emptyList(),
    cloudFormats:List<AndroidDecoderCatalog.Format> = emptyList(),
    cloudTextFormats:List<CloudTextRoute> = emptyList(),
    serverVpnLoading:Boolean=false,
    serverVpnUnavailable:Boolean=false,
    catalogProgress:Int?=null,
    catalogTransfer:CatalogTransferUiState?=null,
    onCancelCatalogTransfer:()->Unit={},
    onFinishCatalogTransfer:()->Unit={},
    onResumeCatalogTransfer:()->Unit={},
    onDiscardCatalogTransfer:()->Unit={},
    onRefreshServerVpn:()->Unit={},
    pendingServerVpnCatalogVersion:Int?=null,
    onConfirmServerVpnUpdate:()->Unit={},
    onDismissServerVpnUpdate:()->Unit={},
    availableAppUpdate:String?=null,
    onDismissAppUpdate:()->Unit={},
    whatsNew:Boolean=false,
    cloudWhatsNew:CloudNewsNotice?=null,
    onDismissWhatsNew:()->Unit={},
    guideStep:Int?=null,
    onGuideNext:()->Unit={},
    onGuideSkip:()->Unit={},
    onGuideRestart:()->Unit={},
    onLegalLink:(String)->Unit={},
    onWithdrawCloudConsent:()->Unit={},
    catalogUpdatesEnabled:Boolean=false,
    onCatalogUpdates:(Boolean)->Unit={},
    usageAnalyticsEnabled:Boolean=false,
    onUsageAnalytics:(Boolean)->Unit={},
    onFeedbackSubmit:suspend (FeedbackDraft)->String={throw IllegalStateException("FEEDBACK_UNAVAILABLE")},
    apkQaRunning:Boolean=false,
    apkQaPhase:String="",
    apkQaFilename:String="",
    apkQaReceived:Long=0L,
    apkQaTotal:Long=0L,
    apkQaReport:String?=null,
    apkQaEvents:List<com.ghostdeveloper.spdecode.cloud.CloudApkQaClient.ActivityEvent> = emptyList(),
    apkQaError:String?=null,
    onApkQaPick:()->Unit={},
    onApkQaCancel:()->Unit={},
    onApkQaRetry:()->Unit={},
){
    var dialog by remember{mutableStateOf<String?>(null)}
    var creditsPage by rememberSaveable { mutableStateOf(false) }
    BackHandler(enabled=creditsPage && activeTab==2) { creditsPage=false }
    SpDecodeAmoledTheme {
      AccountDrawer(busy,onExternalLink) { openMenu ->
        Column(
            modifier=Modifier.fillMaxSize().background(Background).safeDrawingPadding()
        ) {
            BrandHeader(
                onMenu=openMenu,
                onSettings={onTab(4)},
                showCreditsAction=activeTab==2 && !creditsPage,
                showCreditsBack=activeTab==2 && creditsPage,
                onCredits={creditsPage=true},
                onCreditsBack={creditsPage=false},
                showServerVpnRefresh=(activeTab==3 ||
                    (activeTab==2 && !creditsPage)) &&
                    BuildConfig.SPDECODE_CLOUD_ENABLED,
                refreshingServerVpn=serverVpnLoading && catalogTransfer==null,
                enableServerVpnRefresh=!busy && !serverVpnLoading,
                onRefreshServerVpn=onRefreshServerVpn,
            )
            Box(Modifier.weight(1f)) {
                when(activeTab) {
                    0->HomeScreen(current,session,busy,reveal,hideCredentials,onImport,onCancel,onReveal,
                        onCopy={dialog="copy"},onExport={dialog="export"},onSelect=onSelect,
                        onClearResult=onClearResult,onDecodeText=onDecodeText,
                        onDecodeCloud=onDecodeCloud,
                        highlightGuide=if(!whatsNew && !busy)guideStep else null)
                    1->HistoryScreen(session,onSelect,onDeleteSelected,onClear,onImportMultiple,onFavorite)
                    2->if(creditsPage) ApkCreditsComingSoonScreen()
                        else if(BuildConfig.SPDECODE_CLOUD_ENABLED)
                            ApkQaAnalysisScreen(apkQaRunning,apkQaPhase,apkQaReceived,
                                apkQaTotal,apkQaReport,apkQaError,onApkQaPick,onApkQaCancel,
                                events=apkQaEvents,sourceFilename=apkQaFilename,
                                onRetry=onApkQaRetry)
                        else ApkAnalysisComingSoonScreen()
                    3->ServerVpnScreen(busy,serverVpnApps,serverVpnLoading && catalogTransfer==null,serverVpnUnavailable,
                        onDecodeServerCatalog,onDecodeServerApp,catalogProgress)
                    else->FunctionalSettingsPanel(selectedLanguage,hideCredentials,
                        onLanguage,onMaskCredentials,onClear,onExternalLink,
                        retentionDays,onRetention,onShowGuide=onGuideRestart,
                        onLegalLink=onLegalLink,onWithdrawConsent=onWithdrawCloudConsent,
                        catalogUpdatesEnabled=catalogUpdatesEnabled,onCatalogUpdates=onCatalogUpdates,
                        usageAnalyticsEnabled=usageAnalyticsEnabled,onUsageAnalytics=onUsageAnalytics,
                         supportedFormats=cloudFormats,supportedTextFormats=cloudTextFormats,
                         catalogLoading=serverVpnLoading && catalogTransfer==null,catalogProgress=catalogProgress,
                         onFeedbackSubmit=onFeedbackSubmit)
                }
                if(guideStep!=null && !whatsNew && !busy && error==null && dialog==null) {
                    CenteredFirstRunGuide(guideStep,onGuideNext,onGuideSkip)
                }
            }
            BottomTabs(activeTab,onTab={destination->creditsPage=false;onTab(destination)},
                spotlight=if(guideStep!=null && !whatsNew && !busy)
                    FirstRunGuide.targetTab(guideStep) else null)
        }
        if(pendingServerVpnCatalogVersion!=null && !busy) AlertDialog(
            onDismissRequest=onDismissServerVpnUpdate,
            icon={Image(painter=painterResource(R.drawable.ic_launcher_foreground),
                contentDescription=null,modifier=Modifier.size(46.dp))},
            title={Text(stringResource(R.string.catalog_available_title))},
            text={Text(stringResource(R.string.catalog_download_confirm_body),color=Secondary)},
            confirmButton={TextButton(onClick=onConfirmServerVpnUpdate) {
                Text(stringResource(R.string.server_vpn_catalog_download),color=White)
            }},
            dismissButton={TextButton(onClick=onDismissServerVpnUpdate) {
                Text(stringResource(R.string.cancel),color=White)
            }},
            containerColor=Background,
            titleContentColor=White,
            textContentColor=Secondary,
        )
        catalogTransfer?.let { transfer ->
            CatalogTransferDialog(transfer,onCancelCatalogTransfer,onFinishCatalogTransfer,onResumeCatalogTransfer,onDiscardCatalogTransfer)
        }
        if(whatsNew && !busy && (cloudWhatsNew!=null || !BuildConfig.SPDECODE_CLOUD_ENABLED)) AlertDialog(
            onDismissRequest=onDismissWhatsNew,
            icon={Icon(Icons.Outlined.NewReleases,null,tint=Green)},
            title={Text(cloudWhatsNew?.title ?: stringResource(R.string.whats_new_title),fontWeight=FontWeight.Bold)},
            text={
                if(cloudWhatsNew!=null) Column(
                    modifier=Modifier.heightIn(max=430.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement=Arrangement.spacedBy(14.dp)
                ){
                    Text(cloudWhatsNew.subtitle,color=White,fontSize=14.sp)
                    cloudWhatsNew.items.forEach { item ->
                        Row(verticalAlignment=Alignment.Top) {
                            Icon(Icons.Outlined.CheckCircle,null,tint=Green,
                                modifier=Modifier.size(20.dp))
                            Spacer(Modifier.width(11.dp))
                            Column(verticalArrangement=Arrangement.spacedBy(3.dp)) {
                                Text(item.title,color=White,fontWeight=FontWeight.SemiBold,fontSize=14.sp)
                                Text(item.description,color=Secondary,fontSize=13.sp,
                                    lineHeight=18.sp)
                            }
                        }
                    }
                    Text(cloudWhatsNew.publishedAt,color=Secondary,fontSize=11.sp)
                } else Column(verticalArrangement=Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.whats_new_description),
                        color=White,fontSize=14.sp)
                    Row(verticalAlignment=Alignment.Top) {
                        Icon(Icons.Outlined.CheckCircle,null,tint=Green,
                            modifier=Modifier.size(21.dp))
                        Spacer(Modifier.width(9.dp))
                        Text(stringResource(R.string.whats_new_linklayer),
                            color=White,fontSize=14.sp)
                    }
                    Row(verticalAlignment=Alignment.Top) {
                        Icon(Icons.Outlined.DataObject,null,tint=Green,
                            modifier=Modifier.size(21.dp))
                        Spacer(Modifier.width(9.dp))
                        Text(stringResource(R.string.whats_new_fields),
                            color=Secondary,fontSize=13.sp)
                    }
                    Row(verticalAlignment=Alignment.Top) {
                        Icon(Icons.Outlined.Shield,null,tint=Green,
                            modifier=Modifier.size(21.dp))
                        Spacer(Modifier.width(9.dp))
                        Text(stringResource(R.string.whats_new_offline),
                            color=Secondary,fontSize=13.sp)
                    }
                }
            },
            confirmButton={
                TextButton(onClick=onDismissWhatsNew) {
                    Text(stringResource(R.string.whats_new_continue),color=White)
                }
            },
            containerColor=Background,
            titleContentColor=White,
            textContentColor=Secondary,
        )
        // Import progress is modal so it cannot be overlooked or mistaken for a
        // stalled app. Cancellation is explicit; Back never dismisses it silently.
        if(busy) Dialog(
            onDismissRequest={},
            properties=DialogProperties(
                dismissOnBackPress=false,dismissOnClickOutside=false),
        ) {
            Surface(color=Background,shape=RoundedCornerShape(22.dp),
                modifier=Modifier.fillMaxWidth(),
                border=BorderStroke(1.dp,Outline)) {
                Column(
                    Modifier.padding(horizontal=24.dp,vertical=27.dp),
                    verticalArrangement=Arrangement.spacedBy(14.dp),
                    horizontalAlignment=Alignment.CenterHorizontally,
                ) {
                    CircularProgressIndicator(color=White,strokeWidth=3.dp,
                        modifier=Modifier.size(43.dp))
                    Text(stringResource(R.string.decode_progress_title),
                        color=White,fontSize=19.sp,fontWeight=FontWeight.Bold)
                    Text(stringResource(when(progressStage){
                        0->R.string.decode_progress_reading
                        2->R.string.decode_progress_saving
                        else->R.string.decode_progress_decoding
                    }),color=Secondary,fontSize=14.sp,textAlign=TextAlign.Center)
                    if(BuildConfig.SPDECODE_CLOUD_ENABLED && cloudProgressPhase!=null) {
                        Text(stringResource(R.string.decode_progress_wait),
                            color=Secondary,fontSize=13.sp,textAlign=TextAlign.Center)
                        Text(stringResource(when(cloudProgressPhase) {
                            0->R.string.decode_progress_sending
                            1->R.string.decode_progress_processing
                            else->R.string.decode_progress_downloading_results
                        }),color=White,fontSize=15.sp,fontWeight=FontWeight.SemiBold,
                            textAlign=TextAlign.Center)
                    }
                    if(progressTotal>1) Text(
                        stringResource(R.string.batch_progress_count,progressPosition,progressTotal),
                        color=White,fontSize=13.sp)
                    if(!progressFilename.isNullOrBlank()) Text(progressFilename,
                        color=Secondary,fontSize=12.sp,maxLines=2,
                        overflow=TextOverflow.Ellipsis,textAlign=TextAlign.Center)
                    OutlinedButton(onClick=onCancel,modifier=Modifier.fillMaxWidth(),
                        colors=ButtonDefaults.outlinedButtonColors(contentColor=White)) {
                        Text(stringResource(R.string.processing_cancel))
                    }
                }
            }
        }
        if(availableAppUpdate!=null && !busy) AlertDialog(
            onDismissRequest=onDismissAppUpdate,
            icon={Icon(Icons.Outlined.SystemUpdate,null,tint=Green)},
            title={Text(stringResource(R.string.app_update_title))},
            text={Text(stringResource(R.string.app_update_body,availableAppUpdate),color=Secondary)},
            confirmButton={TextButton(onClick={
                onDismissAppUpdate()
                onExternalLink("https://t.me/GhostDeve")
            }){Text(stringResource(R.string.app_update_open),color=White)}},
            dismissButton={TextButton(onClick=onDismissAppUpdate){
                Text(stringResource(R.string.app_update_close),color=White)
            }},containerColor=Background,titleContentColor=White,
        )
        if(error!=null && !busy) AlertDialog(
            onDismissRequest=onDismissError,
            icon={Icon(Icons.Outlined.Info,null,tint=Amber)},
            title={Text(stringResource(errorTitle))},
            text={Text(error,color=Secondary)},
            confirmButton={TextButton(onClick=onDismissError){
                Text(stringResource(R.string.close),color=White)
            }},
            dismissButton={TextButton(onClick={
                if(canReportError)onReportError()
                else {
                    onDismissError()
                    onExternalLink("https://t.me/Gh0stDeveloper")
                }
            }) {
                Text(stringResource(if(canReportError)R.string.cloud_report_action
                    else R.string.decode_notice_contact),color=White)
            }},
            containerColor=Background,
            titleContentColor=White,
            textContentColor=Secondary,
        )
        if(dialog!=null && current!=null) {
            val copy=dialog=="copy"
            AlertDialog(
                onDismissRequest={dialog=null},
                title={Text(stringResource(if(copy)R.string.copy_question else R.string.export_question))},
                text={
                    Column(verticalArrangement=Arrangement.spacedBy(10.dp)) {
                        Text(stringResource(R.string.privacy_warning),
                            color=Secondary,fontSize=13.sp)
                        listOf(
                            Triple(ResultExport.JSON,R.string.json_option,Icons.Outlined.DataObject),
                            Triple(ResultExport.ORDERED,R.string.ordered_option,Icons.Outlined.FormatListBulleted),
                            Triple(ResultExport.ORIGINAL,R.string.original_option,Icons.Outlined.Code)
                        ).forEach { (format,label,icon)->
                            OutlinedButton(
                                modifier=Modifier.fillMaxWidth(),
                                onClick={
                                    if(copy)onCopy(format)else onExport(format)
                                    dialog=null
                                }
                            ){
                                Icon(icon,null)
                                Spacer(Modifier.width(9.dp))
                                Text(stringResource(label))
                            }
                        }
                    }
                },
                confirmButton={TextButton(onClick={dialog=null}){
                    Text(stringResource(R.string.cancel))
                }},
                containerColor=Background,
                titleContentColor=White,
                textContentColor=White,
            )
        }
      }
    }
}

@Composable
private fun BrandHeader(
    onMenu:()->Unit={},
    onSettings:()->Unit,
    showCreditsAction:Boolean=false,
    showCreditsBack:Boolean=false,
    onCredits:()->Unit={},
    onCreditsBack:()->Unit={},
    showServerVpnRefresh:Boolean=false,
    refreshingServerVpn:Boolean=false,
    enableServerVpnRefresh:Boolean=true,
    onRefreshServerVpn:()->Unit={},
){
    Row(
        modifier=Modifier.fillMaxWidth().padding(start=20.dp,end=12.dp,top=14.dp,bottom=11.dp),
        verticalAlignment=Alignment.CenterVertically,
    ){
        IconButton(
            onClick=onMenu,
            modifier=Modifier.size(48.dp).background(Panel,RoundedCornerShape(13.dp)),
        ){
            Icon(Icons.Outlined.Menu,stringResource(R.string.account_open_menu),tint=White,modifier=Modifier.size(26.dp))
        }
        Spacer(Modifier.width(11.dp))
        Column(Modifier.weight(1f)){
            Text("SP-DECODE",color=White,
                fontSize=if(showCreditsAction)21.sp else 23.sp,fontWeight=FontWeight.Bold,
                maxLines=1)
            Text(stringResource(R.string.subtitle),color=Secondary,fontSize=14.sp,
                maxLines=1,overflow=TextOverflow.Ellipsis)
        }
        if(showServerVpnRefresh) {
            if(showCreditsAction) {
                // Keep the APK refresh control without squeezing the brand and Credits button.
                IconButton(onClick=onRefreshServerVpn,
                    enabled=enableServerVpnRefresh,
                    modifier=Modifier.testTag("server_vpn_manual_refresh")) {
                    if(refreshingServerVpn) CircularProgressIndicator(
                        modifier=Modifier.size(18.dp),strokeWidth=2.dp,color=White)
                    else Icon(Icons.Outlined.Refresh,
                        stringResource(R.string.catalog_check_action),tint=White,
                        modifier=Modifier.size(20.dp))
                }
            } else {
                OutlinedButton(
                    onClick=onRefreshServerVpn,enabled=enableServerVpnRefresh,
                    modifier=Modifier.testTag("server_vpn_manual_refresh"),
                    contentPadding=PaddingValues(horizontal=12.dp,vertical=7.dp),
                ) {
                    if(refreshingServerVpn) CircularProgressIndicator(
                        modifier=Modifier.size(17.dp),strokeWidth=2.dp,color=White)
                    else Icon(Icons.Outlined.Refresh,null,tint=White,
                        modifier=Modifier.size(17.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(if(refreshingServerVpn) R.string.catalog_checking
                        else R.string.catalog_check_action),fontSize=12.sp,color=White)
                }
            }
            Spacer(Modifier.width(4.dp))
        }
        if(showCreditsAction) {
            OutlinedButton(onClick=onCredits,
                modifier=Modifier.testTag("apk_credits_open"),
                contentPadding=PaddingValues(horizontal=8.dp,vertical=7.dp),
                shape=RoundedCornerShape(13.dp)) {
                Icon(Icons.Outlined.CreditCard,null,tint=White,
                    modifier=Modifier.size(16.dp))
                Spacer(Modifier.width(5.dp))
                Text(stringResource(R.string.apk_credits_button),
                    color=White,fontSize=11.sp,maxLines=1)
            }
        } else if(showCreditsBack) {
            OutlinedButton(onClick=onCreditsBack,
                modifier=Modifier.testTag("apk_credits_back"),
                contentPadding=PaddingValues(horizontal=9.dp,vertical=7.dp)) {
                Icon(Icons.Outlined.ArrowBack,null,tint=White,
                    modifier=Modifier.size(17.dp))
                Spacer(Modifier.width(5.dp))
                Text(stringResource(R.string.apk_credits_back),
                    color=White,fontSize=12.sp)
            }
        } else IconButton(onClick=onSettings){
            Icon(Icons.Outlined.Tune,stringResource(R.string.options),tint=Secondary)
        }
    }
}

@Composable
private fun HomeScreen(
    current:DecodeView?,
    session:List<DecodeView>,
    busy:Boolean,
    reveal:Boolean,
    hideCredentials:Boolean,
    onImport:()->Unit,
    onCancel:()->Unit,
    onReveal:(Boolean)->Unit,
    onCopy:()->Unit,
    onExport:()->Unit,
    onSelect:(DecodeView)->Unit,
    onClearResult:()->Unit,
    onDecodeText:(String)->Unit,
    onDecodeCloud:(String)->Unit,
    highlightGuide:Int?=null,
) {
    Column(
        modifier=Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal=20.dp,vertical=11.dp),
        verticalArrangement=Arrangement.spacedBy(19.dp),
    ) {
        var textExpanded by rememberSaveable { mutableStateOf(false) }
        var cloudExpanded by rememberSaveable { mutableStateOf(false) }
        var awaitingTextResult by remember { mutableStateOf(false) }
        var awaitingCloudResult by remember { mutableStateOf(false) }
        // Keep previous results visible. Hide the editor only after a new,
        // successfully decoded result arrives; failures leave text editable.
        LaunchedEffect(current?.id) {
            if(awaitingTextResult && current != null) {
                textExpanded=false
                awaitingTextResult=false
            }
            if(awaitingCloudResult && current != null) {
                cloudExpanded=false
                awaitingCloudResult=false
            }
        }
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement=Arrangement.spacedBy(10.dp),
            verticalAlignment=Alignment.CenterVertically,
        ) {
            Button(
                onClick={
                    awaitingTextResult=false
                    awaitingCloudResult=false
                    textExpanded=false
                    cloudExpanded=false
                    onImport()
                },
                enabled=!busy,
                modifier=Modifier.weight(1f).heightIn(min=52.dp)
                    .onGloballyPositioned{ GuideSpotlightTargets.locate(0,it.boundsInWindow()) },
                shape=RoundedCornerShape(14.dp),
                border=if(highlightGuide==0)BorderStroke(2.dp,White)else null,
                contentPadding=PaddingValues(horizontal=8.dp,vertical=12.dp),
                colors=ButtonDefaults.buttonColors(
                    containerColor=Panel,contentColor=White,
                    disabledContainerColor=Panel,disabledContentColor=Secondary),
            ) {
                Icon(Icons.Outlined.FileUpload,null,modifier=Modifier.size(20.dp))
                Spacer(Modifier.width(6.dp))
                Text(stringResource(R.string.home_import_action),
                    fontSize=13.sp,maxLines=2,lineHeight=16.sp,
                    textAlign=TextAlign.Center)
            }
            Button(
                onClick={
                    cloudExpanded=false
                    awaitingCloudResult=false
                    textExpanded=!textExpanded
                },
                enabled=!busy,
                modifier=Modifier.weight(1f).heightIn(min=52.dp)
                    .onGloballyPositioned{ GuideSpotlightTargets.locate(1,it.boundsInWindow()) },
                shape=RoundedCornerShape(14.dp),
                border=if(highlightGuide==1)BorderStroke(2.dp,White)else null,
                contentPadding=PaddingValues(horizontal=8.dp,vertical=12.dp),
                colors=ButtonDefaults.buttonColors(
                    containerColor=if(textExpanded)Raised else Panel,
                    contentColor=White,disabledContainerColor=Panel,
                    disabledContentColor=Secondary),
            ) {
                Icon(Icons.Outlined.DataObject,null,modifier=Modifier.size(20.dp))
                Spacer(Modifier.width(6.dp))
                Text(stringResource(R.string.text_decode_title),
                    fontSize=13.sp,maxLines=2,lineHeight=16.sp,
                    textAlign=TextAlign.Center)
            }
        }
        // Online actions are always separate from the offline Texts panel.
        OutlinedButton(
            onClick={
                textExpanded=false
                awaitingTextResult=false
                cloudExpanded=!cloudExpanded
            },
            enabled=!busy,
            modifier=Modifier.fillMaxWidth().heightIn(min=46.dp)
                .onGloballyPositioned{ GuideSpotlightTargets.locate(2,it.boundsInWindow()) },
            shape=RoundedCornerShape(14.dp),
            colors=ButtonDefaults.outlinedButtonColors(
                contentColor=White,disabledContentColor=Secondary),
            border=BorderStroke(if(highlightGuide==2)2.dp else 1.dp,
                if(highlightGuide==2)White else Outline),
        ) {
            Icon(Icons.Outlined.Cloud,null,modifier=Modifier.size(19.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.cloud_http_injector_open),
                fontSize=13.sp)
        }
        if(cloudExpanded) HttpInjectorCloudPanel(
            enabled=!busy,
            onDecode={input->
                awaitingCloudResult=true
                onDecodeCloud(input)
            },
        )
        if(textExpanded) TextDecoderPanel(
            enabled=!busy,
            onDecode={input->
                awaitingTextResult=true
                onDecodeText(input)
            },
        )

        Row(Modifier.fillMaxWidth()
            .onGloballyPositioned{ GuideSpotlightTargets.locate(3,it.boundsInWindow()) },
            verticalAlignment=Alignment.CenterVertically){
            Text(stringResource(R.string.result),color=White,fontWeight=FontWeight.Bold,
                fontSize=18.sp,modifier=Modifier.weight(1f))
            if(current==null) Text(stringResource(R.string.illustrative),
                color=Secondary,fontSize=12.sp)
            else {
                Text(stringResource(R.string.experimental),
                    color=Secondary,fontSize=12.sp)
                IconButton(onClick=onClearResult,enabled=!busy,
                    modifier=Modifier.size(42.dp)) {
                    Icon(Icons.Outlined.DeleteOutline,
                        contentDescription=stringResource(R.string.clear_current_result),
                        tint=if(busy)Secondary else White,modifier=Modifier.size(21.dp))
                }
            }
        }
        CompleteResultCard(current,reveal,hideCredentials,onReveal,onCopy,onExport)
        Row(verticalAlignment=Alignment.CenterVertically){
            Icon(Icons.Outlined.Lock,null,tint=Secondary,modifier=Modifier.size(15.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.offline_status),fontSize=12.sp,color=Secondary)
        }
        if(session.size>1){
            Text(stringResource(R.string.recent),fontWeight=FontWeight.SemiBold,color=White)
            session.drop(1).take(3).forEach{item->
                Row(
                    modifier=Modifier.fillMaxWidth().clickable{onSelect(item)}
                        .padding(vertical=8.dp),
                    verticalAlignment=Alignment.CenterVertically,
                ){
                    Icon(Icons.Outlined.InsertDriveFile,null,tint=Secondary)
                    Spacer(Modifier.width(10.dp))
                    Text(item.filename,color=White,modifier=Modifier.weight(1f),
                        maxLines=1,overflow=TextOverflow.Ellipsis)
                    Icon(Icons.Outlined.KeyboardArrowRight,null,tint=Secondary)
                }
            }
        }
    }
}

@Composable
private fun HistoryScreen(
    session: List<DecodeView>,
    onSelect: (DecodeView) -> Unit,
    onDeleteSelected: (Set<String>) -> Unit,
    onDeleteAll: () -> Unit,
    onImportMultiple: () -> Unit,
    onFavorite: (String, Boolean) -> Unit,
) {
    var selecting by remember { mutableStateOf(false) }
    val selected = remember { mutableStateListOf<String>() }
    var deletion by remember { mutableStateOf<Set<String>?>(null) }
    var deletingAll by remember { mutableStateOf(false) }
    var query by rememberSaveable { mutableStateOf("") }
    var format by rememberSaveable { mutableStateOf<String?>(null) }
    var favoritesOnly by rememberSaveable { mutableStateOf(false) }
    var sort by rememberSaveable { mutableStateOf(HistorySort.NEWEST) }
    var formatMenu by remember { mutableStateOf(false) }
    var sortMenu by remember { mutableStateOf(false) }
    val formats = session.map { it.extension }.distinct().sorted()
    val visible = HistorySearch.apply(session,HistoryFilter(query,format,favoritesOnly,sort))
    val visibleIds = visible.map { it.id }.toSet()
    val selectedVisible = selected.filter { it in visibleIds }.toSet()
    LaunchedEffect(session.map { it.id }) {
        selected.retainAll(session.map { it.id }.toSet())
        if (session.isEmpty()) selecting = false
    }
    LazyColumn(
        modifier=Modifier.fillMaxSize(),
        verticalArrangement=Arrangement.spacedBy(12.dp),
        contentPadding=PaddingValues(horizontal=20.dp,vertical=16.dp),
    ) {
        item {
            Row(verticalAlignment=Alignment.CenterVertically) {
                Text(stringResource(R.string.history),color=White,
                    fontSize=24.sp,fontWeight=FontWeight.Bold,
                    modifier=Modifier.weight(1f))
                if(session.isNotEmpty()) TextButton(onClick={
                    selecting=!selecting;selected.clear()
                }) { Text(stringResource(if(selecting)R.string.cancel else R.string.history_select)) }
            }
        }
        item { Text(stringResource(R.string.session_only),color=Secondary,fontSize=13.sp) }
        if(session.isNotEmpty()) {
            item {
                OutlinedTextField(
                    value=query,onValueChange={query=it},
                    modifier=Modifier.fillMaxWidth(),
                    singleLine=true,shape=RoundedCornerShape(14.dp),
                    label={Text(stringResource(R.string.history_search))},
                    leadingIcon={Icon(Icons.Outlined.Search,null)},
                    trailingIcon={
                        if(query.isNotEmpty()) IconButton(onClick={query=""}) {
                            Icon(Icons.Outlined.Close,stringResource(R.string.close))
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
                        label={Text(stringResource(R.string.history_favorites))},
                        leadingIcon={Icon(Icons.Outlined.StarBorder,null,
                            modifier=Modifier.size(16.dp))})
                    Box {
                        OutlinedButton(onClick={formatMenu=true},
                            contentPadding=PaddingValues(horizontal=10.dp)) {
                            Text(format?.let{"." + it}?:stringResource(R.string.all_formats),
                                fontSize=12.sp)
                            Icon(Icons.Outlined.ArrowDropDown,null)
                        }
                        DropdownMenu(expanded=formatMenu,onDismissRequest={formatMenu=false},
                            containerColor=Panel) {
                            DropdownMenuItem(
                                text={Text(stringResource(R.string.all_formats))},
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
                            Text(stringResource(R.string.history_sort),fontSize=12.sp)
                        }
                        DropdownMenu(expanded=sortMenu,onDismissRequest={sortMenu=false},
                            containerColor=Panel) {
                            listOf(
                                HistorySort.NEWEST to R.string.history_newest,
                                HistorySort.OLDEST to R.string.history_oldest,
                                HistorySort.NAME to R.string.history_name,
                            ).forEach { (value,label) ->
                                DropdownMenuItem(text={Text(stringResource(label))},
                                    onClick={sort=value;sortMenu=false})
                            }
                        }
                    }
                }
            }
            item {
                Text(stringResource(R.string.history_matches,visible.size),
                    color=Secondary,fontSize=12.sp)
            }
        }
        if(session.isEmpty()) {
            item { CardText(stringResource(R.string.empty_history)) }
        } else {
            if(selecting) item {
                Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically) {
                    TextButton(onClick={
                        if(visibleIds.isNotEmpty() && visibleIds.all { it in selected }) {
                            selected.removeAll(visibleIds)
                        } else selected.addAll(visibleIds.filterNot { it in selected })
                    }) {
                        Text(stringResource(if(visibleIds.isNotEmpty() &&
                            visibleIds.all{it in selected}) R.string.history_deselect_all
                            else R.string.history_select_visible))
                    }
                    Spacer(Modifier.weight(1f))
                    Text(stringResource(R.string.history_selected_count,selected.size),
                        color=Secondary,fontSize=12.sp)
                }
            }
            if(visible.isEmpty()) item {
                CardText(stringResource(R.string.history_no_matches))
            }
            items(visible,key={it.id}) { entry ->
                val checked=entry.id in selected
                Surface(color=Panel,shape=RoundedCornerShape(14.dp),
                    modifier=Modifier.fillMaxWidth().clickable {
                        if(selecting) {
                            if(checked) selected.remove(entry.id) else selected.add(entry.id)
                        }else onSelect(entry)
                    }) {
                    Row(Modifier.padding(horizontal=12.dp,vertical=12.dp),
                        verticalAlignment=Alignment.CenterVertically) {
                        if(selecting) Checkbox(checked=checked,onCheckedChange={
                            if(it && !checked)selected.add(entry.id)
                            else if(!it)selected.remove(entry.id)
                        }) else Icon(Icons.Outlined.InsertDriveFile,null,tint=White)
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(entry.filename,color=White,maxLines=1,
                                overflow=TextOverflow.Ellipsis)
                            Text("." + entry.extension + " · " +
                                stringResource(R.string.experimental),
                                color=Secondary,fontSize=12.sp)
                        }
                        if(!selecting) {
                            IconButton(onClick={onFavorite(entry.id,!entry.favorite)}) {
                                Icon(if(entry.favorite)Icons.Outlined.Star
                                    else Icons.Outlined.StarBorder,
                                    stringResource(R.string.history_favorites),
                                    tint=if(entry.favorite)Amber else Secondary)
                            }
                            IconButton(onClick={
                                deletingAll=false;deletion=setOf(entry.id)
                            }) {
                                Icon(Icons.Outlined.DeleteOutline,
                                    stringResource(R.string.history_delete_one),tint=Secondary)
                            }
                        }
                    }
                }
            }
            item {
                if(selecting) Button(
                    onClick={deletingAll=false;deletion=selected.toSet()},
                    enabled=selected.isNotEmpty(),modifier=Modifier.fillMaxWidth()) {
                    Icon(Icons.Outlined.DeleteOutline,null)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.history_delete_selected))
                }else OutlinedButton(onClick={
                    deletion=session.map{it.id}.toSet();deletingAll=true
                }) {
                    Icon(Icons.Outlined.DeleteOutline,null)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.delete_session))
                }
            }
        }
    }
    if(deletion!=null) AlertDialog(
        onDismissRequest={deletion=null;deletingAll=false},
        title={Text(stringResource(R.string.clear_confirm_title))},
        text={Text(stringResource(R.string.history_delete_confirm,deletion!!.size))},
        confirmButton={TextButton(onClick={
            val ids=deletion.orEmpty()
            deletion=null;selected.clear();selecting=false
            if(deletingAll)onDeleteAll()
            else if(ids.isNotEmpty())onDeleteSelected(ids)
            deletingAll=false
        }){ Text(stringResource(R.string.history_delete_selected)) }},
        dismissButton={TextButton(onClick={deletion=null;deletingAll=false}){
            Text(stringResource(R.string.cancel))
        }},
        containerColor=Background,
        titleContentColor=White,
        textContentColor=White,
    )
}

@Composable
internal fun FormatsScreen(cloudFormats:List<AndroidDecoderCatalog.Format>,
    textFormats:List<CloudTextRoute>,catalogLoading:Boolean=false,
    catalogProgress:Int?=null,onBack:(()->Unit)?=null) {
    val context = LocalContext.current
    val baseline = remember(context) { AndroidDecoderCatalog.read(context) }
    val formats = if(BuildConfig.SPDECODE_CLOUD_ENABLED && cloudFormats.isNotEmpty())
        cloudFormats else baseline
    var query by rememberSaveable { mutableStateOf("") }
    val groups = remember(query, formats) {
        (formats + listOfNotNull(AndroidDecoderCatalog.detect("preview.solid",formats)))
            .groupBy { it.appName }.toList()
            .filter { (name, entries) ->
                query.isBlank() || name.contains(query.trim(), ignoreCase = true) ||
                    entries.any { it.suffix.contains(query.trim(), ignoreCase = true) }
            }
            .sortedBy { it.first.lowercase(java.util.Locale.ROOT) }
    }
    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 12.dp)) {
        if(onBack!=null) {
            Row(verticalAlignment=Alignment.CenterVertically) {
                IconButton(onClick=onBack,modifier=Modifier.testTag("settings_formats_back")) {
                    Icon(Icons.Outlined.ArrowBack,
                        stringResource(R.string.settings),tint=White)
                }
                Text(stringResource(R.string.settings),color=Secondary,fontSize=14.sp)
            }
            Spacer(Modifier.height(5.dp))
        }
        Text(stringResource(R.string.settings_formats_title),
            fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.catalog_note), fontSize = 13.sp,
            color = Secondary, lineHeight = 20.sp)
        if(catalogLoading) Row(verticalAlignment=Alignment.CenterVertically) {
            CircularProgressIndicator(modifier=Modifier.size(18.dp),strokeWidth=2.dp,color=White)
            Spacer(Modifier.width(8.dp))
            Text(if(catalogProgress!=null)stringResource(R.string.catalog_progress,catalogProgress)
                else stringResource(R.string.catalog_checking),color=Secondary,fontSize=12.sp)
        }
        Spacer(Modifier.height(14.dp))
        OutlinedTextField(value = query, onValueChange = { query = it },
            label = { Text(stringResource(R.string.search_formats)) },
            leadingIcon = { Icon(Icons.Outlined.Search, null) },
            singleLine = true, modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(13.dp))
        Spacer(Modifier.height(8.dp))
        LazyColumn(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(3.dp),
            contentPadding = PaddingValues(bottom = 20.dp),
        ) {
            items(groups, key = { it.first }) { (appName, extensions) ->
                Row(Modifier.fillMaxWidth().padding(vertical = 12.dp, horizontal = 4.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.Description, null, tint = Secondary)
                    Spacer(Modifier.width(13.dp))
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                        Text(appName, color = White, fontSize = 15.sp,
                            fontWeight = FontWeight.SemiBold)
                        // 239 formats include large multi-alias families.
                        // FlowRow prevents chips from overflowing small phones.
                        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            extensions.sortedBy { it.suffix }.forEach { ext ->
                                Text("." + ext.suffix,
                                    color = if (ext.isPending) Secondary else White,
                                    fontSize = 12.sp,
                                    modifier = Modifier.background(Raised,
                                        RoundedCornerShape(7.dp))
                                        .padding(horizontal = 9.dp, vertical = 5.dp))
                            }
                        }
                    }
                    Spacer(Modifier.width(5.dp))
                    Text(
                        stringResource(
                            if (extensions.all { it.isPending })
                                R.string.native_decoder_pending_short
                            else if (extensions.all { it.hasNativeDecoder })
                                R.string.experimental
                            else R.string.native_decoder_mixed_short
                        ),
                        color = if (extensions.all { it.isPending }) Secondary else Amber,
                        fontSize = 11.sp
                    )
                }
                HorizontalDivider(color = Outline)
            }
            val textResults=textFormats.filter { entry ->
                query.isBlank() || entry.name.contains(query,ignoreCase=true) ||
                    entry.prefix.contains(query,ignoreCase=true)
            }
            if(BuildConfig.SPDECODE_CLOUD_ENABLED && textResults.isNotEmpty()) {
                item(key="cloud-text-title") {
                    Text(stringResource(R.string.text_decode_title)+" · "+
                        stringResource(R.string.formats_cloud_ready_short),
                        color=White,fontSize=17.sp,fontWeight=FontWeight.Bold,
                        modifier=Modifier.padding(top=20.dp,bottom=8.dp))
                }
                items(textResults,key={ "text:"+it.prefix }) { entry ->
                    Column(modifier=Modifier.fillMaxWidth().padding(vertical=7.dp),
                        verticalArrangement=Arrangement.spacedBy(4.dp)) {
                        Text(entry.name,color=White,fontSize=14.sp,
                            fontWeight=FontWeight.SemiBold)
                        Text(entry.prefix,color=Secondary,fontSize=12.sp)
                    }
                    HorizontalDivider(color=Outline)
                }
            }
        }
    }
}
/**
 * Server VPN is an opt-in catalog reader, not another file decoding shortcut.
 * The NUR logo slot will use the supplied app artwork when available.
 */
@Composable
private fun ServerVpnScreen(
    busy:Boolean,
    apps:List<ServerVpnApp>,
    catalogLoading:Boolean,
    catalogUnavailable:Boolean,
    onDecodeCatalog:()->Unit,
    onDecodeApp:(String)->Unit,
    catalogProgress:Int?=null,
) {
    var selected by rememberSaveable { mutableStateOf(false) }
    var selectedId by rememberSaveable { mutableStateOf("") }
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf(ServerVpnListFilter.ALL) }
    val context=LocalContext.current
    val favoritesStore=remember(context) { ServerVpnFavorites(context) }
    var favoriteIds by remember(favoritesStore) { mutableStateOf(favoritesStore.read()) }
    val visibleApps=remember(apps,query,filter,favoriteIds) {
        ServerVpnDirectory.visible(apps,query,filter,favoriteIds)
    }
    val newBadgeStore=remember(context) { ServerVpnNewBadges(context) }
    var newProviderIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var updatedProviderIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    // New providers and method revisions use independent device-local timers.
    LaunchedEffect(apps,newBadgeStore) {
        if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
            while(true) {
                val snapshot=newBadgeStore.observeCatalog(apps.map { it.id }.toSet())
                val methodSnapshot=newBadgeStore.observeMethods(
                    apps.associate { it.id to it.methodRevision })
                newProviderIds=snapshot.ids
                updatedProviderIds=methodSnapshot.ids
                val nearest=listOfNotNull(snapshot.nextExpiryMs,
                    methodSnapshot.nextExpiryMs).minOrNull() ?:break
                // The same device clock controls the expiry even when the user
                // remains on this screen; reopening never restarts the timer.
                delay(nearest.coerceAtLeast(1L))
            }
        }
    }
    Column(Modifier.fillMaxSize().padding(horizontal=20.dp,vertical=12.dp),
        verticalArrangement=Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.server_vpn),fontSize=24.sp,
            fontWeight=FontWeight.Bold,color=White)
        Text(stringResource(R.string.server_vpn_description),fontSize=13.sp,
            lineHeight=20.sp,color=Secondary)
        if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
            OutlinedTextField(
                value=query,onValueChange={query=it},
                placeholder={Text(stringResource(R.string.server_vpn_search_hint))},
                leadingIcon={Icon(Icons.Outlined.Search,null)},
                trailingIcon={
                    if(query.isNotEmpty()) IconButton(onClick={query=""}) {
                        Icon(Icons.Outlined.Close,stringResource(R.string.close))
                    }
                },
                singleLine=true,modifier=Modifier.fillMaxWidth(),
                shape=RoundedCornerShape(16.dp),
                colors=OutlinedTextFieldDefaults.colors(
                    focusedBorderColor=Color(0xFF8873AC),
                    unfocusedBorderColor=Color(0xFF565656),
                    focusedTextColor=White,unfocusedTextColor=White,
                    cursorColor=White,
                    focusedPlaceholderColor=Secondary,
                    unfocusedPlaceholderColor=Secondary,
                ),
            )
            FlowRow(
                horizontalArrangement=Arrangement.spacedBy(7.dp),
                verticalArrangement=Arrangement.spacedBy(4.dp),
            ) {
                FilterChip(
                    selected=filter==ServerVpnListFilter.ALL,
                    onClick={filter=ServerVpnListFilter.ALL},
                    shape=RoundedCornerShape(12.dp),
                    colors=FilterChipDefaults.filterChipColors(
                        containerColor=Background,labelColor=Secondary,
                        selectedContainerColor=Color(0xFF4E455E),
                        selectedLabelColor=White),
                    label={Text(stringResource(R.string.server_vpn_filter_all))},
                )
                FilterChip(
                    selected=filter==ServerVpnListFilter.ENABLED,
                    onClick={filter=ServerVpnListFilter.ENABLED},
                    shape=RoundedCornerShape(12.dp),
                    colors=FilterChipDefaults.filterChipColors(
                        containerColor=Background,labelColor=Secondary,
                        selectedContainerColor=Color(0xFF4E455E),
                        selectedLabelColor=White),
                    label={Text(stringResource(R.string.server_vpn_filter_enabled))},
                )
                FilterChip(
                    selected=filter==ServerVpnListFilter.FAVORITES,
                    onClick={filter=ServerVpnListFilter.FAVORITES},
                    shape=RoundedCornerShape(12.dp),
                    colors=FilterChipDefaults.filterChipColors(
                        containerColor=Background,labelColor=Secondary,
                        selectedContainerColor=Color(0xFF4E455E),
                        selectedLabelColor=White),
                    label={Text(stringResource(R.string.server_vpn_filter_favorites))},
                    leadingIcon={Icon(Icons.Outlined.StarBorder,null,
                        modifier=Modifier.size(16.dp))},
                )
            }
            if(catalogLoading) {
                Row(verticalAlignment=Alignment.CenterVertically) {
                    CircularProgressIndicator(modifier=Modifier.size(18.dp),
                        strokeWidth=2.dp,color=White)
                    Spacer(Modifier.width(9.dp))
                    Text(if(catalogProgress!=null)
                        stringResource(R.string.catalog_progress,catalogProgress)
                        else stringResource(R.string.catalog_checking),
                        color=Secondary,fontSize=12.sp)
                }
            }
            if(apps.isEmpty()) {
                Text(stringResource(if(catalogLoading) R.string.server_vpn_loading
                    else R.string.server_vpn_unavailable),
                    color=Secondary,fontSize=13.sp)
                if(catalogUnavailable && !catalogLoading) {
                    Text(stringResource(R.string.server_vpn_retry),
                        color=Secondary,fontSize=12.sp)
                }
            }else if(visibleApps.isEmpty()) {
                Text(stringResource(R.string.server_vpn_no_matches),
                    color=Secondary,fontSize=13.sp)
            }else{
                LazyColumn(
                    modifier=Modifier.weight(1f),
                    verticalArrangement=Arrangement.spacedBy(9.dp),
                    contentPadding=PaddingValues(bottom=20.dp),
                ) {
                    items(visibleApps,key={it.id}) { app ->
                        val expanded=selectedId==app.id
                        Column(verticalArrangement=Arrangement.spacedBy(7.dp)) {
                            Surface(
                                modifier=Modifier.fillMaxWidth().clickable {
                                    selectedId=if(expanded)"" else app.id
                                },
                                color=Panel,shape=RoundedCornerShape(15.dp),
                                border=BorderStroke(1.dp,Outline),
                            ) {
                                Row(Modifier.padding(12.dp),
                                    verticalAlignment=Alignment.CenterVertically) {
                                    Surface(color=Raised,shape=RoundedCornerShape(13.dp),
                                        modifier=Modifier.size(52.dp)) {
                                        Box(contentAlignment=Alignment.Center) {
                                            val visibleIcon by produceState(app.icon,app) {
                                                value=kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {app.iconLoader?.invoke()?:app.icon}
                                            }
                                            Image(bitmap=visibleIcon.asImageBitmap(),
                                                contentDescription=app.name,
                                                modifier=Modifier.size(36.dp))
                                        }
                                    }
                                    Spacer(Modifier.width(12.dp))
                                    Column(Modifier.weight(1f),
                                        verticalArrangement=Arrangement.spacedBy(4.dp)) {
                                        Text(app.name,color=White,fontSize=15.sp,
                                            fontWeight=FontWeight.SemiBold,
                                            maxLines=2,overflow=TextOverflow.Ellipsis)
                                        
                                        Text(stringResource(when {
                                            app.maintenance -> R.string.server_vpn_maintenance_detail
                                            app.decodeEnabled -> R.string.server_vpn_catalog_enabled
                                            else -> R.string.server_vpn_catalog_disabled
                                        }),color=Secondary,fontSize=11.sp)
                                        when(ServerVpnBadgePriority.resolve(
                                            maintenance=app.maintenance,
                                            updated=app.id in updatedProviderIds,
                                            newlyAdded=app.id in newProviderIds)) {
                                            ServerVpnBadgeType.MAINTENANCE -> ServerVpnStatusTag(
                                                R.string.server_vpn_maintenance_badge,
                                                "server_vpn_maintenance_badge")
                                            ServerVpnBadgeType.UPDATED -> ServerVpnStatusTag(
                                                R.string.server_vpn_updated_badge,
                                                "server_vpn_updated_badge")
                                            ServerVpnBadgeType.NEW -> ServerVpnNewTag()
                                            null -> Unit
                                        }
                                    }
                                    val isFavorite=app.id in favoriteIds
                                    IconButton(
                                        onClick={favoriteIds=favoritesStore.toggle(app.id)},
                                        modifier=Modifier.size(40.dp),
                                    ) {
                                        Icon(if(isFavorite) Icons.Outlined.Star
                                            else Icons.Outlined.StarBorder,
                                            stringResource(if(isFavorite)
                                                R.string.server_vpn_favorite_remove
                                                else R.string.server_vpn_favorite_add),
                                            tint=if(isFavorite) Color(0xFFB895EC) else Secondary)
                                    }
                                    Icon(if(expanded) Icons.Outlined.ExpandLess
                                        else Icons.Outlined.ChevronRight,
                                        null,tint=Secondary,modifier=Modifier.size(20.dp))
                                }
                            }
                            if(expanded) {
                                Surface(color=Panel,shape=RoundedCornerShape(15.dp),
                                    modifier=Modifier.fillMaxWidth()) {
                                    Column(Modifier.padding(15.dp)) {
                                        Button(
                                            onClick={
                                                if(app.id=="nur-tunnel")onDecodeCatalog()
                                                else onDecodeApp(app.id)
                                            },
                                            enabled=!busy && app.decodeEnabled && !app.maintenance,
                                            modifier=Modifier.fillMaxWidth()
                                                .heightIn(min=50.dp),
                                            shape=RoundedCornerShape(13.dp),
                                            colors=ButtonDefaults.buttonColors(
                                                containerColor=Raised,contentColor=White),
                                        ) {
                                            Icon(Icons.Outlined.CloudDownload,null,
                                                modifier=Modifier.size(19.dp))
                                            Spacer(Modifier.width(8.dp))
                                            Text(stringResource(R.string.nur_servers_decode))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }else{
            Column(Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement=Arrangement.spacedBy(14.dp)) {
        Surface(
            modifier=Modifier.fillMaxWidth().clickable { selected=!selected },
            shape=RoundedCornerShape(15.dp),color=Panel,
            border=BorderStroke(1.dp,Outline),
        ) {
            Row(Modifier.padding(15.dp),verticalAlignment=Alignment.CenterVertically) {
                Surface(color=Raised,shape=RoundedCornerShape(13.dp),
                    modifier=Modifier.size(52.dp)) {
                    Box(contentAlignment=Alignment.Center) {
                        Image(
                            painter=painterResource(id=R.drawable.nur_tunnel_icon),
                            contentDescription=stringResource(R.string.nur_tunnel_name),
                            modifier=Modifier.size(36.dp)
                        )
                    }
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(5.dp)) {
                    Text(stringResource(R.string.nur_tunnel_name),color=White,
                        fontSize=16.sp,fontWeight=FontWeight.SemiBold)
                    Text(stringResource(R.string.nur_servers_description),color=Secondary,
                        fontSize=12.sp,lineHeight=17.sp)
                }
                Icon(if(selected)Icons.Outlined.ExpandLess else Icons.Outlined.ChevronRight,
                    null,tint=Secondary)
            }
        }
        if(selected) {
            Surface(color=Panel,shape=RoundedCornerShape(15.dp),
                modifier=Modifier.fillMaxWidth()) {
                Column(Modifier.padding(15.dp),verticalArrangement=Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.nur_servers_privacy),
                        fontSize=12.sp,lineHeight=18.sp,color=Secondary)
                    Button(onClick=onDecodeCatalog,
                        enabled=!busy,
                        modifier=Modifier.fillMaxWidth().heightIn(min=50.dp),
                        shape=RoundedCornerShape(13.dp),
                        colors=ButtonDefaults.buttonColors(containerColor=Raised,
                            contentColor=White,disabledContainerColor=Raised,
                            disabledContentColor=Secondary)) {
                        Icon(Icons.Outlined.CloudDownload,null,modifier=Modifier.size(19.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.nur_servers_decode))
                    }
                }
            }
        }
            }
        }
    }
}

/** Neutral accessible labels; maintenance has priority over Updated and New. */
@Composable
private fun ServerVpnStatusTag(label:Int,tag:String) {
    Surface(
        color=Raised,shape=RoundedCornerShape(10.dp),
        border=BorderStroke(1.dp,Color(0xFF818181)),
        modifier=Modifier.testTag(tag),
    ) {
        Text(stringResource(label),color=White,fontSize=10.sp,
            maxLines=1,fontWeight=FontWeight.SemiBold,
            modifier=Modifier.padding(horizontal=7.dp,vertical=4.dp))
    }
}

/** Neutral, readable, reusable two-hour marker for new client features and VPNs. */
@Composable
private fun ServerVpnNewTag() {
    Surface(
        color=Color(0xFF352945),
        shape=RoundedCornerShape(10.dp),
        border=BorderStroke(1.dp,Color(0xFFA581D9)),
        modifier=Modifier.testTag("server_vpn_new_badge"),
    ) {
        Text(
            stringResource(R.string.server_vpn_new_badge),
            color=Color(0xFFE4D7FF),
            fontSize=10.sp,
            maxLines=1,
            fontWeight=FontWeight.SemiBold,
            modifier=Modifier.padding(horizontal=7.dp,vertical=4.dp),
        )
    }
}

@Composable
private fun CardText(value:String) {
    Surface(color=Panel,shape=RoundedCornerShape(15.dp),modifier=Modifier.fillMaxWidth()){
        Text(value,modifier=Modifier.padding(20.dp),color=Secondary,fontSize=14.sp)
    }
}

@Composable
private fun BottomTabs(active:Int,onTab:(Int)->Unit,spotlight:Int?=null) {
    val tabs=listOf(
        Triple(R.string.home,Icons.Outlined.Home,0),
        Triple(R.string.history,Icons.Outlined.History,1),
        Triple(R.string.apk_analysis_title,Icons.Outlined.Android,2),
        Triple(R.string.server_vpn,Icons.Outlined.Dns,3),
        Triple(R.string.settings,Icons.Outlined.Settings,4)
    )
    HorizontalDivider(color=Outline)
    Row(Modifier.fillMaxWidth().heightIn(min=65.dp).padding(bottom=2.dp),
        verticalAlignment=Alignment.CenterVertically){
        tabs.forEach{(label,icon,index)->
            val selected=active==index
            Column(Modifier.weight(1f).clickable{onTab(index)}
                    .onGloballyPositioned{ if(index in 1..4) GuideSpotlightTargets.locate(index+3,it.boundsInWindow()) }
                    .then(if(spotlight==index) Modifier
                        .background(Raised,RoundedCornerShape(11.dp))
                        .border(2.dp,Color(0xFF80E6FF),RoundedCornerShape(11.dp))
                        .padding(horizontal=2.dp) else Modifier)
                    .padding(vertical=9.dp),
                horizontalAlignment=Alignment.CenterHorizontally,
                verticalArrangement=Arrangement.spacedBy(4.dp)){
                Icon(icon,stringResource(label),
                    tint=if(selected)White else Secondary,modifier=Modifier.size(21.dp))
                Text(if(index==2) "APK" else stringResource(label),fontSize=11.sp,
                    color=if(selected)White else Secondary,
                    maxLines=1,overflow=TextOverflow.Ellipsis)
            }
        }
    }
}
