package com.ghostdeveloper.spdecode

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.Context
import android.content.res.Configuration
import android.content.ActivityNotFoundException
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.work.WorkManager
import androidx.work.WorkInfo
import androidx.activity.viewModels
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.ghostdeveloper.spdecode.cloud.CloudNewsNotice
import com.ghostdeveloper.spdecode.cloud.CloudWhatsNewRepository
import com.ghostdeveloper.spdecode.cloud.CloudDecodeClient
import com.ghostdeveloper.spdecode.cloud.CloudDiagnosticsPrivacy
import com.ghostdeveloper.spdecode.cloud.CloudCredentialPolicy
import com.ghostdeveloper.spdecode.cloud.CloudUserErrors
import com.ghostdeveloper.spdecode.cloud.NpvsPasswordProbe
import com.ghostdeveloper.spdecode.cloud.V2BoxPasswordProbe
import com.ghostdeveloper.spdecode.cloud.CloudFileFormats
import com.ghostdeveloper.spdecode.cloud.CloudTextFormats
import com.ghostdeveloper.spdecode.cloud.CloudTextRoute
import com.ghostdeveloper.spdecode.cloud.CloudCatalogUpdates
import com.ghostdeveloper.spdecode.cloud.CloudLegalConsent
import com.ghostdeveloper.spdecode.cloud.CloudLegalConsentDialog
import com.ghostdeveloper.spdecode.cloud.ServerVpnApp
import com.ghostdeveloper.spdecode.cloud.ServerVpnCatalogRepository
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.ghostdeveloper.spdecode.parity.HcHccfgPort
import com.ghostdeveloper.spdecode.parity.GenericVpnPort
import com.ghostdeveloper.spdecode.parity.UltraSandokPort
import com.ghostdeveloper.spdecode.parity.RenzPort
import com.ghostdeveloper.spdecode.parity.LinkLayerPort
import com.ghostdeveloper.spdecode.parity.NpvsPort
import com.ghostdeveloper.spdecode.parity.NurTunnelPort
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.first
import android.os.SystemClock
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.Locale
import java.text.DateFormat
import java.util.Date

/**
 * C4: Cloud transport replaces decoding behind the existing UI, history
 * and progress flows in enabled builds. Legacy mode is retained only for
 * regression checks until C5 removes client-side decoder material.
 */
class MainActivity : ComponentActivity() {
    private companion object { const val MAX_BYTES=1024*1024 }
    private val scope=CoroutineScope(SupervisorJob()+Dispatchers.Main.immediate)
    private val cloudClient by lazy { CloudDecodeClient(this) }
    private val serverVpnCatalog by lazy { ServerVpnCatalogRepository(this,cloudClient) }
    private val cloudNewsRepository by lazy { CloudWhatsNewRepository(this,cloudClient) }
    private var serverVpnApps by mutableStateOf<List<ServerVpnApp>>(emptyList())
    private var fileFormats by mutableStateOf<List<AndroidDecoderCatalog.Format>>(emptyList())
    private var textRoutes by mutableStateOf<List<CloudTextRoute>>(emptyList())
    private var noticeTitle by mutableIntStateOf(R.string.decode_notice_title)
    private var availableAppUpdate by mutableStateOf<String?>(null)
    private var showCloudLegal by mutableStateOf(false)
    private var serverVpnRefresh:Job?=null
    private var serverVpnLoading by mutableStateOf(false)
    private var catalogProgress by mutableStateOf<Int?>(null)
    private var catalogTransfer by mutableStateOf<CatalogTransferUiState?>(null)
    private var catalogTransferGeneration=0
    private var serverVpnUnavailable by mutableStateOf(false)
    private var pendingServerVpnCatalogVersion by mutableStateOf<Int?>(null)
    private val privateCredentialVault by lazy { DevicePrivateCredentialVault(this) }
    private data class PendingCredentialImport(
        val uri:Uri,
        val filename:String,
        val bytes:ByteArray,
        val credentials:List<DevicePrivateCredentialVault.Metadata>,
        val requirements:HcHccfgPort.Requirements,
    )
    private var pendingCredentialImport by mutableStateOf<PendingCredentialImport?>(null)
    private data class PendingCloudPasswordFile(val uri:Uri,val name:String,
        val suffix:String,val bytes:ByteArray)
    private var pendingCloudPasswordFile by mutableStateOf<PendingCloudPasswordFile?>(null)
    private data class PendingCloudPasswordText(val text:String,val label:String)
    private var pendingCloudPasswordText by mutableStateOf<PendingCloudPasswordText?>(null)
    private var enteringHcManually by mutableStateOf(false)
    private var credentialPrepareJob:Job?=null
    private var credentialPrepareGeneration=0
    private var selectedLanguage by mutableStateOf("system")
    private var hideCredentials by mutableStateOf(false)
    private val settings get()=getSharedPreferences("spdecode-ui-preferences",MODE_PRIVATE)
    private var job:Job?=null
    private val services by lazy { (application as SpDecodeApplication).services }
    private val historyStore get()=services.records
    private val historyPreferences get()=services.preferences
    private var retentionDays by mutableIntStateOf(0)
    private var historyLoad: Deferred<Unit>? = null
    private val sessionVm by viewModels<DecodeSessionViewModel>()
    private val recent get()=sessionVm.recent
    private var result:DecodeView?
        get()=sessionVm.current
        set(value){sessionVm.current=value}
    private var tab:Int
        get()=sessionVm.tab
        set(value){sessionVm.tab=value}
    private var busy by mutableStateOf(false)
    private var progressStage by mutableIntStateOf(0)
    private var cloudProgressPhase by mutableStateOf<Int?>(null)
    private var progressFilename by mutableStateOf<String?>(null)
    private var progressPosition by mutableIntStateOf(1)
    private var progressTotal by mutableIntStateOf(1)
    private var importGeneration=0
    private var navigationExplicit=false
    private var showBrandedSplash by mutableStateOf(true)
    private var showWhatsNew by mutableStateOf(false)
    private var cloudWhatsNew by mutableStateOf<CloudNewsNotice?>(null)
    private var newsJob:Job?=null
    private var guideStep by mutableStateOf<Int?>(null)
    private var runningVersionCode=0L
    private var message by mutableStateOf<String?>(null)
    private var messageIsCredentialNotice by mutableStateOf(false)
    private var usageOptIn by mutableStateOf(false)
    private var catalogUpdatesEnabled by mutableStateOf(false)
    private var catalogWatchJob:Job?=null
    private var entryProbeJob:Job?=null
    private var availableAppUpdateCode by mutableIntStateOf(0)
    private var reportBusy by mutableStateOf(false)
    private var reveal:Boolean
        get()=sessionVm.reveal
        set(value){sessionVm.reveal=value}
    private var stagedExport:String?=null
    private var runtimeObservation:Job?=null

    // Event-driven own-process inspection off the main thread. No permanent
    // service, package scans, timers, or raw module/debug logs.
    private fun observeRuntime() {
        runtimeObservation?.cancel()
        runtimeObservation=scope.launch(Dispatchers.IO) {
            runCatching { com.ghostdeveloper.spdecode.cloud.CloudNativeTransport.runtimeReport() }
        }
    }

    private val noticePermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted && CloudLegalConsent.accepted(this)) {
            com.ghostdeveloper.spdecode.cloud.CloudNotifications.setEnabled(this, true)
        }
    }

    private fun requestNoticePermissionAfterConsent() {
        if (!BuildConfig.SPDECODE_CLOUD_ENABLED || !CloudLegalConsent.accepted(this)) return
        val savedNoticePreferences = getSharedPreferences("spdecode-notifications", MODE_PRIVATE)
        // Honour a previous explicit in-app opt-out when upgrading.
        if (savedNoticePreferences.contains("enabled") &&
            !savedNoticePreferences.getBoolean("enabled", false)) return
        if (android.os.Build.VERSION.SDK_INT < 33) {
            com.ghostdeveloper.spdecode.cloud.CloudNotifications.setEnabled(this, true)
            return
        }
        if (com.ghostdeveloper.spdecode.cloud.CloudNotifications.allowed(this)) {
            com.ghostdeveloper.spdecode.cloud.CloudNotifications.setEnabled(this, true)
            return
        }
        val flags = getSharedPreferences("spdecode-notifications", MODE_PRIVATE)
        if (!flags.getBoolean("startup-permission-requested-v1", false)) {
            // Persist before launching: process death must not cause repeated prompts.
            flags.edit().putBoolean("startup-permission-requested-v1", true).apply()
            noticePermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }
    }


    private fun syncOptInUsage() {
        if(!BuildConfig.SPDECODE_CLOUD_ENABLED||!CloudLegalConsent.accepted(this))return
        scope.launch {
            try {
                val id=withContext(Dispatchers.IO){
                    CloudDiagnosticsPrivacy.installationIdIfDue(this@MainActivity)
                }?:return@launch
                cloudClient.registerOptInActivity(id)
                withContext(Dispatchers.IO){CloudDiagnosticsPrivacy.markSent(this@MainActivity)}
            }catch(e:CancellationException){throw e}
             catch(_:Exception){ /* Anonymous opt-in telemetry never interrupts decoding. */ }
        }
    }

    private fun sendCurrentFailureReport() {
        if(reportBusy||!BuildConfig.SPDECODE_CLOUD_ENABLED)return
        val details=cloudClient.lastDiagnostic?:return
        if(message==null||!CloudLegalConsent.accepted(this))return
        reportBusy=true
        scope.launch {
            try{
                val id=cloudClient.reportFailure(details)
                message=getString(R.string.cloud_report_sent,id.take(8))
                cloudClient.clearLastDiagnostic()
            }catch(e:CancellationException){throw e}
             catch(_:Exception){message=getString(R.string.cloud_report_failed)}
            finally{reportBusy=false}
        }
    }

    /** Direct VPS watch runs only while the application is visible. */
    private fun startCatalogWatch(){
        if(showCloudLegal || !BuildConfig.SPDECODE_CLOUD_ENABLED ||
            catalogWatchJob?.isActive==true)return
        catalogWatchJob=scope.launch {
            CloudCatalogUpdates.watchWhileVisible(
                this@MainActivity,cloudClient,serverVpnCatalog
            ){version->
                if(version>serverVpnCatalog.currentVersion() &&
                    version>settings.getInt("last_dismissed_catalog_version",0))
                    pendingServerVpnCatalogVersion=version
            }
        }
    }

    /** Pending push hints are local state; navigation never probes the network. */
    private fun probeUpdatesOnEntry(){
        if(!BuildConfig.SPDECODE_CLOUD_ENABLED || showCloudLegal)return
        val latest=CloudCatalogUpdates.pendingVersion(this)
        if(latest>serverVpnCatalog.currentVersion() &&
            latest>settings.getInt("last_dismissed_catalog_version",0))
            pendingServerVpnCatalogVersion=latest
    }

    /** Server publication version is independent of the APK versionCode. */
    private fun refreshCloudWhatsNew() {
        if(!BuildConfig.SPDECODE_CLOUD_ENABLED || showCloudLegal ||
            newsJob?.isActive==true)return
        newsJob=scope.launch {
            try {
                val lastSeen=settings.getInt("last_seen_cloud_news_version",0)
                val next=cloudNewsRepository.latestUnseen(selectedLanguage,lastSeen)
                if(next!=null) {
                    cloudWhatsNew=next
                    showWhatsNew=true
                }
                val update=cloudNewsRepository.cachedAppUpdate()
                if(update!=null && update.first>BuildConfig.VERSION_CODE &&
                    update.first>settings.getInt("last_seen_app_update_code",0)) {
                    availableAppUpdate=update.second
                    availableAppUpdateCode=update.first
                }
            }catch(error:CancellationException){throw error}
             catch(_:Exception){ /* News failure must never prevent decoding or login. */ }
        }
    }

    /** Opening Server VPN without auto-updates reads cached icons only. */
    private fun refreshServerVpn(force:Boolean=false) {
        if(!BuildConfig.SPDECODE_CLOUD_ENABLED || showCloudLegal ||
            serverVpnRefresh?.isActive==true)return
        serverVpnLoading=true
        serverVpnUnavailable=false
        serverVpnRefresh=scope.launch {
            try {
                // Make supported extensions available before decoding and painting
                // the larger icon directory on low-end devices.
                fileFormats=serverVpnCatalog.cachedFormats()
                serverVpnApps=serverVpnCatalog.cached()
                    textRoutes=serverVpnCatalog.cachedTextFormats()
                if(force) {
                    serverVpnApps=serverVpnCatalog.refreshIfDue(force=force)
                    fileFormats=serverVpnCatalog.cachedFormats()
                    textRoutes=serverVpnCatalog.cachedTextFormats()
                }
            }catch(error:CancellationException){throw error}
             catch(_:Exception){ /* An authenticated cached snapshot remains usable. */ }
            finally {
                serverVpnUnavailable=serverVpnApps.isEmpty()
                serverVpnLoading=false
            }
        }
    }

    /** The refresh button asks locally; the confirmed action makes one catalog request. */
    private fun checkServerVpnUpdates() {
        if(!BuildConfig.SPDECODE_CLOUD_ENABLED || showCloudLegal || busy ||
            serverVpnRefresh?.isActive==true)return
        pendingServerVpnCatalogVersion=0 // manual refresh; no invented remote version
    }

    /** Explicit confirmation starts one cancellable, byte-measured catalog transfer. */
    private fun confirmServerVpnUpdate() {
        val version=pendingServerVpnCatalogVersion?:return
        pendingServerVpnCatalogVersion=null
        if(!BuildConfig.SPDECODE_CLOUD_ENABLED || showCloudLegal || busy ||
            serverVpnRefresh?.isActive==true)return
        val generation=++catalogTransferGeneration
        catalogTransfer=CatalogTransferUiState()
        serverVpnLoading=true
        catalogProgress=null
        serverVpnRefresh=scope.launch {
            try {
                val apps=serverVpnCatalog.refreshIfDue(
                    force=true,announcedVersion=version,
                    onTransfer={received,total->
                        scope.launch(Dispatchers.Main.immediate) {
                            if(generation==catalogTransferGeneration &&
                                catalogTransfer?.completed==false)
                                catalogTransfer=CatalogTransferUiState(received,total)
                        }
                    })
                if(generation!=catalogTransferGeneration)return@launch
                serverVpnApps=apps
                fileFormats=serverVpnCatalog.cachedFormats()
                textRoutes=serverVpnCatalog.cachedTextFormats()
                if(version!=0 && serverVpnCatalog.currentVersion()<version){
                    catalogTransfer=null
                    toast(R.string.server_vpn_catalog_update_error)
                }else catalogTransfer=CatalogTransferUiState(completed=true)
            }catch(error:CancellationException){throw error}
             catch(_:Exception){
                if(generation==catalogTransferGeneration) {
                    catalogTransfer=null
                    toast(R.string.server_vpn_catalog_update_error)
                }
             }finally {
                if(generation==catalogTransferGeneration) {
                    serverVpnUnavailable=serverVpnApps.isEmpty()
                    serverVpnLoading=false
                    catalogProgress=null
                }
             }
        }
    }

    /** Cancellation never replaces the previously verified encrypted catalog. */
    private fun cancelCatalogDownload() {
        catalogTransferGeneration++
        com.ghostdeveloper.spdecode.cloud.CloudNativeTransport.cancelCatalogDownload()
        serverVpnRefresh?.cancel()
        catalogTransfer=null
        catalogProgress=null
        serverVpnLoading=false
    }

    private fun requireCloudLegal():Boolean {
        if(!BuildConfig.SPDECODE_CLOUD_ENABLED || CloudLegalConsent.accepted(this))return true
        showCloudLegal=true
        return false
    }

    private fun openLegalPage(url:String) {
        if(url!=CloudLegalConsent.TERMS && url!=CloudLegalConsent.PRIVACY)return
        try {startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(url)))}
        catch(_:ActivityNotFoundException){toast(R.string.read_error)}
    }

    override fun attachBaseContext(base:Context) {
        val tag=base.getSharedPreferences("spdecode-ui-preferences",Context.MODE_PRIVATE)
            .getString("language","system") ?: "system"
        if(tag=="system") {
            super.attachBaseContext(base)
        }else {
            val locale=Locale.forLanguageTag(tag)
            val config=Configuration(base.resources.configuration)
            config.setLocale(locale)
            config.setLayoutDirection(locale)
            super.attachBaseContext(base.createConfigurationContext(config))
        }
    }

    private val picker=registerForActivityResult(ActivityResultContracts.OpenDocument()){uri->
        if(uri!=null)prepareSingleImport(uri)
    }
    private val multiPicker=registerForActivityResult(ActivityResultContracts.OpenMultipleDocuments()){uris->
        if(uris.isNotEmpty())importFiles(uris.take(BatchImportQueue.MAX_FILES))
    }
    private val exporter=registerForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")){uri->saveExport(uri)}

    private val jsonExporter=registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")){uri->
        saveExport(uri)
    }

    private fun saveExport(uri:Uri?){
        val text=stagedExport
        stagedExport=null
        if(uri!=null && text!=null)scope.launch{
            try{
                withContext(Dispatchers.IO){
                    contentResolver.openOutputStream(uri,"w")?.use{
                        it.write(text.toByteArray(Charsets.UTF_8))
                        it.flush()
                    }?:throw IOException("Destination unavailable")
                }
                toast(R.string.saved)
             }catch(_:Exception){
            SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.EXPORT_FAILURE)
            toast(R.string.write_error)
        }
        }
    }

    private fun setLanguage(tag:String){
        if(!SupportedLanguages.supports(tag)||tag==selectedLanguage)return
        // Persist before scheduling Activity.recreate(); the new base context
        // must observe the same locale even under fast Compose/lifecycle changes.
        if(!settings.edit().putString("language",tag).commit())return
        selectedLanguage=tag
        // Finish the Compose click before tearing down its host Activity.
        // The ViewModel survives this configuration-style recreation.
        window.decorView.post {
            if(!isFinishing && !isDestroyed) recreate()
        }
    }

    private fun openExternal(url:String){
        // Exact official destinations only. Never accept an arbitrary URL.
        if(url !in setOf(
            AboutOfficialLinks.WEBSITE,
            AboutOfficialLinks.CHANNEL,
            AboutOfficialLinks.COMMUNITY,
            AboutOfficialLinks.CONTACT,
        ))return
        try {startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(url)))}
        catch(_:ActivityNotFoundException){toast(R.string.read_error)}
    }

    override fun onCreate(savedInstanceState:Bundle?){
        val splashStarted=SystemClock.elapsedRealtime()
        installSplashScreen()
        super.onCreate(savedInstanceState)
        // Fail closed for a release APK re-signed with an unknown certificate.
        if (!ReleaseIntegrity.isTrusted(this)) {
            finishAndRemoveTask()
            return
        }
        // A new launch starts with an empty Home result. Rotation keeps the
        // existing ViewModel result; neither case deletes encrypted history.
        if(savedInstanceState==null) {
            result=null
            tab=0
            reveal=false
        }
        selectedLanguage=settings.getString("language","system") ?: "system"
        hideCredentials=settings.getBoolean("mask_credentials",false)
        usageOptIn=BuildConfig.SPDECODE_CLOUD_ENABLED && CloudDiagnosticsPrivacy.enabled(this)
        @Suppress("DEPRECATION")
        val installed=packageManager.getPackageInfo(packageName,0)
        runningVersionCode=if(Build.VERSION.SDK_INT>=28)installed.longVersionCode else installed.versionCode.toLong()
        showWhatsNew=!BuildConfig.SPDECODE_CLOUD_ENABLED &&
            settings.getLong("last_seen_whats_new_version",0L)<runningVersionCode
        showCloudLegal=BuildConfig.SPDECODE_CLOUD_ENABLED && !CloudLegalConsent.accepted(this)
        if (!showCloudLegal) requestNoticePermissionAfterConsent()
        catalogUpdatesEnabled=CloudCatalogUpdates.enabled(this)
        if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
            // Refresh the visible provider list as soon as a background push completes.
            WorkManager.getInstance(this).getWorkInfosForUniqueWorkLiveData(
                CloudCatalogUpdates.PUSH_WORK_NAME
            ).observe(this) { states ->
                if(states.any { it.state==WorkInfo.State.SUCCEEDED } &&
                    !showCloudLegal)refreshServerVpn()
            }
        }
        if(!showCloudLegal){refreshServerVpn();syncOptInUsage();CloudCatalogUpdates.ensureScheduled(this);refreshCloudWhatsNew()}
        if(savedInstanceState==null && !settings.getBoolean("first_run_guide_completed",false))
            guideStep=0
        @Suppress("DEPRECATION")
        window.statusBarColor=android.graphics.Color.BLACK
        @Suppress("DEPRECATION")
        window.navigationBarColor=android.graphics.Color.BLACK
        window.decorView.systemUiVisibility=0

        historyLoad = scope.async {
            try {
                val preferences = historyPreferences.values.first()
                retentionDays=preferences.retentionDays
                // Keep retention settings. A new app launch always opens Home;
                // returning from Telegram or rotating the device keeps the live UI.
                val saved=withContext(Dispatchers.IO) {
                    val days=preferences.retentionDays
                    if(days>0) historyStore.pruneOlderThan(
                        System.currentTimeMillis()-days.toLong()*86_400_000L)
                    historyStore.load()
                }
                // Load the history list without automatically promoting an old
                // record to the Home result after an app restart.
                val existingIds=recent.map{it.id}.toSet()
                saved.filterNot{it.id in existingIds}.forEach{recent.add(it)}
            }catch(_:CancellationException){throw CancellationException()}
            catch(_:Exception){
                SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.HISTORY_READ_FAILURE)
                toast(R.string.history_storage_error)
            }
        }
        scope.launch {
            // The splash never blocks the user indefinitely if file I/O stalls.
            withTimeoutOrNull(5000L) { historyLoad?.await() }
            val elapsed=SystemClock.elapsedRealtime()-splashStarted
            // Minimum visible branded splash; avoid an artificial delay beyond history load.
            delay((1600L-elapsed).coerceAtLeast(0L))
            showBrandedSplash=false
        }
        setContent {
            SpDecodeAmoledTheme {
            if(showBrandedSplash) SpDecodeSplashScreen()
            else SpDecodeApp(
                activeTab=tab,
                current=result,
                session=recent,
                busy=busy,
                error=message,
                progressStage=progressStage,
                cloudProgressPhase=cloudProgressPhase,
                progressFilename=progressFilename,
                progressPosition=progressPosition,
                progressTotal=progressTotal,
                reveal=reveal,
                onTab={ newTab ->
                    navigationExplicit=true
                    // Explicit navigation to Settings must not leave the first-run
                    // overlay intercepting taps in the language picker.
                    if(newTab==4 && guideStep!=null)guideStep=null
                    tab=newTab
                    reveal=false
                    // Both screens use the already loaded, encrypted catalog snapshot.
                    scope.launch {
                        try { historyPreferences.setLastTab(newTab) }
                        catch(e:CancellationException){throw e}
                        catch(_:Exception){toast(R.string.history_storage_error)}
                    }
                },
                onImport={picker.launch(arrayOf("*/*"))},
                onImportMultiple={multiPicker.launch(arrayOf("*/*"))},
                onCancel={cancelImport()},
                onReveal={reveal=it},
                onCopy={format->result?.let { entry ->
                    val date=DateFormat.getDateTimeInstance(DateFormat.MEDIUM,
                        DateFormat.SHORT,resources.configuration.locales[0])
                        .format(Date(entry.savedAtMillis))
                    copy(TelegramResultCopy.clipboard(entry,format,date))
                }},
                onExport={format->result?.let{export(ResultPresentation.formatted(it.document,format),it.filename,format)}},
                selectedLanguage=selectedLanguage,
                hideCredentials=hideCredentials,
                onLanguage={tag->setLanguage(tag)},
                onMaskCredentials={value->hideCredentials=value;settings.edit().putBoolean("mask_credentials",value).apply()},
                onExternalLink={url->openExternal(url)},
                onFeedbackSubmit={draft-> cloudClient.submitFeedback(draft)},
                onSelect={selectResult(it)},
                onClear={clearHistory()},
                onClearResult={clearVisibleResult()},
                onDeleteSelected={ids->deleteHistory(ids)},
                onFavorite={id,favorite->updateFavorite(id,favorite)},
                retentionDays=retentionDays,
                onRetention={days->setRetention(days)},
                onDismissError={
                    message=null
                    messageIsCredentialNotice=false
                    cloudClient.clearLastDiagnostic()
                },
                errorTitle=noticeTitle,
                canReportError=BuildConfig.SPDECODE_CLOUD_ENABLED && !messageIsCredentialNotice &&
                    !reportBusy && cloudClient.lastDiagnostic!=null,
                onReportError={sendCurrentFailureReport()},
                onDecodeText={input->decodeText(input)},
                onDecodeCloud={reference->decodeCloud("auto",reference)},
                onDecodeServerCatalog={decodeNurServers()},
                onDecodeServerApp={id->decodeServerVpnProvider(id)},
                onLegalLink={which->
                    when(which) {
                        "terms"->openLegalPage(CloudLegalConsent.TERMS)
                        "privacy"->openLegalPage(CloudLegalConsent.PRIVACY)
                    }
                },
                usageAnalyticsEnabled=usageOptIn,
                onUsageAnalytics={enabled->
                    try{
                        CloudDiagnosticsPrivacy.setEnabled(this@MainActivity,enabled)
                        usageOptIn=enabled
                        if(enabled)syncOptInUsage()
                    }catch(_:Exception){message=getString(R.string.history_storage_error)}
                },
                catalogUpdatesEnabled=catalogUpdatesEnabled,
                onCatalogUpdates={enabled->
                    try {
                        CloudCatalogUpdates.setEnabled(this@MainActivity,enabled)
                        catalogUpdatesEnabled=CloudCatalogUpdates.enabled(this@MainActivity)
                        if(catalogUpdatesEnabled) {
                            startCatalogWatch()
                            if(tab==2 || tab==3)refreshServerVpn()
                        }else {
                            serverVpnRefresh?.cancel()
                            serverVpnLoading=false
                        }
                    }catch(_:Exception){message=getString(R.string.history_storage_error)}
                },
                onWithdrawCloudConsent={
                    if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
                        try {
                            CloudDiagnosticsPrivacy.setEnabled(this@MainActivity,false)
                            usageOptIn=false
                            CloudCatalogUpdates.setEnabled(this@MainActivity,false)
                            catalogWatchJob?.cancel()
                            catalogUpdatesEnabled=false
                            CloudLegalConsent.revoke(this@MainActivity)
                            cloudClient.clearSession()
                            serverVpnRefresh?.cancel()
                            job?.cancel()
                            serverVpnApps=emptyList()
                            fileFormats=emptyList()
                            textRoutes=emptyList()
                            availableAppUpdate=null
                            pendingServerVpnCatalogVersion=null
                            showCloudLegal=true
                        }catch(_:Exception){message=getString(R.string.history_storage_error)}
                    }
                },
                serverVpnApps=serverVpnApps,
                cloudFormats=fileFormats,
                cloudTextFormats=textRoutes,
                serverVpnLoading=serverVpnLoading,
                catalogProgress=catalogProgress,
                catalogTransfer=catalogTransfer,
                onCancelCatalogTransfer={cancelCatalogDownload()},
                onFinishCatalogTransfer={catalogTransfer=null},
                serverVpnUnavailable=serverVpnUnavailable,
                onRefreshServerVpn={checkServerVpnUpdates()},
                pendingServerVpnCatalogVersion=pendingServerVpnCatalogVersion,
                availableAppUpdate=availableAppUpdate,
                onDismissAppUpdate={
                    if(availableAppUpdateCode>0)settings.edit()
                        .putInt("last_seen_app_update_code",availableAppUpdateCode).apply()
                    availableAppUpdate=null
                },
                onConfirmServerVpnUpdate={confirmServerVpnUpdate()},
                onDismissServerVpnUpdate={
                    pendingServerVpnCatalogVersion?.let {version ->
                        settings.edit().putInt("last_dismissed_catalog_version",version).apply()
                    }
                    pendingServerVpnCatalogVersion=null
                },
                whatsNew=showWhatsNew,
                cloudWhatsNew=cloudWhatsNew,
                onDismissWhatsNew={
                    if(BuildConfig.SPDECODE_CLOUD_ENABLED){
                        cloudWhatsNew?.let { news ->
                            settings.edit().putInt("last_seen_cloud_news_version",news.version).apply()
                        }
                        cloudWhatsNew=null
                    }else{
                        settings.edit().putLong("last_seen_whats_new_version",runningVersionCode).apply()
                    }
                    showWhatsNew=false
                },
                guideStep=guideStep,
                onGuideNext={
                    val next=(guideStep ?: 0)+1
                    if(next>=FirstRunGuide.STEPS) {
                        guideStep=null
                        settings.edit().putBoolean("first_run_guide_completed",true).apply()
                        tab=0
                    }else {
                        guideStep=next
                        tab=FirstRunGuide.targetTab(next)
                    }
                },
                onGuideSkip={
                    guideStep=null
                    settings.edit().putBoolean("first_run_guide_completed",true).apply()
                    tab=0
                },
                onGuideRestart={
                    guideStep=0
                    tab=0
                },
            )
            if(!showBrandedSplash && showCloudLegal && !showWhatsNew) {
                CloudLegalConsentDialog(
                    onTerms={openLegalPage(CloudLegalConsent.TERMS)},
                    onPrivacy={openLegalPage(CloudLegalConsent.PRIVACY)},
                    onAccept={
                        try {
                            CloudLegalConsent.accept(this@MainActivity)
                            showCloudLegal=false
                            requestNoticePermissionAfterConsent()
                            refreshServerVpn()
                            refreshCloudWhatsNew()
                            probeUpdatesOnEntry()
                            syncOptInUsage()
                            if(savedInstanceState==null && !showCloudLegal)handleExternalIntent(intent)
                        }catch(_:Exception){message=getString(R.string.history_storage_error)}
                    },
                    onDecline={finishAffinity()},
                )
            }
            if(!busy) pendingCloudPasswordFile?.let { candidate ->
                CloudPasswordDialog(candidate.name,
                    onSubmit={value->submitCloudFilePassword(value)},
                    onCancel={clearPendingCloudPassword()})
            }
            if(!busy) pendingCloudPasswordText?.let { candidate ->
                CloudPasswordDialog(candidate.label,
                    onSubmit={password->
                        pendingCloudPasswordText=null
                        decodeText(candidate.text,password.toByteArray(Charsets.UTF_8))
                    },
                    onCancel={pendingCloudPasswordText=null})
            }
            pendingCredentialImport?.let { candidate ->
                if(enteringHcManually || candidate.requirements.hwidRequired ||
                    candidate.credentials.isEmpty()) {
                    HcProtectedImportDialog(
                        filename=candidate.filename,
                        requirements=candidate.requirements,
                        onSubmit={password,hwid->submitHcCredentials(password,hwid)},
                        onCancel={cancelPrivateCredentialSelection()},
                    )
                } else {
                    PrivateCredentialImportDialog(
                        filename=candidate.filename,
                        credentials=candidate.credentials,
                        onChoose={id->
                            if(id==null)enteringHcManually=true
                            else choosePrivateCredential(id)
                        },
                        onCancel={cancelPrivateCredentialSelection()},
                        onManual={enteringHcManually=true},
                    )
                }
            }
            }
        }
        if(savedInstanceState==null && !showCloudLegal)handleExternalIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        if(!ReleaseIntegrity.isTrusted(this)) {
            finishAndRemoveTask()
            return
        }
        observeRuntime()
        if(settings.getBoolean("private-screen",false))
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        else window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        if(!showCloudLegal){
            refreshServerVpn()
            syncOptInUsage()
            CloudCatalogUpdates.ensureScheduled(this)
            startCatalogWatch()
            probeUpdatesOnEntry()
            refreshCloudWhatsNew()
        }
    }

    override fun onNewIntent(intent:Intent){
        super.onNewIntent(intent)
        setIntent(intent)
        if(!showCloudLegal)handleExternalIntent(intent)
    }

    @Suppress("DEPRECATION")
    private fun handleExternalIntent(incoming:Intent?){
        if(incoming==null)return
        val uris=ExternalImportUris.resolve(incoming)
        if(uris.size==1)prepareSingleImport(uris.first())
        else if(uris.isNotEmpty())importFiles(uris.take(BatchImportQueue.MAX_FILES))
    }

    /**
     * Preview one .hc locally. Only authenticated password-locked HCCFG
     * containers can request a saved private password. The same byte array
     * is decoded after authorization, so provider content cannot be swapped
     * between password selection and import.
     */
    private fun prepareSingleImport(uri:Uri) {
        if(!requireCloudLegal())return
        messageIsCredentialNotice=false
        clearPendingCloudPassword()
        pendingCredentialImport?.bytes?.fill(0)
        pendingCredentialImport=null
        enteringHcManually=false
        credentialPrepareJob?.cancel()
        val generation=++credentialPrepareGeneration
        credentialPrepareJob=scope.launch {
            var preview:ByteArray?=null
            try {
                val name=withContext(Dispatchers.IO){displayName(uri)}
                // Detect password-protected V2Box before attempting either decoder.
                // Reuse the existing one-shot password dialog in both build modes.
                if(ImportFilenameNormalizer.forDetection(name)
                    .endsWith(".v2box",ignoreCase=true)){
                    preview=withContext(Dispatchers.IO){readBounded(uri,2*1024*1024)}
                    if(V2BoxPasswordProbe.requiresPassword(preview) &&
                        generation==credentialPrepareGeneration){
                        pendingCloudPasswordFile=PendingCloudPasswordFile(
                            uri,name,"v2box",preview)
                        preview=null
                        return@launch
                    }
                    preview.fill(0)
                    preview=null
                }
                // A signed NPVS v5 passphrase envelope can be identified from
                // bounded local framing. Prompt without waiting for a server
                // that might still be running an older NPVS worker. Only the
                // Cloud worker validates the signature and decrypts the file.
                if(BuildConfig.SPDECODE_CLOUD_ENABLED &&
                    ImportFilenameNormalizer.forDetection(name)
                        .endsWith(".npvs",ignoreCase=true)){
                    preview=withContext(Dispatchers.IO){
                        readBounded(uri,CloudDecodeClient.MAX_INPUT)
                    }
                    if(NpvsPasswordProbe.requiresPassword(preview) &&
                        generation==credentialPrepareGeneration){
                        pendingCloudPasswordFile=PendingCloudPasswordFile(
                            uri,name,"npvs",preview)
                        preview=null // password dialog owns the same input bytes
                        return@launch
                    }
                    preview.fill(0)
                    preview=null
                }
                if(ImportFilenameNormalizer.forDetection(name).endsWith(".hc",ignoreCase=true)){
                    preview=withContext(Dispatchers.IO){readBounded(uri,
                        if(BuildConfig.SPDECODE_CLOUD_ENABLED) CloudDecodeClient.MAX_INPUT else MAX_BYTES)}
                    val requirements=if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
                        // HCCFG inspection may call the server before the normal import
                        // starts; it must show the same request phases and release the
                        // dialog before any password/HWID prompt is displayed.
                        val phaseGeneration=++importGeneration
                        busy=true
                        progressStage=1
                        cloudProgressPhase=0
                        progressPosition=1
                        progressTotal=1
                        progressFilename=name
                        message=null
                        try {
                            cloudClient.inspectHcRequirements(preview,
                                onPhase={phase->markCloudProgress(phaseGeneration,phase)})
                        } finally {
                            if(generation==credentialPrepareGeneration &&
                                phaseGeneration==importGeneration) {
                                busy=false
                                progressStage=0
                                cloudProgressPhase=null
                                progressFilename=null
                            }
                        }
                    } else HcHccfgPort.inspectRequirements(preview)
                    if(requirements?.requiresCredentials==true) {
                        val credentials=if(requirements.passwordRequired &&
                            !requirements.hwidRequired) withContext(Dispatchers.IO){
                                privateCredentialVault.inventory().entries
                            } else emptyList()
                        if(generation==credentialPrepareGeneration){
                            pendingCredentialImport=PendingCredentialImport(
                                uri,name,preview,credentials,requirements)
                            preview=null // pending dialog now owns the buffer
                            return@launch
                        }
                    }
                }
            }catch(e:CancellationException){throw e}
            catch(error:Exception) {
                // Cloud credential inspection can fail before any decoder runs.
                // Never disguise a missing QA code or network failure as a bad HC file.
                if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
                    if(generation==credentialPrepareGeneration)
                        message=com.ghostdeveloper.spdecode.cloud.CloudUserErrors.message(
                            this@MainActivity,error)
                    return@launch
                }
            }
            finally { preview?.fill(0) }
            if(generation==credentialPrepareGeneration) importFiles(listOf(uri))
        }
    }

    /** Pass caller-owned credential bytes only once; never persist either input. */
    private fun submitHcCredentials(password:String?,hwid:String?) {
        val request=pendingCredentialImport?:return
        val required=request.requirements
        val passwordBytes=if(required.passwordRequired)password?.toByteArray(Charsets.UTF_8)
            else null
        if((required.passwordRequired && (passwordBytes==null ||
                passwordBytes.isEmpty() || passwordBytes.size>4096)) ||
            (required.hwidRequired &&
                !hwid.orEmpty().trim().matches(Regex("[0-9a-fA-FhH]{32}")))) {
            passwordBytes?.fill(0)
            message=getString(R.string.hc_auth_input_invalid)
            return
        }
        pendingCredentialImport=null
        enteringHcManually=false
        importFiles(listOf(request.uri),prepared=request,
            hcPassword=passwordBytes,hcHwid=if(required.hwidRequired)hwid else null)
    }

    private fun choosePrivateCredential(id:String?) {
        val request=pendingCredentialImport?:return
        pendingCredentialImport=null
        enteringHcManually=false
        if(id!=null && request.credentials.none{it.id==id}){
            request.bytes.fill(0)
            return
        }
        importFiles(listOf(request.uri),id,request)
    }

    private fun cancelPrivateCredentialSelection() {
        pendingCredentialImport?.bytes?.fill(0)
        pendingCredentialImport=null
        enteringHcManually=false
    }

    private fun clearPendingCloudPassword() {
        pendingCloudPasswordFile?.bytes?.fill(0)
        pendingCloudPasswordFile=null
        pendingCloudPasswordText=null
    }

    private fun submitCloudFilePassword(value:String) {
        val request=pendingCloudPasswordFile?:return
        val pass=value.toByteArray(Charsets.UTF_8)
        if(pass.isEmpty()||pass.size>4096){pass.fill(0);return}
        pendingCloudPasswordFile=null
        importFiles(listOf(request.uri), cloudPrepared=request,cloudPassword=pass)
    }

    /** UI-only phases; cancelled imports cannot update later requests. */
    private suspend fun markCloudProgress(generation:Int,phase:CloudDecodeClient.TransferPhase) {
        withContext(Dispatchers.Main.immediate) {
            if(generation==importGeneration && busy) cloudProgressPhase=phase.ordinal
        }
    }

    private fun cancelImport() {
        // An obsolete worker must not close the new import's progress dialog.
        importGeneration++
        job?.cancel()
        job=null
        busy=false
        progressFilename=null
        cloudProgressPhase=null
    }

    // The Android editor accepts a complete pasted configuration once.
    // Telegram's multipart chat-session protocol does not apply here.
    private fun decodeText(userText:String,password:ByteArray?=null) {
        if(!requireCloudLegal())return
        messageIsCredentialNotice=false
        noticeTitle=R.string.decode_notice_title
        if(busy)return
        if(userText.isBlank()||userText.length>TextProtocolDecoder.MAX_CHARS) {
            message=getString(R.string.text_decode_invalid)
            return
        }
        val candidate=(if(BuildConfig.SPDECODE_CLOUD_ENABLED)
            CloudTextFormats.identify(userText,textRoutes) else null)
            ?:TextProtocolDecoder.identify(userText)
        if(candidate==null) {
            noticeTitle=R.string.unsupported_text_title
            message=getString(R.string.unsupported_text_detail)
            cloudClient.clearLastDiagnostic()
            return
        }
        val generation=++importGeneration
        job=scope.launch {
            busy=true
            progressStage=1
            cloudProgressPhase=if(BuildConfig.SPDECODE_CLOUD_ENABLED) 0 else null
            progressPosition=1
            progressTotal=1
            progressFilename=getString(R.string.text_decode_title)
            message=null
            reveal=false
            try {
                historyLoad?.await()
                val decoded=if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
                    cloudClient.decodeText(userText,password,
                        onPhase={phase->markCloudProgress(generation,phase)})
                } else withContext(Dispatchers.Default) {
                    TextProtocolDecoder.decode(this@MainActivity,candidate)
                }
                if(decoded==null) {
                    SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.TEXT_UNSUPPORTED)
                    noticeTitle=R.string.unsupported_text_title
                    message=getString(R.string.unsupported_text_detail)
                    return@launch
                }
                progressStage=2
                val safeName=candidate.protocol.removePrefix("g:")
                    .replace(':','-').filter { it.isLetterOrDigit()||it=='-' }
                val record=DecodeView("text-"+safeName+"."+candidate.suffix,
                    candidate.suffix,decoded,
                    userText.toByteArray(Charsets.UTF_8).size)
                val stored=try {
                    withContext(Dispatchers.IO){historyStore.save(record)}
                    true
                }catch(e:CancellationException){throw e}
                catch(_:Exception){
                    SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.HISTORY_WRITE_FAILURE)
                    false
                }
                result=record
                recent.add(0,record)
                if(!stored)toast(R.string.history_storage_error)
                try{historyPreferences.setSelectedId(record.id)}
                catch(e:CancellationException){throw e}
                catch(_:Exception){toast(R.string.history_storage_error)}
                tab=0
            }catch(e:CancellationException){throw e}
            catch(error:Exception){if(generation==importGeneration) {
                if(BuildConfig.SPDECODE_CLOUD_ENABLED && password==null &&
                    error is CloudDecodeClient.Failure && error.code=="PASSWORD_REQUIRED" &&
                    CloudCredentialPolicy.textAcceptsPassword(userText)) {
                    pendingCloudPasswordText=PendingCloudPasswordText(userText,candidate.app)
                    return@launch
                }
                val notice=BuildConfig.SPDECODE_CLOUD_ENABLED &&
                    CloudUserErrors.isInformational(error,candidate.suffix,
                        passwordSubmitted=password!=null)
                val incompatible=(error as? CloudDecodeClient.Failure)?.code in
                    setOf("UNSUPPORTED_VERSION","UNSUPPORTED_VARIANT","UNSUPPORTED_METHOD",
                        "UNSUPPORTED_CONFIG_VERSION","DECODE_FAILED")
                if(incompatible){
                    noticeTitle=R.string.unsupported_version_title
                    cloudClient.clearLastDiagnostic()
                }
                if((error as? CloudDecodeClient.Failure)?.code=="UNSUPPORTED_FORMAT") {
                    noticeTitle=R.string.unsupported_text_title
                    cloudClient.clearLastDiagnostic()
                }
                if(!notice)SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.TEXT_FAILURE)
                else cloudClient.clearLastDiagnostic()
                messageIsCredentialNotice=notice
                message=if((error as? CloudDecodeClient.Failure)?.code=="UNSUPPORTED_FORMAT")
                    getString(R.string.unsupported_text_detail)
                    else if(incompatible)getString(R.string.unsupported_version_detail)
                    else if(BuildConfig.SPDECODE_CLOUD_ENABLED)
                        CloudUserErrors.message(this@MainActivity,error,candidate.suffix,
                            passwordSubmitted=password!=null)
                    else getString(R.string.text_format_unsupported_contact)
            }
            }finally {
                password?.fill(0)
                if(generation==importGeneration) {
                    busy=false
                    progressFilename=null
                    progressStage=0
                    cloudProgressPhase=null
                }
            }
        }
    }

    /**
     * User-triggered, opt-in ONLINE import. No network request is made by any
     * offline file/text decoder, and a failed fetch never saves a result.
     */
    private fun decodeCloud(provider:String,reference:String) {
        if(!requireCloudLegal())return
        if(busy)return
        val target=com.ghostdeveloper.spdecode.cloud.CloudOnlineReference.resolve(
            reference,provider,textRoutes)
        if(target==null) {
            message=getString(R.string.cloud_global_invalid)
            return
        }
        val generation=++importGeneration
        job?.cancel()
        job=scope.launch {
            busy=true
            progressStage=1
            cloudProgressPhase=if(BuildConfig.SPDECODE_CLOUD_ENABLED) 0 else null
            progressPosition=1
            progressTotal=1
            progressFilename=target.name
            message=null
            reveal=false
            try {
                historyLoad?.await()
                val decoded=if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
                    cloudClient.decodeOnlineReference(target.provider,target.reference,
                        onPhase={phase->markCloudProgress(generation,phase)})
                } else if(target.provider=="ehi") withContext(Dispatchers.IO) {
                    val parsed=HttpInjectorCloudPort.parseReference(target.reference)
                    HttpInjectorCloudPort.decodeOnline(this@MainActivity,parsed)
                } else throw java.io.IOException("CLOUD_INVALID_INPUT")
                progressStage=2
                // Persist the decoded document, never the original cloud URL/token.
                val record=DecodeView(
                    target.filename,target.suffix,decoded,
                    reference.toByteArray(Charsets.UTF_8).size
                )
                val stored=try {
                    withContext(Dispatchers.IO){historyStore.save(record)}
                    true
                }catch(e:CancellationException){throw e}
                catch(_:Exception){
                    SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.HISTORY_WRITE_FAILURE)
                    false
                }
                result=record
                recent.add(0,record)
                if(!stored)toast(R.string.history_storage_error)
                try { historyPreferences.setSelectedId(record.id) }
                catch(e:CancellationException){throw e}
                catch(_:Exception){toast(R.string.history_storage_error)}
                tab=0
            }catch(e:CancellationException){throw e}
            catch(e:CloudDecodeClient.Failure) {
                if(generation==importGeneration)
                    message=if(target.provider=="ehi")
                        CloudUserErrors.httpInjectorMessage(this@MainActivity,e)
                        else CloudUserErrors.message(this@MainActivity,e)
            }catch(e:HttpInjectorCloudPort.CloudException) {
                if(generation==importGeneration)message=getString(when(e.reason) {
                    HttpInjectorCloudPort.Reason.REFERENCE->R.string.cloud_http_injector_invalid
                    HttpInjectorCloudPort.Reason.NETWORK->R.string.cloud_http_injector_network_error
                    HttpInjectorCloudPort.Reason.SERVER->R.string.cloud_http_injector_server_error
                    HttpInjectorCloudPort.Reason.INTEGRITY->R.string.cloud_http_injector_integrity_error
                    HttpInjectorCloudPort.Reason.DECODER->R.string.cloud_http_injector_decoder_error
                })
            }catch(error:Exception){
                if(generation==importGeneration)
                    message=if(BuildConfig.SPDECODE_CLOUD_ENABLED)
                        CloudUserErrors.message(this@MainActivity,error)
                        else getString(R.string.cloud_http_injector_network_error)
            }finally {
                if(generation==importGeneration) {
                    busy=false
                    progressFilename=null
                    progressStage=0
                    cloudProgressPhase=null
                }
            }
        }
    }

    /** User-triggered NUR catalog fetch; endpoint is read from the encrypted asset vault. */
    private fun decodeNurServers() {
        if(!requireCloudLegal())return
        if(busy)return
        val generation=++importGeneration
        job?.cancel()
        job=scope.launch {
            busy=true
            progressStage=1
            cloudProgressPhase=if(BuildConfig.SPDECODE_CLOUD_ENABLED) 0 else null
            progressPosition=1
            progressTotal=1
            progressFilename=getString(R.string.nur_tunnel_name)
            message=null
            reveal=false
            try {
                historyLoad?.await()
                val pair=if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
                    val decoded=cloudClient.decodeNurCatalog(
                        onPhase={phase->markCloudProgress(generation,phase)})
                    Pair(decoded.rawText,decoded.sourceBytes ?: 0)
                } else withContext(Dispatchers.IO) {
                    val url=NurTunnelServerCatalog.defaultUrl(this@MainActivity)
                    val encrypted=NurTunnelServerCatalog.download(url)
                    try {
                        val decoded=NurTunnelServerCatalog.decodeDownloaded(this@MainActivity,encrypted)
                        Pair(decoded,encrypted.size)
                    } finally { encrypted.fill(0) }
                }
                progressStage=2
                val record=DecodeView("nur-tunnel-servers.json","nurservers",
                    pair.first,pair.second)
                val saved=try {
                    withContext(Dispatchers.IO){historyStore.save(record)}
                    true
                }catch(e:CancellationException){throw e}
                catch(_:Exception) {
                    SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.HISTORY_WRITE_FAILURE)
                    false
                }
                result=record
                recent.add(0,record)
                if(!saved)toast(R.string.history_storage_error)
                try {historyPreferences.setSelectedId(record.id)}
                catch(e:CancellationException){throw e}
                catch(_:Exception){toast(R.string.history_storage_error)}
                tab=0
            }catch(e:CancellationException){throw e}
            catch(error:Exception) {
                if(generation==importGeneration) {
                    SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.FILE_IMPORT_FAILURE)
                    message=if(BuildConfig.SPDECODE_CLOUD_ENABLED)
                        com.ghostdeveloper.spdecode.cloud.CloudUserErrors.message(this@MainActivity,error)
                        else getString(R.string.nur_servers_failed)
                }
            }finally {
                if(generation==importGeneration) {
                    busy=false
                    progressStage=0
                    cloudProgressPhase=null
                    progressFilename=null
                }
            }
        }
    }

    private fun clearVisibleResult() {
        if(busy)return
        result=null
        reveal=false
        message=null
        scope.launch {
            // Only clear the obsolete selection pointer. Do NOT touch records.
            try { historyPreferences.setSelectedId(null) }
            catch(e:CancellationException){throw e}
            catch(_:Exception){toast(R.string.history_storage_error)}
        }
    }

    private fun selectResult(entry:DecodeView) {
        result=entry
        tab=0
        reveal=false
        scope.launch {
            try{historyPreferences.setSelectedId(entry.id)}
            catch(_:CancellationException){throw CancellationException()}
            catch(_:Exception){toast(R.string.history_storage_error)}
        }
    }

    private fun decodeServerVpnProvider(id:String) {
        if(!requireCloudLegal() || busy || !BuildConfig.SPDECODE_CLOUD_ENABLED)return
        val provider=serverVpnApps.firstOrNull { it.id==id && it.decodeEnabled }?:return
        if(!id.matches(Regex("[a-z0-9-]{1,48}")))return
        val generation=++importGeneration
        job?.cancel()
        job=scope.launch {
            busy=true
            progressStage=1
            cloudProgressPhase=0
            progressPosition=1
            progressTotal=1
            progressFilename=provider.name
            message=null
            reveal=false
            try {
                historyLoad?.await()
                val decoded=cloudClient.decodeServerVpnProvider(id,
                    onPhase={phase->markCloudProgress(generation,phase)})
                progressStage=2
                val record=DecodeView("server-vpn-$id.json","vpnservers",
                    decoded.rawText,decoded.sourceBytes?:0)
                val saved=try {
                    withContext(Dispatchers.IO){historyStore.save(record)}
                    true
                }catch(error:CancellationException){throw error}
                 catch(_:Exception){false}
                result=record
                recent.add(0,record)
                if(!saved)toast(R.string.history_storage_error)
                try {historyPreferences.setSelectedId(record.id)}
                catch(error:CancellationException){throw error}
                catch(_:Exception){toast(R.string.history_storage_error)}
                tab=0
            }catch(error:CancellationException){throw error}
             catch(error:Exception) {
                if(generation==importGeneration) {
                    SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.FILE_IMPORT_FAILURE)
                    message=com.ghostdeveloper.spdecode.cloud.CloudUserErrors.message(this@MainActivity,error)
                }
            }finally {
                if(generation==importGeneration) {
                    busy=false
                    progressStage=0
                    cloudProgressPhase=null
                    progressFilename=null
                }
            }
        }
    }

    private fun importFiles(uris:List<Uri>,
        privateCredentialId:String?=null,
        prepared:PendingCredentialImport?=null,
        hcPassword:ByteArray?=null,
        hcHwid:String?=null,
        cloudPrepared:PendingCloudPasswordFile?=null,
        cloudPassword:ByteArray?=null){
        if(!requireCloudLegal())return
        require(privateCredentialId==null || (uris.size==1 && prepared?.uri==uris.single()))
        require(cloudPrepared==null || (uris.size==1 && cloudPrepared.uri==uris.single()))
        require(cloudPassword==null || (cloudPrepared!=null && cloudPassword.isNotEmpty() &&
            cloudPassword.size<=4096))
        require((hcPassword==null && hcHwid==null) ||
            (uris.size==1 && prepared?.uri==uris.single() && privateCredentialId==null))
        job?.cancel()
        messageIsCredentialNotice=false
        noticeTitle=R.string.decode_notice_title
        val generation=++importGeneration
        val inputs=uris.take(BatchImportQueue.MAX_FILES)
        if(inputs.isEmpty())return
        job=scope.launch {
            busy=true
            progressStage=0
            cloudProgressPhase=null
            progressFilename=null
            progressPosition=1
            progressTotal=inputs.size
            message=null
            reveal=false
            try {
                historyLoad?.await()
                // Import routing always uses the latest authenticated encrypted local
                // snapshot, even when an external intent starts the Activity before
                // the asynchronous screen catalog load has finished.
                val verifiedImportFormats=if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
                    val cached=serverVpnCatalog.cachedFormats()
                    if(cached.isNotEmpty()) {
                        fileFormats=cached
                        cached
                    } else fileFormats
                } else emptyList()
                var failedNpvs=false
                var failedProtectedHc=false
                var cloudPasswordError:String?=null
                var cloudCredentialError:String?=null
                var singleCredentialNotice:String?=null
                var unsupportedNotice=false
                var variantNotice=false
                val suppliedPassword=cloudPassword!=null || hcPassword!=null ||
                    privateCredentialId!=null
                val suppliedHwid=hcHwid!=null
                val report=BatchImportQueue.process(inputs,
                    onFailure={uri,cause->
                        val filename=runCatching {
                            withContext(Dispatchers.IO){displayName(uri)}
                        }.getOrDefault("")
                        val format=cloudPrepared?.suffix ?:
                            ImportFilenameNormalizer.forDetection(filename)
                                .substringAfterLast('.',"").lowercase()
                        if((cause is DecodeFailure && cause.stringId==R.string.unsupported) ||
                            (cause as? CloudDecodeClient.Failure)?.code=="UNSUPPORTED_FORMAT") {
                            unsupportedNotice=true
                            cloudClient.clearLastDiagnostic()
                        }
                        if((cause as? CloudDecodeClient.Failure)?.code in setOf(
                            "UNSUPPORTED_VERSION","UNSUPPORTED_VARIANT","UNSUPPORTED_METHOD",
                            "UNSUPPORTED_CONFIG_VERSION","DECODE_FAILED")) {
                            variantNotice=true
                            cloudClient.clearLastDiagnostic()
                        }
                        val notice=CloudUserErrors.isInformational(cause,format,
                            passwordSubmitted=suppliedPassword,
                            hwidSubmitted=suppliedHwid)
                        if(notice && inputs.size==1) {
                            singleCredentialNotice=CloudUserErrors.message(
                                this@MainActivity,cause,format,
                                passwordSubmitted=suppliedPassword,
                                hwidSubmitted=suppliedHwid)
                            cloudClient.clearLastDiagnostic()
                        }
                        // Offline V2Box does not return Cloud error codes. Only a
                        // structurally valid protected envelope with a supplied
                        // password can show this one-shot authentication notice.
                        if(!BuildConfig.SPDECODE_CLOUD_ENABLED &&
                            cloudPassword!=null && format=="v2box" &&
                            cloudPrepared?.bytes?.let { V2BoxPasswordProbe.requiresPassword(it) }==true &&
                            cause is DecodeFailure && inputs.size==1)
                            singleCredentialNotice=getString(R.string.cloud_failure_password_incorrect)
                        if(cloudPassword!=null && cause is CloudDecodeClient.Failure &&
                            cause.code=="INVALID_CREDENTIALS")
                            cloudPasswordError=CloudUserErrors.message(
                                this@MainActivity,cause,format)
                        // Non-password NPVS errors must not collapse into the
                        // generic failed-import summary or prompt for a password.
                        if(cause is CloudDecodeClient.Failure &&
                            cause.code in setOf("PRIVATE_KEY_REQUIRED","RECIPIENT_MISMATCH",
                                "NPVS_PROTECTION_UNSUPPORTED","NPVS_APPKEY_AUTH_FAILED") &&
                            cloudCredentialError==null)
                            cloudCredentialError=CloudUserErrors.message(
                                this@MainActivity,cause,format)
                        // Do not label any Cloud NPVS failure a "private key"
                        // failure unless the worker explicitly reports that.
                        if(ImportFilenameNormalizer.forDetection(prepared?.filename?:filename)
                            .endsWith(".npvs",ignoreCase=true) &&
                            cause is CloudDecodeClient.Failure &&
                            cause.code=="NPVS_PROTECTION_UNSUPPORTED")
                            failedNpvs=true
                        if(ImportFilenameNormalizer.forDetection(prepared?.filename?:filename)
                            .endsWith(".hc",ignoreCase=true) &&
                            prepared?.requirements?.requiresCredentials==true &&
                            cause is CloudDecodeClient.Failure &&
                            cause.code in setOf("AUTH_FAILED","INVALID_CREDENTIALS"))
                            failedProtectedHc=true
                    },
                    isExpectedFailure={cause->
                        (cause is DecodeFailure && cause.stringId==R.string.unsupported) ||
                            (cause as? CloudDecodeClient.Failure)?.let {
                                CloudCredentialPolicy.expectedCredentialResponse(it.code) ||
                                it.code in setOf("UNSUPPORTED_FORMAT","UNSUPPORTED_VERSION",
                                    "UNSUPPORTED_VARIANT","UNSUPPORTED_METHOD","UNSUPPORTED_CONFIG_VERSION")
                            }==true
                    }
                ){uri,index,total->
                    progressPosition=index
                    progressTotal=total
                    progressStage=0
                    cloudProgressPhase=null
                    val name=prepared?.filename?:cloudPrepared?.name
                        ?:withContext(Dispatchers.IO){displayName(uri)}
                    progressFilename=name
                    // Only the decoder route uses this name. History keeps the original.
                    val routingName=ImportFilenameNormalizer.forDetection(name)
                    // After a remote snapshot is validated, its extension list
                    // is authoritative. An unknown extension is a suggestion,
                    // not a decode request or an operational failure.
                    // Historical bundled routes are a fallback only before the
                    // first successful catalog download.
                    val supported=ImportFormatRouter.detect(
                        routingName,BuildConfig.SPDECODE_CLOUD_ENABLED,
                        verifiedImportFormats
                    ) { AndroidDecoderCatalog.read(this@MainActivity) }
                        ?:throw DecodeFailure(R.string.unsupported)
                    // Phase A identifies pending formats but never reads or
                    // sends their bytes to a native decoder that does not exist.
                    // All registered suffixes are decoded on the worker in Cloud
                    // builds; Android's *offline* native decoder status is irrelevant.
                    if (!BuildConfig.SPDECODE_CLOUD_ENABLED && !supported.hasNativeDecoder) {
                        throw DecodeFailure(R.string.native_decoder_pending)
                    }
                    val input=prepared?.bytes?:cloudPrepared?.bytes?:withContext(Dispatchers.IO){readBounded(uri,
                        when {
                            BuildConfig.SPDECODE_CLOUD_ENABLED -> CloudDecodeClient.MAX_INPUT
                            supported.suffix=="solid" -> NurTunnelPort.MAX_INPUT
                            supported.suffix=="lnk" -> LinkLayerPort.MAX_INPUT
                            supported.suffix=="npvs" -> NpvsPort.MAX_INPUT
                            supported.migrationPhase=="B" -> GenericVpnPort.MAX_INPUT_BYTES
                            supported.migrationPhase=="D" -> RenzPort.MAX_INPUT_BYTES
                            supported.migrationPhase=="E" -> 2*1024*1024
                            supported.migrationPhase=="F" -> 2*1024*1024
                            supported.migrationPhase=="C" || supported.suffix=="ost" -> UltraSandokPort.MAX_INPUT_BYTES
                            else -> MAX_BYTES
                        })}
                    progressStage=1
                    cloudProgressPhase=if(BuildConfig.SPDECODE_CLOUD_ENABLED) 0 else null
                    val inputSize=input.size
                    if(!BuildConfig.SPDECODE_CLOUD_ENABLED &&
                        supported.suffix=="v2box" && cloudPassword==null &&
                        V2BoxPasswordProbe.requiresPassword(input)){
                        if(pendingCloudPasswordFile==null)
                            pendingCloudPasswordFile=PendingCloudPasswordFile(
                                uri,name,"v2box",input.copyOf())
                        if(prepared==null && cloudPrepared==null)input.fill(0)
                        throw DecodeFailure(R.string.cloud_failure_password)
                    }
                    var preparedCompatibleExport:com.ghostdeveloper.spdecode.cloud.CompatibleExportArtifact?=null
                    val text=try {
                        if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
                            // Never fall back to local decoders after a Cloud error.
                            if(privateCredentialId!=null) {
                                val secret=withContext(Dispatchers.IO) {
                                    privateCredentialVault.use(privateCredentialId){it.copyOf()}
                                }
                                try { cloudClient.decodeFile(supported.suffix,input,password=secret,
                                    onCompatibleExport={preparedCompatibleExport=it},
                                     onPhase={phase->markCloudProgress(generation,phase)}) }
                                finally { secret.fill(0) }
                            }else cloudClient.decodeFile(supported.suffix,input,
                                cloudPassword?:hcPassword,hcHwid,
                                onCompatibleExport={preparedCompatibleExport=it},
                                 onPhase={phase->markCloudProgress(generation,phase)})
                        } else withContext(Dispatchers.Default) {
                            if(privateCredentialId!=null){
                                privateCredentialVault.use(privateCredentialId){secret->
                                    AndroidOfflineDecoderRouter.decodeWithUserPassword(
                                        this@MainActivity,routingName,input,secret)
                                }
                            }else if(cloudPassword!=null && supported.suffix=="v2box"){
                                AndroidOfflineDecoderRouter.decodeWithUserPassword(
                                    this@MainActivity,routingName,input,cloudPassword)
                            }else if(hcPassword!=null || hcHwid!=null){
                                AndroidOfflineDecoderRouter.decodeWithCredentials(
                                    this@MainActivity,routingName,input,hcPassword,hcHwid)
                            }else AndroidOfflineDecoderRouter.decode(this@MainActivity,routingName,input)
                        }
                    }catch(error:CloudDecodeClient.Failure){
                        if(BuildConfig.SPDECODE_CLOUD_ENABLED && cloudPassword==null &&
                            CloudCredentialPolicy.fileNeedsPasswordDialog(supported.suffix) &&
                            (error.code=="PASSWORD_REQUIRED" ||
                                (supported.suffix=="npvs" &&
                                error.code in setOf("NPVS_PROTECTION_UNSUPPORTED","DECODE_FAILED") &&
                                NpvsPasswordProbe.requiresPassword(input))) &&
                            pendingCloudPasswordFile==null){
                            pendingCloudPasswordFile=PendingCloudPasswordFile(uri,name,
                                supported.suffix,input.copyOf())
                        }
                        throw error
                    }finally {
                        if(prepared==null && cloudPrepared==null)input.fill(0)
                    }?:throw DecodeFailure(R.string.unsupported_variant_message)
                    val processed=DecodeView(name,supported.suffix,text,inputSize,
                        compatibleExport=preparedCompatibleExport)
                    progressStage=2
                    val saved=try {
                        withContext(Dispatchers.IO){historyStore.save(processed)}
                        true
                    }catch(e:CancellationException){throw e}
                    catch(_:Exception){
                        SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.HISTORY_WRITE_FAILURE)
                        false
                    }
                    result=processed
                    recent.add(0,processed)
                    if(!saved)toast(R.string.history_storage_error)
                    // Preference failure must not misreport a valid decoded file
                    // as failed after its encrypted record has already been saved.
                    try { historyPreferences.setSelectedId(processed.id) }
                    catch(e:CancellationException){throw e}
                    catch(_:Exception){toast(R.string.history_storage_error)}
                    tab=0
                }
                if(generation==importGeneration && report.failures>0 &&
                    pendingCloudPasswordFile==null) {
                    val summary=getString(R.string.batch_import_summary,
                        report.successes,report.failures)
                    if(singleCredentialNotice!=null) {
                        // An expected credential/compatibility response is not
                        // an app error: show just one notice and OK. The
                        // password dialog has already been dismissed; a new
                        // attempt must explicitly re-import the file.
                        messageIsCredentialNotice=true
                        cloudClient.clearLastDiagnostic()
                    }
                    if(unsupportedNotice)cloudClient.clearLastDiagnostic()
                    noticeTitle=when {
                        unsupportedNotice -> R.string.unsupported_file_title
                        variantNotice -> R.string.unsupported_version_title
                        else -> R.string.decode_notice_title
                    }
                    message=when {
                        singleCredentialNotice!=null->singleCredentialNotice
                        unsupportedNotice && inputs.size==1->
                            getString(R.string.unsupported_file_detail)
                        unsupportedNotice->
                            getString(R.string.unsupported_file_detail)+"\n\n"+summary
                        variantNotice && inputs.size==1->getString(R.string.unsupported_version_detail)
                        variantNotice->getString(R.string.unsupported_version_detail)+"\n\n"+summary
                        cloudPasswordError!=null->cloudPasswordError+"\n\n"+summary
                        cloudCredentialError!=null->cloudCredentialError+"\n\n"+summary
                        failedProtectedHc->getString(R.string.cloud_failure_credentials)+"\n\n"+summary
                        failedNpvs->getString(R.string.npvs_private_key_unsupported)+"\n\n"+summary
                        else->summary
                    }
                    tab=0
                }
            }catch(e:CancellationException){throw e}
            catch(_:Exception){if(generation==importGeneration){
                SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.FILE_IMPORT_FAILURE)
                message=getString(R.string.read_error);tab=0
            }}
            finally {
                hcPassword?.fill(0)
                cloudPassword?.fill(0)
                cloudPrepared?.bytes?.fill(0)
                prepared?.bytes?.fill(0)
                if(generation==importGeneration) {
                    busy=false
                    cloudProgressPhase=null
                    progressFilename=null
                    progressPosition=1
                    progressTotal=1
                }
            }
        }
    }

    private fun updateFavorite(id:String,favorite:Boolean) {
        scope.launch {
            try {
                historyLoad?.await()
                val updated=withContext(Dispatchers.IO) {
                    historyStore.favorite(id,favorite)
                }
                val index=recent.indexOfFirst{it.id==id}
                if(index>=0)recent[index]=updated
                if(result?.id==id)result=updated
            }catch(_:CancellationException){throw CancellationException()}
            catch(_:Exception){toast(R.string.history_storage_error)}
        }
    }

    private fun setRetention(days:Int) {
        if(days !in HistoryPreferences.choices)return
        scope.launch {
            try {
                historyLoad?.await()
                historyPreferences.setRetentionDays(days)
                retentionDays=days
                if(days>0) {
                    val pruned=withContext(Dispatchers.IO) {
                        historyStore.pruneOlderThan(
                            System.currentTimeMillis()-days.toLong()*86_400_000L)
                    }
                    recent.removeAll { it.id in pruned }
                    if(result?.id in pruned) {
                        result=null
                        historyPreferences.setSelectedId(null)
                    }
                }
            }catch(_:CancellationException){throw CancellationException()}
            catch(_:Exception){toast(R.string.history_storage_error)}
        }
    }

    private fun clearHistory() {
        scope.launch {
            try {
                historyLoad?.await()
                withContext(Dispatchers.IO) { historyStore.clear() }
                historyPreferences.setSelectedId(null)
                recent.clear()
                result = null
                reveal = false
            } catch (_: Exception) {
                toast(R.string.history_storage_error)
            }
        }
    }

    private fun deleteHistory(ids:Set<String>) {
        scope.launch {
            try {
                historyLoad?.await()
                val targets = if (ids.isEmpty()) recent.map { it.id }.toSet() else ids
                if (targets.isEmpty()) return@launch
                withContext(Dispatchers.IO) { historyStore.delete(targets) }
                recent.removeAll { it.id in targets }
                if (result?.id in targets) {
                    historyPreferences.setSelectedId(null)
                    result = null
                    reveal = false
                }
            } catch (_: Exception) {
                toast(R.string.history_storage_error)
                // Resync after a partial disk failure, avoiding a false success.
                val saved = runCatching {
                    withContext(Dispatchers.IO) { historyStore.load() }
                }.getOrNull()
                if (saved != null) {
                    recent.clear()
                    recent.addAll(saved)
                    if (result != null && recent.none { it.id == result?.id }) result = null
                }
            }
        }
    }

    private class DecodeFailure(val stringId:Int):Exception()
    private fun readBounded(uri:Uri,maxBytes:Int=MAX_BYTES):ByteArray{
        val stream=contentResolver.openInputStream(uri)?:throw DecodeFailure(R.string.read_error)
        return stream.use {input->
            val out=ByteArrayOutputStream()
            val buf=ByteArray(8192)
            while(true){
                val n=input.read(buf)
                if(n<0)break
                if(out.size().toLong()+n>maxBytes)throw DecodeFailure(R.string.file_too_large)
                out.write(buf,0,n)
            }
            out.toByteArray()
        }
    }
    private fun displayName(uri:Uri):String{
        try{
            contentResolver.query(uri,arrayOf(OpenableColumns.DISPLAY_NAME),
                null,null,null)?.use{cursor->
                if(cursor.moveToFirst()) {
                    val i=cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if(i>=0)return cursor.getString(i).take(220)
                }
            }
        }catch(_:Exception){}
        return uri.lastPathSegment?.substringAfterLast('/')?.take(220) ?:"file"
    }
    private fun copy(text:String){
        val manager=getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        val clip=ClipData.newPlainText("SP-DECODE",text)
        if(Build.VERSION.SDK_INT>=33){
            clip.description.extras=PersistableBundle().apply{
                putBoolean("android.content.extra.IS_SENSITIVE",true)
            }
        }
        manager.setPrimaryClip(clip)
        toast(R.string.copied)
    }
    private fun export(text:String,filename:String,format:ResultExport){
        stagedExport=text
        val safe=filename.substringBeforeLast('.').replace(Regex("[^A-Za-z0-9._-]"),"_")
            .take(50).ifEmpty{"spdecode"}
        if(format==ResultExport.JSON) jsonExporter.launch("$safe-decoded.json")
        else exporter.launch("$safe-decoded.txt")
    }
    private fun toast(id:Int)=Toast.makeText(this,id,Toast.LENGTH_SHORT).show()

    override fun onStop(){
        catalogWatchJob?.cancel()
        reveal=false
        super.onStop()
    }
    override fun onDestroy(){
        credentialPrepareJob?.cancel()
        cancelPrivateCredentialSelection()
        job?.cancel()
        scope.cancel()
        super.onDestroy()
    }
}
