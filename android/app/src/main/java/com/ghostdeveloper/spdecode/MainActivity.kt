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
import com.ghostdeveloper.spdecode.cloud.CloudFileFormats
import com.ghostdeveloper.spdecode.cloud.CloudTextFormats
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
    private var showCloudLegal by mutableStateOf(false)
    private var serverVpnRefresh:Job?=null
    private var serverVpnLoading by mutableStateOf(false)
    private var serverVpnUnavailable by mutableStateOf(false)
    private val privateCredentialVault by lazy { DevicePrivateCredentialVault(this) }
    private data class PendingCredentialImport(
        val uri:Uri,
        val filename:String,
        val bytes:ByteArray,
        val credentials:List<DevicePrivateCredentialVault.Metadata>,
        val requirements:HcHccfgPort.Requirements,
    )
    private var pendingCredentialImport by mutableStateOf<PendingCredentialImport?>(null)
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
    private var usageOptIn by mutableStateOf(false)
    private var catalogUpdatesEnabled by mutableStateOf(false)
    private var catalogWatchJob:Job?=null
    private var reportBusy by mutableStateOf(false)
    private var reveal:Boolean
        get()=sessionVm.reveal
        set(value){sessionVm.reveal=value}
    private var stagedExport:String?=null

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
        if(showCloudLegal || !CloudCatalogUpdates.enabled(this) ||
            catalogWatchJob?.isActive==true)return
        catalogWatchJob=scope.launch {
            CloudCatalogUpdates.watchWhileVisible(
                this@MainActivity,cloudClient,serverVpnCatalog
            ){apps->
                serverVpnApps=apps
                serverVpnUnavailable=apps.isEmpty()
            }
        }
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
            }catch(error:CancellationException){throw error}
             catch(_:Exception){ /* News failure must never prevent decoding or login. */ }
        }
    }

    private fun refreshServerVpn(force:Boolean=false) {
        if(!BuildConfig.SPDECODE_CLOUD_ENABLED || showCloudLegal ||
            serverVpnRefresh?.isActive==true)return
        serverVpnLoading=true
        serverVpnUnavailable=false
        serverVpnRefresh=scope.launch {
            try {
                serverVpnApps=serverVpnCatalog.cached()
                serverVpnApps=serverVpnCatalog.refreshIfDue(force=force)
            }catch(error:CancellationException){throw error}
             catch(_:Exception){ /* An authenticated cached snapshot remains usable. */ }
            finally {
                serverVpnUnavailable=serverVpnApps.isEmpty()
                serverVpnLoading=false
            }
        }
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
        settings.edit().putString("language",tag).apply()
        selectedLanguage=tag
        recreate()
    }

    private fun openExternal(url:String){
        if(url !in setOf(
            "https://t.me/Gh0stDeveloper",
            "https://t.me/CodeBreakersHub",
            "https://t.me/GhostDeve"
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
        catalogUpdatesEnabled=CloudCatalogUpdates.enabled(this)
        if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
            // Refresh the visible provider list as soon as a background push completes.
            WorkManager.getInstance(this).getWorkInfosForUniqueWorkLiveData(
                CloudCatalogUpdates.PUSH_WORK_NAME
            ).observe(this) { states ->
                if(states.any { it.state==WorkInfo.State.SUCCEEDED } &&
                    !showCloudLegal && tab==3)refreshServerVpn()
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
            if(showBrandedSplash) SpDecodeSplashScreen()
            else SpDecodeApp(
                activeTab=tab,
                current=result,
                session=recent,
                busy=busy,
                error=message,
                progressStage=progressStage,
                progressFilename=progressFilename,
                progressPosition=progressPosition,
                progressTotal=progressTotal,
                reveal=reveal,
                onTab={ newTab ->
                    navigationExplicit=true
                    tab=newTab
                    reveal=false
                    if(newTab==3)refreshServerVpn()
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
                onSelect={selectResult(it)},
                onClear={clearHistory()},
                onClearResult={clearVisibleResult()},
                onDeleteSelected={ids->deleteHistory(ids)},
                onFavorite={id,favorite->updateFavorite(id,favorite)},
                retentionDays=retentionDays,
                onRetention={days->setRetention(days)},
                onDismissError={message=null;cloudClient.clearLastDiagnostic()},
                canReportError=BuildConfig.SPDECODE_CLOUD_ENABLED && !reportBusy && cloudClient.lastDiagnostic!=null,
                onReportError={sendCurrentFailureReport()},
                onDecodeText={input->decodeText(input)},
                onDecodeCloud={reference->decodeCloud(reference)},
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
                        if(catalogUpdatesEnabled)startCatalogWatch()
                        else catalogWatchJob?.cancel()
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
                            showCloudLegal=true
                        }catch(_:Exception){message=getString(R.string.history_storage_error)}
                    }
                },
                serverVpnApps=serverVpnApps,
                serverVpnLoading=serverVpnLoading,
                serverVpnUnavailable=serverVpnUnavailable,
                onRefreshServerVpn={refreshServerVpn(force=true)},
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
                            refreshServerVpn()
                            refreshCloudWhatsNew()
                            syncOptInUsage()
                            if(savedInstanceState==null && !showCloudLegal)handleExternalIntent(intent)
                        }catch(_:Exception){message=getString(R.string.history_storage_error)}
                    },
                    onDecline={finishAffinity()},
                )
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
        if(savedInstanceState==null && !showCloudLegal)handleExternalIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        // A signature/debuggable check that runs only at cold start can be
        // bypassed by a later process attachment. Defense-in-depth recheck.
        if(!ReleaseIntegrity.isTrusted(this)) finishAndRemoveTask()
        if(!showCloudLegal){refreshServerVpn();syncOptInUsage();CloudCatalogUpdates.ensureScheduled(this);startCatalogWatch();refreshCloudWhatsNew()}
    }

    override fun onNewIntent(intent:Intent){
        super.onNewIntent(intent)
        setIntent(intent)
        if(!showCloudLegal)handleExternalIntent(intent)
    }

    @Suppress("DEPRECATION")
    private fun handleExternalIntent(incoming:Intent?){
        if(incoming==null)return
        val uris: List<Uri> = when(incoming.action){
            Intent.ACTION_VIEW->listOfNotNull(incoming.data)
            Intent.ACTION_SEND->listOfNotNull(incoming.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri)
            Intent.ACTION_SEND_MULTIPLE->
                incoming.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)?.take(BatchImportQueue.MAX_FILES).orEmpty()
            else->emptyList()
        }
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
        pendingCredentialImport?.bytes?.fill(0)
        pendingCredentialImport=null
        enteringHcManually=false
        credentialPrepareJob?.cancel()
        val generation=++credentialPrepareGeneration
        credentialPrepareJob=scope.launch {
            var preview:ByteArray?=null
            try {
                val name=withContext(Dispatchers.IO){displayName(uri)}
                if(name.endsWith(".hc",ignoreCase=true)){
                    preview=withContext(Dispatchers.IO){readBounded(uri,
                        if(BuildConfig.SPDECODE_CLOUD_ENABLED) CloudDecodeClient.MAX_INPUT else MAX_BYTES)}
                    val requirements=if(BuildConfig.SPDECODE_CLOUD_ENABLED)
                        cloudClient.inspectHcRequirements(preview)
                    else HcHccfgPort.inspectRequirements(preview)
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

    private fun cancelImport() {
        // An obsolete worker must not close the new import's progress dialog.
        importGeneration++
        job?.cancel()
        job=null
        busy=false
        progressFilename=null
    }

    // The Android editor accepts a complete pasted configuration once.
    // Telegram's multipart chat-session protocol does not apply here.
    private fun decodeText(userText:String) {
        if(!requireCloudLegal())return
        if(busy)return
        if(userText.isBlank()||userText.length>TextProtocolDecoder.MAX_CHARS) {
            message=getString(R.string.text_decode_invalid)
            return
        }
        val candidate=(if(BuildConfig.SPDECODE_CLOUD_ENABLED)CloudTextFormats.identify(userText) else null)
            ?:TextProtocolDecoder.identify(userText)
        if(candidate==null) {
            message=getString(R.string.text_decode_invalid)
            return
        }
        val generation=++importGeneration
        job=scope.launch {
            busy=true
            progressStage=1
            progressPosition=1
            progressTotal=1
            progressFilename=getString(R.string.text_decode_title)
            message=null
            reveal=false
            try {
                historyLoad?.await()
                val decoded=if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
                    cloudClient.decodeText(userText)
                } else withContext(Dispatchers.Default) {
                    TextProtocolDecoder.decode(this@MainActivity,candidate)
                }
                if(decoded==null) {
                    SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.TEXT_UNSUPPORTED)
                    message=getString(R.string.text_decode_unsupported)
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
                SafeDecodeDiagnostics.record(SafeDecodeDiagnostics.Event.TEXT_FAILURE)
                message=if(BuildConfig.SPDECODE_CLOUD_ENABLED)
                    com.ghostdeveloper.spdecode.cloud.CloudUserErrors.message(this@MainActivity,error)
                    else getString(R.string.text_decode_unsupported)
            }
            }finally {
                if(generation==importGeneration) {
                    busy=false
                    progressFilename=null
                    progressStage=0
                }
            }
        }
    }

    /**
     * User-triggered, opt-in ONLINE import. No network request is made by any
     * offline file/text decoder, and a failed fetch never saves a result.
     */
    private fun decodeCloud(reference:String) {
        if(!requireCloudLegal())return
        if(busy)return
        if(reference.isBlank() || reference.length>1024) {
            message=getString(R.string.cloud_http_injector_invalid)
            return
        }
        val parsed=try { HttpInjectorCloudPort.parseReference(reference) }
        catch(_:HttpInjectorCloudPort.CloudException) {
            message=getString(R.string.cloud_http_injector_invalid)
            return
        }
        val generation=++importGeneration
        job?.cancel()
        job=scope.launch {
            busy=true
            progressStage=1
            progressPosition=1
            progressTotal=1
            progressFilename=getString(R.string.cloud_http_injector_title)
            message=null
            reveal=false
            try {
                historyLoad?.await()
                val decoded=if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
                    cloudClient.decodeHttpInjectorCloud(parsed)
                } else withContext(Dispatchers.IO) {
                    HttpInjectorCloudPort.decodeOnline(this@MainActivity,parsed)
                }
                progressStage=2
                val record=DecodeView(
                    "http-injector-cloud.ehi","ehi",decoded,
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
                if(generation==importGeneration) {
                    message=if(BuildConfig.SPDECODE_CLOUD_ENABLED)
                        com.ghostdeveloper.spdecode.cloud.CloudUserErrors.message(this@MainActivity,e)
                        else getString(R.string.cloud_http_injector_network_error)
                }
            }catch(e:HttpInjectorCloudPort.CloudException) {
                if(generation==importGeneration) {
                    message=getString(when(e.reason) {
                        HttpInjectorCloudPort.Reason.REFERENCE->R.string.cloud_http_injector_invalid
                        HttpInjectorCloudPort.Reason.NETWORK->R.string.cloud_http_injector_network_error
                        HttpInjectorCloudPort.Reason.SERVER->R.string.cloud_http_injector_server_error
                        HttpInjectorCloudPort.Reason.INTEGRITY->R.string.cloud_http_injector_integrity_error
                        HttpInjectorCloudPort.Reason.DECODER->R.string.cloud_http_injector_decoder_error
                    })
                }
            }catch(error:Exception){
                if(generation==importGeneration)
                    message=if(BuildConfig.SPDECODE_CLOUD_ENABLED)
                        com.ghostdeveloper.spdecode.cloud.CloudUserErrors.message(this@MainActivity,error)
                        else getString(R.string.cloud_http_injector_network_error)
            }finally {
                if(generation==importGeneration) {
                    busy=false
                    progressFilename=null
                    progressStage=0
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
            progressPosition=1
            progressTotal=1
            progressFilename=getString(R.string.nur_tunnel_name)
            message=null
            reveal=false
            try {
                historyLoad?.await()
                val pair=if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
                    val decoded=cloudClient.decodeNurCatalog()
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
            progressPosition=1
            progressTotal=1
            progressFilename=provider.name
            message=null
            reveal=false
            try {
                historyLoad?.await()
                val decoded=cloudClient.decodeServerVpnProvider(id)
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
                    progressFilename=null
                }
            }
        }
    }

    private fun importFiles(uris:List<Uri>,
        privateCredentialId:String?=null,
        prepared:PendingCredentialImport?=null,
        hcPassword:ByteArray?=null,
        hcHwid:String?=null){
        if(!requireCloudLegal())return
        require(privateCredentialId==null || (uris.size==1 && prepared?.uri==uris.single()))
        require((hcPassword==null && hcHwid==null) ||
            (uris.size==1 && prepared?.uri==uris.single() && privateCredentialId==null))
        job?.cancel()
        val generation=++importGeneration
        val inputs=uris.take(BatchImportQueue.MAX_FILES)
        if(inputs.isEmpty())return
        job=scope.launch {
            busy=true
            progressStage=0
            progressFilename=null
            progressPosition=1
            progressTotal=inputs.size
            message=null
            reveal=false
            try {
                historyLoad?.await()
                var failedNpvs=false
                var failedProtectedHc=false
                val report=BatchImportQueue.process(inputs,
                    onFailure={uri,_-> 
                        val filename=runCatching {
                            withContext(Dispatchers.IO){displayName(uri)}
                        }.getOrDefault("")
                        // Do not label any Cloud NPVS failure a "private key"
                        // failure unless the worker explicitly reports that.
                        if(!BuildConfig.SPDECODE_CLOUD_ENABLED &&
                            filename.endsWith(".npvs",ignoreCase=true))
                            failedNpvs=true
                        if((prepared?.filename?:filename).endsWith(".hc",ignoreCase=true) &&
                            prepared?.requirements?.requiresCredentials==true)failedProtectedHc=true
                    }
                ){uri,index,total->
                    progressPosition=index
                    progressTotal=total
                    progressStage=0
                    val name=prepared?.filename
                        ?:withContext(Dispatchers.IO){displayName(uri)}
                    progressFilename=name
                    val supported=(if(BuildConfig.SPDECODE_CLOUD_ENABLED)
                        CloudFileFormats.detect(name) else null)
                        ?:AndroidDecoderCatalog.detect(
                            name,AndroidDecoderCatalog.read(this@MainActivity))
                        ?:throw DecodeFailure(R.string.unsupported)
                    // Phase A identifies pending formats but never reads or
                    // sends their bytes to a native decoder that does not exist.
                    // All registered suffixes are decoded on the worker in Cloud
                    // builds; Android's *offline* native decoder status is irrelevant.
                    if (!BuildConfig.SPDECODE_CLOUD_ENABLED && !supported.hasNativeDecoder) {
                        throw DecodeFailure(R.string.native_decoder_pending)
                    }
                    val input=prepared?.bytes?:withContext(Dispatchers.IO){readBounded(uri,
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
                    val inputSize=input.size
                    val text=try {
                        if(BuildConfig.SPDECODE_CLOUD_ENABLED) {
                            // Never fall back to local decoders after a Cloud error.
                            if(privateCredentialId!=null) {
                                val secret=withContext(Dispatchers.IO) {
                                    privateCredentialVault.use(privateCredentialId){it.copyOf()}
                                }
                                try { cloudClient.decodeFile(supported.suffix,input,password=secret) }
                                finally { secret.fill(0) }
                            }else cloudClient.decodeFile(supported.suffix,input,hcPassword,hcHwid)
                        } else withContext(Dispatchers.Default) {
                            if(privateCredentialId!=null){
                                privateCredentialVault.use(privateCredentialId){secret->
                                    AndroidOfflineDecoderRouter.decodeWithUserPassword(
                                        this@MainActivity,name,input,secret)
                                }
                            }else if(hcPassword!=null || hcHwid!=null){
                                AndroidOfflineDecoderRouter.decodeWithCredentials(
                                    this@MainActivity,name,input,hcPassword,hcHwid)
                            }else AndroidOfflineDecoderRouter.decode(this@MainActivity,name,input)
                        }
                    }finally {
                        if(prepared==null)input.fill(0)
                    }?:throw DecodeFailure(R.string.unsupported_variant_message)
                    val processed=DecodeView(name,supported.suffix,text,inputSize)
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
                if(generation==importGeneration && report.failures>0) {
                    val summary=getString(R.string.batch_import_summary,
                        report.successes,report.failures)
                    message=when {
                        failedProtectedHc->getString(R.string.hc_auth_failed)+"\n\n"+summary
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
                prepared?.bytes?.fill(0)
                if(generation==importGeneration) {
                    busy=false
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
