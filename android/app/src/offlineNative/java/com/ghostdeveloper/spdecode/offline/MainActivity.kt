package com.ghostdeveloper.spdecode.offline

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.os.PersistableBundle
import android.provider.OpenableColumns
import android.view.View
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.mutableStateOf
import androidx.activity.result.contract.ActivityResultContracts
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.UUID

/**
 * Isolated native Offline UI. All configuration decoding and NPV P-256
 * generation are JNI/C++; Kotlin only handles UI, SAF and Keystore storage.
 */
class MainActivity : ComponentActivity() {
    private val ui=OfflineUiState()
    private val showBrandedSplash=mutableStateOf(true)
    private lateinit var storage:OfflineSecureStore
    private val settings by lazy { getSharedPreferences("offline-ui-v1",MODE_PRIVATE) }
    private var pendingFile:Uri?=null
    private var pendingText:String?=null
    private var pendingName:String="document"
    private var pendingSuffix:String=""
    private var exportPayload:String=""
    private var exportingIdentity=false

    private val supportedFiles=setOf(
        "hc","ehi","nm","npv","npv4","npvt","npvs",
        "dark","dt","dtunnel","darktunnel","hat"
    )

    private val importer=registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if(uri!=null) importIncomingFile(uri)
    }
    private val identityImporter=registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if(uri!=null) Thread {
            val result=runCatching {
                val bytes=readBounded(uri,16384)
                try {
                    val text=String(bytes,Charsets.UTF_8)
                    val data=JSONObject(text)
                    require(data.optString("schema")=="spdecode.npvs.recipient.v1" &&
                        data.optString("publicKey").isNotBlank() &&
                        data.optString("privateKey").isNotBlank()) { "INVALID_IDENTITY" }
                    storage.storeIdentity(text)
                    storage.readIdentity()
                } finally {bytes.fill(0)}
            }
            runOnUiThread {
                result.onSuccess { ui.identity=it;ui.message=txt("identity_saved",ui.language) }
                    .onFailure { ui.error=OfflineUiError(
                        if(ui.language=="es")"Identidad incorrecta" else "Invalid identity",
                        if(ui.language=="es")"El archivo no contiene una identidad NPV válida. Necesitas las claves originales correspondientes." else "This file does not contain a valid NPV identity. Use the matching original keys."
                    ) }
            }
        }.start()
    }
    private val exporter=registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        if(uri!=null && exportPayload.isNotEmpty()) {
            val value=exportPayload
            Thread {
                val ok=runCatching {
                    contentResolver.openOutputStream(uri)?.use {
                        it.write(value.toByteArray(Charsets.UTF_8))
                    } ?: error("Unable to export")
                }.isSuccess
                runOnUiThread {
                    ui.message=txt(if(ok)"export_success" else "export_failed",ui.language)
                    exportPayload=""
                    exportingIdentity=false
                }
            }.start()
        } else {
            exportPayload=""
            exportingIdentity=false
        }
    }

    override fun onCreate(savedInstanceState:Bundle?) {
        val splashStarted=SystemClock.elapsedRealtime()
        super.onCreate(savedInstanceState)
        // Screen capture and recording are intentionally unrestricted in Offline.
        storage=OfflineSecureStore(applicationContext)
        ui.theme=settings.getString("theme","amoled")?.takeIf {
            it in setOf("amoled","dark","light")
        }?:"amoled"
        ui.language=settings.getString("language","system")?.takeIf {
            key->supportedOfflineLanguages.any{it.first==key}
        }?:"system"
        setBars()
        setContent {
            if(showBrandedSplash.value) OfflineSplashScreen(ui.language)
            else OfflineScreen(ui,OfflineActions(
                importFile={importer.launch(arrayOf("*/*"))},
                copyResult={ui.result?.let{copy(OfflineJson.format(it))}},
                exportResult={
                    ui.result?.let {
                        exportPayload=OfflineJson.format(it)
                        exporter.launch(ui.fileName.orEmpty().substringBeforeLast('.')+".json")
                    }
                },
                clearResult={
                    ui.result=null
                    ui.fileName=null
                    ui.extension=""
                    ui.message=null
                },
                decodeText={beginText(it)},
                retryWithCredentials={password,hwid,recipient->
                    val requestedIdentity=ui.pendingPrompt?.requireIdentity==true
                    ui.pendingPrompt=null
                    // A password-protected NPVS must NOT receive an unused
                    // saved recipient identity: the authenticated modes are distinct.
                    val identity=recipient.takeIf{it.isNotBlank()}
                        ?: if(requestedIdentity) ui.identity.orEmpty() else ""
                    decodeAttempt(password,hwid,identity)
                },
                dismissPrompt={ui.pendingPrompt=null},
                selectHistory={item->
                    ui.result=OfflineJson.format(item.json);ui.fileName=item.filename
                    ui.extension=item.extension;ui.tab=0;ui.message=null
                },
                deleteHistory={item->deleteHistory(item)},
                clearHistory={clearHistory()},
                favoriteHistory={item->toggleFavorite(item)},
                createIdentity={generateIdentity()},
                importIdentity={identityImporter.launch(arrayOf("application/json","*/*"))},
                exportIdentity={
                    ui.identity?.let{
                        exportPayload=it;exportingIdentity=true
                        exporter.launch("npv-identity.json")
                    }
                },
                deleteIdentity={deleteIdentity()},
                copyValue={value->copy(value)},
                setTheme={mode->
                    ui.theme=mode
                    settings.edit().putString("theme",mode).apply()
                    setBars()
                },
                setLanguage={lang->
                    ui.language=lang
                    settings.edit().putString("language",lang).apply()
                },
                openUrl={url->
                    try { startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(url))) }
                    catch (_:Exception) {ui.message=txt("open_link_failed",ui.language)}
                },
            ))
        }
        // Match the online startup: initialize stored history behind a branded
        // splash, show it for a minimum 1.6 s and never block longer than 5 s.
        val splashHandler=Handler(Looper.getMainLooper())
        splashHandler.postDelayed({showBrandedSplash.value=false},5_000L)
        Thread {
            val records=runCatching{storage.load()}
            val identity=runCatching{storage.readIdentity()}
            runOnUiThread {
                records.onSuccess{ui.history=it}.onFailure{
                    ui.message=txt("history_unavailable",ui.language)
                }
                identity.onSuccess{ui.identity=it}.onFailure{
                    ui.message=txt("identity_invalid",ui.language)
                }
                val remaining=(1_600L-(SystemClock.elapsedRealtime()-splashStarted))
                    .coerceAtLeast(0L)
                splashHandler.postDelayed({showBrandedSplash.value=false},remaining)
            }
        }.start()
        if(savedInstanceState==null)handleExternalIntent(intent)
    }

    override fun onNewIntent(intent:Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleExternalIntent(intent)
    }

    /** Files offered by Android's Open With and Share dialogs are read through
     * granted content URIs. Never assume a provider filename proves compatibility.
     */
    private fun handleExternalIntent(shared:Intent?) {
        val incoming=shared?:return
        val action=incoming.action?:return
        if(action !in setOf(Intent.ACTION_VIEW,Intent.ACTION_SEND,Intent.ACTION_SEND_MULTIPLE))return
        if(action==Intent.ACTION_SEND_MULTIPLE){
            ui.error=readableDecodeError("UNSUPPORTED_FORMAT","multiple",ui.language)
            return
        }
        val attached=if(action==Intent.ACTION_SEND) {
            if(Build.VERSION.SDK_INT>=33)
                incoming.getParcelableExtra(Intent.EXTRA_STREAM,Uri::class.java)
            else {
                @Suppress("DEPRECATION")
                incoming.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
            }
        }else null
        val uri=attached ?: incoming.data ?: incoming.clipData?.let {
            if(it.itemCount>0)it.getItemAt(0).uri else null
        }
        if(uri!=null){
            if(uri.scheme!="content"&&uri.scheme!="file"){
                ui.error=readableDecodeError("UNSUPPORTED_FORMAT","",ui.language)
            }else importIncomingFile(uri)
            return
        }
        if(action==Intent.ACTION_SEND){
            val plain=incoming.getStringExtra(Intent.EXTRA_TEXT)
            if(!plain.isNullOrBlank()) beginText(plain)
            else ui.error=readableDecodeError("UNSUPPORTED_FORMAT","",ui.language)
        }
    }

    private fun importIncomingFile(uri:Uri) {
        if(ui.busy){
            ui.error=readableDecodeError("BUSY","",ui.language)
            return
        }
        val filename=nameOf(uri).ifBlank{"document"}
        val guess=filename.substringAfterLast('.', "").lowercase()
        val fallback=uri.lastPathSegment.orEmpty().substringAfterLast('.', "").lowercase()
        val suffix=if(guess in supportedFiles)guess else fallback.takeIf{it in supportedFiles}?:guess
        if(suffix !in supportedFiles){
            ui.error=readableDecodeError("UNSUPPORTED_FORMAT",suffix,ui.language)
            return
        }
        pendingFile=uri
        pendingText=null
        pendingName=filename
        pendingSuffix=suffix
        ui.tab=0
        ui.pendingPrompt=null
        ui.error=null
        decodeAttempt()
    }

    private fun setBars() {
        @Suppress("DEPRECATION")
        window.statusBarColor=if(ui.theme=="light")android.graphics.Color.rgb(248,249,251)
            else if(ui.theme=="dark")android.graphics.Color.rgb(17,19,22)
            else android.graphics.Color.BLACK
        @Suppress("DEPRECATION")
        window.navigationBarColor=if(ui.theme=="light")android.graphics.Color.WHITE
            else android.graphics.Color.BLACK
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility=if(ui.theme=="light")
            View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
        else 0
    }

    private fun nameOf(uri:Uri):String {
        var cursor:Cursor?=null
        return try {
            cursor=contentResolver.query(uri,arrayOf(OpenableColumns.DISPLAY_NAME),null,null,null)
            val index=cursor?.getColumnIndex(OpenableColumns.DISPLAY_NAME)?:-1
            if(cursor?.moveToFirst()==true && index>=0)
                cursor.getString(index)?.take(255) ?: "document"
            else "document"
        }catch (_:Exception){"document"}finally{cursor?.close()}
    }

    private fun readBounded(uri:Uri,limit:Int):ByteArray {
        return try {
            contentResolver.openInputStream(uri)?.use{ stream->
                val out=ByteArrayOutputStream()
                val buffer=ByteArray(8192)
                while(true){
                    val read=stream.read(buffer)
                    if(read<0)break
                    if(out.size()+read>limit)error("FILE_TOO_LARGE")
                    out.write(buffer,0,read)
                }
                out.toByteArray()
            }?:error("FILE_UNAVAILABLE")
        }catch(error:SecurityException){
            throw IllegalArgumentException("FILE_UNAVAILABLE",error)
        }catch(error:java.io.IOException){
            throw IllegalArgumentException("FILE_UNAVAILABLE",error)
        }
    }

    private fun beginText(text:String) {
        val value=text.trim()
        if(value.isBlank() || value.length>2*1024*1024){
            ui.error=readableDecodeError("INVALID_TEXT","",ui.language);return
        }
        val first=value.substringBefore("://").lowercase()
        val npv=first in setOf("npvt","npvt-ssh","npvt-vless","npvt-vmess","npv","dns") ||
            value.startsWith("npvs1:",ignoreCase=true)
        val dark=first in setOf("dt","dtunnel","dark","darktunnel","dark-tunnel")
        val netmod=first.startsWith("nm-") || !value.contains("://")
        if(!npv && !netmod && !dark){
            ui.error=readableDecodeError("UNSUPPORTED_TEXT","",ui.language);return
        }
        pendingFile=null
        pendingText=if(first.startsWith("nm-")&&value.contains("://"))
            value.substringAfter("://").trim() else value
        pendingName=when {npv->"NPV text";dark->"Dark Tunnel text";else->"NetMod text"}
        pendingSuffix=when {npv->"npv";dark->"dark";else->"autotext"}
        ui.pendingPrompt=null
        decodeAttempt()
    }

    private fun decodeAttempt(pass:String="",hwid:String="",recipient:String="") {
        if(ui.busy)return
        ui.busy=true;ui.message=null;ui.error=null
        val file=pendingFile;val text=pendingText
        val suffix=pendingSuffix;val name=pendingName
        Thread {
            val result=runCatching {
                val bytes=if(file!=null)readBounded(file,4*1024*1024)
                    else (text?:error("EMPTY_FILE")).toByteArray(Charsets.UTF_8)
                try {
                    val decoded=NativeOffline.decodeNative(bytes,suffix,pass,hwid,recipient)
                    try{
                        val source=StandardCharsets.UTF_8.newDecoder()
                            .onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT)
                            .decode(ByteBuffer.wrap(decoded)).toString()
                        OfflineJson.format(source)
                    }finally{decoded.fill(0)}
                }finally{bytes.fill(0)}
            }
            runOnUiThread {
                ui.busy=false
                result.onSuccess{json->
                    ui.result=json
                    ui.fileName=name
                    ui.extension=suffix
                    ui.tab=0
                    ui.message=txt("decode_success",ui.language)
                    val record=OfflineRecord(UUID.randomUUID().toString(),name,suffix,
                        json,System.currentTimeMillis())
                    Thread {
                        val outcome=runCatching{storage.save(record);storage.load()}
                        runOnUiThread {
                            outcome.onSuccess{ui.history=it}
                                .onFailure{ui.message=txt("history_unavailable",ui.language)}
                        }
                    }.start()
                }.onFailure{problem->
                    val reason=problem.message.orEmpty()
                    when(reason){
                        "PASSWORD_REQUIRED"->ui.pendingPrompt=OfflinePrompt(requirePassword=true,
                            errorMessage=reason)
                        "HWID_REQUIRED"->ui.pendingPrompt=OfflinePrompt(requireHwid=true,
                            errorMessage=reason)
                        "HWID_PASSWORD_REQUIRED"->ui.pendingPrompt=OfflinePrompt(
                            requirePassword=true,requireHwid=true,errorMessage=reason)
                        "PRIVATE_KEY_REQUIRED"->{
                            val saved=ui.identity
                            if(saved!=null && recipient.isEmpty()){
                                decodeAttempt(pass,hwid,saved)
                            } else ui.pendingPrompt=OfflinePrompt(requireIdentity=true,errorMessage=reason)
                        }
                        "RECIPIENT_MISMATCH","NPV_RECIPIENT_MISMATCH"->{
                            ui.pendingPrompt=OfflinePrompt(requireIdentity=true,errorMessage=reason)
                        }
                        else->ui.error=readableDecodeError(reason,suffix,ui.language)
                    }
                }
            }
        }.start()
    }

    private fun copy(text:String) {
        val clip=ClipData.newPlainText("SP-DECODE Offline",text)
        if(Build.VERSION.SDK_INT>=33)clip.description.extras=
            PersistableBundle().apply{putBoolean(ClipDescription.EXTRA_IS_SENSITIVE,true)}
        (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(clip)
        ui.message=txt("copied",ui.language)
    }

    private fun generateIdentity() {
        if(ui.busy)return
        ui.busy=true
        Thread {
            val result=runCatching {
                val json=NativeOffline.generateIdentityNative()
                storage.storeIdentity(json)
                storage.readIdentity()
            }
            runOnUiThread {
                ui.busy=false
                result.onSuccess {
                    ui.identity=it
                    ui.message=txt("identity_saved",ui.language)
                }.onFailure{ui.message=txt("identity_invalid",ui.language)}
            }
        }.start()
    }

    private fun deleteIdentity() {
        Thread {
            val ok=runCatching{storage.removeIdentity()}.isSuccess
            runOnUiThread {
                if(ok)ui.identity=null
                ui.message=txt(if(ok)"identity_deleted" else "identity_invalid",ui.language)
            }
        }.start()
    }

    private fun deleteHistory(item:OfflineRecord) {
        Thread {
            val result=runCatching{storage.delete(item.id);storage.load()}
            runOnUiThread{
                result.onSuccess{ui.history=it}
                    .onFailure{ui.message=txt("history_unavailable",ui.language)}
            }
        }.start()
    }

    private fun clearHistory() {
        Thread {
            val result=runCatching{storage.clear();storage.load()}
            runOnUiThread{
                result.onSuccess{ui.history=it}
                    .onFailure{ui.message=txt("history_unavailable",ui.language)}
            }
        }.start()
    }

    private fun toggleFavorite(record:OfflineRecord) {
        Thread {
            val result=runCatching{
                storage.save(record.copy(favorite=!record.favorite))
                storage.load()
            }
            runOnUiThread {
                result.onSuccess{ui.history=it}
                    .onFailure{ui.message=txt("history_unavailable",ui.language)}
            }
        }.start()
    }
}
