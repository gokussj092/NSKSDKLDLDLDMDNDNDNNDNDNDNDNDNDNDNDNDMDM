package com.ghostdeveloper.spdecode.cloud

import com.ghostdeveloper.spdecode.NativeCommerceAuth
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.SystemClock
import android.provider.OpenableColumns
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.coroutines.coroutineContext

/**
 * One device-bound, authenticated and credit-backed upload at a time. Each checkpoint (including
 * opaque bearer capability and SAF URI) is encrypted with AndroidKeyStore.
 * Worker may be stopped at any time: resume reads the server-acknowledged
 * nextChunk/receivedBytes and never trusts a local progress estimate.
 */
internal class CloudApkQaClient(context:Context,private val cloud:CloudDecodeClient) {
    private val app=context.applicationContext
    private val resolver=app.contentResolver
    private val checkpoint=CloudApkQaCheckpoint(app)
    private val history=ApkQaHistoryStore(app)
    private var cachedReportId=""
    private var cachedReport:String?=null
    companion object {
        const val MAX_BYTES=100L*1000L*1000L
        private const val MAX_CHUNK=2*1024*1024
        // WorkManager regular workers have a limited execution window.
        // Return RETRY before that deadline; progress is durable.
        private const val WORK_BUDGET_MS=6L*60L*1000L
    }

    data class ActivityEvent(val sequence:Int,val code:String,val status:String)
    data class Snapshot(
        val active:Boolean,val phase:String,val receivedBytes:Long,
        val totalBytes:Long,val report:String?,val error:String?,val filename:String,
        val events:List<ActivityEvent>
    )
    private val allowedEvents=setOf(
        "UPLOAD_STARTED","UPLOAD_RECEIVED","UPLOAD_REJECTED",
        "PACKAGE_VALIDATION","PACKAGE_VALIDATED","COMPONENT_INSPECTION",
        "COMPONENTS_INSPECTED","REPORT_PREPARATION","REPORT_READY",
        "ANALYSIS_FAILED","ANALYSIS_RESUMED",
        "ADVANCED_ANALYSIS","ADVANCED_ANALYSIS_COMPLETE",
        "ADVANCED_ANALYSIS_PARTIAL","ADVANCED_ANALYSIS_SKIPPED",
        "APK_METADATA_INSPECTION","DEX_BYTECODE_INSPECTION",
        "NATIVE_LIBRARY_INSPECTION","CODE_DECOMPILATION",
        "DEX_RECOVERY","CRYPTO_EVIDENCE_CORRELATION","ADVANCED_HEARTBEAT"
    )

    private fun safeEvents(message:JSONObject):JSONArray {
        val entries=message.optJSONArray("events") ?: return JSONArray()
        val result=JSONArray()
        for(i in 0 until minOf(entries.length(),64)) {
            val item=entries.optJSONObject(i) ?: break
            val sequence=item.optInt("sequence",-1)
            val code=item.optString("code")
            val status=item.optString("status")
            if(sequence!=i+1 || code !in allowedEvents ||
                status !in setOf("RUNNING","DONE","FAILED","PARTIAL")) break
            result.put(JSONObject().put("sequence",sequence).put("code",code)
                .put("status",status))
        }
        return result
    }

    private fun eventsOf(serialized:String):List<ActivityEvent> {
        val raw=try {JSONArray(serialized)} catch (_:Exception) {return emptyList()}
        val events=ArrayList<ActivityEvent>()
        for(i in 0 until minOf(raw.length(),64)){
            val item=raw.optJSONObject(i) ?: break
            val code=item.optString("code")
            val status=item.optString("status")
            if(item.optInt("sequence")!=i+1 || code !in allowedEvents ||
               status !in setOf("RUNNING","DONE","FAILED","PARTIAL")) break
            events.add(ActivityEvent(i+1,code,status))
        }
        return events
    }

    fun snapshot():Snapshot? {
        val state=checkpoint.load() ?: return null
        // Migrate legacy single-checkpoint reports without modifying them.
        if(!state.active && state.report.isNotBlank() &&
            history.list().none { it.id==state.startId }) {
            history.save(state,state.report)
        }
        val saved=if(!state.active && state.report.isBlank()) {
            if(cachedReportId==state.startId &&
                history.list().none { it.id==state.startId }) {
                cachedReportId=""
                cachedReport=null
            }
            if(cachedReportId!=state.startId) {
                cachedReport=history.read(state.startId)?.report
                cachedReportId=state.startId
            }
            cachedReport
        }else state.report.takeIf { it.isNotBlank() }
        return Snapshot(state.active,state.phase,state.receivedBytes,state.totalBytes,
            saved,state.error.takeIf{it.isNotBlank()},state.filename,eventsOf(state.events))
    }

    fun historyItems():List<ApkQaHistoryStore.Item> = history.list()
    fun historyRecord(id:String):ApkQaHistoryStore.Record? = history.read(id)
    fun deleteHistory(id:String) {
        history.delete(id)
        if(cachedReportId==id){cachedReportId="";cachedReport=null}
    }

    fun hasActiveJob():Boolean=checkpoint.hasActive()

    private fun hex(bytes:ByteArray):String=bytes.joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }

    private fun filename(uri:Uri):String {
        var raw=""
        resolver.query(uri,arrayOf(OpenableColumns.DISPLAY_NAME),null,null,null)?.use { c->
            if(c.moveToFirst()){
                val column=c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if(column>=0)raw=c.getString(column).orEmpty()
            }
        }
        val extension=raw.substringAfterLast('.',missingDelimiterValue="").lowercase()
        if(extension !in setOf("apk","apks"))throw IOException("APK_QA_FORMAT_UNSUPPORTED")
        val base=raw.substringBeforeLast('.')
            .replace(Regex("[^A-Za-z0-9_. -]"),"_")
            .trim('.',' ').take(88)
        return (base.ifEmpty{"spdecode-sample"})+"."+extension
    }

    /** Called only after user consent and an OpenDocument picker result. */
    fun queue(uri:Uri) {
        if(checkpoint.hasActive())throw IOException("APK_QA_ALREADY_ACTIVE")
        checkpoint.load()?.let { previous ->
            if(!previous.active && previous.report.isNotBlank() &&
                history.list().none{it.id==previous.startId})
                history.save(previous,previous.report)
        }
        cachedReportId="";cachedReport=null
        // Read grant is required across process death; never store a file copy.
        try {
            resolver.takePersistableUriPermission(uri,Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } catch (_:SecurityException) {
            throw IOException("APK_QA_PERSISTENT_FILE_PERMISSION_REQUIRED")
        }
        val seed=ByteArray(32).also{SecureRandom().nextBytes(it)}
        val startId=hex(seed)
        seed.fill(0)
        checkpoint.save(CloudApkQaCheckpoint.State(
            uri=uri.toString(),filename=filename(uri),startId=startId))
    }

    private suspend fun hashFile(uri:Uri):Pair<Long,String> = withContext(Dispatchers.IO) {
        val digest=MessageDigest.getInstance("SHA-256")
        val buffer=ByteArray(256*1024)
        var total=0L
        try {
            (resolver.openInputStream(uri) ?: throw IOException("APK_QA_FILE_UNAVAILABLE")).use{src->
                while(true) {
                    coroutineContext.ensureActive()
                    val count=src.read(buffer)
                    if(count<0)break
                    if(count==0)continue
                    total+=count
                    if(total>MAX_BYTES)throw IOException("APK_QA_INPUT_TOO_LARGE")
                    digest.update(buffer,0,count)
                }
            }
            if(total==0L)throw IOException("APK_QA_EMPTY_FILE")
            total to hex(digest.digest())
        } finally {buffer.fill(0)}
    }

    private suspend fun qaPost(op:Int,payload:JSONObject,bytes:ByteArray?=null):JSONObject {
        var attempts=0
        while(true) {
            coroutineContext.ensureActive()
            val accountToken=NativeCommerceAuth(app).sessionToken()
                ?:throw CloudDecodeClient.Failure("SIGN_IN_REQUIRED",401)
            // The bearer travels ONLY within the V2 HPKE-encrypted request.
            // It is never saved in WorkManager or sent to the APK lab.
            val bound=JSONObject(payload.toString()).put("accountToken",accountToken)
            try {return cloud.apkQaRequest(op,bound,bytes)}
            catch(error:CloudDecodeClient.Failure) {
                if(error.code !in setOf("RATE_LIMITED","SERVICE_UNAVAILABLE",
                        "APK_QA_UNAVAILABLE") || attempts>=5)throw error
                attempts++
                delay(maxOf(error.retryAfterMillis,15_000L).coerceAtMost(60_000L))
            }
        }
    }

    private fun capability(state:CloudApkQaCheckpoint.State):JSONObject {
        if(state.jobId.isBlank()||state.uploadToken.isBlank())
            throw IOException("APK_QA_LOCAL_STATE_INVALID")
        return JSONObject().put("jobId",state.jobId).put("uploadToken",state.uploadToken)
    }

    private fun savedProgress(state:CloudApkQaCheckpoint.State,response:JSONObject)
        :CloudApkQaCheckpoint.State {
        val events=safeEvents(response).toString()
        return state.copy(
            phase=response.optString("status",state.phase),
            receivedBytes=response.optLong("receivedBytes",state.receivedBytes),
            events=events,error="")
    }

    private suspend fun sendRemaining(state0:CloudApkQaCheckpoint.State,
                                      response:JSONObject):CloudApkQaCheckpoint.State {
        var state=state0
        val step=response.optInt("chunkBytes",state.chunkBytes)
        val index=response.optInt("nextChunk",-1)
        val received=response.optLong("receivedBytes",-1L)
        val expected=if(index>=0 && step in 1..MAX_CHUNK)
            minOf(index.toLong()*step,state.totalBytes) else -1L
        if(received!=expected || received !in 0L..state.totalBytes ||
           step !in 1..MAX_CHUNK)
            throw IOException("APK_QA_SERVER_CHECKPOINT_INVALID")

        val uri=Uri.parse(state.uri)
        val (total,digest)=hashFile(uri)
        if(total!=state.totalBytes || digest!=state.sha256)
            throw IOException("APK_QA_FILE_CHANGED")
        var sent=received
        var next=index
        state=state.copy(phase="UPLOADING",receivedBytes=received,chunkBytes=step)
        checkpoint.save(state)
        val block=ByteArray(step)
        val discard=ByteArray(256*1024)
        try {
            (resolver.openInputStream(uri) ?: throw IOException("APK_QA_FILE_UNAVAILABLE")).use { src->
                var remaining=received
                while(remaining>0L) {
                    coroutineContext.ensureActive()
                    val count=src.read(discard,0,minOf(remaining,discard.size.toLong()).toInt())
                    if(count<0)throw IOException("APK_QA_FILE_CHANGED")
                    if(count==0)continue
                    remaining-=count
                }
                while(sent<total) {
                    coroutineContext.ensureActive()
                    var count=0
                    val expectedSize=minOf(step.toLong(),total-sent).toInt()
                    while(count<expectedSize) {
                        coroutineContext.ensureActive()
                        val n=src.read(block,count,expectedSize-count)
                        if(n<0)throw IOException("APK_QA_FILE_CHANGED")
                        if(n==0)continue
                        count+=n
                    }
                    val piece=block.copyOf(count)
                    try {
                        val payload=capability(state).put("index",next)
                            .put("chunkSha256",hex(MessageDigest.getInstance("SHA-256").digest(piece)))
                        val ack=qaPost(CloudOperation.APK_QA_CHUNK,payload,piece)
                        if(ack.optLong("receivedBytes",-1L)!=sent+count ||
                           ack.optInt("nextChunk",-1)!=next+1)
                            throw IOException("APK_QA_CHUNK_ACK_INVALID")
                        sent+=count
                        next++
                        state=state.copy(receivedBytes=sent,error="")
                        checkpoint.save(state)
                        if(sent<total)delay(4500L)
                    }finally {piece.fill(0)}
                }
            }
        } finally {block.fill(0);discard.fill(0)}
        return state
    }

    private fun storeRemoteTerminal(state:CloudApkQaCheckpoint.State,
                                    response:JSONObject) {
        val status=response.optString("status")
        if(status=="COMPLETED") {
            val report=response.optJSONObject("report")
                ?:throw IOException("APK_QA_REPORT_MISSING")
            if(report.optString("reportKind") !in setOf(
                    "APK_STATIC_QA_FIRST_PASS","APK_STATIC_QA_DEEP_V2"))
                throw IOException("APK_QA_REPORT_INVALID")
            val terminal=savedProgress(state,response).copy(
                phase="COMPLETED",receivedBytes=state.totalBytes,
                report="",error="")
            // Persist before the checkpoint becomes terminal. A failed write
            // is retried by WorkManager without losing the server capability.
            history.save(terminal,report.toString())
            checkpoint.save(terminal)
            cachedReportId="";cachedReport=null
        } else if(status in setOf("FAILED","REJECTED")) {
            val terminal=savedProgress(state,response).copy(
                phase=status,report="",error="APK_QA_ANALYSIS_FAILED")
            history.save(terminal,response.optJSONObject("report")?.toString().orEmpty())
            checkpoint.save(terminal)
            cachedReportId="";cachedReport=null
        } else throw IOException("APK_QA_INVALID_STATE")
    }

    /**
     * Single durable WorkManager unit. Reentrant: every retry re-verifies both
     * selected content and server-authoritative progress. A fresh clientStartId
     * is created ONLY by queue(), never by a retried request.
     */
    suspend fun executeQueued():Unit = withContext(Dispatchers.IO) {
        var state=checkpoint.load() ?: return@withContext
        if(!state.active)return@withContext
        val deadline=SystemClock.elapsedRealtime()+WORK_BUDGET_MS
        if(state.sha256.isBlank()) {
            val (total,digest)=hashFile(Uri.parse(state.uri))
            state=state.copy(sha256=digest,totalBytes=total,phase="QUEUED")
            checkpoint.save(state)
        }
        if(state.jobId.isBlank()) {
            val started=qaPost(CloudOperation.APK_QA_START,JSONObject()
                .put("filename",state.filename).put("totalBytes",state.totalBytes)
                .put("sha256",state.sha256).put("consent",true)
                .put("qaFirstPass",true).put("clientStartId",state.startId))
            val id=started.optString("jobId")
            val token=started.optString("uploadToken")
            val step=started.optInt("chunkBytes")
            if(!Regex("[a-f0-9]{32}").matches(id) ||
               !Regex("[A-Za-z0-9_-]{43}").matches(token) ||
               step !in 1..MAX_CHUNK)throw IOException("APK_QA_INVALID_SESSION")
            state=state.copy(jobId=id,uploadToken=token,chunkBytes=step,
                phase=started.optString("status","UPLOADING"),
                events=safeEvents(started).toString())
            checkpoint.save(state)
        }
        while(SystemClock.elapsedRealtime()<deadline) {
            coroutineContext.ensureActive()
            val status=qaPost(CloudOperation.APK_QA_RESULT,capability(state))
            // Never publish a terminal state until its final report and events
            // have been validated and durably encrypted in the same write.
            if(status.optString("status") in setOf("COMPLETED","FAILED","REJECTED")) {
                storeRemoteTerminal(state,status)
                return@withContext
            }
            state=savedProgress(state,status)
            checkpoint.save(state)
            when(status.optString("status")) {
                "UPLOADING"->{
                    state=sendRemaining(state,status)
                    val finish=qaPost(CloudOperation.APK_QA_FINISH,capability(state))
                    if(finish.optString("status")!="PROCESSING")
                        throw IOException("APK_QA_INVALID_STATE")
                    state=state.copy(phase="PROCESSING",
                        receivedBytes=state.totalBytes)
                    checkpoint.save(state)
                }
                "PROCESSING"->delay(12_000L)
                else->throw IOException("APK_QA_INVALID_STATE")
            }
        }
        throw IOException("APK_QA_RETRY_SCHEDULED")
    }

    /** Record only whitelisted, non-sensitive error codes; keep remote lock. */
    fun noteRecoverableError(code:String) {
        val state=checkpoint.load() ?: return
        if(!state.active)return
        val safe=code.takeIf { it.matches(Regex("[A-Z_]{3,60}")) }
            ?: "APK_QA_RECONNECTING"
        checkpoint.save(state.copy(error=safe))
    }

    /** Used for confirmed terminal errors only, never for loss of connectivity. */
    fun noteTerminalError(code:String) {
        val state=checkpoint.load() ?: return
        if(!state.active)return
        val safe=code.takeIf { it.matches(Regex("[A-Z_]{3,60}")) }
            ?: "APK_QA_ANALYSIS_FAILED"
        checkpoint.save(state.copy(phase="FAILED",error=safe))
    }
}
