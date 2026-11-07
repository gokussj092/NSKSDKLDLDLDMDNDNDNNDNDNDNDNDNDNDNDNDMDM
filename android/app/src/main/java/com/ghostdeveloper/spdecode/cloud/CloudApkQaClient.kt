package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.security.MessageDigest
import kotlin.coroutines.coroutineContext

/**
 * Temporary account-free/credit-free real APK first-pass QA.
 *
 * APK bytes are never interpreted or executed locally; Android only reads
 * the chosen document and hands bounded pieces to the existing C++ native
 * V2 HPKE transport. This is NOT a bypass around attestation or device PoP.
 * The QA server validates the whole-file and per-chunk SHA-256 separately.
 */
internal class CloudApkQaClient(context:Context,private val cloud:CloudDecodeClient) {
    private val resolver=context.applicationContext.contentResolver

    companion object {
        const val MAX_BYTES=96L*1024L*1024L
        private const val MAX_CHUNK=2*1024*1024
        private const val MAX_POLL=45
    }

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
        // Document providers may return slashes or Unicode names. The sandbox
        // receives only a neutral filename, never a filesystem path.
        val base=raw.substringBeforeLast('.')
            .replace(Regex("[^A-Za-z0-9_. -]"),"_")
            .trim('.',' ').take(88)
        return (base.ifEmpty{"spdecode-sample"})+"."+extension
    }

    private fun digestAndSize(uri:Uri):Pair<Long,String> {
        val md=MessageDigest.getInstance("SHA-256")
        var total=0L
        val buffer=ByteArray(256*1024)
        (resolver.openInputStream(uri)?:throw IOException("APK_QA_FILE_UNAVAILABLE")).use { src ->
            while(true){
                coroutineCheck()
                val n=src.read(buffer)
                if(n<0)break
                if(n==0)continue
                total+=n
                if(total>MAX_BYTES)throw IOException("APK_QA_INPUT_TOO_LARGE")
                md.update(buffer,0,n)
            }
        }
        if(total<=0L)throw IOException("APK_QA_EMPTY_FILE")
        buffer.fill(0)
        return total to hex(md.digest())
    }

    private fun coroutineCheck() { /* Coroutine cancellation checked at each I/O loop by caller. */ }

    suspend fun analyze(uri:Uri,onProgress:suspend (String,Long,Long)->Unit):JSONObject =
        withContext(Dispatchers.IO) {
            val name=filename(uri)
            coroutineContext.ensureActive()
            onProgress("READING",0,0)
            val (total,fullDigest)=digestAndSize(uri)
            coroutineContext.ensureActive()
            val started=cloud.apkQaRequest(CloudOperation.APK_QA_START,JSONObject()
                .put("filename",name).put("totalBytes",total)
                .put("sha256",fullDigest).put("consent",true)
                .put("qaFirstPass",true))
            val id=started.getString("jobId")
            val token=started.getString("uploadToken")
            val step=started.getInt("chunkBytes")
            if (!id.matches(Regex("[a-f0-9]{32}")) ||
                !token.matches(Regex("[A-Za-z0-9_-]{43}")) ||
                step !in 1..MAX_CHUNK)throw IOException("APK_QA_INVALID_SESSION")

            val base=JSONObject().put("jobId",id).put("uploadToken",token)
            var sent=0L
            var index=0
            val block=ByteArray(step)
            try {
                (resolver.openInputStream(uri)?:throw IOException("APK_QA_FILE_UNAVAILABLE")).use { src->
                    while(sent<total){
                        coroutineContext.ensureActive()
                        var count=0
                        val next=minOf(step.toLong(),total-sent).toInt()
                        while(count<next){
                            coroutineContext.ensureActive()
                            val n=src.read(block,count,next-count)
                            if(n<0)throw IOException("APK_QA_FILE_CHANGED")
                            if(n==0)continue
                            count+=n
                        }
                        val content=block.copyOf(count)
                        try {
                            val hash=hex(MessageDigest.getInstance("SHA-256").digest(content))
                            // Binary attachment is encrypted inside native HPKE and
                            // encoded for the private QA worker on the server only.
                            val response=cloud.apkQaRequest(CloudOperation.APK_QA_CHUNK,
                                JSONObject(base.toString())
                                    .put("index",index).put("chunkSha256",hash),content)
                            val received=response.getLong("receivedBytes")
                            if(received!=sent+count || response.getInt("nextChunk")!=index+1)
                                throw IOException("APK_QA_CHUNK_ACK_INVALID")
                            sent=received
                            index++
                            onProgress("SENDING",sent,total)
                        }finally{content.fill(0)}
                    }
                }
                val finish=cloud.apkQaRequest(CloudOperation.APK_QA_FINISH,JSONObject(base.toString()))
                if(finish.optString("status")!="PROCESSING")
                    throw IOException("APK_QA_INVALID_STATE")
                onProgress("PROCESSING",total,total)
                repeat(MAX_POLL){
                    coroutineContext.ensureActive()
                    delay(2000L)
                    val status=cloud.apkQaRequest(CloudOperation.APK_QA_RESULT,JSONObject(base.toString()))
                    when(status.optString("status")){
                        "COMPLETED"-> {
                            val report=status.optJSONObject("report")
                                ?:throw IOException("APK_QA_REPORT_MISSING")
                            if(report.optString("reportKind")!="APK_STATIC_QA_FIRST_PASS")
                                throw IOException("APK_QA_REPORT_INVALID")
                            onProgress("COMPLETE",total,total)
                            return@withContext report
                        }
                        "FAILED","REJECTED"->throw IOException("APK_QA_ANALYSIS_FAILED")
                        "PROCESSING","UPLOADING"->{}
                        else->throw IOException("APK_QA_INVALID_STATE")
                    }
                }
                throw IOException("APK_QA_RESULT_TIMEOUT")
            }finally{block.fill(0)}
        }
}
