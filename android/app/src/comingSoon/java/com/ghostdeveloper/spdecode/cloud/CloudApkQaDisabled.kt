package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import android.net.Uri
import java.io.IOException

/** Production build only: zero network endpoints, tokens or background uploads. */
internal class CloudApkQaClient(context:Context,cloud:CloudDecodeClient) {
    data class ActivityEvent(val sequence:Int,val code:String,val status:String)
    data class Snapshot(
        val active:Boolean,val phase:String,val receivedBytes:Long,
        val totalBytes:Long,val report:String?,val error:String?,val filename:String,
        val events:List<ActivityEvent>
    )
    fun snapshot():Snapshot?=null
    fun hasActiveJob():Boolean=false
    fun queue(uri:Uri):Nothing=throw IOException("APK_ANALYSIS_COMING_SOON")
}
internal object ApkQaWorker {
    fun enqueue(context:Context,replace:Boolean=false) { /* disabled */ }
}
