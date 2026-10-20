package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkerParameters
import androidx.work.WorkManager
import androidx.work.workDataOf
import com.ghostdeveloper.spdecode.BuildConfig
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException

/**
 * C10 notifications are opt-in, metadata-only and never carry a VPN payload.
 * FCM is optional; a WorkManager recovery check works without a configured FCM project.
 */
internal object CloudCatalogUpdates {
    private const val TOPIC="spdecode-vpn-catalog"
    private const val PREFS="spdecode-catalog-sync"
    private const val CONSENT="allow-background-sync"
    private const val BACKUP="catalog-version-recovery"
    internal const val PUSH_WORK_NAME="catalog-version-push"

    fun enabled(context:Context):Boolean =
        BuildConfig.SPDECODE_CLOUD_ENABLED &&
            context.getSharedPreferences(PREFS,Context.MODE_PRIVATE).getBoolean(CONSENT,false)

    private fun messaging(context:Context):FirebaseMessaging? {
        if(!BuildConfig.SPDECODE_CLOUD_ENABLED || !BuildConfig.SPDECODE_FCM_CONFIGURED)return null
        return try {
            val existing=FirebaseApp.getApps(context)
                .firstOrNull{it.name==FirebaseApp.DEFAULT_APP_NAME}
            if(existing!=null &&
                existing.options.applicationId!=BuildConfig.SPDECODE_FCM_APP_ID)return null
            if(existing==null)FirebaseApp.initializeApp(context,FirebaseOptions.Builder()
                .setProjectId(BuildConfig.SPDECODE_FCM_PROJECT_ID)
                .setApplicationId(BuildConfig.SPDECODE_FCM_APP_ID)
                .setApiKey(BuildConfig.SPDECODE_FCM_API_KEY)
                .setGcmSenderId(BuildConfig.SPDECODE_FCM_SENDER_ID)
                .build(),FirebaseApp.DEFAULT_APP_NAME)
            FirebaseMessaging.getInstance().also{it.isAutoInitEnabled=false}
        }catch(_:Exception){null}
    }

    @Synchronized fun setEnabled(context:Context,value:Boolean) {
        if(value && !CloudLegalConsent.accepted(context))return
        context.getSharedPreferences(PREFS,Context.MODE_PRIVATE)
            .edit().putBoolean(CONSENT,value).apply()
        if(value){
            ensureScheduled(context)
            // Firebase handles its own token. SP-DECODE neither reads nor stores it.
            messaging(context)?.subscribeToTopic(TOPIC)
        }else{
            val wm=WorkManager.getInstance(context)
            wm.cancelUniqueWork(BACKUP)
            wm.cancelUniqueWork(PUSH_WORK_NAME)
            messaging(context)?.let{
                it.unsubscribeFromTopic(TOPIC)
                it.deleteToken()
            }
        }
    }

    fun ensureScheduled(context:Context) {
        if(!enabled(context)||!CloudLegalConsent.accepted(context))return
        val constraints=Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
        val fallback=PeriodicWorkRequestBuilder<CloudCatalogSyncWorker>(12,TimeUnit.HOURS)
            .setConstraints(constraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL,30,TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            BACKUP,ExistingPeriodicWorkPolicy.KEEP,fallback)
    }

    /** An untrusted version hint can never supply URLs, icons or provider metadata. */
    fun onVersionHint(context:Context,rawVersion:String) {
        if(!enabled(context)||!CloudLegalConsent.accepted(context))return
        if(!rawVersion.matches(Regex("[1-9][0-9]{0,8}")))return
        val version=rawVersion.toIntOrNull()?:return
        val constraints=Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
        val immediate=OneTimeWorkRequestBuilder<CloudCatalogSyncWorker>()
            .setInputData(workDataOf("catalogVersion" to version))
            .setConstraints(constraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL,30,TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(PUSH_WORK_NAME,ExistingWorkPolicy.REPLACE,immediate)
    }

    /** Firebase must exist before a headless message service starts after process death. */
    fun restoreOnProcessStart(context:Context) {
        if(enabled(context) && CloudLegalConsent.accepted(context))messaging(context)
    }

    fun onTokenRotation(context:Context) {
        if(enabled(context)&&CloudLegalConsent.accepted(context))
            messaging(context)?.subscribeToTopic(TOPIC)
    }
}

internal class CloudCatalogPushService:FirebaseMessagingService() {
    override fun onMessageReceived(message:RemoteMessage) {
        if(message.data["type"]!="catalog_update")return
        val version=message.data["catalogVersion"]?:return
        CloudCatalogUpdates.onVersionHint(applicationContext,version)
    }
    override fun onNewToken(token:String) {
        // Token is deliberately not sent to SP-DECODE's own servers.
        CloudCatalogUpdates.onTokenRotation(applicationContext)
    }
}

internal class CloudCatalogSyncWorker(
    appContext:Context,parameters:WorkerParameters
):CoroutineWorker(appContext,parameters) {
    override suspend fun doWork():Result {
        if(!CloudCatalogUpdates.enabled(applicationContext) ||
            !CloudLegalConsent.accepted(applicationContext))return Result.success()
        val requested=inputData.getInt("catalogVersion",0)
        return try{
            val repository=ServerVpnCatalogRepository(applicationContext,
                CloudDecodeClient(applicationContext))
            repository.refreshIfDue(announcedVersion=requested)
            // Cached data survives transient offline/error states; retry only when
            // the announced version is still missing.
            if(requested>0 && repository.currentVersion()<requested && runAttemptCount<4)Result.retry()
            else Result.success()
        }catch(error:CancellationException){throw error}
         catch(_:Exception){Result.retry()}
    }
}
