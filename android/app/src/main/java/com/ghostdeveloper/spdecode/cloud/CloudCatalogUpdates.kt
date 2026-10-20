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
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

/** No Firebase, user accounts, device messaging tokens, or persistent background sockets. */
internal object CloudCatalogUpdates {
    private const val PREFS="spdecode-catalog-sync"
    private const val CONSENT="allow-background-sync"
    private const val BACKUP="catalog-version-recovery"
    internal const val PUSH_WORK_NAME="catalog-version-push"

    fun enabled(context:Context):Boolean =
        BuildConfig.SPDECODE_CLOUD_ENABLED &&
            context.getSharedPreferences(PREFS,Context.MODE_PRIVATE).getBoolean(CONSENT,false)

    @Synchronized fun setEnabled(context:Context,value:Boolean) {
        if(value && !CloudLegalConsent.accepted(context))return
        context.getSharedPreferences(PREFS,Context.MODE_PRIVATE)
            .edit().putBoolean(CONSENT,value).apply()
        if(value)ensureScheduled(context)
        else {
            val wm=WorkManager.getInstance(context)
            wm.cancelUniqueWork(BACKUP)
            wm.cancelUniqueWork(PUSH_WORK_NAME)
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

    /** Untrusted version hints never carry URLs, icon bytes or provider metadata. */
    fun onVersionHint(context:Context,rawVersion:String) {
        if(!enabled(context)||!CloudLegalConsent.accepted(context))return
        if(!rawVersion.matches(Regex("[1-9][0-9]{0,8}")))return
        val version=rawVersion.toIntOrNull()?:return
        val constraints=Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
        val work=OneTimeWorkRequestBuilder<CloudCatalogSyncWorker>()
            .setInputData(workDataOf("catalogVersion" to version))
            .setConstraints(constraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL,30,TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            PUSH_WORK_NAME,ExistingWorkPolicy.REPLACE,work)
    }

    /** The VPS returns a version over native HTTPS; this coroutine runs only while visible. */
    suspend fun watchWhileVisible(
        context:Context,client:CloudDecodeClient,repository:ServerVpnCatalogRepository,
        onUpdated:(List<ServerVpnApp>)->Unit
    ) {
        while(currentCoroutineContext().isActive && enabled(context) &&
            CloudLegalConsent.accepted(context)){
            try {
                val local=repository.currentVersion()
                val hint=client.watchCatalogVersion(local)
                if(hint>local) {
                    val fresh=repository.refreshIfDue(announcedVersion=hint)
                    if(repository.currentVersion()>=hint)onUpdated(fresh)
                    else {
                        onVersionHint(context,hint.toString())
                        delay(15000)
                    }
                }else delay(2000)
            }catch(error:CancellationException){throw error}
             catch(_:Exception){delay(15000)}
        }
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
            if(requested>0 && repository.currentVersion()<requested && runAttemptCount<4)
                Result.retry()
            else Result.success()
        }catch(error:CancellationException){throw error}
         catch(_:Exception){if(runAttemptCount<4)Result.retry() else Result.failure()}
    }
}
