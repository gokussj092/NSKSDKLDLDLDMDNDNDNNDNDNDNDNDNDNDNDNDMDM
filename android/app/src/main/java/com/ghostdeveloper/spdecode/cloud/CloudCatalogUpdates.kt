package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkerParameters
import androidx.work.WorkManager
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
    private const val PENDING_VERSION="latest-offered-catalog"

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
        val fallback=PeriodicWorkRequestBuilder<CloudCatalogSyncWorker>(24,TimeUnit.HOURS)
            .setConstraints(constraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL,30,TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            BACKUP,ExistingPeriodicWorkPolicy.KEEP,fallback)
        WorkManager.getInstance(context).cancelUniqueWork(PUSH_WORK_NAME)
    }

    fun pendingVersion(context:Context):Int =
        context.getSharedPreferences(PREFS,Context.MODE_PRIVATE).getInt(PENDING_VERSION,0)

    fun markOffered(context:Context,version:Int){
        if(version !in 1..999999999)return
        val prefs=context.getSharedPreferences(PREFS,Context.MODE_PRIVATE)
        if(version>prefs.getInt(PENDING_VERSION,0))
            prefs.edit().putInt(PENDING_VERSION,version).apply()
    }

    /** Untrusted version hints never carry URLs, icon bytes or provider metadata. */
    fun onVersionHint(context:Context,rawVersion:String) {
        if(!enabled(context)||!CloudLegalConsent.accepted(context))return
        if(!rawVersion.matches(Regex("[1-9][0-9]{0,8}")))return
        val version=rawVersion.toIntOrNull()?:return
        markOffered(context,version)
        // A push already supplies a version hint. Verify/download only after the user's tap.
    }

    /** Only reads local push hints while visible. Network recovery is opt-in and daily. */
    suspend fun watchWhileVisible(
        context:Context,client:CloudDecodeClient,repository:ServerVpnCatalogRepository,
        onAvailable:(Int)->Unit
    ) {
        while(currentCoroutineContext().isActive && enabled(context) &&
            CloudLegalConsent.accepted(context)){
            try {
                val local=repository.currentVersion()
                val hint=pendingVersion(context)
                if(hint>local) {
                    markOffered(context,hint)
                    onAvailable(hint)
                }
                delay(60_000)
            }catch(error:CancellationException){throw error}
             catch(_:Exception){delay(60_000)}
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
            // Background recovery only retains a version hint. Never download
            // new catalogs without the user confirming the foreground dialog.
            val remote=CloudDecodeClient(applicationContext).watchCatalogVersion(0)
            CloudCatalogUpdates.markOffered(applicationContext,maxOf(requested,remote))
            Result.success()
        }catch(error:CancellationException){throw error}
         catch(_:Exception){Result.failure()}
    }
}
