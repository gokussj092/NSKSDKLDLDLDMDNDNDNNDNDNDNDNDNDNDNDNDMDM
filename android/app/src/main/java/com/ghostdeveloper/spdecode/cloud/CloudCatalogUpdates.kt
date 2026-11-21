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
    private const val DOWNLOAD="catalog-download-in-background"
    private const val BACKUP="catalog-version-recovery"
    private const val IMMEDIATE_CHECK="catalog-version-opt-in-check"
    internal const val PUSH_WORK_NAME="catalog-version-push"
    private const val PENDING_VERSION="latest-offered-catalog"
    private const val AUTO_VERSION="last-automatic-catalog-version"
    private const val AUTO_TIME="last-automatic-catalog-time"

    fun enabled(context:Context):Boolean =
        BuildConfig.SPDECODE_CLOUD_ENABLED &&
            context.getSharedPreferences(PREFS,Context.MODE_PRIVATE).getBoolean(CONSENT,false)

    @Synchronized fun setEnabled(context:Context,value:Boolean) {
        if(value && !CloudLegalConsent.accepted(context))return
        context.getSharedPreferences(PREFS,Context.MODE_PRIVATE)
            .edit().putBoolean(CONSENT,value).apply()
        if(value) {
            ensureScheduled(context)
            if (downloadInBackground(context)) checkNow(context)
        }
        else {
            val wm=WorkManager.getInstance(context)
            wm.cancelUniqueWork(BACKUP)
            wm.cancelUniqueWork(PUSH_WORK_NAME)
            wm.cancelUniqueWork(IMMEDIATE_CHECK)
            wm.cancelAllWorkByTag(CatalogTransferWorker.AUTO_TAG)
        }
    }

    fun backgroundEnabled(context: Context): Boolean =
        BuildConfig.SPDECODE_CLOUD_ENABLED &&
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(DOWNLOAD, false)

    fun downloadInBackground(context: Context): Boolean = enabled(context) && backgroundEnabled(context)

    fun setBackgroundEnabled(context: Context, value: Boolean) {
        if (value && !CloudLegalConsent.accepted(context)) return
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(DOWNLOAD, value).remove(AUTO_VERSION).remove(AUTO_TIME).apply()
        if (value && enabled(context)) checkNow(context)
        else WorkManager.getInstance(context).cancelAllWorkByTag(CatalogTransferWorker.AUTO_TAG)
    }

    private fun checkNow(context: Context) {
        val check = OneTimeWorkRequestBuilder<CloudCatalogSyncWorker>()
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(IMMEDIATE_CHECK, ExistingWorkPolicy.KEEP, check)
    }

    /** Version hints are untrusted; the Worker authenticates and verifies the actual snapshot. */
    @Synchronized fun queueAutomaticDownload(context: Context, version: Int, installed: Int) {
        if (version !in 1..999999999 || version <= installed || !downloadInBackground(context) ||
            !CloudLegalConsent.accepted(context)) return
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        // Failed or cancelled work is not recreated repeatedly for the same hint.
        val age = now - prefs.getLong(AUTO_TIME, 0)
        if (prefs.getInt(AUTO_VERSION, 0) >= version && age in 0 until TimeUnit.HOURS.toMillis(24)) return
        CatalogTransferWorker.enqueue(context, version, automatic = true, background = true)
    }

    fun recordAutomaticAttempt(context: Context, version: Int) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putInt(AUTO_VERSION, version).putLong(AUTO_TIME, System.currentTimeMillis()).apply()
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
        if (downloadInBackground(context)) checkNow(context)
    }

    /** HTTPS long-poll from the VPS while the consenting app is visible.
     * The server responds only on a newer version or after a bounded timeout.
     * Version hints never trigger catalog downloads or decode operations.
     */
    suspend fun watchWhileVisible(
        context:Context,client:CloudDecodeClient,repository:ServerVpnCatalogRepository,
        onAvailable:(Int)->Unit
    ) {
        var known=repository.currentVersion()
        var lastNotified=known
        while(currentCoroutineContext().isActive && BuildConfig.SPDECODE_CLOUD_ENABLED &&
            CloudLegalConsent.accepted(context)){
            try {
                val cached=pendingVersion(context)
                if(cached>lastNotified && cached>repository.currentVersion()){
                    lastNotified=cached
                    onAvailable(cached)
                }
                // Keep the watch at the latest observed version even if the
                // user postponed downloading it. This avoids busy-loop requests.
                known=maxOf(known,repository.currentVersion(),cached)
                val remote=client.watchCatalogVersion(known)
                if(remote>known){
                    known=remote
                    markOffered(context,remote)
                    if(remote>lastNotified && remote>repository.currentVersion()){
                        lastNotified=remote
                        onAvailable(remote)
                    }
                }
                // A 12-second long-poll already detects updates promptly.
                // If the backend returns immediately (e.g. unchanged or at
                // watch capacity), do not busy-loop an authenticated request
                // every 1.5 seconds while the user merely views the app.
                delay(15_000)
            }catch(error:CancellationException){throw error}
             catch(_:Exception){
                // Rate limits and connectivity errors must never block the UI.
                delay(30_000)
            }
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
            val client = CloudDecodeClient(applicationContext)
            val remote = client.watchCatalogVersion(0)
            val offered = maxOf(requested, remote)
            CloudCatalogUpdates.markOffered(applicationContext, offered)
            if (CloudCatalogUpdates.downloadInBackground(applicationContext)) {
                val installed = ServerVpnCatalogRepository(applicationContext, client).currentVersion()
                CloudCatalogUpdates.queueAutomaticDownload(applicationContext, remote, installed)
            }
            Result.success()
        }catch(error:CancellationException){throw error}
         catch(_:Exception){Result.failure()}
    }
}
