package com.ghostdeveloper.spdecode.cloud

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.content.res.Configuration
import android.os.Build
import android.os.SystemClock
import android.text.format.Formatter
import androidx.core.app.NotificationCompat
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.ForegroundInfo
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import com.ghostdeveloper.spdecode.MainActivity
import com.ghostdeveloper.spdecode.R
import java.io.IOException
import java.util.Locale
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout

/** The only owner of catalog network transfers. Activity observers can come and go. */
internal class CatalogTransferWorker(
    context: Context,
    parameters: WorkerParameters,
) : CoroutineWorker(context, parameters) {
    companion object {
        const val WORK_NAME = "spdecode-catalog-transfer"
        const val AUTO_TAG = "spdecode-catalog-automatic"
        const val BACKGROUND_TAG = "spdecode-catalog-in-notifications"
        const val VERSION = "catalog-version"
        const val RECEIVED = "received-bytes"
        const val TOTAL = "total-bytes"
        const val RESUMABLE = "resumable"
        const val DISPLAY_VERSION = "display-version"
        private const val CHANNEL = "catalog-transfer-v1"
        private const val MAX_ATTEMPTS = 4

        fun enqueue(context: Context, version: Int, automatic: Boolean, background: Boolean) {
            if (!CloudLegalConsent.accepted(context)) return
            if (automatic && !CloudCatalogUpdates.downloadInBackground(context)) return
            val request = OneTimeWorkRequestBuilder<CatalogTransferWorker>()
                .setInputData(workDataOf(VERSION to version))
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .apply {
                    if (automatic) addTag(AUTO_TAG)
                    if (background || automatic) addTag(BACKGROUND_TAG)
                }.build()
            WorkManager.getInstance(context).enqueueUniqueWork(WORK_NAME, ExistingWorkPolicy.KEEP, request)
        }
    }

    private val app = applicationContext
    private val textContext: Context by lazy {
        val tag = app.getSharedPreferences("spdecode-ui-preferences", Context.MODE_PRIVATE)
            .getString("language", "system")
        if (tag == null || tag == "system") app
        else app.createConfigurationContext(Configuration(app.resources.configuration).apply {
            setLocale(Locale.forLanguageTag(tag))
        })
    }
    private val notifications = app.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    private val automatic = AUTO_TAG in tags
    private val background = BACKGROUND_TAG in tags
    private val notificationId = 0x41000000 or (id.hashCode() and 0x00ffffff)
    private val version = inputData.getInt(VERSION, 0)
    private var received = 0L
    private var total = -1L
    private var resumable = false
    private var verifying = false
    private var lastPostedAt = -1L

    private fun progress() = workDataOf(
        VERSION to version, RECEIVED to received, TOTAL to total, RESUMABLE to resumable,
    )

    private fun notification(title: Int, text: String?, ongoing: Boolean): Notification {
        val destination = PendingIntent.getActivity(app, 0,
            Intent(app, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val percent = if (total > 0) (received.coerceIn(0, total) * 100 / total).toInt() else 0
        return NotificationCompat.Builder(app, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle(textContext.getString(title))
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(destination)
            .setOnlyAlertOnce(true)
            .setOngoing(ongoing)
            .setAutoCancel(!ongoing)
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .apply {
                if (ongoing) {
                    setProgress(100, percent, total <= 0 || verifying)
                    addAction(android.R.drawable.ic_menu_close_clear_cancel,
                        textContext.getString(android.R.string.cancel),
                        WorkManager.getInstance(app).createCancelPendingIntent(id))
                }
            }.build()
    }

    private fun transferNotification(): Notification {
        val text = when {
            verifying -> textContext.getString(R.string.catalog_transfer_verifying)
            total > 0 -> {
                val bytes = received.coerceIn(0, total)
                textContext.getString(R.string.catalog_background_progress,
                    (bytes * 100 / total).toInt(),
                    Formatter.formatFileSize(textContext, bytes),
                    Formatter.formatFileSize(textContext, total),
                    Formatter.formatFileSize(textContext, total - bytes))
            }
            received > 0 -> Formatter.formatFileSize(textContext, received)
            else -> null
        }
        return notification(R.string.catalog_transfer_downloading, text, ongoing = true)
    }

    private fun publishProgress(force: Boolean = false) {
        val now = SystemClock.elapsedRealtime()
        if (!force && lastPostedAt >= 0 && now - lastPostedAt < 450L) return
        lastPostedAt = now
        setProgressAsync(progress())
        if (background || !automatic) {
            try { notifications.notify(notificationId, transferNotification()) }
            catch (_: SecurityException) { /* Permission controls display, not the transfer. */ }
        }
    }

    private fun finalNotice(title: Int) {
        if (!background) return
        try { notifications.notify(notificationId xor 0x01000000, notification(title, null, ongoing = false)) }
        catch (_: SecurityException) { /* User may have disabled this channel. */ }
    }

    override suspend fun doWork(): Result {
        if (!CloudLegalConsent.accepted(app) ||
            (automatic && !CloudCatalogUpdates.downloadInBackground(app))) return Result.success()
        val repository = ServerVpnCatalogRepository(app, CloudDecodeClient(app))
        val previous = repository.currentVersion()
        if (automatic && version <= previous) return Result.success()
        if (automatic) CloudCatalogUpdates.recordAutomaticAttempt(app, version)
        resumable = background || app.getSharedPreferences("spdecode-catalog-sync", Context.MODE_PRIVATE)
            .getBoolean("download-by-chunks", false)
        if (Build.VERSION.SDK_INT >= 26) {
            notifications.createNotificationChannel(NotificationChannel(
                CHANNEL, textContext.getString(R.string.catalog_background_channel), NotificationManager.IMPORTANCE_LOW))
        }
        var foreground = false
        if (!automatic) {
            // Promotion is attempted for a transfer initiated by a visible user action.
            // Android may deny it if the app was already backgrounded when the job started.
            try {
                val info = if (Build.VERSION.SDK_INT >= 29) ForegroundInfo(
                    notificationId, transferNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
                else ForegroundInfo(notificationId, transferNotification())
                setForeground(info)
                foreground = true
            } catch (error: CancellationException) {
                throw error
            } catch (_: IllegalStateException) {
                // Retain scheduled work and retry verified fragments if the OS stops it.
            } catch (_: SecurityException) {
                // The transfer can still use ordinary WorkManager scheduling.
            }
        }
        publishProgress(force = true)
        return try {
            withTimeout(if (foreground) TimeUnit.HOURS.toMillis(1) else TimeUnit.MINUTES.toMillis(8)) {
                coroutineScope {
                    val owner = currentCoroutineContext()
                    val cancellation = launch(start = CoroutineStart.UNDISPATCHED) {
                        try { awaitCancellation() }
                        finally {
                            // The full native download can be blocked in an HTTP read.
                            if (!owner.isActive && !resumable) CloudNativeTransport.cancelCatalogDownload()
                        }
                    }
                    try {
                        repository.refreshIfDue(
                            force = true, announcedVersion = version, useChunks = resumable,
                            onTransfer = { downloaded, size ->
                                received = downloaded
                                total = size
                                publishProgress()
                            },
                            onProgress = {
                                if (!verifying) {
                                    verifying = true
                                    publishProgress(force = true)
                                }
                            },
                        )
                    } finally { cancellation.cancel() }
                }
            }
            val installed = repository.currentVersion()
            if (installed < version || installed < 1) {
                finalNotice(R.string.server_vpn_catalog_update_error)
                return Result.failure(progress())
            }
            if (installed > previous || !automatic) finalNotice(R.string.catalog_transfer_completed)
            Result.success(workDataOf(DISPLAY_VERSION to repository.displayVersion().orEmpty()))
        } catch (_: TimeoutCancellationException) {
            if (runAttemptCount + 1 < MAX_ATTEMPTS) Result.retry()
            else Result.failure(progress()).also { finalNotice(R.string.catalog_transfer_paused) }
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            val transient = error is IOException ||
                (error is CloudDecodeClient.Failure && error.httpStatus in setOf(408, 429, 500, 502, 503, 504))
            if (transient && runAttemptCount + 1 < MAX_ATTEMPTS) Result.retry()
            else Result.failure(progress()).also { finalNotice(R.string.catalog_transfer_paused) }
        } finally {
            notifications.cancel(notificationId)
        }
    }
}
