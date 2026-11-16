package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.CancellationException
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Survives Activity closure and Android process recreation. WorkManager may
 * postpone execution under Doze/network restrictions; a retry always resumes
 * the same encrypted checkpoint and never starts another APK or reserves a
 * second credit (the server binds the reservation to the job id).
 *
 * There is no consent gate here: this flow has no checkbox (Pedro, P2), and
 * the server never requires consent for app analysis. The LEGAL consent
 * below is different: it is the app-wide terms acceptance
 * (CloudLegalConsent), which the V2 transport path requires on every call
 * (same pre-check as ApkQaWorker). A withdrawn legal consent pauses work
 * as a failure instead of retrying forever.
 */
internal class AppAnalysisWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    companion object {
        private const val UNIQUE_NAME = "spdecode-app-analysis-single"
        fun enqueue(context: Context, replace: Boolean = false) {
            val request = OneTimeWorkRequestBuilder<AppAnalysisWorker>()
                .setConstraints(Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED).build())
                .setBackoffCriteria(BackoffPolicy.LINEAR, 20, TimeUnit.SECONDS)
                .addTag(UNIQUE_NAME)
                .build()
            WorkManager.getInstance(context.applicationContext).enqueueUniqueWork(
                UNIQUE_NAME,
                if (replace) ExistingWorkPolicy.REPLACE else ExistingWorkPolicy.KEEP,
                request)
        }
    }

    override suspend fun doWork(): Result {
        val client = AppAnalysisClient(applicationContext)
        if(!CloudLegalConsent.accepted(applicationContext)) {
            // Withdrawal pauses work without pretending the remote job ended.
            client.noteRecoverableError("LEGAL_CONSENT_REQUIRED")
            return Result.failure()
        }
        return try {
            client.executeQueued()
            Result.success()
        } catch (error: CancellationException) {
            throw error
        } catch (error: AppAnalysisClient.Failure) {
            if (error.code in setOf("SIGN_IN_REQUIRED", "INSUFFICIENT_CREDITS",
                    "APP_ANALYSIS_ACCESS_DENIED", "APP_ANALYSIS_JOB_NOT_FOUND",
                    "APP_ANALYSIS_FORMAT_UNSUPPORTED", "APP_ANALYSIS_INPUT_TOO_LARGE",
                    "APP_ANALYSIS_EMPTY_FILE", "APP_ANALYSIS_INVALID_SESSION",
                    "APP_ANALYSIS_SHA_MISMATCH", "LEGAL_CONSENT_REQUIRED",
                    "INTEGRITY_REJECTED")) {
                client.noteTerminalError(error.code)
                Result.failure()
            } else {
                client.noteRecoverableError(error.code)
                Result.retry()
            }
        } catch (error: IOException) {
            val code = error.message.orEmpty()
            if (code == "APP_ANALYSIS_RETRY_SCHEDULED") return Result.retry()
            if (code in setOf("APP_ANALYSIS_INPUT_TOO_LARGE", "APP_ANALYSIS_EMPTY_FILE",
                    "APP_ANALYSIS_FORMAT_UNSUPPORTED", "APP_ANALYSIS_FILE_CHANGED")) {
                client.noteTerminalError(code)
                Result.failure()
            } else {
                client.noteRecoverableError(code)
                Result.retry()
            }
        } catch (_: Exception) {
            // Never serialize exception messages, stack traces, tokens, URIs,
            // filenames or internal methods into WorkManager or logs.
            client.noteRecoverableError("APP_ANALYSIS_RECONNECTING")
            Result.retry()
        }
    }
}
