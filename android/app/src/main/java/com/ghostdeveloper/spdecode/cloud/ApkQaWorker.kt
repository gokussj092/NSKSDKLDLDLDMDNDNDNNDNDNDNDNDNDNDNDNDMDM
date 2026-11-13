package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import kotlinx.coroutines.CancellationException
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkerParameters
import androidx.work.WorkManager
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Survives Activity closure and Android process recreation. WorkManager may
 * postpone execution under Doze/network restrictions; a retry always resumes
 * the same encrypted checkpoint and never starts another APK.
 */
internal class ApkQaWorker(context:Context,params:WorkerParameters):
    CoroutineWorker(context,params) {

    companion object {
        private const val UNIQUE_NAME="spdecode-apk-qa-single-upload"
        fun enqueue(context:Context,replace:Boolean=false) {
            val request=OneTimeWorkRequestBuilder<ApkQaWorker>()
                .setConstraints(Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED).build())
                .setBackoffCriteria(BackoffPolicy.LINEAR,20,TimeUnit.SECONDS)
                .addTag(UNIQUE_NAME)
                .build()
            WorkManager.getInstance(context.applicationContext).enqueueUniqueWork(
                UNIQUE_NAME,
                if(replace) ExistingWorkPolicy.REPLACE else ExistingWorkPolicy.KEEP,
                request)
        }
    }

    override suspend fun doWork():Result {
        val client=CloudApkQaClient(applicationContext,CloudDecodeClient(applicationContext))
        if(!CloudLegalConsent.accepted(applicationContext)) {
            // Withdrawal pauses work without pretending the remote job ended.
            client.noteRecoverableError("LEGAL_CONSENT_REQUIRED")
            return Result.failure()
        }
        return try {
            client.executeQueued()
            Result.success()
        }catch(error:CancellationException) {
            throw error
        }catch(error:CloudDecodeClient.Failure) {
            if(error.code in setOf("JOB_UNAVAILABLE","JOB_EXPIRED",
                    "INPUT_TOO_LARGE","UNSUPPORTED_FORMAT","INVALID_START_ID",
                    "INSUFFICIENT_CREDITS","SIGN_IN_REQUIRED","APK_QA_ACCESS_DENIED")) {
                client.noteTerminalError(error.code)
                Result.failure()
            } else {
                client.noteRecoverableError(error.code)
                Result.retry()
            }
        }catch(error:IOException) {
            val code=error.message.orEmpty()
            // WorkManager time-slice rollover is an automatic continuation,
            // not a disconnected QA session requiring manual intervention.
            if(code=="APK_QA_RETRY_SCHEDULED")return Result.retry()
            if(code in setOf("APK_QA_INPUT_TOO_LARGE","APK_QA_EMPTY_FILE",
                    "APK_QA_FORMAT_UNSUPPORTED")) {
                client.noteTerminalError(code)
                Result.failure()
            } else {
                client.noteRecoverableError(code)
                Result.retry()
            }
        }catch(error:Exception) {
            // Never serialize exception messages, stack traces, tokens, URIs,
            // filenames or internal methods into WorkManager or logs.
            client.noteRecoverableError("APK_QA_RECONNECTING")
            Result.retry()
        }
    }
}
