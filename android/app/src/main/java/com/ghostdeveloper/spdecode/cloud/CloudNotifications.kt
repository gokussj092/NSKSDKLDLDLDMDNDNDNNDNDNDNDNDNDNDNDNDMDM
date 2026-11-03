package com.ghostdeveloper.spdecode.cloud

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.media.AudioAttributes
import android.net.Uri
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.work.*
import com.ghostdeveloper.spdecode.BuildConfig
import com.ghostdeveloper.spdecode.MainActivity
import com.ghostdeveloper.spdecode.R
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException

/** Subscription policy: never replay notices published before user opt-in.
 * Convert local opt-in elapsed time to the trusted server clock at first sync;
 * device clock offset cancels, including incorrectly configured time zones.
 */
internal object NoticeSubscriptionPolicy {
    const val MAX_ALERTS_PER_SYNC=3
    private const val MAX_LOOKBACK=7L*24*60*60*1000
    fun cutoff(serverTime:Long,enabledAtWall:Long,deviceTime:Long):Long {
        require(serverTime>0)
        val elapsed=if(enabledAtWall>0)
            (deviceTime-enabledAtWall).coerceIn(0L,MAX_LOOKBACK) else 0L
        return serverTime-elapsed
    }
    fun eligible(createdAt:Long,expiresAt:Long,serverTime:Long,cutoff:Long):Boolean =
        createdAt>=cutoff && createdAt<=serverTime+5000L &&
            createdAt>=serverTime-MAX_LOOKBACK && expiresAt>serverTime &&
            expiresAt<=createdAt+MAX_LOOKBACK
}

/** Optional push implementation is installed only by the Cloud source set. */
internal object CloudNoticePush {
    var configure:(Context,Boolean)->Unit={_,_->}
}

internal object CloudNotifications {
    private const val PREFS="spdecode-notifications"
    private const val CHANNEL="service-notices-chime-v2"
    private const val LEGACY_CHANNEL="service-notices-v1"
    private const val PERIODIC="service-notices-recovery"
    private const val IMMEDIATE="service-notices-refresh"
    private fun prefs(c:Context)=c.applicationContext.getSharedPreferences(PREFS,Context.MODE_PRIVATE)

    // Stable resource name instead of a generated R.raw integer, which can
    // change during Play updates. Android notification channels own their sound.
    private fun notificationSound(c:Context):Uri =
        Uri.parse("android.resource://" + c.packageName + "/raw/spdecode_notification")

    private fun ensureSoundChannel(c:Context) {
        if(Build.VERSION.SDK_INT<26)return
        val manager=c.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        // Preserve a previous system-level mute or reduced importance when
        // moving from v1. Do not forcibly re-enable silenced notifications.
        val previous=manager.getNotificationChannel(LEGACY_CHANNEL)
        val importance=if(previous!=null && previous.importance<NotificationManager.IMPORTANCE_DEFAULT)
            previous.importance else NotificationManager.IMPORTANCE_DEFAULT
        val channel=NotificationChannel(
            CHANNEL,c.getString(R.string.notifications_title),importance)
        if(previous!=null && previous.sound==null) {
            channel.setSound(null,null)
        } else {
            val attributes=AudioAttributes.Builder()
                .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                .setUsage(AudioAttributes.USAGE_NOTIFICATION)
                .build()
            channel.setSound(notificationSound(c),attributes)
        }
        manager.createNotificationChannel(channel)
    }
    fun enabled(c:Context)=BuildConfig.SPDECODE_CLOUD_ENABLED && prefs(c).getBoolean("enabled",false)
    fun allowed(c:Context)=Build.VERSION.SDK_INT<33 || ContextCompat.checkSelfPermission(c,
        Manifest.permission.POST_NOTIFICATIONS)==PackageManager.PERMISSION_GRANTED
    fun setEnabled(c:Context,value:Boolean) {
        if(value && (!CloudLegalConsent.accepted(c)||!allowed(c)))return
        val preferences=prefs(c)
        val wasEnabled=preferences.getBoolean("enabled",false)
        val edit=preferences.edit().putBoolean("enabled",value)
        if(value && !wasEnabled) {
            // Persist before subscription, WorkManager and FCM can fetch.
            edit.putLong("opt_in_at_wall",System.currentTimeMillis())
                .remove("eligible_since_server")
        } else if(!value) {
            // Re-subscribing never resurrects stale notices.
            edit.remove("opt_in_at_wall").remove("eligible_since_server")
        }
        edit.commit()
        CloudNoticePush.configure(c,value)
        if(value) {ensureScheduled(c);enqueue(c)} else {
            WorkManager.getInstance(c).cancelUniqueWork(PERIODIC)
            WorkManager.getInstance(c).cancelUniqueWork(IMMEDIATE)
            NotificationManagerCompat.from(c).cancelAll()
        }
    }
    fun ensureScheduled(c:Context) {
        if(!enabled(c)||!CloudLegalConsent.accepted(c))return
        val work=PeriodicWorkRequestBuilder<CloudNoticeWorker>(15,TimeUnit.MINUTES)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL,30,TimeUnit.SECONDS).build()
        WorkManager.getInstance(c).enqueueUniquePeriodicWork(PERIODIC,ExistingPeriodicWorkPolicy.KEEP,work)
    }
    fun enqueue(c:Context) {
        if(!enabled(c)||!allowed(c)||!CloudLegalConsent.accepted(c))return
        val work=OneTimeWorkRequestBuilder<CloudNoticeWorker>()
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL,30,TimeUnit.SECONDS).build()
        WorkManager.getInstance(c).enqueueUniqueWork(IMMEDIATE,ExistingWorkPolicy.KEEP,work)
    }
    /** Arbitrary push text/URLs are never displayed; fetch the authenticated feed first. */
    fun hint(c:Context,id:String) {
        if(id.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")))enqueue(c)
    }
    @Synchronized fun show(c:Context,body:org.json.JSONObject) {
        if(!enabled(c)||!allowed(c)||!CloudLegalConsent.accepted(c))return
        val manager=NotificationManagerCompat.from(c)
        if(!manager.areNotificationsEnabled())return
        ensureSoundChannel(c)
        val list=body.getJSONArray("notices");require(list.length()<=20)
        // A missing server timestamp fails closed: older servers cannot safely
        // distinguish published-before-opt-in from newly published notices.
        val serverTime=body.optLong("serverTime",0L)
        if(serverTime<=0L)return
        val preferences=prefs(c)
        var cutoff=preferences.getLong("eligible_since_server",0L)
        if(cutoff<=0L) {
            // Older installations migrated from the legacy no-cutoff client
            // intentionally discard their first backlog; new opt-ins keep
            // notices created after the opt-in even before their first sync.
            cutoff=NoticeSubscriptionPolicy.cutoff(serverTime,
                preferences.getLong("opt_in_at_wall",0L),System.currentTimeMillis())
            preferences.edit().putLong("eligible_since_server",cutoff).commit()
        }
        val seen=preferences.getStringSet("seen",emptySet()).orEmpty().toMutableSet()
        val eligible=mutableListOf<org.json.JSONObject>()
        val retained=mutableSetOf<String>()
        for(i in 0 until list.length()) {
            val n=list.getJSONObject(i)
            val id=n.optString("id")
            retained.add(id)
            val title=n.optString("title");val text=n.optString("body")
            val created=n.optLong("createdAt",0L);val expiry=n.optLong("expiresAt",0L)
            val type=n.optString("type","general")
            val importance=n.optString("importance","normal")
            val delivery=n.optString("delivery","push")
            if(!id.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")) ||
                id in seen || title.isBlank() || title.length>80 || text.isBlank() || text.length>500 ||
                type !in setOf("general","update","maintenance","catalog","security") ||
                importance !in setOf("normal","important") ||
                delivery !in setOf("push","poll") ||
                !NoticeSubscriptionPolicy.eligible(created,expiry,serverTime,cutoff))continue
            eligible.add(n)
        }
        // Never create a notification storm after a long time offline.
        // Important notices take precedence, then most recent publication.
        val sorted=eligible.sortedWith(
            compareByDescending<org.json.JSONObject>{it.optString("importance")=="important"}
                .thenByDescending{it.optLong("createdAt")})
        for((index,n) in sorted.withIndex()) {
            val id=n.getString("id")
            if(index>=NoticeSubscriptionPolicy.MAX_ALERTS_PER_SYNC) {
                // Mark omitted older notices processed so they do not flood
                // subsequent reconnects. Admin history remains available.
                seen.add(id)
                continue
            }
            val title=n.getString("title");val text=n.getString("body")
            val expiry=n.getLong("expiresAt")
            val intent=Intent(c,MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            val tap=PendingIntent.getActivity(c,0,intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val notification=NotificationCompat.Builder(c,CHANNEL)
                .setSmallIcon(R.drawable.ic_service_notice)
                .setContentTitle(title).setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setContentIntent(tap).setAutoCancel(true)
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setTimeoutAfter(expiry-serverTime)
                .setPriority(if(n.optString("importance")=="important")
                    NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
            // Android 8+ notification channel preferences always take precedence.
            if(Build.VERSION.SDK_INT<26)notification.setSound(notificationSound(c))
            try {manager.notify(id,0,notification.build());seen.add(id)}
            catch(_:SecurityException){break}
        }
        preferences.edit().putStringSet("seen",seen.intersect(retained)).apply()
    }
}

internal class CloudNoticeWorker(c:Context,p:WorkerParameters):CoroutineWorker(c,p) {
    override suspend fun doWork():Result {
        if(!CloudNotifications.enabled(applicationContext)||!CloudNotifications.allowed(applicationContext)||
            !CloudLegalConsent.accepted(applicationContext))return Result.success()
        return try {
            CloudNotifications.show(applicationContext,CloudDecodeClient(applicationContext).notifications())
            Result.success()
        }catch(e:CancellationException){throw e}
         catch(_:Exception){if(runAttemptCount<3)Result.retry() else Result.failure()}
    }
}
