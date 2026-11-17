package com.ghostdeveloper.spdecode.cloud

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.*
import com.ghostdeveloper.spdecode.MainActivity
import com.ghostdeveloper.spdecode.NativeCommerceAuth
import com.ghostdeveloper.spdecode.R
import org.json.JSONObject
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.util.concurrent.TimeUnit

/** Local WorkManager reminders. No FCM message or network is needed to notify. */
internal object StreakReminders {
    private const val WORK="streak-inactivity-local-v1"
    private const val CHANNEL="streak-reminders-v1"
    private const val NOTIFICATION=4107
    private fun prefs(c:Context)=c.getSharedPreferences("spdecode-local-streak",Context.MODE_PRIVATE)
    private fun boot(c:Context)=Settings.Global.getInt(c.contentResolver,Settings.Global.BOOT_COUNT,-1)
    private fun day(value:String?)=runCatching{LocalDate.parse(value)}.getOrNull()
    private fun permitted(c:Context)=CloudNotifications.enabled(c)&&CloudNotifications.allowed(c)&&
        CloudLegalConsent.accepted(c)

    @Synchronized fun sync(c:Context,accountId:String,streak:JSONObject?) {
        if(streak==null||accountId.isBlank()||NativeCommerceAuth(c).cachedAccountId()!=accountId)return
        val server=runCatching{Instant.parse(streak.getString("serverNow")).toEpochMilli()}.getOrNull()?:return
        val zone=runCatching{ZoneId.of(streak.getString("timeZone"))}.getOrNull()?:return
        val today=day(streak.optString("today"))?:return
        val p=prefs(c)
        if(p.getString("account",null)!=accountId)p.edit().clear().commit()
        val edit=p.edit().putString("account",accountId).putString("zone",zone.id)
            .putLong("server",server).putLong("elapsed",SystemClock.elapsedRealtime()).putInt("boot",boot(c))
        if(streak.optBoolean("completedToday"))edit.putString("completed",today.toString())
        edit.commit()
        if(streak.optBoolean("completedToday"))NotificationManagerCompat.from(c).cancel(NOTIFICATION)
        schedule(c)
    }

    @Synchronized fun clear(c:Context){
        prefs(c).edit().clear().commit()
        cancel(c)
    }
    fun cancel(c:Context){
        WorkManager.getInstance(c).cancelUniqueWork(WORK)
        NotificationManagerCompat.from(c).cancel(NOTIFICATION)
    }
    @Synchronized fun schedule(c:Context){
        if(!permitted(c)){cancel(c);return}
        val p=prefs(c)
        val account=p.getString("account",null)?:return
        if(NativeCommerceAuth(c).cachedAccountId()!=account){clear(c);return}
        val zone=runCatching{ZoneId.of(p.getString("zone",null))}.getOrNull()?:return
        val delay=StreakReminderPolicy.initialDelay(now(c),zone,day(p.getString("completed",null)),day(p.getString("notified",null)))
        val work=PeriodicWorkRequestBuilder<StreakReminderWorker>(1,TimeUnit.HOURS)
            .setInitialDelay(delay,TimeUnit.MILLISECONDS).build()
        // A confirmed decode moves the next reminder to the following day.
        WorkManager.getInstance(c).enqueueUniquePeriodicWork(WORK,ExistingPeriodicWorkPolicy.CANCEL_AND_REENQUEUE,work)
    }
    private fun now(c:Context):Long{
        val p=prefs(c);val currentBoot=boot(c)
        return StreakReminderPolicy.trustedNow(p.getLong("server",0),p.getLong("elapsed",0),
            SystemClock.elapsedRealtime(),currentBoot>=0&&p.getInt("boot",-2)==currentBoot,System.currentTimeMillis())
    }
    @Synchronized fun check(c:Context){
        if(!permitted(c))return
        val p=prefs(c)
        val account=p.getString("account",null)?:return
        if(NativeCommerceAuth(c).cachedAccountId()!=account){clear(c);return}
        val zone=runCatching{ZoneId.of(p.getString("zone",null))}.getOrNull()?:return
        val now=now(c)
        if(!StreakReminderPolicy.shouldNotify(now,zone,day(p.getString("completed",null)),day(p.getString("notified",null))))return
        val manager=NotificationManagerCompat.from(c)
        if(!manager.areNotificationsEnabled())return
        if(Build.VERSION.SDK_INT>=26){
            val system=c.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            system.createNotificationChannel(NotificationChannel(CHANNEL,c.getString(R.string.streak_reminder_channel),NotificationManager.IMPORTANCE_DEFAULT))
        }
        val intent=Intent(c,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val tap=PendingIntent.getActivity(c,NOTIFICATION,intent,PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification=NotificationCompat.Builder(c,CHANNEL).setSmallIcon(R.drawable.ic_service_notice)
            .setContentTitle(c.getString(R.string.streak_reminder_title)).setContentText(c.getString(R.string.streak_reminder_body))
            .setContentIntent(tap).setAutoCancel(true).setVisibility(NotificationCompat.VISIBILITY_PRIVATE).build()
        try{
            manager.notify(NOTIFICATION,notification)
            p.edit().putString("notified",Instant.ofEpochMilli(now).atZone(zone).toLocalDate().toString()).commit()
        }catch(_:SecurityException){}
    }
}

class StreakReminderWorker(context:Context,params:WorkerParameters):Worker(context,params){
    override fun doWork():Result {
        StreakReminders.check(applicationContext)
        return Result.success()
    }
}
