package com.ghostdeveloper.spdecode.cloud

import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId

/** Reminder timing only. This policy never awards a day or a credit. */
internal object StreakReminderPolicy {
    fun trustedNow(serverMillis:Long,anchorElapsed:Long,elapsed:Long,
                   sameBoot:Boolean,wallMillis:Long):Long =
        if(sameBoot && elapsed>=anchorElapsed)serverMillis+(elapsed-anchorElapsed) else wallMillis

    fun shouldNotify(now:Long,zone:ZoneId,completedDay:LocalDate?,notifiedDay:LocalDate?):Boolean {
        val local=Instant.ofEpochMilli(now).atZone(zone)
        return local.hour in 20..22 && local.toLocalDate()!=completedDay && local.toLocalDate()!=notifiedDay
    }

    fun initialDelay(now:Long,zone:ZoneId,completedDay:LocalDate?,notifiedDay:LocalDate?):Long {
        if(shouldNotify(now,zone,completedDay,notifiedDay))return 60_000L
        val local=Instant.ofEpochMilli(now).atZone(zone)
        val today=local.toLocalDate()
        val day=if(local.hour>=20||completedDay==today||notifiedDay==today)today.plusDays(1) else today
        return (day.atTime(20,0).atZone(zone).toInstant().toEpochMilli()-now).coerceAtLeast(60_000L)
    }
}
