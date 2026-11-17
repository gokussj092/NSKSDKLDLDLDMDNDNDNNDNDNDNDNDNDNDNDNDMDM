package com.ghostdeveloper.spdecode.cloud

import org.junit.Assert.*
import org.junit.Test
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId

class StreakReminderPolicyTest {
    private val zone=ZoneId.of("America/Tijuana")
    private fun at(value:String)=Instant.parse(value).toEpochMilli()
    @Test fun completedDayAndAlreadyNotifiedDayStayQuiet(){
        val now=at("2026-11-18T04:00:00Z") // Nov 17, 20:00 in Tijuana
        val today=LocalDate.parse("2026-11-17")
        assertTrue(StreakReminderPolicy.shouldNotify(now,zone,null,null))
        assertFalse(StreakReminderPolicy.shouldNotify(now,zone,today,null))
        assertFalse(StreakReminderPolicy.shouldNotify(now,zone,null,today))
        assertFalse(StreakReminderPolicy.shouldNotify(at("2026-11-18T08:00:00Z"),zone,null,null))
    }
    @Test fun phoneClockChangesDoNotChangeTheSameBootServerAnchor(){
        val server=at("2026-11-17T12:00:00Z")
        assertEquals(server+5000,StreakReminderPolicy.trustedNow(server,1000,6000,true,at("2099-01-01T00:00:00Z")))
        // After reboot the wall clock is used ONLY to time a local reminder.
        assertEquals(9000L,StreakReminderPolicy.trustedNow(server,1000,500,false,9000))
    }
    @Test fun successSchedulesTomorrowAndDstKeepsTheLocalEvening(){
        val now=at("2026-11-17T12:00:00Z")
        assertEquals(16*60*60*1000L,StreakReminderPolicy.initialDelay(now,zone,null,null))
        assertEquals(40*60*60*1000L,StreakReminderPolicy.initialDelay(now,zone,LocalDate.parse("2026-11-17"),null))
        val dst=at("2026-11-01T07:00:00Z")
        assertEquals(21*60*60*1000L,StreakReminderPolicy.initialDelay(dst,zone,null,null))
    }
}
