package com.ghostdeveloper.spdecode.cloud

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** No Firebase or cloud account is needed to verify the anti-replay contract. */
class NoticeSubscriptionPolicyInstrumentedTest {
    @Test fun firstOptInUsesServerClockNotDeviceClock() {
        val server=2_000_000L
        val localOptIn=50_000_000L
        val localNow=50_060_000L
        val cutoff=NoticeSubscriptionPolicy.cutoff(server,localOptIn,localNow)
        assertEquals(1_940_000L,cutoff)
        assertFalse(NoticeSubscriptionPolicy.eligible(1_939_999L,2_020_000L,server,cutoff))
        assertTrue(NoticeSubscriptionPolicy.eligible(1_950_000L,2_020_000L,server,cutoff))
    }
    @Test fun existingInstallationWithoutEnrollmentTimestampSkipsBacklog() {
        val cutoff=NoticeSubscriptionPolicy.cutoff(5_000_000L,0L,100_000L)
        assertEquals(5_000_000L,cutoff)
        assertFalse(NoticeSubscriptionPolicy.eligible(4_999_999L,5_001_000L,5_000_000L,cutoff))
        assertTrue(NoticeSubscriptionPolicy.eligible(5_000_000L,5_001_000L,5_000_000L,cutoff))
    }
    @Test fun maliciousOrExpiredNoticeNeverNotifies() {
        val now=10_000_000L
        assertFalse(NoticeSubscriptionPolicy.eligible(now+5001,now+10000,now,now-3000))
        assertFalse(NoticeSubscriptionPolicy.eligible(now-2000,now-1,now,now-3000))
        assertEquals(3,NoticeSubscriptionPolicy.MAX_ALERTS_PER_SYNC)
    }
}
