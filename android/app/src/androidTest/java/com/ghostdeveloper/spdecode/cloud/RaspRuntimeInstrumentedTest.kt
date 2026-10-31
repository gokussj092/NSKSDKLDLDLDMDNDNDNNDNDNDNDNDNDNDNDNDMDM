package com.ghostdeveloper.spdecode.cloud

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Real runtime smoke. Does not claim Play/HPKE E2E or override server policy. */
@RunWith(AndroidJUnit4::class)
class RaspRuntimeInstrumentedTest {
    @Test fun ownProcessReportIsBoundedAndRepeatable() {
        repeat(8) {
            val report=JSONObject(CloudNativeTransport.runtimeReport())
            assertEquals(1,report.getInt("v"))
            assertTrue(report.getInt("signals") in 0..15)
            assertTrue(report.getInt("evaluated") in 0..15)
            assertEquals(0,report.getInt("signals") and report.getInt("evaluated").inv())
            assertTrue(report.getLong("elapsedUs") in 0L..60_000_000L)
        }
    }
}
