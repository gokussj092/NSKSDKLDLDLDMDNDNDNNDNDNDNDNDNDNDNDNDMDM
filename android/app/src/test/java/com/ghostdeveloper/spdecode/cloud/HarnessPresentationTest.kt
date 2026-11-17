package com.ghostdeveloper.spdecode.cloud

import org.junit.Assert.*
import org.junit.Test

class HarnessPresentationTest {
    @Test fun nullNamesNeverMaskTheFilename() {
        for (value in listOf(null, "", "  ", "null", " NULL ")) {
            assertNull(HarnessPresentation.text(value))
            assertEquals("DeepTune-VPN", HarnessPresentation.name(value, "DeepTune-VPN.apks", "com.example.vpn"))
        }
        assertEquals("DeepTune VPN", HarnessPresentation.name(" DeepTune VPN ", "base.apk", null))
        assertEquals("com.example.vpn", HarnessPresentation.name(null, null, "com.example.vpn"))
        assertEquals("APK", HarnessPresentation.name(null, "null", null))
    }
    @Test fun statusTakesPrecedenceOverStalePhase() {
        assertEquals("QUEUED", HarnessPresentation.stage("QUEUED_FOR_ANALYSIS", "UPLOAD_RECEIVED"))
        assertEquals("REVIEW", HarnessPresentation.stage("AWAITING_HUMAN", "ANALYSIS_STARTED"))
        assertEquals("COMPLETED", HarnessPresentation.stage("COMPLETED", "RESULT_PREPARATION"))
        assertEquals("FAILED", HarnessPresentation.stage("FAILED", "REPORT_READY"))
        assertEquals("CODE", HarnessPresentation.stage("ANALYZING", "DEX_BYTECODE_INSPECTION"))
        assertEquals("NATIVE", HarnessPresentation.stage("ANALYZING", "NATIVE_LIBRARY_INSPECTION"))
        assertEquals("ANALYZING", HarnessPresentation.stage("ANALYZING", "ADVANCED_HEARTBEAT"))
        assertEquals("PREPARING", HarnessPresentation.stage(null, null))
    }
    @Test fun normalTransferHasNoArtificialPause() {
        assertEquals(0L, HarnessPresentation.pauseMillis(false))
        assertEquals(4500L, HarnessPresentation.pauseMillis(true))
        assertEquals("download-by-chunks", HarnessPresentation.TRANSFER_KEY)
        assertEquals("spdecode-catalog-sync", HarnessPresentation.TRANSFER_PREFS)
    }
}
