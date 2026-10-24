package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.cloud.CloudFileFormats
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** R3: SAF duplicate counters only affect decoder routing, never file bytes. */
@RunWith(AndroidJUnit4::class)
class DuplicateImportFilenameInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val formats by lazy { AndroidDecoderCatalog.read(context) }

    @Test fun duplicatesAfterExtensionsResolveIncludingCompoundAndUnicode() {
        val cases = mapOf(
            "config.hc (1)" to "hc",
            "config.HC(2)" to "hc",
            "dir/config (1).hc" to "hc",
            "dir\\config.ehi (23)" to "ehi",
            "backup.sksrv.png (4)" to "sksrv.png",
            "export.Fɴ (5)" to "fɴ",
            "config.npvs (3)" to "npvs",
            "backup.7NET(14)" to "7net",
            "backup.solid (2)" to "solid",
        )
        for ((name,suffix) in cases) {
            assertEquals(name, suffix, AndroidDecoderCatalog.detect(name,formats)?.suffix)
        }
    }

    @Test fun cloudSpecificRoutesShareExactlyTheSameRule() {
        val cases = mapOf(
            "downloads/profile.tgv (1)" to "tgv",
            "download.MTP(2)" to "mtp",
            "path\\profile.ACTUN (12)" to "actun",
            "cloud.4ULITE (3)" to "4ulite",
            "cloud.ROY(4)" to "roy",
        )
        for ((name,suffix) in cases) {
            val detected=CloudFileFormats.detect(name)
            assertEquals(name,suffix,detected?.suffix)
            assertFalse(name,detected!!.hasNativeDecoder)
        }
    }

    @Test fun invalidAndSpoofedNamesStayUnsupported() {
        val cases = listOf(
            "payload.unknown (1)", "payload.hc (0)", "payload.hc (-1)",
            "payload.hc (9999999)", "payload.hc (1).bak", "payload.hc (test)",
            "payload.hc (1) extra", "payload.hc (1) ", "payload.hc (1).txt",
            "payload.hc (1)\\malware.exe", "payload.hc (1)/malware.exe"
        )
        for (name in cases) {
            assertNull(name,AndroidDecoderCatalog.detect(name,formats))
            assertNull(name,CloudFileFormats.detect(name))
        }
    }

    @Test fun originalNameAndOriginalContentArePreserved() {
        val original="folder/user-config.EHI (27)"
        val bytes=byteArrayOf(0,1,2,3,4,-1)
        val snapshot=bytes.copyOf()
        val routing=ImportFilenameNormalizer.forDetection(original)
        assertEquals("user-config.EHI",routing)
        assertEquals(routing,ImportFilenameNormalizer.forDetection(routing))
        assertEquals("folder/user-config.EHI (27)",original)
        assertArrayEquals(snapshot,bytes)
        assertEquals(original,DecodeView(original,"ehi","{}",bytes.size).filename)
        assertNull(AndroidOfflineDecoderRouter.decode(context,original,byteArrayOf(1,2,3)))
    }

    @Test fun existingNormalNamesStillWork() {
        val names=listOf("normal.hc","config (2).hc",
            "folder/config (11).ehi","all.sksrv.png","name (draft).hc")
        for (name in names) {
            assertEquals(name.substringAfterLast('/'),
                ImportFilenameNormalizer.forDetection(name))
        }
        assertEquals("hc",AndroidDecoderCatalog.detect("config (2).hc",formats)?.suffix)
        assertEquals("sksrv.png",AndroidDecoderCatalog.detect("all.sksrv.png",formats)?.suffix)
    }
}
