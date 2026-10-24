package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Phase F: all 239 native routes registered; 13 independent, 0 pending. */
@RunWith(AndroidJUnit4::class)
class PhaseA239CatalogInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val catalog get() = AndroidDecoderCatalog.read(context)

    @Test fun exactInventoryAndDisabledNativeCounts() {
        val formats = catalog
        assertEquals(AndroidDecoderCatalog.TOTAL_SUFFIXES, formats.size)
        assertEquals(239, formats.map { it.suffix }.toSet().size)
        assertEquals(239, formats.count { it.hasNativeDecoder })
        assertEquals(81, formats.count { it.migrationPhase == "B" && it.hasNativeDecoder })
        assertEquals(0, formats.count { it.isPending })
        assertEquals(0, formats.count { it.androidVerified })
        val planned = formats.filter { it.isPending }
        assertEquals(0, planned.count { it.migrationPhase == "B" })
        assertEquals(41, formats.count { it.migrationPhase == "C" && it.hasNativeDecoder })
        assertEquals(0, planned.count { it.migrationPhase == "C" })
        assertEquals(16, formats.count { it.migrationPhase == "D" && it.hasNativeDecoder })
        assertEquals(0, planned.count { it.migrationPhase == "D" })
        assertEquals(27, formats.count { it.hasNativeDecoder && it.migrationPhase == "E" })
        assertEquals(0, planned.count { it.migrationPhase == "E" })
        assertEquals(13, formats.count { it.migrationPhase == "F" && it.hasNativeDecoder })
        assertEquals(0, planned.count { it.migrationPhase == "F" })
        assertTrue(planned.all { it.portStatus == AndroidDecoderCatalog.PENDING_STATUS })
        // Public asset no longer includes implementation details or Python paths.
        val bundled=context.assets.open("decoder_catalog.json").bufferedReader().use { it.readText() }
        assertFalse(bundled.contains("decoders/Python/"))
        assertFalse(bundled.contains("\"script\""))
        assertFalse(bundled.contains("\"originalRuntime\""))
        assertFalse(bundled.contains("\"sourceCatalog\""))
        assertTrue(formats.filter { it.migrationPhase == "B" }.all { it.hasNativeDecoder })
    }

    @Test fun migrationSuffixesHaveNoAccidentalDecodeFallback() {
        val inputs = listOf(
            "archive.IZPH", "archive.flexnet", "archive.𝐭𝐞𝐬𝐭"
        )
        val detected = inputs.dropLast(1)
        for (filename in detected) {
            val format = AndroidDecoderCatalog.detect(filename, catalog)
            assertNotNull("Source format must be registered: $filename", format)
            assertTrue("Phase F suffix must be native: $filename", format!!.hasNativeDecoder)
            assertNull(AndroidOfflineDecoderRouter.decode(
                context, filename, byteArrayOf(1,2,3,4,5,6,7,8)))
        }
        // Phase C and D now have native ports; it must no longer be classified
        // as an unimplemented format. The historical .ost route is unchanged.
        val ultra = AndroidDecoderCatalog.detect("archive.ULTRA", catalog)
        assertNotNull(ultra)
        assertEquals("C", ultra!!.migrationPhase)
        assertTrue(ultra.hasNativeDecoder)
        assertEquals("legacy", AndroidDecoderCatalog.detect("old.ost", catalog)?.migrationPhase)
        assertEquals("D", AndroidDecoderCatalog.detect("archive.7NET", catalog)?.migrationPhase)
        assertTrue(AndroidDecoderCatalog.detect("archive.7NET", catalog)!!.hasNativeDecoder)
        assertTrue(AndroidDecoderCatalog.detect("archive.ITV", catalog)!!.hasNativeDecoder)
        assertTrue(AndroidDecoderCatalog.detect("archive.4ULITE", catalog)!!.hasNativeDecoder)
        assertNull(AndroidOfflineDecoderRouter.decode(context, "invalid.ultra",
            byteArrayOf(1,2,3,4,5,6,7,8)))
        assertNull(AndroidDecoderCatalog.detect(inputs.last(), catalog))
        assertNull(AndroidOfflineDecoderRouter.decode(
            context, "unknown.invalid", byteArrayOf(1,2,3)))
    }

    @Test fun legacyCompoundUnicodeAndVersionedNamesStillResolve() {
        val formats = catalog
        val sksrv = AndroidDecoderCatalog.detect("CONFIG.SKSRV.PNG",formats)
        assertEquals("sksrv.png",sksrv?.suffix)
        assertTrue(sksrv!!.hasNativeDecoder)
        val unicode = AndroidDecoderCatalog.detect("PROFILE.Fɴ",formats)
        assertEquals("fɴ",unicode?.suffix)
        assertTrue(unicode!!.hasNativeDecoder)
        assertEquals("npvs",AndroidDecoderCatalog.detect("tunnel.npvs",formats)?.suffix)
        assertEquals("ost",AndroidDecoderCatalog.detect("old.ost",formats)?.suffix)
        assertTrue(AndroidDecoderCatalog.detect("old.ost",formats)!!.hasNativeDecoder)
    }
}
