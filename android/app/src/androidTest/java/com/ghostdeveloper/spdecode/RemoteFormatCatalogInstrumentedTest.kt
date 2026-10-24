package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.cloud.CloudDecodeClient
import com.ghostdeveloper.spdecode.cloud.ServerVpnCatalogRepository
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** No live network, production keys or file credentials needed. */
@RunWith(AndroidJUnit4::class)
class RemoteFormatCatalogInstrumentedTest {
    private val context get()=InstrumentationRegistry.getInstrumentation().targetContext
    private fun repository()=ServerVpnCatalogRepository(context,CloudDecodeClient(context))

    private fun fixture():JSONObject {
        fun record(suffix:String,name:String):JSONObject=JSONObject()
            .put("suffix",suffix).put("name",name).put("kind","file")
            .put("offlineSupported",true).put("cloudSupported",true)
            .put("credentialFields",JSONArray())
        return JSONObject().put("formatsSchemaVersion",1).put("formatCount",2)
            .put("formatDetection",JSONObject()
                .put("rule","longest-filename-suffix").put("caseInsensitive",true)
                .put("separator","."))
            .put("formats",JSONArray()
                .put(record("sksrv.png","PNG format"))
                .put(record("npvs","NPV Tunnel")))
    }

    @Test fun compoundExtensionsAreDetectedWithoutExecutingNativeDecoders() {
        val values=repository().validateFormats(fixture())
        assertEquals(2,values.size)
        assertEquals("sksrv.png",AndroidDecoderCatalog.detect("PROFILE.SKSRV.PNG",values)?.suffix)
        assertEquals("npvs",AndroidDecoderCatalog.detect("config.NPVS",values)?.suffix)
        assertNull(AndroidDecoderCatalog.detect("unknown.xyz",values))
        assertFalse(values[0].hasNativeDecoder)
        assertTrue(values[0].cloudSupported)
    }

    @Test fun invalidOrExecutableMetadataIsRejected() {
        val repo=repository()
        val invalid=fixture()
        invalid.getJSONArray("formats").getJSONObject(0).put("script","unsafe.py")
        assertThrows(IllegalArgumentException::class.java) { repo.validateFormats(invalid) }
        val duplicate=fixture()
        duplicate.getJSONArray("formats").getJSONObject(1).put("suffix","sksrv.png")
        assertThrows(IllegalArgumentException::class.java) { repo.validateFormats(duplicate) }
        val wrong=fixture().put("formatCount",9)
        assertThrows(IllegalArgumentException::class.java) { repo.validateFormats(wrong) }
    }

    @Test fun legacyLocalInventoryHasNoPythonExecutionRoutes() {
        val embedded=context.assets.open("decoder_catalog.json")
            .bufferedReader(Charsets.UTF_8).use { it.readText() }
        val document=JSONObject(embedded)
        assertEquals(4,document.getInt("schemaVersion"))
        assertEquals(239,document.getJSONArray("entries").length())
        assertFalse(embedded.contains("decoders/Python/"))
        assertFalse(embedded.contains("\"script\""))
    }
}
