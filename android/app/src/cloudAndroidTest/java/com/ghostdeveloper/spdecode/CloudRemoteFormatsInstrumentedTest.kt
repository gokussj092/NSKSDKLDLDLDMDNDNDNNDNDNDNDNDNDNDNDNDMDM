package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.cloud.CloudTextFormats
import com.ghostdeveloper.spdecode.cloud.CloudTextRoute
import com.ghostdeveloper.spdecode.cloud.CloudDecodeClient
import com.ghostdeveloper.spdecode.cloud.CloudUserErrors
import com.ghostdeveloper.spdecode.cloud.ServerVpnCatalogRepository
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Tests the compiled Cloud-only APK; no network or private keys. */
@RunWith(AndroidJUnit4::class)
class CloudRemoteFormatsInstrumentedTest {
    private val context get()=InstrumentationRegistry.getInstrumentation().targetContext

    private fun metadata():JSONObject {
        fun entry(suffix:String,label:String)=JSONObject()
            .put("suffix",suffix).put("name",label).put("kind","file")
            .put("offlineSupported",false).put("cloudSupported",true)
            .put("credentialFields",JSONArray())
        return JSONObject().put("formatsSchemaVersion",1)
            .put("formatCount",2)
            .put("formatDetection",JSONObject()
                .put("rule","longest-filename-suffix")
                .put("caseInsensitive",true).put("separator","."))
            .put("formats",JSONArray()
                .put(entry("sksrv.png","Server PNG"))
                .put(entry("npvs","NPV Tunnel")))
    }

    @Test fun cloudRoutesDetectLongestCompoundSuffix() {
        val repo=ServerVpnCatalogRepository(context,CloudDecodeClient(context))
        val entries=repo.validateFormats(metadata())
        assertEquals(2,entries.size)
        assertEquals("sksrv.png",AndroidDecoderCatalog.detect("MYSERVER.SKSRV.PNG",entries)?.suffix)
        assertEquals("npvs",AndroidDecoderCatalog.detect("file.npvs",entries)?.suffix)
        assertNull(AndroidDecoderCatalog.detect("file.unknown",entries))
        assertFalse(entries[0].hasNativeDecoder)
    }

    @Test fun cloudCatalogAddsNewSuffixesAndPasswordMetadataWithoutLocalRegistrations() {
        val repo=ServerVpnCatalogRepository(context,CloudDecodeClient(context))
        val fixture=metadata()
        val prior=repo.validateFormats(fixture)
        assertNull(AndroidDecoderCatalog.detect("ملف.NEWVPN",prior))
        fun entry(suffix:String,name:String,needsPassword:Boolean=false)=JSONObject()
            .put("suffix",suffix).put("name",name).put("kind","file")
            .put("offlineSupported",false).put("cloudSupported",true)
            .put("credentialFields",if(needsPassword) JSONArray().put("password") else JSONArray())
        // Server format contract: longest suffix first, lexicographic ties.
        val initial=fixture.getJSONArray("formats")
        val latest=JSONArray().put(initial.getJSONObject(0))
            .put(entry("newvpn","Future Cloud Decoder"))
            .put(initial.getJSONObject(1))
            .put(entry("awg","AboWaged VPN"))
            .put(entry("ua","Ultra Custom",needsPassword=true))
        fixture.put("formats",latest).put("formatCount",latest.length())
        val updated=repo.validateFormats(fixture)
        assertEquals("newvpn",AndroidDecoderCatalog.detect("ملف.NEWVPN",updated)?.suffix)
        assertEquals("awg",AndroidDecoderCatalog.detect("متعدد شبكات  AbowagedDevX .AWG",updated)?.suffix)
        val ultra=AndroidDecoderCatalog.detect("Movistar sin redes.UA",updated)
        assertEquals("ua",ultra?.suffix)
        assertEquals(setOf("password"),ultra?.credentialFields)
        assertTrue(ultra!!.cloudSupported)
        assertFalse(ultra.hasNativeDecoder)
    }

    @Test fun cloudRejectsUnexpectedScriptsDuplicateSuffixesAndRollbackPayload() {
        val repo=ServerVpnCatalogRepository(context,CloudDecodeClient(context))
        val executable=metadata()
        executable.getJSONArray("formats").getJSONObject(0).put("script","evil")
        assertThrows(IllegalArgumentException::class.java) {
            repo.validateFormats(executable)
        }
        val count=metadata().put("formatCount",1)
        assertThrows(IllegalArgumentException::class.java) { repo.validateFormats(count) }
        val duplicate=metadata()
        duplicate.getJSONArray("formats").getJSONObject(1).put("suffix","sksrv.png")
        assertThrows(IllegalArgumentException::class.java) { repo.validateFormats(duplicate) }
    }


    @Test fun validatedTextCatalogIsAuthoritativeAndRejectsUnknownLinks() {
        val repo=ServerVpnCatalogRepository(context,CloudDecodeClient(context))
        val catalog=JSONObject()
            .put("textSchemaVersion",1).put("textCount",2)
            .put("textFormats",JSONArray()
                .put(JSONObject().put("prefix","npvt-vless://")
                    .put("name","NPV Tunnel").put("suffix","npvs").put("kind","text"))
                .put(JSONObject().put("prefix","1FTnl.")
                    .put("name","1FTunnel").put("suffix","1ftnl").put("kind","text")))
        val routes=repo.validateTextFormats(catalog)
        assertEquals(2,routes.size)
        assertEquals("npvs",CloudTextFormats.identify("npvt-vless://something",routes)?.suffix)
        assertEquals("1ftnl",CloudTextFormats.identify("1FTnl.token",routes)?.suffix)
        assertNull(CloudTextFormats.identify("mkk://unpublished",routes))
        assertNull(CloudTextFormats.identify("unknown://payload",routes))
        assertNull(CloudTextFormats.identify("npvt-vless://",routes))
    }

    @Test fun invalidTextCatalogPrefixesFailClosed() {
        val repo=ServerVpnCatalogRepository(context,CloudDecodeClient(context))
        for(prefix in listOf("../evil","evil://../secret","https://attacker.invalid/",
            "evil.com","evil://a.b")) {
            val fixture=JSONObject()
                .put("textSchemaVersion",1).put("textCount",1)
                .put("textFormats",JSONArray().put(JSONObject()
                    .put("prefix",prefix).put("name","Unsafe")
                    .put("suffix","bad").put("kind","text")))
            assertThrows(IllegalArgumentException::class.java) {
                repo.validateTextFormats(fixture)
            }
        }
    }

    @Test fun cloudPackagedCatalogHasNoPythonRoutesAndHttpInjectorErrorIsSpecific() {
        val asset=context.assets.open("decoder_catalog.json")
            .bufferedReader(Charsets.UTF_8).use { it.readText() }
        assertEquals(4,JSONObject(asset).getInt("schemaVersion"))
        assertFalse(asset.contains("decoders/Python/"))
        assertFalse(asset.contains("\"script\""))
        val issue=CloudDecodeClient.Failure("REMOTE_NOT_CONFIGURED",503)
        assertEquals(context.getString(R.string.cloud_http_injector_not_configured),
            CloudUserErrors.httpInjectorMessage(context,issue))
        assertTrue(context.getString(R.string.file_extension_unsupported_contact).isNotBlank())
        assertTrue(context.getString(R.string.text_format_unsupported_contact).isNotBlank())
    }
}
