package com.ghostdeveloper.spdecode

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.ByteArrayOutputStream
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class V2rayShareLinksInstrumentedTest {
    private val id="00000000-0000-4000-8000-000000000001"

    private fun outbound(protocol:String):JSONObject {
        val server=JSONObject().put("address","demo.example.invalid").put("port",443)
        if(protocol=="trojan")server.put("password","synthetic-only")
        else server.put("users",JSONArray().put(JSONObject().put("id",id).put("alterId",0)))
        val settings=JSONObject().put(if(protocol=="trojan")"servers" else "vnext",
            JSONArray().put(server))
        val stream=JSONObject().put("network","ws").put("security","tls")
            .put("tlsSettings",JSONObject().put("serverName","sni.example.invalid"))
            .put("wsSettings",JSONObject().put("path","/demo")
                .put("headers",JSONObject().put("Host","host.example.invalid")))
        return JSONObject().put("protocol",protocol).put("tag","Demo")
            .put("settings",settings).put("streamSettings",stream)
    }

    private fun wrapped(vararg protocols:String):String {
        val outbounds=JSONArray()
        protocols.forEach{outbounds.put(outbound(it))}
        val v2ray=JSONObject().put("inbounds",JSONArray()).put("outbounds",outbounds)
        return JSONObject().put("Config",
            JSONObject().put("v2rayConfig",v2ray.toString())).toString()
    }

    @Test fun nestedJsonPreviewHasObjectsAndNoEscapedString(){
        val raw=wrapped("vmess")
        val formatted=ResultJsonDisplay.render(raw,"hc")
        assertEquals("vmess",JSONObject(formatted).getJSONObject("Config")
            .getJSONObject("v2rayConfig").getJSONArray("outbounds")
            .getJSONObject(0).getString("protocol"))
        openJsonResultForViewer(raw,"hc").use{doc->
            val output=ByteArrayOutputStream()
            doc.exportOriginal(output)
            val rendered=output.toString("UTF-8")
            assertTrue(JSONObject(rendered).getJSONObject("Config")
                .getJSONObject("v2rayConfig").has("outbounds"))
        }
    }

    @Test fun vmessLinkRetainsCompleteWebsocketTlsFields(){
        val links=V2rayShareLinks.extract(wrapped("vmess"))
        assertEquals(1,links.size)
        assertTrue(links.single().value.startsWith("vmess://"))
        val uri=links.single().value.removePrefix("vmess://")
        val data=JSONObject(String(Base64.decode(uri,Base64.DEFAULT),Charsets.UTF_8))
        assertEquals("demo.example.invalid",data.getString("add"))
        assertEquals("443",data.getString("port"))
        assertEquals(id,data.getString("id"))
        assertEquals("ws",data.getString("net"))
        assertEquals("/demo",data.getString("path"))
        assertEquals("host.example.invalid",data.getString("host"))
        assertEquals("tls",data.getString("tls"))
        assertEquals("sni.example.invalid",data.getString("sni"))
    }

    @Test fun onlyRealProtocolOutboundsProduceLinks(){
        assertEquals(listOf("vmess"),V2rayShareLinks.extract(wrapped("vmess"))
            .map{it.protocol})
        val links=V2rayShareLinks.extract(wrapped("vmess","vless","trojan"))
        assertEquals(setOf("vmess","vless","trojan"),links.map{it.protocol}.toSet())
        assertTrue(links.single{it.protocol=="vless"}.value.contains("path=%2Fdemo"))
        assertTrue(links.single{it.protocol=="trojan"}.value.startsWith(
            "trojan://synthetic-only@demo.example.invalid:443?"))
    }

    @Test fun telegramCreditsAreNormalizedAndNotDuplicated(){
        assertEquals("@ejemplo",TelegramResultCopy.normalizeUsername("@@@ejemplo"))
        assertNull(TelegramResultCopy.normalizeUsername("@bad user"))
        assertEquals("",TelegramResultCopy.normalizeUsername(""))
        val raw=wrapped("vmess")
        val record=DecodeView("synthetic.hc","hc",raw,raw.length)
        val text=TelegramResultCopy.clipboard(record,ResultExport.JSON,
            "2026-11-11","Descifrado por @ejemplo")
        assertEquals(1,Regex("Ghost Developer").findAll(text).count())
        assertEquals(1,Regex("@ejemplo").findAll(text).count())
        assertTrue(TelegramResultCopy.clipboard(record,ResultExport.ORDERED,
            "2026-11-11","Descifrado por @ejemplo").startsWith("// Descifrado por @ejemplo"))
    }
}
