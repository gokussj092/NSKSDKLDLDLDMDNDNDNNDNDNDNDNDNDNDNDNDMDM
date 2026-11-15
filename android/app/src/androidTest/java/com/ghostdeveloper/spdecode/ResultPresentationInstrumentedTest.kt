package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.gson.JsonParser
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Regression: a direct_v2r .ehi profile carries its whole V2Ray document as a
 * multi-line string field (v2rRawJson). ResultPresentation must not mistake
 * the first inbound object's "{" line inside that field value for a standalone
 * JSON document, or the JSON copy shows only the first inbound (tun-inbound)
 * and drops the rest of the config. All servers, hosts and passwords here are
 * synthetic (TEST-NET-3 / .invalid), never real profile values.
 */
@RunWith(AndroidJUnit4::class)
class ResultPresentationInstrumentedTest {
    private val syntheticV2ray="""{ 
"log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": "1080",
      "protocol": "dokodemo-door",
      "settings": {
        "network": "tcp,udp",
        "followRedirect": true
      },
      "tag": "tun-inbound"
    },
    {
      "listen": "127.0.0.1",
      "port": "10808",
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      },
      "tag": "socks-inbound"
    }
  ],
  "outbounds": [
    {
      "protocol": "trojan",
      "settings": {
        "servers": [
          {
            "address": "203.0.113.10",
            "port": 8443,
            "password": "Ficticia123"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": true,
          "serverName": "ejemplo.invalid"
        },
        "wsSettings": {
          "path": "/ficticio",
          "headers": {
            "Host": "ejemplo.invalid"
          }
        }
      },
      "tag": "sintetico-trojan"
    },
    {
      "protocol": "http",
      "settings": {
        "servers": [
          {
            "address": "198.51.100.20",
            "port": 8080
          }
        ]
      },
      "tag": "sintetico-http"
    },
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}"""
    private val rawEhi="""┌───────────────
│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.ehi)
│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu
├───────────────
│[۞] tunnelType: direct_v2r
│[۞] v2rProtocol: vmess
│[۞] v2rCoreType: xray
│[۞] v2rRawJson: $syntheticV2ray
│[۞] configMessage: Mensaje sintetico de prueba
│[۞] isConfigLock: false

├───────────────
│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub
│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve
└───────────────
"""

    @Test fun multilineV2rayFieldKeepsWholeConfigInJsonCopy() {
        val doc=ResultPresentation.parse(rawEhi,"ehi")
        assertFalse("no standalone document may be extracted from a field value",
            doc.jsonParsed)
        val rendered=ResultJsonDisplay.render(rawEhi,"ehi",false)
        val root=JsonParser.parseString(rendered).asJsonObject
        // Not just the first inbound: the top level is the whole profile.
        assertTrue(root.has("tunnelType"))
        assertTrue(root.has("v2rRawJson"))
        assertFalse(root.has("listen"))
        val v2r=root.getAsJsonObject("v2rRawJson")
        val inbounds=v2r.getAsJsonArray("inbounds")
        assertEquals(2,inbounds.size())
        assertEquals("tun-inbound",inbounds[0].asJsonObject.get("tag").asString)
        assertEquals("socks-inbound",inbounds[1].asJsonObject.get("tag").asString)
        val outbounds=v2r.getAsJsonArray("outbounds")
        assertEquals(4,outbounds.size())
        assertEquals("sintetico-trojan",outbounds[0].asJsonObject.get("tag").asString)
        assertEquals("sintetico-http",outbounds[1].asJsonObject.get("tag").asString)
        assertEquals("direct",outbounds[2].asJsonObject.get("tag").asString)
        assertEquals("block",outbounds[3].asJsonObject.get("tag").asString)
        assertEquals("203.0.113.10",outbounds[0].asJsonObject
            .getAsJsonObject("settings").getAsJsonArray("servers")[0].asJsonObject
            .get("address").asString)
    }

    @Test fun genuineStandaloneJsonDocumentStillExtracts() {
        val raw="""┌───────────────
│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.ehi)
│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu
├───────────────
{
  "standalone": true,
  "n": 1
}
└───────────────
"""
        val doc=ResultPresentation.parse(raw,"ehi")
        assertTrue(doc.jsonParsed)
        val root=JsonParser.parseString(doc.json).asJsonObject
        assertTrue(root.get("standalone").asBoolean)
        assertEquals(1,root.get("n").asInt)
    }
}
