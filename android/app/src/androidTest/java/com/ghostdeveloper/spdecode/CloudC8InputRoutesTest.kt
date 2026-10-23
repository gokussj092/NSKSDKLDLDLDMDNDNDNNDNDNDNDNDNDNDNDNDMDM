package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ghostdeveloper.spdecode.cloud.CloudFileFormats
import com.ghostdeveloper.spdecode.cloud.CloudTextFormats
import com.ghostdeveloper.spdecode.cloud.CloudCredentialPolicy
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Source-exact C8 client routing checks; no network access, secrets or VPN connections.
 * The backend remains responsible for all decoding.
 */
@RunWith(AndroidJUnit4::class)
class CloudC8InputRoutesTest {
    @Test fun cloudFilesKeepExactWorkerSuffixes() {
        val supported=mapOf(
            "profile.1FTNL" to Pair("1ftnl","1FTunnel 0.6.99"),
            "export.TGV" to Pair("tgv","TunelGuard VPN 12.8"),
            "test.mtp" to Pair("mtp","My Tunnel Proxy"),
            "royal.ROY" to Pair("roy","Royal Tunnel VPN 7.0"),
            "export.ACTUN" to Pair("actun","AC TUNNEL VPN 1.4"),
            "profile.4ULITE" to Pair("4ulite","4U TUNNEL LITE 2.2"),
            "old.hxt" to Pair("hxt","HX Tunnel VPN"),
        )
        for ((filename,expected) in supported) {
            val format=CloudFileFormats.detect("content/folder/$filename")
            assertNotNull(filename,format)
            assertEquals(filename,expected.first,format!!.suffix)
            assertEquals(filename,expected.second,format.appName)
            assertEquals(filename,"C8",format.migrationPhase)
            assertFalse(format.hasNativeDecoder)
        }
        assertNull(CloudFileFormats.detect("test.mtp.bak"))
        assertNull(CloudFileFormats.detect("test-notmtp"))
        assertNull(CloudFileFormats.detect("file.actunnelvpn"))
    }

    @Test fun cloudTextVendorLinksReachExactServerPrefixes() {
        val cases=mapOf(
            "1FTnl.cipher" to Triple("oneftunnel","1ftnl","1FTunnel"),
            "1FT1.cipher" to Triple("oneftunnel","1ftnl","1FTunnel"),
            "1ftunnel://1FTnl/cipher" to Triple("oneftunnel","1ftnl","1FTunnel"),
            "1ftunnel://1FT1/cipher" to Triple("oneftunnel","1ftnl","1FTunnel"),
            "mytunnelproxy://cipher" to Triple("mytunnelproxy","mtp","My Tunnel Proxy"),
            "MYTUNNELPROXY://cipher" to Triple("mytunnelproxy","mtp","My Tunnel Proxy"),
            "actunnelvpn://cipher" to Triple("actunnelvpn","actun","AC TUNNEL VPN"),
            "ACTUNNELVPN://cipher" to Triple("actunnelvpn","actun","AC TUNNEL VPN"),
        )
        for ((text,expected) in cases) {
            val input=CloudTextFormats.identify(text)
            assertNotNull(text,input)
            assertEquals(expected.first,input!!.protocol)
            assertEquals(expected.second,input.suffix)
            assertEquals(expected.third,input.app)
            assertEquals(text,input.content)
        }
        assertNull(CloudTextFormats.identify("mytunnelproxy://"))
        assertNull(CloudTextFormats.identify("actunnelvpn://"))
        assertNull(CloudTextFormats.identify("1FTnl."))
        assertNull(CloudTextFormats.identify("1ftnl.cipher"))
        assertNull(CloudTextFormats.identify("https://example.invalid"))
    }

    @Test fun npvTextAndCredentialRoutesAreExplicit() {
        val prefixes=listOf("npvt://","npvt-ssh://","npvt-vless://",
            "npvt-vmess://","npv://")
        for(prefix in prefixes) {
            val input=CloudTextFormats.identify(prefix+"YWJj")
            assertNotNull(prefix,input)
            assertEquals("npvs",input!!.suffix)
            assertTrue(CloudCredentialPolicy.textAcceptsPassword(prefix+"YWJj"))
            assertNull(CloudTextFormats.identify(prefix))
        }
        for(suffix in listOf("hc","ua","npvs","1ftnl","tut"))
            assertTrue(CloudCredentialPolicy.fileAcceptsPassword(suffix))
        assertFalse(CloudCredentialPolicy.fileNeedsPasswordDialog("hc"))
        for(suffix in listOf("ua","npvs","1ftnl","tut"))
            assertTrue(CloudCredentialPolicy.fileNeedsPasswordDialog(suffix))
        assertFalse(CloudCredentialPolicy.fileAcceptsPassword("ehi"))
        assertFalse(CloudCredentialPolicy.textAcceptsPassword("dns://YWJj"))
        assertTrue(CloudCredentialPolicy.textAcceptsPassword("1FTnl.YWJj"))
    }

    @Test fun historicalCloudLinksAreUnaffected() {
        assertEquals("ua",CloudTextFormats.identify("ua://fake")?.suffix)
        assertEquals("mkk",CloudTextFormats.identify("mkk://fake")?.suffix)
        assertEquals("vpn",CloudTextFormats.identify("vpn://fake")?.suffix)
    }
}
