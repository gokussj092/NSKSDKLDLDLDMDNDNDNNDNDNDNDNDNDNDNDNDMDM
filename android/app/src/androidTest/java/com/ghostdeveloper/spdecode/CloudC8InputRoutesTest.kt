package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ghostdeveloper.spdecode.cloud.CloudFileFormats
import com.ghostdeveloper.spdecode.cloud.CloudTextFormats
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
        assertNull(CloudTextFormats.identify("https://example.invalid"))
    }

    @Test fun historicalCloudLinksAreUnaffected() {
        assertEquals("ua",CloudTextFormats.identify("ua://fake")?.suffix)
        assertEquals("mkk",CloudTextFormats.identify("mkk://fake")?.suffix)
        assertEquals("vpn",CloudTextFormats.identify("vpn://fake")?.suffix)
    }
}
