package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ghostdeveloper.spdecode.cloud.CloudOnlineReference
import com.ghostdeveloper.spdecode.cloud.CloudTextFormats
import com.ghostdeveloper.spdecode.cloud.CloudTextRoute
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Only deterministic parsing; never fetches a real vendor reference. */
@RunWith(AndroidJUnit4::class)
class GlobalCloudImportInstrumentedTest {
    private val published=listOf(
        CloudTextRoute("https://link.playsmarty.uk/","HTTP Custom Cloud","hc","cloud"),
        CloudTextRoute("https://cloudvpn.mrfrankofc.com/","HTTP Custom Cloud","hc","cloud"),
        CloudTextRoute("hccloud://","HTTP Custom Cloud","hc","cloud"),
        CloudTextRoute("mnrtunneludp://","MNR","stp","cloud"),
        CloudTextRoute("npvt://","NPV Tunnel","npvs","text"),
    )

    @Test fun autoRoutesInjectorLinksKeysAndHcHosts() {
        assertEquals("ehi",CloudOnlineReference.resolve("TEST1234","auto",published)?.provider)
        assertEquals("ehi",CloudOnlineReference.resolve("https://ehi.link/TEST1234","auto",published)?.provider)
        assertEquals("hc",CloudOnlineReference.resolve("https://link.playsmarty.uk/Test-Only","auto",published)?.provider)
        assertEquals("hc",CloudOnlineReference.resolve("https://cloudvpn.mrfrankofc.com/Ab12Cd","auto",published)?.provider)
    }

    @Test fun legacyHttpCustomAliasesMoveToCloudWithoutExtraDownloads() {
        val source=CloudOnlineReference.resolve("hccloud://mrfrank/Ab12Cd","auto",published)
        assertEquals("hc",source?.provider)
        assertEquals("https://cloudvpn.mrfrankofc.com/Ab12Cd",source?.reference)
        assertEquals("https://link.playsmarty.uk/Ab12Cd",
            CloudOnlineReference.resolve("hccloud://playsmarty/Ab12Cd","hc",published)?.reference)
    }

    @Test fun hexCustomKeysAndMnrReferencesResolveToTheirOwnProviders() {
        val hex=CloudOnlineReference.resolve("HexCustom-BoKo2Q5gQR","auto",published)
        assertEquals("hexcustom",hex?.provider)
        assertEquals("HexCustom-BoKo2Q5gQR",hex?.reference)
        assertEquals("Hex Custom Cloud",hex?.name)
        assertEquals("hexcm",hex?.suffix)
        assertEquals("HexCustom-KHrIQs3HfI",
            CloudOnlineReference.resolve("HexCustom-KHrIQs3HfI","hexcustom",published)?.reference)
        val mnr=CloudOnlineReference.resolve("mnrtunneludp://AABBCCDDDD","auto",published)
        assertEquals("mnr",mnr?.provider)
        assertEquals("mnrtunneludp://AABBCCDDDD",mnr?.reference)
        assertEquals("stp",mnr?.suffix)
        // A Hex Custom key never crosses to another provider, and malformed
        // keys (wrong length, lowercase prefix) resolve to nothing.
        assertNull(CloudOnlineReference.resolve("HexCustom-BoKo2Q5gQR","hc",published))
        assertNull(CloudOnlineReference.resolve("HexCustom-BoKo2Q5gQ","auto",published))
        assertNull(CloudOnlineReference.resolve("HexCustom-BoKo2Q5gQR1","auto",published))
        assertNull(CloudOnlineReference.resolve("hexcustom-BoKo2Q5gQR","auto",published))
        assertNull(CloudOnlineReference.resolve("mnrtunneludp://AABBCCDDD","auto",published))
    }

    @Test fun explicitProviderNeverSilentlyCrossesToAnotherService() {
        assertNull(CloudOnlineReference.resolve("https://ehi.link/TEST1234","hc",published))
        assertNull(CloudOnlineReference.resolve("https://link.playsmarty.uk/Test-Only","ehi",published))
        for(bad in listOf("http://127.0.0.1/x",
            "https://link.playsmarty.uk.evil.invalid/Ab12Cd",
            "https://cloudvpn.mrfrankofc.com/Ab12Cd?url=http://127.0.0.1",
            "https://link.playsmarty.uk:444/Ab12Cd","file:///etc/passwd"))
            assertNull(CloudOnlineReference.resolve(bad,"auto",published))
    }

    @Test fun textPanelNoLongerHandlesHcCloudButKeepsRealTextProtocols() {
        assertNull(CloudTextFormats.identify("hccloud://mrfrank/Ab12Cd",published))
        assertNull(CloudTextFormats.identify("https://link.playsmarty.uk/Ab12Cd",published))
        assertEquals("npvs",CloudTextFormats.identify("npvt://123456",published)?.suffix)
        assertEquals("stp",CloudTextFormats.identify("mnrtunneludp://AABBCCDDDD",published)?.suffix)
    }
}
