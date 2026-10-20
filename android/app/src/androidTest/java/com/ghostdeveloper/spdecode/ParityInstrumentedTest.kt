package com.ghostdeveloper.spdecode

import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.V2RayReferencePort
import com.ghostdeveloper.spdecode.parity.TlsReferencePort
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Executes on an actual Android runtime. CI may only mark parity verified
 * once the emulator job itself succeeds; a JVM compile is not equivalent.
 */
@RunWith(AndroidJUnit4::class)
class ParityInstrumentedTest {
    private val assets get() = InstrumentationRegistry.getInstrumentation().context.assets
    private val target get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun fixture(name: String): ByteArray =
        assets.open("parity/$name").use { it.readBytes() }

    @Test
    fun syntheticPlainV2MatchesLinuxRawUtf8() {
        assertArrayEquals(
            fixture("ev2ray-plain.txt"),
            V2RayReferencePort.decode(fixture("ev2ray-plain.v2"))?.toByteArray(Charsets.UTF_8)
        )
    }

    @Test
    fun syntheticAesV2MatchesLinuxRawUtf8() {
        assertArrayEquals(
            fixture("ev2ray-aes128.txt"),
            V2RayReferencePort.decode(fixture("ev2ray-aes128.v2"))?.toByteArray(Charsets.UTF_8)
        )
    }

    @Test
    fun syntheticTlsAesGcmMatchesLinuxRawUtf8() {
        assertArrayEquals(
            fixture("tls-aesgcm.txt"),
            TlsReferencePort.decode(target,fixture("tls-aesgcm.tls"))?.toByteArray(Charsets.UTF_8)
        )
    }

    @Test
    fun tlsRejectsCorruptionAndOversizedInput() {
        assertNull(TlsReferencePort.decode(target,byteArrayOf()))
        assertNull(TlsReferencePort.decode(target,"not a TLS profile".toByteArray()))
        assertNull(TlsReferencePort.decode(target,ByteArray(1024 * 1024 + 1)))
        val damaged = fixture("tls-aesgcm.tls").clone()
        damaged[damaged.size / 2] = (damaged[damaged.size / 2].toInt() xor 1).toByte()
        assertNull(TlsReferencePort.decode(target,damaged))
    }

    @Test
    fun malformedProfileAndOversizedDataAreNotSuccessful() {
        assertNull(V2RayReferencePort.decode(byteArrayOf()))
        assertNull(V2RayReferencePort.decode("bad-profile".toByteArray()))
        assertNull(V2RayReferencePort.decode(ByteArray(1024 * 1024 + 1)))
        val damaged = fixture("ev2ray-aes128.v2").clone()
        damaged[damaged.size / 2] = (damaged[damaged.size / 2].toInt() xor 1).toByte()
        assertNull(V2RayReferencePort.decode(damaged))
    }

    @Test
    fun registryHas239NativeSuffixesWithNoPendingPorts() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val formats = com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog.read(context)
        val resolver = com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
        assertEquals(239, formats.size)
        assertEquals(239, formats.count { it.hasNativeDecoder })
        assertEquals(0, formats.count { it.isPending })
        assertEquals("sksrv.png", resolver.detect("MYCONFIG.SKSRV.PNG", formats)?.suffix)
        assertEquals("fɴ", resolver.detect("MYCONFIG.Fɴ", formats)?.suffix)
        assertEquals("v2", resolver.detect("test.v2", formats)?.suffix)
        assertEquals("prototype_two_synthetic_cases", resolver.detect("test.v2", formats)?.portStatus)
        assertEquals(0, formats.count { it.androidVerified })
        assertEquals("prototype_tls_aesgcm_synthetic_case", resolver.detect("test.TLS", formats)?.portStatus)
        assertEquals(0, formats.count { it.portStatus == "registered_not_implemented" })
        assertEquals("B", resolver.detect("test.ace", formats)?.migrationPhase)
        assertEquals("C", resolver.detect("test.ultra", formats)?.migrationPhase)
        assertEquals("D", resolver.detect("test.7NET", formats)?.migrationPhase)
        assertEquals("E", resolver.detect("test.ITV", formats)?.migrationPhase)
        assertEquals("F", resolver.detect("test.Izph", formats)?.migrationPhase)
        assertTrue(resolver.detect("test.ace", formats)?.hasNativeDecoder ?: false)
        assertTrue(resolver.detect("test.izph", formats)?.hasNativeDecoder ?: false)
        assertEquals(7, formats.count { it.portStatus == "experimental_final7_synthetic_subset" })
        assertEquals(4, formats.count { it.portStatus == "experimental_final_extra4_synthetic" })
        assertEquals(11, formats.count { it.portStatus == "experimental_final11_synthetic" })
        assertEquals(15, formats.count { it.portStatus == "experimental_batch15_synthetic" })
        assertEquals(10, formats.count { it.portStatus == "experimental_batch20_synthetic" })
        assertEquals(10, formats.count { it.portStatus == "experimental_batch10_synthetic" })
        assertNull(resolver.detect("unrecognized.unknown", formats))
    }

    @Test
    fun mergedManifestAllowsOnlyExplicitCloudInternetAndNoStoragePermissions() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        val requested = info.requestedPermissions.orEmpty().toSet()
        // AndroidX declares this app-local signature permission for safe receivers.
        // It grants neither network nor storage access.
        assertEquals(setOf(
            "android.permission.INTERNET",
            // WorkManager requires these for network-constrained recovery and rescheduling.
            "android.permission.WAKE_LOCK",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.FOREGROUND_SERVICE",
            "com.ghostdeveloper.spdecode.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
        ),requested)
        for (forbidden in listOf(
            "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
        )) {
            assertFalse("Forbidden permission $forbidden", requested.contains(forbidden))
        }
    }
}
