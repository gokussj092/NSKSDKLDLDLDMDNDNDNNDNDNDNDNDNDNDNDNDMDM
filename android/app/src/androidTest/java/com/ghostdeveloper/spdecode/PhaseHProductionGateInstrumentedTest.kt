package com.ghostdeveloper.spdecode

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase H compiled-package release safety smoke. This checks the INSTALLED
 * app manifest, not merely source XML. Does not claim physical device testing.
 */
@RunWith(AndroidJUnit4::class)
class PhaseHProductionGateInstrumentedTest {
    private val ctx get()=InstrumentationRegistry.getInstrumentation().targetContext

    @Suppress("DEPRECATION")
    @Test fun installedManifestAllowsOnlyCloudInternetAndNoUnsafeStoragePermissions(){
        val info=ctx.packageManager.getPackageInfo(
            ctx.packageName,PackageManager.GET_PERMISSIONS)
        val permissions=info.requestedPermissions?.toSet().orEmpty()
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
        ),permissions)
        for(name in listOf("android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.QUERY_ALL_PACKAGES"))
            assertFalse("Production app must never request "+name,name in permissions)
        assertEquals("com.ghostdeveloper.spdecode",ctx.packageName)
        assertEquals("1.1.4",info.versionName)
        val code=if(android.os.Build.VERSION.SDK_INT>=28) info.longVersionCode
            else info.versionCode.toLong()
        assertEquals(25L,code)
    }
    @Test fun appBackupDisabledInInstalledPackage(){
        val info=ctx.applicationInfo
        assertEquals(0,info.flags and ApplicationInfo.FLAG_ALLOW_BACKUP)
    }
    @Test fun all239NativeRoutesPresentButNotRealExportCertified(){
        val formats=AndroidDecoderCatalog.read(ctx)
        assertEquals(239,formats.size)
        assertEquals(239,formats.count{it.hasNativeDecoder})
        assertEquals(0,formats.count{it.isPending})
        assertEquals(0,formats.count{it.androidVerified})
        assertEquals(13,formats.count{it.migrationPhase=="F"})
        assertEquals(27,formats.count{it.migrationPhase=="E"})
    }
    @Test fun textNeverReportsHappSuccessWithoutPrivateRsaKey(){
        for(version in listOf("crypt","crypt2","crypt3","crypt4")){
            val input=TextProtocolDecoder.identify("happ://"+version+"/AAAA")
            assertNotNull(input)
            assertNull(TextProtocolDecoder.decode(ctx,input!!))
        }
        assertNull(TextProtocolDecoder.identify("regular message without link"))
        assertNull(TextProtocolDecoder.identify("x".repeat(TextProtocolDecoder.MAX_CHARS+1)))
    }
}
