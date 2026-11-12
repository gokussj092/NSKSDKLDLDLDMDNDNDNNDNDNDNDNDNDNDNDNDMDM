package com.ghostdeveloper.spdecode

import android.content.ClipData
import android.content.Intent
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Regression: external app opening a file must use the encrypted Cloud snapshot. */
@RunWith(AndroidJUnit4::class)
class ExternalCatalogImportInstrumentedTest {
    private fun uri(n:Int)=Uri.parse("content://com.example.provider/shared/$n")

    @Test fun viewAndSendReadDataAndClipUri() {
        val file=uri(7)
        assertEquals(listOf(file),ExternalImportUris.resolve(
            Intent(Intent.ACTION_VIEW,file)))
        assertEquals(listOf(file),ExternalImportUris.resolve(
            Intent(Intent.ACTION_VIEW).apply {
                clipData=ClipData.newRawUri("config",file)
            }))
        assertEquals(listOf(file),ExternalImportUris.resolve(
            Intent(Intent.ACTION_SEND).apply {
                type="application/octet-stream"
                putExtra(Intent.EXTRA_STREAM,file)
            }))
        assertEquals(listOf(file),ExternalImportUris.resolve(
            Intent(Intent.ACTION_SEND).apply {
                type="application/octet-stream"
                clipData=ClipData.newRawUri("config",file)
            }))
    }

    @Test fun sendMultipleMergesClipAndExtraWithoutDuplicates() {
        val first=uri(1)
        val second=uri(2)
        val intent=Intent(Intent.ACTION_SEND_MULTIPLE).apply {
            type="application/octet-stream"
            putParcelableArrayListExtra(Intent.EXTRA_STREAM,arrayListOf(first))
            clipData=ClipData.newRawUri("configs",first).also {
                it.addItem(ClipData.Item(second))
            }
        }
        assertEquals(listOf(first,second),ExternalImportUris.resolve(intent))
    }

    @Test fun cloudOnlyFormatUsesVerifiedSnapshotAtColdStart() {
        val remote=AndroidDecoderCatalog.Format(
            suffix="examplevpn",appName="Example VPN",
            portStatus="cloud_server_only",androidVerified=false,migrationPhase="C8"
        )
        val resolved=ImportFormatRouter.detect(
            "from-telegram.examplevpn",true,listOf(remote)
        ) { fail("Bundled catalog must not replace a verified Cloud snapshot");emptyList() }
        assertEquals("examplevpn",resolved?.suffix)
        assertEquals("examplevpn",ImportFormatRouter.detect(
            "backup.examplevpn (2)",true,listOf(remote)
        ) { emptyList() }?.suffix)
        assertNull(ImportFormatRouter.detect(
            "renamed.examplevpn.txt",true,listOf(remote)
        ) { emptyList() })
    }

    @Test fun onlyUseBundledFormatsWhenNoVerifiedSnapshot() {
        val bundled=AndroidDecoderCatalog.Format(
            suffix="ehi",appName="HTTP Injector",
            portStatus="registered_not_implemented",androidVerified=false,
            migrationPhase="legacy"
        )
        assertEquals("ehi",ImportFormatRouter.detect(
            "profile.ehi",true,emptyList()
        ) { listOf(bundled) }?.suffix)
        assertNull(ImportFormatRouter.detect(
            "profile.unknown",true,listOf(bundled)
        ) { fail("No fallback to unrelated bundled formats");emptyList() })
    }
}
