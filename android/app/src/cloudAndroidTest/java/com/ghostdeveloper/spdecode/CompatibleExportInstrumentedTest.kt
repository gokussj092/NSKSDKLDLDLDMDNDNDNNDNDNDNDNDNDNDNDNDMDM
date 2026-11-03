package com.ghostdeveloper.spdecode

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.cloud.CompatibleExportArtifact
import com.ghostdeveloper.spdecode.cloud.CompatibleExportCatalog
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Synthetic data only. Exercises real Android JSON, Base64 and KeyStore. */
@RunWith(AndroidJUnit4::class)
class CompatibleExportInstrumentedTest {
    private val text="{\"configs\":[{\"label\":\"synthetic-export\"}]}"
    private val bytes=("NPVO1\n"+text).toByteArray()
    private fun envelope():JSONObject=JSONObject()
        .put("status","ready").put("schemaVersion",1).put("profile","original-app-open-v1")
        .put("targetAppId","npv-tunnel").put("targetAppName","NPV Tunnel")
        .put("extension",".npvs").put("filename","config-SP-DECODE.npvs")
        .put("mimeType","application/octet-stream").put("sizeBytes",bytes.size)
        .put("sourceSha256","a".repeat(64))
        .put("decodedSha256",CompatibleExportArtifact.digest(text.toByteArray()))
        .put("sha256",CompatibleExportArtifact.digest(bytes))
        .put("dataBase64",Base64.encodeToString(bytes,Base64.NO_WRAP))
        .put("protections",JSONObject().put("filePasswordRequired",false)
            .put("hwidRequired",false).put("recipientPrivateKeyRequired",false))

    @Test fun rejectsArtifactFromAnotherResultSourceOrFormatAndModifiedBytes() {
        val valid=CompatibleExportArtifact.parse(envelope(),"npvs",text,"a".repeat(64))!!
        assertArrayEquals(bytes,valid.bytes())
        assertFalse(valid.toString().contains("synthetic-export"))
        val invalid=listOf<()->Unit>(
            { CompatibleExportArtifact.parse(envelope(),"npvs",text+" ") },
            { CompatibleExportArtifact.parse(envelope(),"npvs",text,"b".repeat(64)) },
            { CompatibleExportArtifact.parse(envelope(),"hc",text) },
            { CompatibleExportArtifact.parse(envelope().put("sha256","0".repeat(64)),"npvs",text) },
            { CompatibleExportArtifact.parse(envelope().put("filename","../unexpected.npvs"),"npvs",text) },
            { val e=envelope();e.getJSONObject("protections").put("hwidRequired",true)
                CompatibleExportArtifact.parse(e,"npvs",text) },
        )
        invalid.forEach { action->assertTrue(runCatching(action).isFailure) }
    }


    @Test fun futureUnlockedTargetRequiresOnlyAReadyBoundArtifact() {
        val future=envelope()
            .put("targetAppId","hex-tunnel")
            .put("targetAppName","Hex Tunnel")
            .put("extension",".hexcm")
            .put("filename","config-SP-DECODE.hexcm")
        val parsed=CompatibleExportArtifact.parse(future,"hexcm",text,"a".repeat(64))!!
        assertEquals("Hex Tunnel",parsed.targetAppName)
        assertEquals("Hex Tunnel",parsed.toJson().getString("targetAppName"))
        assertEquals("synthetic (Unlocked).hexcm",parsed.filenameFor("synthetic.hexcm"))
        assertArrayEquals(bytes,parsed.bytes())
        // A malicious or corrupted response must never produce an export button.
        assertTrue(runCatching { CompatibleExportArtifact.parse(
            JSONObject(future.toString()).put("targetAppId","../invalid"),"hexcm",text) }.isFailure)
        assertTrue(runCatching { CompatibleExportArtifact.parse(
            JSONObject(future.toString()).put("sha256","0".repeat(64)),"hexcm",text) }.isFailure)
        assertTrue(runCatching { CompatibleExportArtifact.parse(
            future,"hc",text) }.isFailure)
    }

    @Test fun catalogProtocolTwoAcceptsFutureFormatsWithoutBundledLists() {
        val format=JSONObject().put("suffix","hexcm").put("targetAppId","hex-tunnel")
            .put("name","Hex Tunnel").put("banner","none")
        val catalog=JSONObject()
            .put("schemaVersion",2).put("revision",5).put("enabled",true)
            .put("minimumAppVersion","1.1.26")
            .put("profile","original-app-open-v1").put("maxArtifactBytes",1024*1024)
            .put("formats",org.json.JSONArray().put(format))
        assertTrue("hexcm" in CompatibleExportCatalog.parse(catalog).suffixes)
        assertTrue(runCatching {
            CompatibleExportCatalog.parse(JSONObject(catalog.toString())
                .put("schemaVersion",1))
        }.isFailure)
        assertTrue(runCatching {
            CompatibleExportCatalog.parse(JSONObject(catalog.toString())
                .put("enabled",false))
        }.isFailure)
    }

    @Test fun preparedFileSurvivesHistoryReloadFavoriteAndDeletionWithoutPlaintext() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val artifact=CompatibleExportArtifact.parse(envelope(),"npvs",text)!!
        val entry=DecodeView("synthetic.npvs","npvs",text,12,compatibleExport=artifact)
        val store=SecureDecodeHistory(context)
        val disk=File(context.noBackupFilesDir,"decode-history/${entry.id}.bin")
        try {
            store.save(entry)
            val ciphertext=disk.readBytes().toString(Charsets.UTF_8)
            assertFalse(ciphertext.contains("synthetic-export"))
            assertFalse(ciphertext.contains(envelope().getString("dataBase64")))
            store.setFavorite(entry.id,true)
            val restored=SecureDecodeHistory(context).load().single{it.id==entry.id}
            assertTrue(restored.favorite)
            assertArrayEquals(bytes,restored.compatibleExport!!.bytes())
            assertTrue(restored.compatibleExport!!.matches(restored.rawText))
        } finally { store.delete(setOf(entry.id)) }
        assertFalse(disk.exists())
    }
}
