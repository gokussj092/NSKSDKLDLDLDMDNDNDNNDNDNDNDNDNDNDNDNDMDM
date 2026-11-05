package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.results.NativeResultEngine
import com.ghostdeveloper.spdecode.cloud.ServerVpnSecureCache
import java.io.ByteArrayOutputStream
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Device gates; source added here, execution requires an Android test device. */
@RunWith(AndroidJUnit4::class)
class LargeResultEngineInstrumentedTest {
    private val context get()=InstrumentationRegistry.getInstrumentation().targetContext
    @Test fun nativePagesAndOriginalRemainComplete() {
        for(size in listOf(8000,20000,50000)) {
            val raw=(0 until size).joinToString(",\r\n","[\r\n","\r\n]"){"{\"id\":$it,\"name\":\"demo🌎\"}"}
            NativeResultEngine.open(raw).use { doc ->
                var offset=0
                while(true){val page=doc.page(0,offset,false);assertTrue(page.getJSONArray("rows").length() in 1..64);offset=page.getInt("next");if(!page.getBoolean("hasMore"))break}
                assertEquals(size,offset)
                val output=ByteArrayOutputStream();doc.exportOriginal(output)
                assertEquals(raw,output.toString("UTF-8"))
            }
        }
    }
    @Test fun privacyToggleDoesNotRetainUnmaskedNativePage() {
        NativeResultEngine.open("{\"password\":\"FICTIONAL_ONLY\",\"host\":\"example.invalid\"}").use {doc->
            repeat(100){assertTrue(doc.page(0,0,false).toString().contains("FICTIONAL_ONLY"));assertFalse(doc.page(0,0,true).toString().contains("FICTIONAL_ONLY"))}
        }
    }
    @Test fun encryptedHistoryListsMetadataAndReopensCompleteBody() {
        val history=SecureDecodeHistory(context)
        val raw=(0 until 20000).joinToString(",\n","[\n","\n]"){"{\"id\":$it}"}
        val record=DecodeView("fictional.json","json",raw,raw.length)
        try {
            history.save(record)
            val summary=history.load(metadataOnly=true).single{it.id==record.id}
            assertTrue(summary.metadataOnly);assertEquals("",summary.rawText)
            assertEquals(raw,history.open(record.id).rawText)
            history.setFavorite(record.id,true)
            assertTrue(history.open(record.id).favorite)
        }finally{history.delete(setOf(record.id))}
    }
    @Test fun encryptedChunkSurvivesNewCacheInstance() {
        val name="part-test-"+UUID.randomUUID().toString()
        val cache=ServerVpnSecureCache(context);val bytes="Fictional persisted fragment 🌎".toByteArray()
        try {cache.write(name,bytes);assertArrayEquals(bytes,ServerVpnSecureCache(context).read(name))}
        finally{cache.delete(name)}
    }
}
