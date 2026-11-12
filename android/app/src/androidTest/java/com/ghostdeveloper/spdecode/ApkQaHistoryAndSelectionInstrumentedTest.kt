package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.cloud.ApkQaHistoryStore
import com.ghostdeveloper.spdecode.cloud.CloudApkQaCheckpoint
import com.ghostdeveloper.spdecode.results.NativeResultEngine
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

/** Explicit regression for large continuous selections and encrypted history. */
@RunWith(AndroidJUnit4::class)
class ApkQaHistoryAndSelectionInstrumentedTest {
    @Test fun longNativeRangeIncludesBothEndpointsAndMoreThanOneThousandLines() {
        val raw=buildString {
            append("{\"values\":[")
            repeat(1500) { n ->
                if(n>0)append(",")
                append("\"entry-").append(n).append("\"")
            }
            append("]}")
        }
        NativeResultEngine.open(raw).use { doc ->
            assertTrue(doc.lineCount>1500)
            val selected=doc.selectedText(20,0,1420,doc.columnCount,false)
            assertTrue(selected.contains("entry-35"))
            assertTrue(selected.contains("entry-900"))
            assertTrue(selected.contains("entry-1300"))
            assertFalse(selected.contains("entry-1499"))
        }
    }

    @Test fun hiddenCredentialsAreNeverExtractedFromSelection() {
        NativeResultEngine.open("{\"password\":\"secret-only-for-test\",\"name\":\"public\"}").use { doc ->
            val visible=doc.selectedText(0,0,doc.lineCount-1,doc.columnCount,true)
            assertFalse(visible.contains("secret-only-for-test"))
            assertTrue(visible.contains("public"))
            val original=doc.selectedText(0,0,doc.lineCount-1,doc.columnCount,false)
            assertTrue(original.contains("secret-only-for-test"))
        }
    }

    @Test fun reportHistorySurvivesStoreRecreationAndIsEncryptedOnDisk() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val key=UUID.randomUUID().toString().replace("-","").repeat(2)
        val store=ApkQaHistoryStore(context)
        val report="{\"analysis\":{\"stage\":\"DEEP_STATIC_METADATA\"},\"evidence\":\"fictional-history-data\"}"
        val state=CloudApkQaCheckpoint.State(uri="",filename="sample.apks",
            startId=key,phase="COMPLETED",totalBytes=38003378L,
            sha256="a".repeat(64),events="[]")
        try {
            store.save(state,report)
            val reopened=ApkQaHistoryStore(context)
            assertTrue(reopened.list().any{it.id==key})
            assertEquals(report,reopened.read(key)?.report)
            val encrypted=File(context.noBackupFilesDir,"apk-qa-history-v1/$key.gcm").readBytes()
            assertFalse(String(encrypted,Charsets.ISO_8859_1).contains("fictional-history-data"))
        } finally {
            store.delete(key)
        }
    }
}
