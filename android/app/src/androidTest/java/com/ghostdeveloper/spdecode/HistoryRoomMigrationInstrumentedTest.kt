package com.ghostdeveloper.spdecode

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.flow.first
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Proves pre-Room ciphertext is still authoritative and no data is re-encoded. */
@RunWith(AndroidJUnit4::class)
class HistoryRoomMigrationInstrumentedTest {
    private val ctx get()=InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun preRoomEncryptedFilesRestoreAndIndexRebuilds()=runBlocking {
        val store=SecureDecodeHistory(ctx)
        val record=DecodeView("old-profile.ehi","ehi",
            "password: synthetic-PRIVATE-DO-NOT-INDEX",123)
        val db=Room.inMemoryDatabaseBuilder(ctx,HistoryIndexDatabase::class.java).build()
        try {
            store.save(record) // simulates a pre-Room 0.3.4 installation
            val repo=HistoryRepository(store,db)
            val recovered=repo.load().single{it.id==record.id}
            assertTrue(recovered.metadataOnly)
            assertEquals("",recovered.rawText)
            assertEquals(record.rawText,repo.open(record.id).rawText)
            assertEquals(record.id,repo.indexRows().single{it.id==record.id}.id)
            val name=ctx.getDatabasePath("history-index.db")
            // Tests use in-memory DB; inspect only stored row model.
            assertFalse(repo.indexRows().joinToString().contains("PRIVATE"))
            assertFalse(repo.indexRows().joinToString().contains("old-profile"))
            db.records().clear()
            assertTrue(repo.indexRows().isEmpty())
            assertTrue(repo.load().any{it.id==record.id})
            assertTrue(repo.indexRows().any{it.id==record.id})
            val favored=repo.favorite(record.id,true)
            assertTrue(favored.favorite)
            assertTrue(repo.load().single{it.id==record.id}.favorite)
        } finally {
            store.delete(setOf(record.id))
            db.close()
        }
    }

    @Test fun RoomUsesOnlyOpaqueIdsAndTimestamps() {
        val fields=HistoryIndexRow::class.java.declaredFields.map{it.name}
            .filterNot{it.contains("$"+"")}
        assertTrue(fields.contains("id"))
        assertTrue(fields.contains("savedAtMillis"))
        assertFalse(fields.any{it.contains("password",ignoreCase=true)||
            it.contains("rawText",ignoreCase=true)||
            it.contains("filename",ignoreCase=true)})
    }

    @Test fun newMetadataRestoresNavTabAndOpaqueIdAfterNewDataStoreInstance()=runBlocking {
        val preference=HistoryPreferences(ctx)
        val original=preference.values.first()
        val uuid=java.util.UUID.randomUUID().toString()
        try {
            preference.setLastTab(1)
            preference.setSelectedId(uuid)
            val restored=HistoryPreferences(ctx).values.first()
            assertEquals(1,restored.lastTab)
            assertEquals(uuid,restored.selectedId)
        } finally {
            preference.setLastTab(original.lastTab)
            preference.setSelectedId(original.selectedId)
        }
    }
}
