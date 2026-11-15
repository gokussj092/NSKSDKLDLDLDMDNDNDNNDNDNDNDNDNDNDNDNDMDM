package com.ghostdeveloper.spdecode

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.withTransaction
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Secondary index only. No filename, decrypted field, profile, password or
 * ciphertext is stored in SQLite: the Keystore AES-GCM AtomicFile remains
 * authoritative, including favorites and full decoded content.
 *
 * It is safe to rebuild this database after any interrupted transaction,
 * upgrade from 0.3.4 or accidental index deletion.
 */
@Entity(tableName = "history_index")
data class HistoryIndexRow(
    @PrimaryKey val id: String,
    val savedAtMillis: Long,
)

@Dao
interface HistoryIndexDao {
    @Query("SELECT * FROM history_index ORDER BY savedAtMillis DESC, id ASC")
    suspend fun all(): List<HistoryIndexRow>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(record: HistoryIndexRow)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(records: List<HistoryIndexRow>)

    @Query("DELETE FROM history_index WHERE id IN (:ids)")
    suspend fun delete(ids: Set<String>)

    @Query("DELETE FROM history_index")
    suspend fun clear()
}

@Database(entities=[HistoryIndexRow::class],version=1,exportSchema=false)
abstract class HistoryIndexDatabase:RoomDatabase() {
    abstract fun records():HistoryIndexDao
}

/**
 * Locked repository maintains eventual index consistency. If the write to the
 * Room index fails after an encrypted record was committed, a subsequent
 * load reconstructs the index from encrypted files. Failures must be surfaced,
 * never silently delete ciphertext.
 */
class HistoryRepository(
    private val encrypted: SecureDecodeHistory,
    private val index: HistoryIndexDatabase,
) {
    private val mutex=Mutex()

    suspend fun load():List<DecodeView> = withContext(Dispatchers.IO) {
        mutex.withLock {
            val records=encrypted.load(metadataOnly=true)
            val rows=records.map { HistoryIndexRow(it.id,it.savedAtMillis) }
            // The index is an optimization, never a prerequisite to see an
            // authenticated encrypted file. Rebuild on the next successful load.
            runCatching {
                index.withTransaction {
                    index.records().clear()
                    if(rows.isNotEmpty())index.records().upsertAll(rows)
                }
            }.onFailure { if(it is kotlinx.coroutines.CancellationException)throw it }
            records
        }
    }

    suspend fun save(entry:DecodeView) = withContext(Dispatchers.IO) {
        mutex.withLock {
            encrypted.save(entry)
            runCatching {
                index.records().upsert(HistoryIndexRow(entry.id,entry.savedAtMillis))
            }.onFailure { if(it is kotlinx.coroutines.CancellationException)throw it }
        }
    }

    suspend fun open(id:String):DecodeView = withContext(Dispatchers.IO) {
        mutex.withLock { encrypted.open(id) }
    }

    suspend fun favorite(id:String,value:Boolean):DecodeView = withContext(Dispatchers.IO) {
        mutex.withLock { encrypted.setFavorite(id,value) }
    }

    suspend fun delete(ids:Set<String>) = withContext(Dispatchers.IO) {
        mutex.withLock {
            encrypted.delete(ids)
            if(ids.isNotEmpty())runCatching {index.records().delete(ids)}
                .onFailure { if(it is kotlinx.coroutines.CancellationException)throw it }
        }
    }

    suspend fun clear() = withContext(Dispatchers.IO) {
        mutex.withLock {
            encrypted.clearAll()
            runCatching { index.records().clear() }
                .onFailure { if(it is kotlinx.coroutines.CancellationException)throw it }
        }
    }

    suspend fun pruneOlderThan(cutoffMillis:Long):Set<String> =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val removed=encrypted.pruneOlderThan(cutoffMillis)
                if(removed.isNotEmpty())runCatching {index.records().delete(removed)}
                    .onFailure { if(it is kotlinx.coroutines.CancellationException)throw it }
                removed
            }
        }

    suspend fun indexRows():List<HistoryIndexRow> = withContext(Dispatchers.IO) {
        index.records().all()
    }

    companion object {
        fun create(context:Context):HistoryRepository {
            val app=context.applicationContext
            val db=Room.databaseBuilder(app,HistoryIndexDatabase::class.java,
                "history-index.db")
                // Don't enable destructive migration: encrypted files are authoritative.
                .build()
            return HistoryRepository(SecureDecodeHistory(app),db)
        }
    }
}
