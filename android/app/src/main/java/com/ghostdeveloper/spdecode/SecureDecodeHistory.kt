package com.ghostdeveloper.spdecode

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Offline, app-private, no-backup history. Each successful result is saved as a
 * separate crash-safe AES-256-GCM encrypted record, with its key in AndroidKeyStore.
 * The records survive process death and reboot, never leave this device, and are
 * removed only when the user requests deletion or uninstalls the app.
 *
 * No decoded content or passwords are written to plaintext SharedPreferences.
 * Corrupt or undecryptable entries are skipped, never automatically deleted.
 * This class performs disk and crypto operations; call it from Dispatchers.IO.
 */
class SecureDecodeHistory(context: Context) {
    private val directory = File(context.noBackupFilesDir, "decode-history")
    private val alias = "spdecode.history.aes.v1"
    private val secretKey: SecretKey by lazy { key() }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    fun load(metadataOnly:Boolean=false): List<DecodeView> =
        directory.listFiles().orEmpty()
            .filter { it.isFile && (it.name.endsWith(".bin") || it.name.endsWith(".bin.bak")) }
            .map { if (it.name.endsWith(".bak")) File(directory, it.name.removeSuffix(".bak")) else it }
            .distinctBy { it.name }
            .mapNotNull { file -> runCatching { read(file,metadataOnly) }.getOrNull() }
            .sortedWith(compareByDescending<DecodeView> { it.savedAtMillis }.thenBy { it.id })

    fun save(record: DecodeView) {
        require(!record.metadataOnly)
        require(UUID.fromString(record.id).toString() == record.id)
        if (!directory.isDirectory && !directory.mkdirs()) {
            error("Unable to create private history directory")
        }
        val metadata=JSONObject().put("version",4).put("id",record.id)
            .put("filename",record.filename).put("extension",record.extension)
            .put("fileBytes",record.fileBytes).put("savedAtMillis",record.savedAtMillis).put("favorite",record.favorite)
            .put("compatibleExport",record.compatibleExport?.also{require(it.matches(record.rawText))}?.toJson()?:JSONObject.NULL)
        val atomic=AtomicFile(File(directory,"${record.id}.bin"));var stream:java.io.FileOutputStream?=null
        try {
            stream=atomic.startWrite();ResultSnapshotCodec.write(record.id,record.rawText,metadata,secretKey,stream);atomic.finishWrite(stream)
        }catch(error:Exception){stream?.let{atomic.failWrite(it)};throw error}
    }

    fun delete(ids: Set<String>) {
        for (id in ids) {
            require(UUID.fromString(id).toString() == id)
            val atomic = AtomicFile(File(directory, "${id}.bin"))
            if (atomic.baseFile.exists()) {
                atomic.delete()
                check(!atomic.baseFile.exists()) { "Unable to delete history entry" }
            }
        }
    }

    /** Atomic favorite update: metadata remains encrypted in its full record. */
    fun setFavorite(id:String, favorite:Boolean):DecodeView {
        require(UUID.fromString(id).toString() == id)
        val file=File(directory,"${id}.bin")
        val previous=read(file)
        val updated=previous.copy(favorite=favorite)
        save(updated)
        return updated
    }

    /** User-configured retention. Favorited records are deliberately exempt. */
    fun pruneOlderThan(cutoffMillis:Long):Set<String> {
        val expired=load(metadataOnly=true).filter {
            !it.favorite && it.savedAtMillis < cutoffMillis
        }.map { it.id }.toSet()
        if(expired.isNotEmpty()) delete(expired)
        return expired
    }

    /** Remove even unreadable/corrupt ciphertext on explicit clear-all request. */
    fun clearAll() {
        if (directory.exists()) check(directory.deleteRecursively()) {
            "Unable to remove private history directory"
        }
    }

    fun open(id:String):DecodeView {
        require(UUID.fromString(id).toString()==id)
        return read(File(directory,"$id.bin"))
    }

    private fun readModern(file:File,metadataOnly:Boolean):DecodeView {
        val opened=AtomicFile(file).openRead().use {source ->
            require(file.length() in 1L..48L*1024*1024)
            if(metadataOnly)ResultSnapshotCodec.inspect(file.name.removeSuffix(".bin"),source,secretKey) to ""
            else ResultSnapshotCodec.read(file.name.removeSuffix(".bin"),source,secretKey)
        }
        val data=opened.first;val text=opened.second;val id=data.getString("id");val suffix=data.getString("extension")
        require(UUID.fromString(id).toString()==id && file.name=="$id.bin" && data.getInt("version")==4)
        return DecodeView(data.getString("filename"),suffix,text,data.getInt("fileBytes"),id,data.getLong("savedAtMillis"),data.optBoolean("favorite",false),
            if(metadataOnly)null else runCatching{com.ghostdeveloper.spdecode.cloud.CompatibleExportArtifact.parse(data.optJSONObject("compatibleExport"),suffix,text)}.getOrNull(),metadataOnly)
    }

    private fun read(file: File,metadataOnly:Boolean=false): DecodeView {
        val modern=AtomicFile(file).openRead().use { val header=DataInputStream(it);require(header.readInt()==MAGIC);header.readUnsignedByte()==2 }
        if(modern)return readModern(file,metadataOnly)
        // Avoid exhausting heap on a corrupted or maliciously oversized record.
        val atomic = AtomicFile(file)
        val bytes = atomic.openRead().use { stream ->
            // openRead restores any interrupted .bak before checking file length.
            require(atomic.baseFile.length() in 1L..MAX_RECORD_BYTES)
            stream.readBytes()
        }
        val input = DataInputStream(ByteArrayInputStream(bytes))
        val payload = input.use {
            require(it.readInt() == MAGIC && it.readUnsignedByte() == 1)
            val ivLength = it.readUnsignedByte()
            require(ivLength == 12)
            val iv = ByteArray(ivLength)
            it.readFully(iv)
            val encrypted = it.readBytes()
            require(encrypted.size >= 16)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            cipher.doFinal(encrypted)
        }
        val objectData = JSONObject(payload.toString(Charsets.UTF_8))
        val version = objectData.getInt("version")
        require(version in 1..3)
        val id = objectData.getString("id")
        require(file.name == "${id}.bin" && UUID.fromString(id).toString() == id)
        val record=DecodeView(
            filename = objectData.getString("filename"),
            extension = objectData.getString("extension"),
            rawText = objectData.getString("rawText"),
            fileBytes = objectData.getInt("fileBytes"),
            id = id,
            savedAtMillis = objectData.getLong("savedAtMillis"),
            favorite = if(version >= 2) objectData.optBoolean("favorite",false) else false,
            compatibleExport = if(version >= 3) runCatching {
                com.ghostdeveloper.spdecode.cloud.CompatibleExportArtifact.parse(
                    objectData.optJSONObject("compatibleExport"),objectData.getString("extension"),objectData.getString("rawText"))
            }.getOrNull() else null,
        )
        return if(metadataOnly)record.historySummary() else record
    }

    private companion object {
        const val MAGIC = 0x53504448 // SPDH
        const val MAX_RECORD_BYTES = 16L * 1024 * 1024
    }
}
