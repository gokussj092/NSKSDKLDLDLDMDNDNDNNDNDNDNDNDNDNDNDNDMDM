package com.ghostdeveloper.spdecode.offline

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Android Keystore is used only for encrypted local persistence.
 * All configuration decoding and NPV key generation remain in native C++.
 */
internal data class OfflineRecord(
    val id: String,
    val filename: String,
    val extension: String,
    val json: String,
    val created: Long,
    val favorite: Boolean = false,
)

internal class OfflineSecureStore(private val context: Context) {
    private val root = File(context.filesDir, "offline-secure-v1")
    private val history = File(root, "results")
    private val identity = File(root, "npv-identity.enc")
    private val alias = "spdecode.offline.local.aes.v1"
    private val historyKind = "spdecode.offline.history.v1"
    private val identityKind = "spdecode.offline.identity.v1"

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        keyGenerator.init(
            KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return keyGenerator.generateKey()
    }

    private fun seal(plain: ByteArray, kind: String): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(kind.toByteArray(Charsets.UTF_8))
        val nonce = cipher.iv
        require(nonce.size == 12) { "Invalid Keystore nonce" }
        return byteArrayOf(1) + nonce + cipher.doFinal(plain)
    }

    private fun open(ciphertext: ByteArray, kind: String): ByteArray {
        require(ciphertext.size >= 30 && ciphertext[0] == 1.toByte()) {
            "Invalid encrypted data"
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, ciphertext, 1, 12))
        cipher.updateAAD(kind.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(ciphertext, 13, ciphertext.size - 13)
    }

    private fun writeAtomically(file: File, content: ByteArray) {
        file.parentFile?.mkdirs()
        val atomic = AtomicFile(file)
        val output = atomic.startWrite()
        try {
            output.write(content)
            atomic.finishWrite(output)
        } catch (error: Exception) {
            atomic.failWrite(output)
            throw error
        }
    }

    @Synchronized
    fun save(record: OfflineRecord) {
        require(UUID.fromString(record.id).toString() == record.id)
        val serialized = JSONObject().apply {
            put("id", record.id)
            put("filename", record.filename.take(255))
            put("extension", record.extension)
            put("json", record.json)
            put("created", record.created)
            put("favorite", record.favorite)
        }.toString().toByteArray(Charsets.UTF_8)
        try {
            writeAtomically(File(history, record.id + ".bin"), seal(serialized, historyKind))
        } finally { serialized.fill(0) }
    }

    @Synchronized
    fun load(): List<OfflineRecord> {
        if (!history.exists()) return emptyList()
        return history.listFiles { file -> file.isFile && file.name.endsWith(".bin") }
            .orEmpty().mapNotNull { file ->
                // A single malformed result must not corrupt other history entries.
                try {
                    val plain = open(file.readBytes(), historyKind)
                    try {
                        val data = JSONObject(String(plain, Charsets.UTF_8))
                        OfflineRecord(
                            data.getString("id"), data.getString("filename"),
                            data.getString("extension"), data.getString("json"),
                            data.getLong("created"), data.optBoolean("favorite", false)
                        )
                    } finally { plain.fill(0) }
                } catch (_: Exception) { null }
            }.sortedByDescending { it.created }
    }

    @Synchronized
    fun delete(id: String) {
        require(UUID.fromString(id).toString() == id)
        if (!File(history, id + ".bin").delete() && File(history, id + ".bin").exists()) {
            error("Cannot delete history entry")
        }
    }

    @Synchronized
    fun clear() {
        history.listFiles().orEmpty().filter { it.isFile && it.name.endsWith(".bin") }
            .forEach { if (!it.delete()) error("Cannot clear encrypted history") }
    }

    @Synchronized
    fun storeIdentity(json: String) {
        val data = JSONObject(json)
        require(data.optString("schema") == "spdecode.npvs.recipient.v1" &&
            data.has("privateKey") && data.has("publicKey"))
        val raw = json.toByteArray(Charsets.UTF_8)
        try { writeAtomically(identity, seal(raw, identityKind)) }
        finally { raw.fill(0) }
    }

    @Synchronized
    fun readIdentity(): String? {
        if (!identity.isFile) return null
        val plain = open(identity.readBytes(), identityKind)
        return try { String(plain, Charsets.UTF_8) }
        finally { plain.fill(0) }
    }

    @Synchronized
    fun removeIdentity() {
        if (identity.exists() && !identity.delete()) error("Cannot remove NPV identity")
    }
}
