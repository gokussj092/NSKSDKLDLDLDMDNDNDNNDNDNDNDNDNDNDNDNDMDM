package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * One active APK/APKS QA job, encrypted at rest with a non-exportable
 * AndroidKeyStore AES-256-GCM key. No upload tokens, job IDs or selected document
 * references are written to plaintext preferences, Room or WorkManager Data.
 * Android backup is disabled, and this file is in noBackupFilesDir.
 */
internal class CloudApkQaCheckpoint(context: Context) {
    internal data class State(
        val uri: String,
        val filename: String,
        val startId: String,
        val jobId: String = "",
        val uploadToken: String = "",
        val sha256: String = "",
        val totalBytes: Long = 0L,
        val receivedBytes: Long = 0L,
        val chunkBytes: Int = 0,
        val phase: String = "QUEUED",
        val events: String = "[]",
        val report: String = "",
        val error: String = ""
    ) {
        val active: Boolean get() = phase !in setOf("COMPLETED","FAILED","REJECTED")
        fun toJson(): JSONObject = JSONObject()
            .put("version",1).put("uri",uri).put("filename",filename)
            .put("startId",startId).put("jobId",jobId).put("uploadToken",uploadToken)
            .put("sha256",sha256).put("totalBytes",totalBytes)
            .put("receivedBytes",receivedBytes).put("chunkBytes",chunkBytes)
            .put("phase",phase).put("events",events).put("report",report).put("error",error)
    }

    companion object {
        private const val ALIAS = "spdecode_apk_qa_resume_v1"
        private val LOCK = Any()
        private val JOB = Regex("[a-f0-9]{32}")
        private val HEX = Regex("[a-f0-9]{64}")
        private val TOKEN = Regex("[A-Za-z0-9_-]{43}")
    }

    private val file = AtomicFile(File(context.applicationContext.noBackupFilesDir,
        "apk-qa-checkpoint-v1.gcm"))

    private fun key(): SecretKey {
        val store=KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing=store.getKey(ALIAS,null) as? SecretKey
        if(existing!=null) return existing
        val generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build())
        return generator.generateKey()
    }

    private fun validate(value: State): State {
        if (!HEX.matches(value.startId) ||
            (value.jobId.isNotEmpty() && !JOB.matches(value.jobId)) ||
            (value.uploadToken.isNotEmpty() && !TOKEN.matches(value.uploadToken)) ||
            (value.sha256.isNotEmpty() && !HEX.matches(value.sha256)) ||
            value.totalBytes !in 0L..CloudApkQaClient.MAX_BYTES ||
            value.receivedBytes !in 0L..value.totalBytes ||
            value.chunkBytes !in 0..(2*1024*1024) ||
            value.filename.length !in 1..100 ||
            value.phase !in setOf("QUEUED","UPLOADING","PROCESSING",
                "COMPLETED","FAILED","REJECTED") ||
            value.events.length>16384 || value.report.length>200000 ||
            value.error.length>80
        ) throw IOException("APK_QA_LOCAL_STATE_INVALID")
        return value
    }

    fun load(): State? = synchronized(LOCK) {
        // AtomicFile.openRead() can recover a .bak after process death.
        // Checking baseFile.exists() first would lose that recoverable state.
        val ciphertext=try {file.openRead().use { it.readBytes() }}
            catch(_:FileNotFoundException){return@synchronized null}
        try {
            if(ciphertext.size<29 || ciphertext.size>350000)
                throw IOException("APK_QA_LOCAL_STATE_INVALID")
            val cipher=Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE,key(),GCMParameterSpec(128,ciphertext.copyOfRange(0,12)))
            val json=JSONObject(String(cipher.doFinal(ciphertext,12,ciphertext.size-12),Charsets.UTF_8))
            if(json.optInt("version")!=1)throw IOException("APK_QA_LOCAL_STATE_INVALID")
            validate(State(
                uri=json.getString("uri"),filename=json.getString("filename"),
                startId=json.getString("startId"),jobId=json.optString("jobId"),
                uploadToken=json.optString("uploadToken"),sha256=json.optString("sha256"),
                totalBytes=json.optLong("totalBytes"),receivedBytes=json.optLong("receivedBytes"),
                chunkBytes=json.optInt("chunkBytes"),phase=json.optString("phase"),
                events=json.optString("events","[]"),report=json.optString("report"),
                error=json.optString("error")))
        } catch (error: Exception) {
            // Keep damaged ciphertext: never clear a possibly active remote job.
            throw IOException("APK_QA_LOCAL_STATE_UNAVAILABLE",error)
        }
    }

    fun save(state: State) = synchronized(LOCK) {
        val json=validate(state).toJson().toString().toByteArray(Charsets.UTF_8)
        val cipher=Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE,key())
        val encrypted=cipher.iv + cipher.doFinal(json)
        var stream:java.io.FileOutputStream?=null
        try {
            stream=file.startWrite()
            stream.write(encrypted)
            file.finishWrite(stream)
        } catch (error: Exception) {
            if(stream!=null)file.failWrite(stream)
            throw IOException("APK_QA_LOCAL_STATE_WRITE_FAILED",error)
        } finally {
            json.fill(0)
            encrypted.fill(0)
        }
    }

    fun hasActive(): Boolean = load()?.active ?: false
}
