package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Local, durable APK QA reports: one AES-256-GCM file per analysis and a small
 * encrypted index. Neither uploaded APK bytes nor server tokens are retained.
 * Never prune automatically; deletion is an explicit user action.
 */
internal class ApkQaHistoryStore(context:Context) {
    data class Item(val id:String,val filename:String,val phase:String,
        val createdAt:Long,val bytes:Long,val sha256:String,val hasReport:Boolean)
    data class Record(val item:Item,val report:String,val events:String,val error:String)

    companion object {
        private const val KEY_ALIAS="spdecode_apk_qa_history_v1"
        private const val MAX_RECORD_BYTES=32*1024*1024
        private val IDENTIFIER=Regex("[0-9a-f]{64}")
        private val LOCK=Any()
    }
    private val root=File(context.applicationContext.noBackupFilesDir,"apk-qa-history-v1")
        .also { if(!it.isDirectory && !it.mkdirs())throw IOException("APK_QA_HISTORY_UNAVAILABLE") }
    private val index=AtomicFile(File(root,"index.gcm"))

    private fun key():SecretKey {
        val store=KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing=store.getKey(KEY_ALIAS,null) as? SecretKey
        if(existing!=null)return existing
        val generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true).build())
        return generator.generateKey()
    }
    private fun decrypt(file:AtomicFile):ByteArray {
        val encrypted=file.openRead().use { stream ->
            val bytes=stream.readBytes()
            if(bytes.size<29 || bytes.size>MAX_RECORD_BYTES+48)
                throw IOException("APK_QA_HISTORY_CORRUPT")
            bytes
        }
        try {
            val cipher=Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE,key(),
                GCMParameterSpec(128,encrypted.copyOfRange(0,12)))
            return cipher.doFinal(encrypted,12,encrypted.size-12)
        } finally {encrypted.fill(0)}
    }
    private fun encrypt(file:AtomicFile,plain:ByteArray) {
        if(plain.size>MAX_RECORD_BYTES)throw IOException("APK_QA_HISTORY_TOO_LARGE")
        val cipher=Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE,key())
        val content=cipher.iv+cipher.doFinal(plain)
        var stream:java.io.FileOutputStream?=null
        try {
            stream=file.startWrite()
            stream.write(content)
            file.finishWrite(stream)
        }catch(error:Exception) {
            if(stream!=null)file.failWrite(stream)
            throw IOException("APK_QA_HISTORY_WRITE_FAILED",error)
        }finally{content.fill(0);plain.fill(0)}
    }
    private fun indexItems():MutableList<Item> {
        val plain=try {decrypt(index)}catch(_:FileNotFoundException){return mutableListOf()}
        try {
            val array=JSONArray(String(plain,Charsets.UTF_8))
            val entries=mutableListOf<Item>()
            for(i in 0 until array.length()) {
                val v=array.getJSONObject(i)
                val id=v.getString("id")
                if(!IDENTIFIER.matches(id))throw IOException("APK_QA_HISTORY_CORRUPT")
                entries.add(Item(id,v.getString("filename"),v.getString("phase"),
                    v.getLong("createdAt"),v.getLong("bytes"),v.optString("sha256"),
                    v.optBoolean("hasReport")))
            }
            return entries
        }finally{plain.fill(0)}
    }
    private fun writeIndex(items:List<Item>) {
        val arr=JSONArray()
        items.forEach { item ->
            arr.put(JSONObject().put("id",item.id).put("filename",item.filename)
                .put("phase",item.phase).put("createdAt",item.createdAt)
                .put("bytes",item.bytes).put("sha256",item.sha256)
                .put("hasReport",item.hasReport))
        }
        encrypt(index,arr.toString().toByteArray(Charsets.UTF_8))
    }
    fun list():List<Item> = synchronized(LOCK) {
        indexItems().sortedByDescending { it.createdAt }
    }
    fun save(state:CloudApkQaCheckpoint.State,report:String):Unit = synchronized(LOCK) {
        val id=state.startId
        if(!IDENTIFIER.matches(id) ||
            state.phase !in setOf("COMPLETED","FAILED","REJECTED"))
            throw IOException("APK_QA_HISTORY_INVALID_STATE")
        val item=Item(id,state.filename,state.phase,System.currentTimeMillis(),
            state.totalBytes,state.sha256,report.isNotEmpty())
        val record=JSONObject().put("version",1)
            .put("id",id).put("filename",state.filename).put("phase",state.phase)
            .put("events",state.events).put("report",report).put("error",state.error)
        val target=AtomicFile(File(root,"$id.gcm"))
        // Report goes first. A failed index update leaves an encrypted orphan
        // which is recoverable on a retry; it never exposes plaintext.
        encrypt(target,record.toString().toByteArray(Charsets.UTF_8))
        val items=indexItems()
        val old=items.indexOfFirst{it.id==id}
        if(old>=0) {
            val original=items[old]
            items[old]=item.copy(createdAt=original.createdAt)
        }else items.add(item)
        writeIndex(items)
    }
    fun read(id:String):Record? = synchronized(LOCK) {
        if(!IDENTIFIER.matches(id))return@synchronized null
        val item=indexItems().firstOrNull {it.id==id}?:return@synchronized null
        val target=AtomicFile(File(root,"$id.gcm"))
        val plain=try {decrypt(target)}catch(_:FileNotFoundException){return@synchronized null}
        try {
            val doc=JSONObject(String(plain,Charsets.UTF_8))
            if(doc.optInt("version")!=1 || doc.optString("id")!=id)
                throw IOException("APK_QA_HISTORY_CORRUPT")
            Record(item,doc.optString("report"),doc.optString("events","[]"),
                doc.optString("error"))
        }finally{plain.fill(0)}
    }
    fun delete(id:String):Unit = synchronized(LOCK) {
        if(!IDENTIFIER.matches(id))throw IOException("APK_QA_HISTORY_INVALID_ID")
        val current=indexItems()
        if(current.none{it.id==id})return@synchronized
        writeIndex(current.filterNot {it.id==id})
        File(root,"$id.gcm").delete()
    }
}
