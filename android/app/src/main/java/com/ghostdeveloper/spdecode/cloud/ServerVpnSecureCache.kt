package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Device-bound, encrypted cache. No encryption key is embedded in the APK.
 * Android Keystore + AES-256-GCM protect metadata and original icon bytes at
 * rest, with authenticated filenames. A rooted/instrumented runtime may still
 * inspect content after decryption: this is not anti-Frida DRM.
 */
internal class ServerVpnSecureCache(context: Context) {
    private val directory = File(context.applicationContext.noBackupFilesDir, "server_vpn_cache/v1")
    private val magic = byteArrayOf(0x53,0x56,0x43,0x32)
    private val oldMagic = byteArrayOf(0x53,0x56,0x43,0x31)
    private val alias = "spdecode.server-vpn.device-cache.v1"
    private val store = "AndroidKeyStore"
    private val maxPlain = ServerVpnIconPolicy.CACHE_RECORD_BYTES

    companion object {
        // All cache instances in this process must share one key-creation lock.
        private val keyLock=Any()
    }

    private fun checkName(name:String) {
        require(name.matches(Regex("[a-z0-9-]{1,64}"))) { "Invalid cache identifier" }
    }

    private fun key(): SecretKey = synchronized(keyLock) {
        val ks=KeyStore.getInstance(store)
        ks.load(null)
        val existing=ks.getKey(alias,null) as? SecretKey
        if(existing!=null)return existing
        val generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,store)
        generator.init(KeyGenParameterSpec.Builder(alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
            .build())
        generator.generateKey()
    }

    @Synchronized
    fun read(name:String):ByteArray? {
        checkName(name)
        val file=File(directory,name)
        if(!file.isFile || file.length() !in 33L..(maxPlain+2048).toLong())return null
        return try {
            val bytes=file.readBytes()
            val compressed=bytes.copyOfRange(0,4).contentEquals(magic)
            if(!compressed && !bytes.copyOfRange(0,4).contentEquals(oldMagic))return null
            val cipher=Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE,key(),GCMParameterSpec(128,bytes.copyOfRange(4,16)))
            cipher.updateAAD("spdecode:server-vpn:v${if(compressed)2 else 1}:$name".toByteArray(Charsets.UTF_8))
            val plain=cipher.doFinal(bytes,16,bytes.size-16)
            if(compressed)try {CatalogEnvelope.inflate(plain,maxPlain)}finally{plain.fill(0)}
            else plain.takeIf {it.size<=maxPlain}
        }catch (_:Exception) {null}
    }

    @Synchronized
    fun delete(name:String) {
        checkName(name)
        val file=File(directory,name)
        if(file.exists() && !file.delete())throw IllegalStateException("Cannot clear consent")
    }

    /** Only derived download staging is evicted; active catalog/icons are retained. */
    @Synchronized
    fun pruneDownloadCache(discard:Boolean=false) {
        val files=directory.listFiles().orEmpty().filter {it.isFile && (it.name.startsWith("part-")||it.name.startsWith("object-")||it.name=="chunk-journal")}.sortedBy{it.lastModified()}
        var bytes=files.sumOf{it.length()};val cutoff=System.currentTimeMillis()-7L*86400_000
        for(file in files)if(discard||file.lastModified()<cutoff||bytes>96L*1024*1024){val size=file.length();check(file.delete());bytes-=size}
    }

    @Synchronized
    fun write(name:String,plain:ByteArray) {
        checkName(name)
        require(plain.size in 1..maxPlain) { "Cache record exceeds limit" }
        val cipher=Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE,key())
        require(cipher.iv.size==12)
        cipher.updateAAD("spdecode:server-vpn:v2:$name".toByteArray(Charsets.UTF_8))
        val packed=ByteArrayOutputStream().also {out->GZIPOutputStream(out).use {it.write(plain)}}.toByteArray()
        val sealed=try {cipher.doFinal(packed)}finally{packed.fill(0)}
        require(directory.isDirectory || directory.mkdirs()) { "Cannot create private cache" }
        val destination=File(directory,name)
        val temporary=File(directory, "temp-"+UUID.randomUUID().toString())
        try {
            FileOutputStream(temporary).use { stream ->
                stream.write(magic)
                stream.write(cipher.iv)
                stream.write(sealed)
                stream.fd.sync()
            }
            require(temporary.renameTo(destination)) { "Atomic encrypted cache write failed" }
        }finally{temporary.delete()}
    }
}
