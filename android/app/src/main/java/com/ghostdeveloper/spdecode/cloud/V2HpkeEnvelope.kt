package com.ghostdeveloper.spdecode.cloud

import org.bouncycastle.crypto.hpke.HPKE
import org.json.JSONObject
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * RFC 9180 base mode, X25519/HKDF-SHA256/AES-256-GCM.
 * Server key authenticates through application-pinned PUBLIC key; the signing
 * key remains Android Keystore P-256 and is independent of the HPKE recipient.
 * Both the encapsulation and reply key schedule are per-request.
 */
internal object V2HpkeEnvelope {
    private val random=SecureRandom()
    private val info="SPDECODE-V2-HPKE-TRANSPORT-1".toByteArray(Charsets.US_ASCII)
    private val exportContext="SPDECODE-V2-HPKE-RESPONSE-KEY-NONCE-1".toByteArray(Charsets.US_ASCII)
    private val replyAad="SPDECODE-V2-HPKE-RESPONSE-AAD-1".toByteArray(Charsets.US_ASCII)
    private const val HEADER=71
    private const val REPLY_HEADER=27
    private const val MAX_FILE=8*1024*1024
    private const val MAX_REQUEST=11*1024*1024
    private const val MAX_REPLY=96*1024*1024

    data class Prepared(
        val wire:ByteArray,
        private val replyMaterial:ByteArray,
        private val messageId:ByteArray,
    ) {
        fun open(status:Int, bytes:ByteArray):JSONObject {
            try {
                if(bytes.size<REPLY_HEADER+16||bytes.size>MAX_REPLY+REPLY_HEADER+16)
                    throw IOException("CLOUD_HPKE_REPLY_INVALID")
                val header=ByteBuffer.wrap(bytes,0,REPLY_HEADER).order(ByteOrder.BIG_ENDIAN)
                val magic=ByteArray(4).also(header::get)
                if(!magic.contentEquals("SPR2".toByteArray(Charsets.US_ASCII)) ||
                    header.get().toInt()!=1 || (header.short.toInt() and 0xffff) != status)
                    throw IOException("CLOUD_HPKE_REPLY_INVALID")
                val id=ByteArray(16).also(header::get)
                val encryptedBytes=header.int
                if(!id.contentEquals(messageId) || encryptedBytes!=bytes.size-REPLY_HEADER)
                    throw IOException("CLOUD_HPKE_REPLY_INVALID")
                val key=replyMaterial.copyOfRange(0,32)
                val nonce=replyMaterial.copyOfRange(32,44)
                val cipher=Cipher.getInstance("AES/GCM/NoPadding")
                try {
                    cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),GCMParameterSpec(128,nonce))
                    cipher.updateAAD(replyAad+sha256(wire)+bytes.copyOfRange(0,REPLY_HEADER))
                    val plain=cipher.doFinal(bytes,REPLY_HEADER,encryptedBytes)
                    return try { JSONObject(String(plain,Charsets.UTF_8)) }
                        finally {plain.fill(0)}
                } finally {key.fill(0);nonce.fill(0)}
            } finally {replyMaterial.fill(0);wire.fill(0)}
        }
        fun discard(){replyMaterial.fill(0);wire.fill(0)}
    }
    private fun sha256(data:ByteArray)=MessageDigest.getInstance("SHA-256").digest(data)
    private fun pin():Pair<ByteArray,ByteArray> {
        val material=CloudNativeTransport.hpkePublicPin()
        try {
            if(material.size!=40)throw IOException("CLOUD_HPKE_PIN_MISSING")
            val id=material.copyOfRange(0,8)
            val key=material.copyOfRange(8,40)
            if(!MessageDigest.isEqual(id,sha256(key).copyOfRange(0,8)))
                throw IOException("CLOUD_HPKE_PIN_INVALID")
            return id to key
        } finally { material.fill(0) }
    }
    fun prepare(operation:Int,metadata:JSONObject,attachment:ByteArray?=null):Prepared {
        require(operation in 1..17 && operation!=3)
        if(operation==5) {
            require(attachment!=null && attachment.isNotEmpty() && attachment.size<=MAX_FILE)
            require(!metadata.has("dataBase64"))
        } else require(attachment==null)
        val json=metadata.toString().toByteArray(Charsets.UTF_8)
        require(json.size in 2..1024*1024)
        val body=ByteBuffer.allocate(4+json.size+(attachment?.size?:0)).order(ByteOrder.BIG_ENDIAN)
            .putInt(json.size).put(json).apply{if(attachment!=null)put(attachment)}.array()
        require(body.size<=MAX_REQUEST-HEADER-16)
        val (kid,recipient)=pin()
        val hpke=HPKE(HPKE.mode_base,HPKE.kem_X25519_SHA256,HPKE.kdf_HKDF_SHA256,HPKE.aead_AES_GCM256)
        try {
            val context=hpke.setupBaseS(hpke.deserializePublicKey(recipient),info)
            val enc=context.encapsulation
            if(enc.size!=32)throw IOException("CLOUD_HPKE_ENCAPSULATION")
            val id=ByteArray(16).also(random::nextBytes)
            val header=ByteBuffer.allocate(HEADER).order(ByteOrder.BIG_ENDIAN)
                .put("SPH2".toByteArray(Charsets.US_ASCII)).put(1)
                .putShort(0x0020).putShort(1).putShort(2)
                .put(kid).put(id).put(enc).putInt(body.size+16).array()
            val ct=context.seal(header+byteArrayOf(operation.toByte()),body)
            if(ct.size!=body.size+16)throw IOException("CLOUD_HPKE_CIPHERTEXT")
            val reply=context.export(exportContext,44)
            return Prepared(header+ct,reply,id)
        } catch(e:Exception){throw IOException("CLOUD_HPKE_ENCRYPT_FAILED",e)}
        finally {body.fill(0);json.fill(0)}
    }
}
