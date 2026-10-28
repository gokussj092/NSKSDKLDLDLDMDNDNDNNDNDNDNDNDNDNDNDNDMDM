package com.ghostdeveloper.spdecode.cloud

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.zip.GZIPInputStream
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Ephemeral recipient key per request; TLS authenticates the server. No APK secret. */
internal class CatalogEnvelope(private val pair:java.security.KeyPair=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()) {
    val publicKey:String=encode(pair.public.encoded)
    fun open(body:JSONObject,purpose:String):JSONObject {
        require(body.getInt("envelope")==1 && body.getString("purpose")==purpose)
        val server=body.getString("serverKey")
        val pub=KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(decode(server,91,91))) as ECPublicKey
        require(pub.params== (pair.public as ECPublicKey).params ||
            (pub.params.curve== (pair.public as ECPublicKey).params.curve &&
             pub.params.generator== (pair.public as ECPublicKey).params.generator &&
             pub.params.order== (pair.public as ECPublicKey).params.order && pub.params.cofactor==1))
        val salt=decode(body.getString("salt"),32,32);val iv=decode(body.getString("iv"),12,12)
        val size=body.getInt("plainBytes");require(size in 1..MAX_PLAIN)
        val ciphertext=decode(body.getString("data"),17,MAX_PLAIN+2048)
        val agreement=KeyAgreement.getInstance("ECDH");agreement.init(pair.private);agreement.doPhase(pub,true)
        val shared=agreement.generateSecret()
        val prk=hmac(salt,shared)
        val key=hmac(prk,("SPDECODE-CATALOG-1:"+purpose).toByteArray(Charsets.UTF_8)+byteArrayOf(1))
        try {
            val cipher=Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),GCMParameterSpec(128,iv))
            cipher.updateAAD(listOf("SPDECODE-CATALOG-1",purpose,publicKey,server,size.toString()).joinToString("\n").toByteArray(Charsets.UTF_8))
            val packed=cipher.doFinal(ciphertext)
            val plain=try {inflate(packed,size).also {require(it.size==size)}}finally{packed.fill(0)}
            return try {JSONObject(String(plain,Charsets.UTF_8))}finally{plain.fill(0)}
        }finally {shared.fill(0);prk.fill(0);key.fill(0)}
    }
    companion object {
        const val MAX_PLAIN=4*1024*1024
        private const val FLAGS=Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        private fun encode(b:ByteArray)=Base64.encodeToString(b,FLAGS)
        private fun decode(s:String,min:Int,max:Int):ByteArray {
            require(s.length<=((max+2)/3)*4 && s.matches(Regex("[A-Za-z0-9_-]+")))
            val bytes=Base64.decode(s,FLAGS);require(bytes.size in min..max && encode(bytes)==s);return bytes
        }
        private fun hmac(key:ByteArray,value:ByteArray)=Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(key,"HmacSHA256"))
        }.doFinal(value)
        internal fun inflate(bytes:ByteArray,limit:Int):ByteArray {
            require(limit in 1..MAX_PLAIN)
            val out=ByteArrayOutputStream()
            GZIPInputStream(ByteArrayInputStream(bytes)).use {stream->
                val buffer=ByteArray(8192)
                while(true) {val n=stream.read(buffer);if(n<0)break
                    require(out.size()+n<=limit);out.write(buffer,0,n)}
            }
            return out.toByteArray()
        }
    }
}
