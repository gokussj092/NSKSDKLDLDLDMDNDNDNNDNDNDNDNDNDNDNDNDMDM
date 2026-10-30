package com.ghostdeveloper.spdecode.cloud

import android.util.Base64
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

/**
 * HPKE RFC 9180 base mode: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
 * AES-256-GCM. Bootstrap recipient key comes from authenticated HTTPS.
 * One encapsulation per request; reply AEAD uses a disjoint exported key/nonce.
 */
internal object CloudV2Hpke {
    private val random=SecureRandom()
    private val start="HPKE-v1".toByteArray(Charsets.US_ASCII)
    private val kem=byteArrayOf(0x4b,0x45,0x4d,0x00,0x20)
    private val suite=byteArrayOf(0x48,0x50,0x4b,0x45,0x00,0x20,0x00,0x01,0x00,0x02)
    private val info="SPDECODE-V2-HTTP-HPKE-1".toByteArray(Charsets.US_ASCII)
    private val empty=byteArrayOf()
    private val flags=Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
    private val reqMagic="SP2Q".toByteArray(Charsets.US_ASCII)
    private val resMagic="SP2R".toByteArray(Charsets.US_ASCII)
    @Volatile private var publicKey:ByteArray?=null

    fun configure(encoded:String) {
        if(!encoded.matches(Regex("[A-Za-z0-9_-]{43}")))throw IOException("CLOUD_HPKE_KEY_INVALID")
        val raw=Base64.decode(encoded,flags)
        if(raw.size!=32||Base64.encodeToString(raw,flags)!=encoded)
            throw IOException("CLOUD_HPKE_KEY_INVALID")
        synchronized(this) {publicKey=raw.copyOf()}
    }
    fun clear(){synchronized(this){publicKey?.fill(0);publicKey=null}}
    private fun sha(data:ByteArray)=MessageDigest.getInstance("SHA-256").digest(data)
    private fun hmac(key:ByteArray,data:ByteArray):ByteArray {
        val mac=Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key,"HmacSHA256"))
        return mac.doFinal(data)
    }
    private fun extract(salt:ByteArray,ikm:ByteArray)=
        hmac(if(salt.isEmpty()) ByteArray(32) else salt,ikm)
    private fun expand(key:ByteArray,details:ByteArray,size:Int):ByteArray {
        require(size in 0..(255*32))
        val out=ByteArray(size)
        var previous=empty
        var offset=0
        var n=1
        while(offset<size) {
            previous=hmac(key,previous+details+byteArrayOf(n.toByte()))
            val take=minOf(previous.size,size-offset)
            previous.copyInto(out,offset,0,take)
            offset+=take
            n++
        }
        return out
    }
    private fun labeledExtract(which:ByteArray,salt:ByteArray,label:String,data:ByteArray)=
        extract(salt,start+which+label.toByteArray(Charsets.US_ASCII)+data)
    private fun labeledExpand(which:ByteArray,prk:ByteArray,label:String,details:ByteArray,size:Int)=
        expand(prk,byteArrayOf((size shr 8).toByte(),size.toByte())+start+which+
            label.toByteArray(Charsets.US_ASCII)+details,size)
    private fun aad(direction:String,op:Int,version:String,timestamp:String,nonce:String,
                    bearer:String,wire:ByteArray=empty,status:Int=0):ByteArray {
        val fields=mutableListOf("SPDECODE-V2-HPKE-1",direction,op.toString(),version,
            timestamp,nonce,sha(bearer.toByteArray(Charsets.UTF_8)).toHex())
        if(direction=="response"){fields.add(sha(wire).toHex());fields.add(status.toString())}
        return fields.joinToString("\n").toByteArray(Charsets.UTF_8)
    }
    private fun ByteArray.toHex():String=joinToString(""){"%02x".format(it.toInt() and 255)}

    data class Exchange(private val requestWire:ByteArray,private val exporter:ByteArray,
                        private val op:Int,private val version:String,
                        private val timestamp:String,private val nonce:String,
                        private val bearer:String) {
        fun openReply(status:Int,body:ByteArray):ByteArray {
            if(body.size<4+16 || !body.copyOfRange(0,4).contentEquals(resMagic))
                throw IOException("CLOUD_HPKE_RESPONSE_REQUIRED")
            val fingerprint=sha(requestWire)
            val key=labeledExpand(suite,exporter,"sec",
                "SPDECODE-REPLY-KEY".toByteArray(Charsets.US_ASCII)+fingerprint,32)
            val iv=labeledExpand(suite,exporter,"sec",
                "SPDECODE-REPLY-NONCE".toByteArray(Charsets.US_ASCII)+fingerprint,12)
            return try {
                val cipher=Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),GCMParameterSpec(128,iv))
                cipher.updateAAD(aad("response",op,version,timestamp,nonce,bearer,requestWire,status))
                cipher.doFinal(body,4,body.size-4)
            } catch(_:Exception){throw IOException("CLOUD_HPKE_AUTH_FAILED")}
            finally {key.fill(0);iv.fill(0);exporter.fill(0)}
        }
    }
    fun seal(op:Int,version:String,timestamp:String,nonce:String,bearer:String,
             plaintext:ByteArray):Pair<ByteArray,Exchange> {
        val recipient=publicKey?.copyOf() ?: throw IOException("CLOUD_HPKE_REQUIRED")
        val privateKey=X25519PrivateKeyParameters(random)
        val enc=privateKey.generatePublicKey().encoded
        val shared=ByteArray(32)
        privateKey.generateSecret(X25519PublicKeyParameters(recipient,0),shared,0)
        if(shared.all {it==0.toByte()})throw IOException("CLOUD_HPKE_INVALID_DH")
        val eae=labeledExtract(kem,empty,"eae_prk",shared)
        val secret=labeledExpand(kem,eae,"shared_secret",enc+recipient,32)
        val pskHash=labeledExtract(suite,empty,"psk_id_hash",empty)
        val infoHash=labeledExtract(suite,empty,"info_hash",info)
        val ctx=byteArrayOf(0)+pskHash+infoHash
        val derived=labeledExtract(suite,secret,"secret",empty)
        val key=labeledExpand(suite,derived,"key",ctx,32)
        val iv=labeledExpand(suite,derived,"base_nonce",ctx,12)
        val exporter=labeledExpand(suite,derived,"exp",ctx,32)
        shared.fill(0);eae.fill(0);secret.fill(0);derived.fill(0)
        return try {
            val cipher=Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE,SecretKeySpec(key,"AES"),GCMParameterSpec(128,iv))
            cipher.updateAAD(aad("request",op,version,timestamp,nonce,bearer))
            val wire=reqMagic+enc+cipher.doFinal(plaintext)
            wire to Exchange(wire,exporter,op,version,timestamp,nonce,bearer)
        } finally {key.fill(0);iv.fill(0);recipient.fill(0)}
    }
}
