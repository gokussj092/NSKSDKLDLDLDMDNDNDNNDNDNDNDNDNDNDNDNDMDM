package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Separate, opt-in NPV identities. No backups, preferences, history or telemetry. */
internal class NpvsIdentityVault(context:Context) {
    private val directory=File(context.applicationContext.noBackupFilesDir,"npvs-identities-v1")
    data class Entry(val id:String,val material:JSONObject) {
        val fingerprint:String get()=material.getString("fingerprint")
        val source:String get()=material.getString("source")
        val kind:String get()=material.getString("kind")
    }
    private fun key():SecretKey {
        val store=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
        (store.getKey("spdecode.npvs.identity.v1",null) as? SecretKey)?.let{return it}
        return KeyGenerator.getInstance("AES","AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder("spdecode.npvs.identity.v1",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    private fun file(id:String):File {
        require(UUID.fromString(id).toString()==id)
        return File(directory,"$id.npvk")
    }
    private fun write(id:String,bytes:ByteArray) {
        directory.mkdirs()
        val cipher=Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE,key());cipher.updateAAD(id.toByteArray())
        val raw=cipher.iv+cipher.doFinal(bytes)
        val atomic=AtomicFile(file(id));val stream=atomic.startWrite()
        try{stream.write(raw);atomic.finishWrite(stream)}
        catch(error:Exception){atomic.failWrite(stream);throw error}
        finally{raw.fill(0)}
    }
    fun save(value:JSONObject):Entry {
        validate(value)
        val stored=entries()
        val existing=stored.firstOrNull { it.fingerprint==value.getString("fingerprint") &&
            it.kind==value.getString("kind") && it.material.optString("fileSha256")==value.optString("fileSha256") }
        // One generated SP Cloud keypair per installation until explicitly deleted.
        // Imported captured identities remain independently selectable.
        if(value.optString("source")=="generated" && value.optString("kind")=="keypair")
            require(stored.none { it.source=="generated" && it.kind=="keypair" &&
                it.fingerprint!=value.getString("fingerprint") })
        require(existing!=null || stored.size<64)
        val id=existing?.id?:UUID.randomUUID().toString()
        val bytes=value.toString().toByteArray()
        try{write(id,bytes)}finally{bytes.fill(0)}
        return Entry(id,value)
    }
    fun entries():List<Entry> = directory.listFiles().orEmpty()
        .filter{it.name.endsWith(".npvk")}.map { path ->
            require(path.length() in 29L..16412L)
            val id=path.name.removeSuffix(".npvk");val raw=AtomicFile(file(id)).readFully()
            try {
                val cipher=Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE,key(),GCMParameterSpec(128,raw.copyOfRange(0,12)))
                cipher.updateAAD(id.toByteArray());val clear=cipher.doFinal(raw,12,raw.size-12)
                try{Entry(id,parse(String(clear,Charsets.UTF_8)))}finally{clear.fill(0)}
            }finally{raw.fill(0)}
        }.sortedBy{it.id}
    fun delete(id:String){AtomicFile(file(id)).delete()}
    fun enabled():Boolean=File(directory,"enabled").exists()
    fun enable(value:Boolean){directory.mkdirs();val marker=File(directory,"enabled")
        if(value)marker.writeText("1") else marker.delete()}
    fun matching(bytes:ByteArray):List<Entry> {
        if(!enabled())return emptyList()
        val fingerprints=NpvsRecipientProbe.fingerprints(bytes)
        if(fingerprints.isEmpty())return emptyList()
        val hash=hex(MessageDigest.getInstance("SHA-256").digest(bytes))
        return entries().filter{it.fingerprint in fingerprints &&
            (it.kind=="keypair" || it.material.optString("fileSha256")==hash)}
    }
    companion object {
        fun hex(bytes:ByteArray)=bytes.joinToString(""){"%02x".format(it.toInt() and 255)}
        private fun decode(value:String,size:Int?=null):ByteArray {
            require(value.matches(Regex("[A-Za-z0-9_-]{1,2048}")))
            return Base64.decode(value,Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING).also {
                require(size==null || it.size==size)
                require(Base64.encodeToString(it,Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)==value)
            }
        }
        fun parse(text:String):JSONObject {
            require(text.toByteArray().size<=16384)
            // Reject duplicate keys before JSONObject's last-value-wins parser.
            val reader=com.google.gson.stream.JsonReader(java.io.StringReader(text))
            val names=mutableSetOf<String>();reader.beginObject()
            while(reader.hasNext()){require(names.add(reader.nextName()));reader.nextString()}
            reader.endObject();require(reader.peek()==com.google.gson.stream.JsonToken.END_DOCUMENT)
            return JSONObject(text).also{validate(it)}
        }
        fun validate(value:JSONObject) {
            require(value.optString("schema")=="spdecode.npvs.recipient.v1" &&
                value.optString("curve")=="P-256" && value.optString("source") in setOf("generated","captured"))
            val fingerprint=value.getString("fingerprint");require(fingerprint.matches(Regex("[a-f0-9]{64}")))
            val common=setOf("schema","kind","source","curve","fingerprint")
            val names=value.keys().asSequence().toSet()
            when(value.getString("kind")) {
                "keypair"->{
                    require(names==common+setOf("publicKey","privateKey"))
                    val pub=decode(value.getString("publicKey"),33);require(pub[0].toInt() in 2..3)
                    require(hex(MessageDigest.getInstance("SHA-256").digest(pub))==fingerprint)
                    val privateBytes=decode(value.getString("privateKey"))
                    try {
                        val factory=KeyFactory.getInstance("EC")
                        val key=factory.generatePrivate(PKCS8EncodedKeySpec(privateBytes)) as java.security.interfaces.ECPrivateKey
                        val parameters=java.security.AlgorithmParameters.getInstance("EC").apply {
                            init(java.security.spec.ECGenParameterSpec("secp256r1"))
                        }.getParameterSpec(java.security.spec.ECParameterSpec::class.java)
                        require(key.params.order==parameters.order && key.s.signum()>0 && key.s<parameters.order)
                        val p=(parameters.curve.field as java.security.spec.ECFieldFp).p
                        val x=java.math.BigInteger(1,pub.copyOfRange(1,33));require(x<p)
                        val rhs=x.pow(3).add(parameters.curve.a.multiply(x)).add(parameters.curve.b).mod(p)
                        var y=rhs.modPow(p.add(java.math.BigInteger.ONE).shiftRight(2),p)
                        require(y.pow(2).mod(p)==rhs)
                        if(y.testBit(0)!=(pub[0].toInt()==3))y=p.subtract(y)
                        val publicKey=factory.generatePublic(java.security.spec.ECPublicKeySpec(java.security.spec.ECPoint(x,y),parameters))
                        val sign=Signature.getInstance("SHA256withECDSA");sign.initSign(key);sign.update(pub)
                        val signature=sign.sign();sign.initVerify(publicKey);sign.update(pub);require(sign.verify(signature))
                    }finally{privateBytes.fill(0)}
                }
                "agreement"->{
                    require(names==common+setOf("fileSha256","peer","sharedSecret") && value.getString("source")=="captured")
                    require(value.getString("fileSha256").matches(Regex("[a-f0-9]{64}")))
                    val peer=decode(value.getString("peer"),33);require(peer[0].toInt() in 2..3)
                    val shared=decode(value.getString("sharedSecret"),32)
                    try{require(shared.any{it!=0.toByte()})}finally{shared.fill(0)}
                }
                else->error("Invalid identity")
            }
        }
    }
}

/** Structural hint only. The server authenticates the signature before using keys. */
internal object NpvsRecipientProbe {
    fun fingerprints(data:ByteArray):Set<String> {
        if(data.size !in 89..4*1024*1024 || String(data,0,4,Charsets.US_ASCII)!="NPVS" ||
            data[4].toInt() !in setOf(5,6))return emptySet()
        fun u32(pos:Int)=java.nio.ByteBuffer.wrap(data,pos,4).int.toLong() and 0xffffffffL
        val size=u32(5)
        if(size !in 73L..262144L || 9+size+80>data.size || data[9]!=1.toByte() || data[59]!=0.toByte())return emptySet()
        val count=((data[60].toInt() and 255) shl 8) or (data[61].toInt() and 255)
        val end=53L+125L*count+(if(data[4].toInt()==6)16 else 0)
        if(count !in 1..1024 || end+20>size)return emptySet()
        return (0 until count).map { i ->
            NpvsIdentityVault.hex(data.copyOfRange(62+125*i,94+125*i))
        }.toSet()
    }
}
