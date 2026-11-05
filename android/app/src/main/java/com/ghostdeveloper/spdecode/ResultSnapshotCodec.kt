package com.ghostdeveloper.spdecode

import org.json.JSONObject
import java.io.*
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Pure streaming record codec. Android Keystore owns the supplied nonexportable key. */
internal object ResultSnapshotCodec {
    const val MAGIC=0x53504448
    /** Explicit doFinal: authentication failures must never be swallowed by a stream helper. */
    private class GcmInput(private val source:InputStream,private val cipher:Cipher):InputStream() {
        private val input=ByteArray(8192)
        private var clear=ByteArray(0)
        private var offset=0
        private var finished=false
        private var received=0L
        private fun availableBlock():Boolean {
            while(offset==clear.size&&!finished) {
                clear.fill(0);offset=0
                val size=source.read(input)
                if(size<0){clear=cipher.doFinal();finished=true}
                else {
                    require(size>0);received+=size;require(received<=48L*1024*1024)
                    clear=cipher.update(input,0,size)?:ByteArray(0)
                }
            }
            return offset<clear.size
        }
        override fun read():Int=if(availableBlock())clear[offset++].toInt() and 255 else -1
        override fun read(destination:ByteArray,start:Int,length:Int):Int {
            require(start>=0&&length>=0&&start<=destination.size-length)
            if(length==0)return 0
            if(!availableBlock())return -1
            val count=minOf(length,clear.size-offset);clear.copyInto(destination,start,offset,offset+count);offset+=count;return count
        }
        override fun close(){input.fill(0);clear.fill(0);source.close()}
    }
    fun write(id:String,raw:String,metadata:JSONObject,key:SecretKey,destination:OutputStream) {
        val snapshot=DecodedResultSnapshot.describe(raw)
        val bytes=metadata.put("snapshot",snapshot.toJson()).toString().toByteArray(Charsets.UTF_8)
        require(bytes.size<=12*1024*1024)
        try {
            val cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key)
            cipher.updateAAD(("spdecode:history:v2:"+id).toByteArray(Charsets.UTF_8))
            val header=DataOutputStream(destination);header.writeInt(MAGIC);header.writeByte(2);header.writeByte(cipher.iv.size);header.write(cipher.iv);header.flush()
            val nonClosing=object:FilterOutputStream(destination){override fun close(){flush()}}
            val encrypted=CipherOutputStream(nonClosing,cipher)
            val data=DataOutputStream(encrypted);data.writeInt(bytes.size);data.writeInt(snapshot.byteLength);data.write(bytes);data.flush()
            val encoder=Charsets.UTF_8.newEncoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            OutputStreamWriter(encrypted,encoder).use {writer->raw.reader().use{it.copyTo(writer,8192)}}
        }finally{bytes.fill(0)}
    }
    fun read(id:String,source:InputStream,key:SecretKey)=readRecord(id,source,key,true)
    fun inspect(id:String,source:InputStream,key:SecretKey)=readRecord(id,source,key,false).first
    private fun readRecord(id:String,source:InputStream,key:SecretKey,includeRaw:Boolean):Pair<JSONObject,String> {
        var metadata=ByteArray(0);var raw=ByteArray(0);val buffer=ByteArray(8192)
        val digest=MessageDigest.getInstance("SHA-256");var rawLength=0
        try {
            val header=DataInputStream(source);require(header.readInt()==MAGIC&&header.readUnsignedByte()==2&&header.readUnsignedByte()==12)
            val iv=ByteArray(12);header.readFully(iv)
            val cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key,GCMParameterSpec(128,iv))
            cipher.updateAAD(("spdecode:history:v2:"+id).toByteArray(Charsets.UTF_8))
            DataInputStream(GcmInput(source,cipher)).use {input->
                val m=input.readInt();val r=input.readInt();require(m in 1..12*1024*1024&&r in 0..32*1024*1024)
                metadata=ByteArray(m);rawLength=r;if(includeRaw)raw=ByteArray(r)
                input.readFully(metadata);var offset=0
                while(offset<r){val n=input.read(buffer,0,minOf(buffer.size,r-offset));require(n>0);digest.update(buffer,0,n);if(includeRaw)buffer.copyInto(raw,offset,0,n);offset+=n}
                require(input.read()==-1) // Fully authenticate before interpreting JSON or publishing plaintext.
            }
            val meta=JSONObject(metadata.toString(Charsets.UTF_8));val descriptor=meta.getJSONObject("snapshot")
            require(descriptor.getInt("byteLength")==rawLength&&descriptor.getString("sha256")==digest.digest().joinToString(""){"%02x".format(it)})
            val text=if(includeRaw)Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(raw)).toString() else ""
            return meta to text
        }finally{metadata.fill(0);raw.fill(0);buffer.fill(0)}
    }
}
