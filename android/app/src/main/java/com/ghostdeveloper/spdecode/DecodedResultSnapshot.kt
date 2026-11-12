package com.ghostdeveloper.spdecode

import java.io.OutputStream
import java.io.OutputStreamWriter
import java.security.MessageDigest
import java.security.DigestOutputStream
import org.json.JSONObject

/** Immutable identity of the complete UTF-8 result, independent of its view index. */
internal data class DecodedResultSnapshot(val byteLength:Int,val sha256:String,val indexVersion:Int=1) {
    fun toJson()=JSONObject().put("byteLength",byteLength).put("sha256",sha256).put("indexVersion",indexVersion)
    companion object {
        fun describe(raw:String):DecodedResultSnapshot {
            val digest=MessageDigest.getInstance("SHA-256");var count=0
            val sink=object:OutputStream(){override fun write(value:Int){count++;require(count<=32*1024*1024)}
                override fun write(bytes:ByteArray,offset:Int,length:Int){count+=length;require(count<=32*1024*1024)}}
            val encoder=Charsets.UTF_8.newEncoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            OutputStreamWriter(DigestOutputStream(sink,digest),encoder).use {writer->raw.reader().use{it.copyTo(writer,8192)}}
            return DecodedResultSnapshot(count,digest.digest().joinToString(""){"%02x".format(it)})
        }
    }
}
