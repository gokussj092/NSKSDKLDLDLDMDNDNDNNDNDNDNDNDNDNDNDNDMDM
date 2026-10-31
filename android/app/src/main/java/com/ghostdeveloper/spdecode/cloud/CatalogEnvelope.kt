package com.ghostdeveloper.spdecode.cloud

import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.util.zip.GZIPInputStream

/** One-shot native P-256 catalog recipient. The ephemeral private key stays in C++.
 * The JVM sees only the public SPKI and an opaque, single-use native handle.
 * The protocol and authenticated response envelope are unchanged.
 */
internal class CatalogEnvelope : Closeable {
    private val issued = CloudNativeTransport.beginCatalog()
    private val valid = issued.size==2 && issued[0].length in 120..130
    val publicKey: String = if(valid) issued[0] else
        throw IOException("CLOUD_CATALOG_KEY_UNAVAILABLE")
    private var handle: Long = issued[1].toLong().also { require(it>0L) }

    @Synchronized private fun consume(): Long {
        if(handle==0L)throw IOException("CLOUD_CATALOG_ALREADY_CONSUMED")
        return handle.also {handle=0L}
    }

    fun open(body: JSONObject, purpose: String): JSONObject {
        require(body.getInt("envelope")==1 && body.getString("purpose")==purpose)
        require(purpose=="catalog" || purpose=="icon")
        val size=body.getInt("plainBytes")
        require(size in 1..MAX_PLAIN)
        val packed=CloudNativeTransport.openCatalogHandle(consume(),publicKey,purpose,
            body.getString("serverKey"),body.getString("salt"),body.getString("iv"),
            size,body.getString("data"))
        val plain=try {inflate(packed,size).also {require(it.size==size)}}
                  finally {packed.fill(0)}
        return try {JSONObject(String(plain,Charsets.UTF_8))}
               finally {plain.fill(0)}
    }

    @Synchronized override fun close() {
        val current=handle
        handle=0L
        if(current!=0L)CloudNativeTransport.discardCatalogHandle(current)
    }

    companion object {
        const val MAX_PLAIN=4*1024*1024
        internal fun inflate(bytes:ByteArray,limit:Int):ByteArray {
            require(limit in 1..maxOf(MAX_PLAIN,ServerVpnIconPolicy.CACHE_RECORD_BYTES))
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
