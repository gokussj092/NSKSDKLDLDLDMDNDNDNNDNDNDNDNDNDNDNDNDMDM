package com.ghostdeveloper.spdecode.results

import androidx.annotation.Keep
import org.json.JSONObject
import java.io.Closeable
import java.io.OutputStream

/** Indexes authorized result bytes only; no provider method, endpoint or key. */
@Keep
internal object NativeResultEngine {
    init { System.loadLibrary("spdecode_result_engine") }
    @JvmStatic private external fun nativeOpen(data:String):Long
    @JvmStatic private external fun nativeLength(handle:Long):Int
    @JvmStatic private external fun nativePage(handle:Long,parent:Int,offset:Int,limit:Int,mask:Boolean):ByteArray
    @JvmStatic private external fun nativeValue(handle:Long,node:Int,offset:Int,limit:Int,mask:Boolean):ByteArray
    @JvmStatic private external fun nativeOriginal(handle:Long,offset:Int,limit:Int):ByteArray
    @JvmStatic private external fun nativeClose(handle:Long)
    fun open(raw:String):Document {
        val handle=nativeOpen(raw)
        return try { Document(handle,nativeLength(handle)) }catch(error:Exception){nativeClose(handle);throw error}
    }
    class Document internal constructor(private var handle:Long,val byteLength:Int):Closeable {
        @Synchronized fun page(parent:Int,offset:Int,mask:Boolean):JSONObject {
            check(handle!=0L);return JSONObject(nativePage(handle,parent,offset,64,mask).toString(Charsets.UTF_8))
        }
        @Synchronized fun value(node:Int,offset:Int,mask:Boolean):JSONObject {
            check(handle!=0L);return JSONObject(nativeValue(handle,node,offset,4096,mask).toString(Charsets.UTF_8))
        }
        @Synchronized fun exportOriginal(output:OutputStream) {
            check(handle!=0L);var offset=0
            while(offset<byteLength){val bytes=nativeOriginal(handle,offset,minOf(65536,byteLength-offset));check(bytes.isNotEmpty());try{output.write(bytes);offset+=bytes.size}finally{bytes.fill(0)}}
            check(offset==byteLength)
        }
        @Synchronized override fun close(){if(handle!=0L){nativeClose(handle);handle=0L}}
    }
}
