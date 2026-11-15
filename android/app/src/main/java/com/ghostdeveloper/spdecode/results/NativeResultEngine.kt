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
    @JvmStatic private external fun nativeLineCount(handle:Long):Int
    @JvmStatic private external fun nativeColumnCount(handle:Long):Int
    @JvmStatic private external fun nativeLineWindow(handle:Long,line:Int,column:Int,count:Int,mask:Boolean):ByteArray
    @JvmStatic private external fun nativeFindNext(handle:Long,term:ByteArray,start:Int,mask:Boolean):Int
    @JvmStatic private external fun nativeClose(handle:Long)
    fun open(raw:String):Document {
        val handle=nativeOpen(raw)
        return try { Document(handle,nativeLength(handle)) }catch(error:Exception){nativeClose(handle);throw error}
    }
    class Document internal constructor(private var handle:Long,val byteLength:Int):Closeable {
        val lineCount:Int = nativeLineCount(handle)
        val columnCount:Int = nativeColumnCount(handle)
        @Synchronized fun findNext(term:String,start:Int,mask:Boolean):Int {
            check(handle!=0L)
            val bytes=term.trim().toByteArray(Charsets.UTF_8)
            if(bytes.isEmpty()||bytes.size>256)return -1
            return nativeFindNext(handle,bytes,start.coerceAtLeast(0),mask)
        }
        @Synchronized fun lineWindow(line:Int,column:Int,count:Int,mask:Boolean):JSONObject {
            check(handle!=0L)
            return JSONObject(nativeLineWindow(handle,line,column,count,mask).toString(Charsets.UTF_8))
        }
        /**
         * Copy arbitrary continuous ranges from the indexed, rendered document.
         * No document-wide Compose Text or pagination. Columns are monospace
         * display cells, and all reads go through the existing privacy mask.
         */
        @Synchronized fun selectedText(
            fromLine:Int,fromColumn:Int,toLine:Int,toColumn:Int,mask:Boolean
        ):String {
            check(handle!=0L)
            require(fromLine in 0 until lineCount && toLine in 0 until lineCount)
            val points=listOf(fromLine to fromColumn.coerceAtLeast(0),
                              toLine to toColumn.coerceAtLeast(0)).sortedWith(
                compareBy<Pair<Int,Int>> { it.first }.thenBy { it.second })
            val start=points.first()
            val end=points.last()
            val result=StringBuilder()
            for(line in start.first..end.first) {
                val begin=if(line==start.first)start.second else 0
                val limit=if(line==end.first)end.second else columnCount
                var col=begin
                while(col<limit) {
                    val row=lineWindow(line,col,minOf(2048,limit-col),mask)
                    val text=row.optString("text")
                    if(text.isEmpty())break
                    val at=row.optInt("column",col)
                    var cell=at
                    var index=0
                    while(index<text.length) {
                        val codePoint=Character.codePointAt(text,index)
                        val cells=if(codePoint<128 || codePoint==0x2022)1 else 2
                        if(cell>=begin && cell<limit)result.appendCodePoint(codePoint)
                        cell+=cells
                        index+=Character.charCount(codePoint)
                    }
                    if(cell<=col)break
                    col=cell
                }
                if(line<end.first)result.append('\n')
            }
            return result.toString()
        }

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

