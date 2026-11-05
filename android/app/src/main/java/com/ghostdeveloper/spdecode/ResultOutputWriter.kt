package com.ghostdeveloper.spdecode

import com.google.gson.Strictness
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonWriter
import com.google.gson.stream.JsonToken
import java.io.Writer

/** Streaming exports independent of the preview's node/field budget. */
internal object ResultOutputWriter {
    fun isLarge(raw:String)=raw.length>=64*1024 || raw.count{it=='\n'||it=='\r'}>1000
    private data class Frame(val path:String,val array:Boolean,var index:Int=0,var name:String="")
    private fun walk(raw:String,field:((String,String)->Unit)?) {
        JsonReader(raw.reader()).use { reader ->
            reader.strictness=Strictness.STRICT
            val stack=ArrayDeque<Frame>()
            fun path():String {
                val parent=stack.lastOrNull()?:return ""
                return if(parent.array)parent.path+" ["+(++parent.index)+"]"
                    else if(parent.path.isEmpty())parent.name else parent.path+" › "+parent.name
            }
            while(true)when(reader.peek()) {
                JsonToken.BEGIN_OBJECT,JsonToken.BEGIN_ARRAY -> {
                    val array=reader.peek()==JsonToken.BEGIN_ARRAY;val current=path()
                    require(stack.size<200){"RESULT_DEPTH_LIMIT"}
                    if(array)reader.beginArray() else reader.beginObject()
                    if(!reader.hasNext())field?.invoke(current,if(array)"[]" else "{}")
                    stack.addLast(Frame(current,array))
                }
                JsonToken.END_ARRAY -> {reader.endArray();stack.removeLast()}
                JsonToken.END_OBJECT -> {reader.endObject();stack.removeLast()}
                JsonToken.NAME -> stack.last().name=reader.nextName()
                JsonToken.STRING,JsonToken.NUMBER -> {val current=path();val value=reader.nextString();field?.invoke(current,value)}
                JsonToken.BOOLEAN -> {val current=path();val value=reader.nextBoolean();field?.invoke(current,value.toString())}
                JsonToken.NULL -> {val current=path();reader.nextNull();field?.invoke(current,"null")}
                JsonToken.END_DOCUMENT -> {require(stack.isEmpty());return}
                else -> error("RESULT_JSON_INVALID")
            }
        }
    }
    fun write(raw:String,suffix:String,format:ResultExport,output:Writer) {
        if(format==ResultExport.ORIGINAL){raw.reader().use{it.copyTo(output,8192)};return}
        val first=raw.firstOrNull{!it.isWhitespace()}
        if(first=='{' || first=='[') {
            // Complete strict validation precedes any output; no recursive DOM.
            walk(raw,null)
            if(format==ResultExport.JSON)raw.reader().use{it.copyTo(output,8192)}
            else {
                output.write("┌────────────────────────────\n│ SP-DECODE (.$suffix)\n│ Decodificado por: SP-DECODE\n│ Desarrollado por: Ghost Developer\n├────────────────────────────\n")
                walk(raw){path,value->output.write("│[۞] ");output.write(path);output.write(": ");output.write(value);output.write("\n")}
                output.write("├────────────────────────────\n└────────────────────────────")
            }
        }else if(format==ResultExport.ORDERED) {
            // Mixed bot text already has its field order and attribution.
            raw.reader().use{it.copyTo(output,8192)}
        }else {
            // Preserve all characters, including CRLF and duplicate text fields.
            val json=JsonWriter(output);json.beginObject();json.name("format").value(suffix)
            json.name("raw").value(raw);json.endObject();json.flush()
        }
    }
}
