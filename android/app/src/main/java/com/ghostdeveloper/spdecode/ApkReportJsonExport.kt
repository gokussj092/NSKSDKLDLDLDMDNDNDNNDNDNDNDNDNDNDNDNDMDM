package com.ghostdeveloper.spdecode

import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import com.google.gson.stream.JsonWriter
import java.io.StringReader
import java.io.Writer
import java.math.BigDecimal

/** Formats JSON while writing it: does not materialize a second JSON tree. */
internal object ApkReportJsonExport {
    fun writeIndented(source:String, output:Writer) {
        JsonReader(StringReader(source)).use { reader ->
            reader.isLenient=false
            val writer=JsonWriter(output)
            writer.setIndent("  ")
            writer.serializeNulls=true
            copy(reader,writer,0)
            if(reader.peek()!=JsonToken.END_DOCUMENT)
                throw IllegalArgumentException("Trailing JSON tokens")
            writer.flush()
            output.write("\n")
        }
    }
    private fun copy(reader:JsonReader,writer:JsonWriter,depth:Int) {
        if(depth>96)throw IllegalArgumentException("JSON nesting limit")
        when(reader.peek()) {
            JsonToken.BEGIN_OBJECT -> {
                reader.beginObject()
                writer.beginObject()
                while(reader.hasNext()) {
                    writer.name(reader.nextName())
                    copy(reader,writer,depth+1)
                }
                reader.endObject()
                writer.endObject()
            }
            JsonToken.BEGIN_ARRAY -> {
                reader.beginArray()
                writer.beginArray()
                while(reader.hasNext())copy(reader,writer,depth+1)
                reader.endArray()
                writer.endArray()
            }
            JsonToken.STRING -> writer.value(reader.nextString())
            JsonToken.NUMBER -> writer.value(BigDecimal(reader.nextString()))
            JsonToken.BOOLEAN -> writer.value(reader.nextBoolean())
            JsonToken.NULL -> { reader.nextNull();writer.nullValue() }
            else -> throw IllegalArgumentException("Invalid JSON token")
        }
    }
}
