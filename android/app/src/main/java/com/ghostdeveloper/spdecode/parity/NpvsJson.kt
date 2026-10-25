package com.ghostdeveloper.spdecode.parity

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** Canonicalize signed NPVS source headers as Python json.dumps sort_keys=True. */
internal object NpvsJson {
    fun parse(input:ByteArray):Any {
        val utf8=StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(input)).toString()
        val reader=JSONTokener(utf8)
        val value=reader.nextValue()
        require(reader.nextClean()=='\u0000')
        return value
    }
    private fun quote(value:String):String=buildString {
        append('"')
        for(c in value)when(c){
            '"'->append("\\\"")
            '\\'->append("\\\\")
            '\b'->append("\\b")
            '\u000c'->append("\\f")
            '\n'->append("\\n")
            '\r'->append("\\r")
            '\t'->append("\\t")
            else->if(c.code<32){
                append("\\u")
                append(c.code.toString(16).padStart(4,'0'))
            }else append(c)
        }
        append('"')
    }
    fun canonical(value:Any?,depth:Int=0):String {
        require(depth<=128)
        return when(value){
            null,JSONObject.NULL->"null"
            is Boolean->if(value)"true" else "false"
            is String->quote(value)
            is Number->value.toString()
            is JSONObject->LegacyPortPrimitives.keys(value).sorted().joinToString(",", "{","}") {
                quote(it)+":"+canonical(value.get(it),depth+1)
            }
            is Map<*,*>->value.keys.map{it as String}.sorted().joinToString(",","{","}") {
                quote(it)+":"+canonical(value[it],depth+1)
            }
            is JSONArray->(0 until value.length()).joinToString(",","[","]"){
                canonical(value.get(it),depth+1)
            }
            else->throw IllegalArgumentException("Unsupported JSON type")
        }
    }
    fun get(obj:JSONObject,key:String,fallback:Any?):Any? =
        if(obj.has(key))obj.get(key) else fallback
}
