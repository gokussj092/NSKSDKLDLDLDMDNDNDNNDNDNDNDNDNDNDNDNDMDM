package com.ghostdeveloper.spdecode

import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive

/** Read-only presentation: immutable native decoder outputs never rewritten. */
data class ResultField(val path:String,val value:String,val confidential:Boolean)
data class ResultDocument(
    val fields:List<ResultField>,val json:String,val structured:String,
    val original:String,val jsonParsed:Boolean
)
enum class ResultExport { JSON, ORDERED, ORIGINAL }

object ResultPresentation {
    private val pretty=GsonBuilder().serializeNulls().setPrettyPrinting().disableHtmlEscaping().create()
    private val credentials=Regex("(?i)(?:password|passwd|passphrase|mypass|credential|privatekey|private_key|apisecret|accesstoken|refreshtoken|authtoken|apitoken|secretkey|sshpass)")
    private val decoration=Regex("(?i)(DEVELOPER|GROUP|CHANNEL|COPYRIGHT|CREDITS|SP\\s*-\\s*DECODE|Aplicaci[oó]n)")
    private val sourceLine=Regex("""^\s*│\[[^]]+]\s*([^:\r\n]+):\s*(.*)$""")
    private val decorativeLine=Regex("""^[\s│┌┐└┘├┤─═╔╗╚╝╠╣]+$""")
    private val decoratedHeading=Regex(
        """(?i)^\s*│?\s*(?:SP\s*[-–]\s*DECODE|[┌└├╔╚].*|(?:Developer|Group|Channel|Créditos|Credits|Copyright)\s*:)""")
    private const val MAX_DEPTH=16
    private const val MAX_FIELDS=1500

    fun isCredential(key:String)=credentials.containsMatchIn(key)
    fun parse(text:String,suffix:String):ResultDocument {
        val data=extractStandaloneJsonObject(text)
        if(data!=null){
            val rows=mutableListOf<ResultField>()
            flatten(data,"",rows,0)
            if(rows.isNotEmpty())
                return ResultDocument(rows,pretty.toJson(data),
                    structure(suffix,rows),text,true)
        }
        val obj=JsonObject()
        val rows=mutableListOf<ResultField>()
        var currentKey:String?=null
        var pendingSeparator=""
        // Unlike lineSequence(), this preserves CRLF, LF and CR in HTTP
        // payloads. The original source text remains immutable.
        val physicalLines=Regex("""([^\r\n]*)(\r\n|\n|\r|$)""").findAll(text)
        for(match in physicalLines){
            val raw=match.groupValues[1]
            val lineEnding=match.groupValues[2]
            val field=sourceLine.matchEntire(raw)
            if(field!=null){
                currentKey=null
                pendingSeparator=""
                val key=field.groupValues[1].trim()
                val value=field.groupValues[2].trim()
                if(key.isEmpty() || decoration.containsMatchIn(key) ||
                    key.contains("𝗚𝗥𝗢𝗨𝗣") || key.contains("𝗖𝗛𝗔𝗡𝗡𝗘𝗟") ||
                    key.contains("𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥"))continue
                var unique=key
                var count=2
                while(obj.has(unique)){
                    unique=key+" ("+count+")"
                    count++
                }
                obj.add(unique,parseInlineJson(value))
                currentKey=unique
                pendingSeparator=lineEnding
                continue
            }
            val key=currentKey?:continue
            if(decorativeLine.matches(raw.trim())||
                decoratedHeading.containsMatchIn(raw.trim())){
                currentKey=null
                pendingSeparator=""
                continue
            }
            if(raw.isBlank()){
                // Only commit blank lines if real content follows, avoiding
                // the decorative spacer after the final field.
                pendingSeparator+=raw+lineEnding
                continue
            }
            val before=obj.get(key)
            val previous=if(before!=null && before.isJsonPrimitive &&
                before.asJsonPrimitive.isString)before.asString else before.toString()
            obj.add(key,parseInlineJson(previous+pendingSeparator+raw))
            pendingSeparator=lineEnding
        }
        // JSON conversion is lossless even if the human-readable field list
        // is capped for rendering very large nested documents.
        for((key,value) in obj.entrySet()){
            if(rows.size>=MAX_FIELDS)break
            flatten(value,key,rows,0)
        }
        if(rows.isNotEmpty())
            return ResultDocument(rows,pretty.toJson(obj),
                structure(suffix,rows),text,false)
        val fallback=JsonObject()
        fallback.addProperty("format",suffix)
        fallback.addProperty("raw",text)
        return ResultDocument(emptyList(),pretty.toJson(fallback),text,text,false)
    }
    /** Start only on a standalone JSON opening line, not a nested "Config: {}". */
    private fun extractStandaloneJsonObject(text:String):JsonObject? {
        var offset=0
        var insideField=false
        for(line in text.lineSequence()){
            val trimmed=line.trim()
            // A "{" line inside a multi-line field value (e.g. the v2rRawJson
            // V2Ray document of a direct_v2r .ehi profile) is content, not a
            // standalone document: its first inbound object would otherwise
            // be returned alone and the rest of the result discarded. A field
            // line opens a value; a decorative line closes the field section.
            if(sourceLine.matchEntire(line)!=null)insideField=true
            else if(decorativeLine.matches(trimmed)||
                decoratedHeading.containsMatchIn(trimmed))insideField=false
            if(trimmed=="{"&&!insideField){
                val pos=offset+line.indexOf('{')
                val json=balancedObject(text,pos)
                if(json!=null)try{
                    val item=JsonParser.parseString(json)
                    if(item.isJsonObject)return item.asJsonObject
                }catch(_:Exception){}
            }
            offset+=line.length+1
        }
        return null
    }
    private fun balancedObject(text:String,start:Int):String?{
        var depth=0
        var quote=false
        var escaped=false
        for(i in start until text.length){
            val c=text[i]
            if(quote){
                if(escaped)escaped=false
                else when(c){'\\'->escaped=true; '"'->quote=false}
            }else when(c){
                '"'->quote=true
                '{'->depth++
                '}'->{depth--;if(depth==0)return text.substring(start,i+1);if(depth<0)return null}
            }
        }
        return null
    }
    private val decimalNumber=Regex("""-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?""")
    private fun parseInlineJson(value:String):JsonElement {
        val trimmed=value.trim()
        // Source scripts format JSON primitives without quotes in bot text;
        // preserve booleans, null and numeric port/expiry values as JSON types.
        // Other strings (including HTTP payload lines) remain exact.
        if(trimmed=="true"||trimmed=="false"||trimmed=="null"||
            decimalNumber.matches(trimmed)||
            trimmed.startsWith("{")||trimmed.startsWith("[")){
            try{return JsonParser.parseString(trimmed)}catch(_:Exception){}
        }
        return JsonPrimitive(value)
    }
    private fun flatten(node:JsonElement,path:String,rows:MutableList<ResultField>,depth:Int){
        if(rows.size>=MAX_FIELDS)return
        if(depth>MAX_DEPTH){
            rows.add(ResultField(path,pretty.toJson(node),isCredential(path)));return
        }
        when {
            node.isJsonObject ->{
                val entries=node.asJsonObject.entrySet()
                if(entries.isEmpty()&&path.isNotBlank())rows.add(ResultField(path,"{}",isCredential(path)))
                for((key,v) in entries){
                    if(rows.size>=MAX_FIELDS)break
                    flatten(v,if(path.isEmpty())key else path+" › "+key,rows,depth+1)
                }
            }
            node.isJsonArray ->{
                val arr:JsonArray=node.asJsonArray
                if(arr.size()==0)rows.add(ResultField(path,"[]",isCredential(path)))
                for(i in 0 until arr.size()){
                    if(rows.size>=MAX_FIELDS)break
                    flatten(arr[i],path+" ["+(i+1)+"]",rows,depth+1)
                }
            }
            else->{
                val display=if(node.isJsonNull)"null" else if(
                    node.isJsonPrimitive&&node.asJsonPrimitive.isString
                )node.asString else node.toString()
                rows.add(ResultField(path,display,isCredential(path)))
            }
        }
    }
    // Ordered projection has built-in attribution. TelegramResultCopy adds an
    // external credited Markdown wrapper for clipboard JSON and original text;
    // file exports from this object remain pure JSON or exact raw text.
    // Keep the official SP-DECODE group/channel consistent with Settings links.
    fun structure(suffix:String,fields:List<ResultField>):String=buildString {
        append("┌────────────────────────────\n")
        append("│ SP-DECODE (.").append(suffix).append(")\n")
        append("│ Decodificado por: SP-DECODE\n")
        append("│ Desarrollado por: Ghost Developer\n")

        append("├────────────────────────────\n")
        for(field in fields){
            append("│[۞] ").append(field.path).append(": ")
                .append(field.value).append('\n')
        }
        append("├────────────────────────────\n")


        append("└────────────────────────────")
    }
    fun formatted(doc:ResultDocument,format:ResultExport)=when(format){
        ResultExport.JSON->doc.json
        ResultExport.ORDERED->doc.structured
        ResultExport.ORIGINAL->doc.original
    }
}
