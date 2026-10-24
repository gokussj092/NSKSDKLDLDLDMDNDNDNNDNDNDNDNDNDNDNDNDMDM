package com.ghostdeveloper.spdecode.parity

import android.content.Context

import android.util.Base64
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.security.MessageDigest

/**
 * Phase E.1: ST, ITV, EUT, V2Box, SlipNet, JuanScript/Juan/Mobi.
 * Each suffix uses ONLY its own source-matched algorithm, no cross-key guesses.
 */
internal object SpecialE1Port {
    private val p=SpecialCrypto
    private val html=Regex("<[^>]+>")
    private val entry=Regex("""<entry\s+key="([^"]+)"(?:>([\s\S]*?)</entry>|/>)""")

    fun decode(context:Context,suffix:String,data:ByteArray,password:ByteArray?=null):String? {
        if(!p.check(data))return null
        return try{
            val keys=PhaseS2FamilyMaterials.e1(context)
            when(suffix) {
                "st"->sentinel(data,keys)
                "itv"->itv(data)
                "eut"->eut(data,keys)
                "v2box"->v2box(data,keys,password)
                "slipnet"->slipnet(data,keys)
                "juanscript","juan","mobi"->juan(data,keys)
                else->null
            }
        }catch(_:Exception){null}
    }

    private fun sentinel(data:ByteArray,keys:PhaseS2FamilyMaterials.E1):String? {
        require(data.size>=8)
        val decoded=data.clone()
        // Source reverses each 16-byte leading half-block BEFORE XORing.
        for(i in decoded.indices step 32)if(i+16<decoded.size){
            var left=i;var right=i+15
            while(left<right){val t=decoded[left];decoded[left]=decoded[right];decoded[right]=t;left++;right--}
        }
        for(i in decoded.indices)decoded[i]=(decoded[i].toInt() xor keys.sentinelKey[i%32].toInt()).toByte()
        require(String(decoded.copyOfRange(0,4),Charsets.US_ASCII)=="STCF" &&
            decoded[4].toInt()==1)
        val obj=JsonParser.parseString(p.utf8(decoded.copyOfRange(5,decoded.size))).asJsonObject
        val content=obj.getAsJsonObject("configData")?:return null
        val salt=p.b64(content.get("keySalt").asString)
        val nonce=p.b64(content.get("iv").asString)
        val tag=p.b64(content.get("hmac").asString)
        val raw=p.b64(content.get("data").asString)
        val key= if(obj.has("passwordHash") && !obj.get("passwordHash").isJsonNull &&
            obj.get("passwordHash").asString.isNotEmpty()) p.b64(obj.get("passwordHash").asString)
            else p.sha(keys.sentinelKey+salt)
        require(MessageDigest.isEqual(p.hmac(key,nonce+raw),tag))
        val decrypted=p.gcm(key,nonce,raw)
        obj.add("configData",JsonParser.parseString(p.utf8(decrypted)))
        return p.gson.toJson(obj)
    }

    /** Original Python ITV does not verify a GCM tag; reproduce only its
     * AES-GCM CTR keystream. Never label this family authenticated. */
    private fun itv(data:ByteArray):String? {
        require(data.size>=44)
        val clear=p.gcmUnauthenticatedStream(data.copyOfRange(0,32),
            data.copyOfRange(32,44),data.copyOfRange(44,data.size))
        val text=String(clear,Charsets.UTF_8)
        val lines=entry.findAll(text).map { m ->
            val key=m.groupValues[1]
            var value=m.groupValues[2].trim()
            if("<" in value && ">" in value && !value.startsWith("{")){
                val decoded=value.replace("&lt;","<").replace("&gt;",">")
                    .replace("&amp;","&").replace("&quot;","\"").replace("&#39;","'")
                value=html.replace(decoded,"").lineSequence().map{it.trim()}
                    .filter{it.isNotEmpty()}.joinToString(" ")
            }
            if(value.startsWith("{")&&value.endsWith("}")){
                try{value="\n"+p.gson.toJson(JsonParser.parseString(value))}catch(_:Exception){}
            }
            "$key = $value"
        }.toList()
        return if(lines.isNotEmpty()) lines.joinToString("\n") else text
    }

    private fun eutLayer(text:String,keys:PhaseS2FamilyMaterials.E1):String {
        if(text.isEmpty()||text=="null")return text
        val i=text.indexOf(':')
        if(i<0)return text
        val enc=text.substring(0,i)
        val iv=text.substring(i+1)
        if(!iv.matches(Regex("[A-Za-z0-9+/=]+")))return text
        return try{
            val clear=p.cbc(keys.eutKey,p.b64(iv),p.b64(enc))
            p.utf8(clear)
        }catch(_:Exception){text}
    }
    private fun eutNested(node:JsonElement,depth:Int,keys:PhaseS2FamilyMaterials.E1):JsonElement {
        if(depth>32)return node
        return when{
            node.isJsonObject->{
                val obj=node.asJsonObject
                for((k,v) in obj.entrySet().toList())obj.add(k,eutNested(v,depth+1,keys))
                obj
            }
            node.isJsonArray->{
                val arr=node.asJsonArray
                for(i in 0 until arr.size())arr.set(i,eutNested(arr[i],depth+1,keys))
                arr
            }
            node.isJsonPrimitive && node.asJsonPrimitive.isString -> {
                val raw=node.asString
                if(raw.count{it==':'}!=1)node
                else {
                    val decrypted=eutLayer(raw,keys)
                    val nested=p.parse(decrypted)
                    if(nested!=null)eutNested(nested,depth+1,keys)
                    else JsonParser.parseString(p.gson.toJson(decrypted))
                }
            }
            else->node
        }
    }
    private fun eut(data:ByteArray,keys:PhaseS2FamilyMaterials.E1):String? {
        val original=String(data,Charsets.UTF_8).trim()
        if(original.isEmpty())return null
        val text=if(original.startsWith("eut-settings://"))original.substring(15)else original
        val first=eutLayer(text,keys)
        val el=p.parse(first)
        if(el!=null) return p.gson.toJson(eutNested(el,0,keys))
        if(first==original)return null
        return first
    }

    private fun v2box(data:ByteArray,keys:PhaseS2FamilyMaterials.E1,password:ByteArray?):String? {
        var raw=String(data,Charsets.UTF_8).trim()
        for(scheme in listOf("v2box://","locked="))if(scheme in raw)raw=raw.substringAfter(scheme)
        raw=raw.filterNot{it.isWhitespace()}
        val decoded=try{p.utf8(p.b64(raw.padEnd((raw.length+3)/4*4,'=')))}catch(_:Exception){raw}
        val wrapper=(p.parse(decoded)?:p.parse(raw))?.takeIf{it.isJsonObject}?.asJsonObject ?:return null
        if(wrapper.get("magic")?.asString!="v2box_export")return null
        val protected=wrapper.get("isPasswordProtected")?.asBoolean==true
        if(protected && (password==null || password.isEmpty() || password.size>4096))return null
        if(!protected && password!=null)return null
        val nonce=p.b64(wrapper.get("nonce").asString)
        val ciphertext=p.b64(wrapper.get("ciphertext").asString)
        val tag=p.b64(wrapper.get("tag").asString)
        if(nonce.size!=12 || tag.size!=16 || ciphertext.isEmpty())return null
        // Match the exporter's SHA-256(UTF8(password)); no key fallback on auth failure.
        val keysToTry=if(protected)listOf(p.sha(password!!))
            else listOf(keys.v2boxKey,p.sha(keys.v2boxKey))
        for(key in keysToTry){
            try {
                return p.gson.toJson(JsonParser.parseString(p.utf8(p.gcm(key,nonce,ciphertext+tag))))
            }catch(_:Exception){}
        }
        return null
    }

    private fun slipnet(data:ByteArray,keys:PhaseS2FamilyMaterials.E1):String? {
        var text=String(data,Charsets.UTF_8)
        if(text.startsWith("slipnet-enc://"))text=text.substringAfter("://")
        val bytes=try{p.b64(text)}catch(_:Exception){data}
        var decrypted:String?=null
        for(offset in listOf(1,0)){
            try{
                require(bytes.size>=offset+28)
                val iv=bytes.copyOfRange(offset,offset+12)
                decrypted=p.utf8(p.gcm(keys.slipKey,iv,bytes.copyOfRange(offset+12,bytes.size)))
                break
            }catch(_:Exception){}
        }
        val parts=decrypted?.split("|")?:return null
        fun get(i:Int)=parts.getOrElse(i){""}
        val pairs=listOf(
            "version" to get(0),"tunnel_type" to (get(1).ifEmpty{get(21)}),
            "name" to get(2),"domain" to get(3),"keepalive" to get(6),
            "congestion" to get(7),"tcp_port" to get(8),"tcp_host" to get(9),
            "gso" to get(5),"dnstt_key" to get(4),"ssh_enabled" to get(16),
            "ssh_user" to get(14),"ssh_pass" to get(15),"ssh_port" to get(17),
            "ssh_host" to get(18),"dns_transport" to get(22),"ssh_auth_type" to get(23),
            "naive_port" to get(24),"hwid" to get(25),"expiry_timestamp" to get(26),
            "locked" to get(33),"authoritative_mode" to get(34),"resolvers" to get(27),
            "local_port" to get(36),"dns_record_type" to get(37),"proxy_port" to get(38),
            "load_balance_mode" to get(39),"tls_mode" to get(40),"transport" to get(20),
            "ws_path" to (get(41).ifEmpty{"/"}),"tls_port" to get(28).ifEmpty{get(35)},
            "sni_mode" to get(42).ifEmpty{"sni_split"},
            "mux_concurrency" to get(43).ifEmpty{"8"}
        )
        val out=JsonObject()
        for((key,value) in pairs)if(value.isNotEmpty())out.addProperty(key,value)
        return p.gson.toJson(out)
    }

    private fun juan(data:ByteArray,keys:PhaseS2FamilyMaterials.E1):String? {
        var text=String(data,Charsets.UTF_8).trim()
        if(text.startsWith("juanscript://"))text=text.substring(13)
        else if(text.startsWith("mobi://"))text=text.substring(7)
        if(text.startsWith("2:"))text=text.substring(2)
        val dot=text.lastIndexOf('.')
        require(dot>0)
        val payload=text.substring(0,dot)
        val checksum=text.substring(dot+1)
        val hash=p.sha(payload.toByteArray()).take(8).joinToString(""){"%02x".format(it)}
        require(hash.equals(checksum,ignoreCase=true))
        val packed=p.b64(payload.replace('_','/').replace('-','+').padEnd((payload.length+3)/4*4,'='))
        require(packed.size>=8)
        val b=java.nio.ByteBuffer.wrap(packed).order(java.nio.ByteOrder.BIG_ENDIAN)
        val saltLen=b.int
        require(saltLen in 1..64 && b.remaining()>=saltLen+4+12+16)
        val salt=ByteArray(saltLen).also{b.get(it)}
        val nonceLen=b.int
        require(nonceLen==12 && b.remaining()>=nonceLen+16)
        val nonce=ByteArray(nonceLen).also{b.get(it)}
        val sealed=ByteArray(b.remaining()).also{b.get(it)}
        val key=p.pbkdf(keys.juanPassword,salt,120000,32)
        val clear=p.gcm(key,nonce,sealed)
        val payloadClear=try{p.gzip(clear)}catch(_:Exception){clear}
        return p.render(p.utf8(payloadClear))
    }
}
