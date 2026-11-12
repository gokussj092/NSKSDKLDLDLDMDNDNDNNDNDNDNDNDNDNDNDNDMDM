package com.ghostdeveloper.spdecode

import android.net.Uri
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

/**
 * Local read-only presentation of existing V2Ray outbound profiles.
 * Never invent another protocol, user, server, password or REALITY key.
 * The worker's original result and any file export remain unchanged.
 */
internal object V2rayShareLinks {
    data class Link(val protocol:String,val value:String)

    fun extract(decoded:String):List<Link> {
        if(decoded.length !in 1..500_000)return emptyList()
        val root=runCatching { JSONObject(ResultJsonDisplay.render(decoded,"hc")) }.getOrNull()
            ?:return emptyList()
        val pending=ArrayDeque<Any>()
        val results=ArrayList<Link>()
        pending.add(root)
        var visited=0
        while(pending.isNotEmpty() && visited++<2000 && results.size<16) {
            when(val item=pending.removeLast()){
                is JSONObject -> {
                    val outbounds=item.optJSONArray("outbounds")
                    if(outbounds!=null)for(i in 0 until minOf(outbounds.length(),32)){
                        val outbound=outbounds.optJSONObject(i)?:continue
                        val link=convert(outbound)
                        if(link!=null && results.none{it.value==link.value})results.add(link)
                        if(results.size==16)break
                    }
                    val keys=item.keys()
                    while(keys.hasNext()){
                        when(val child=item.opt(keys.next())){
                            is JSONObject,is JSONArray -> pending.add(child)
                        }
                    }
                }
                is JSONArray -> for(i in 0 until minOf(item.length(),128)) {
                    when(val child=item.opt(i)){
                        is JSONObject,is JSONArray -> pending.add(child)
                    }
                }
            }
        }
        return results
    }

    private fun validAddress(value:String):Boolean {
        if(value.isBlank() || value.length>255)return false
        return value.none{it.isWhitespace() || it=='@' || it=='/' || it=='?' || it=='#' || it=='\\'}
    }
    private fun port(server:JSONObject):Int {
        val p=server.opt("port")?.toString()?.toIntOrNull()?:return 0
        return p.takeIf{it in 1..65535}?:0
    }
    private val uuid=Regex("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    private fun endpoint(address:String):String =
        if(address.contains(':') && !address.startsWith("["))"["+address+"]" else address

    private fun convert(outbound:JSONObject):Link? {
        val protocol=outbound.optString("protocol").lowercase(Locale.ROOT)
        if(protocol !in setOf("vmess","vless","trojan"))return null
        val settings=outbound.optJSONObject("settings")?:return null
        val server=if(protocol=="trojan")settings.optJSONArray("servers")?.optJSONObject(0)
            else settings.optJSONArray("vnext")?.optJSONObject(0)
        if(server==null)return null
        val address=server.optString("address").trim()
        val p=port(server)
        if(!validAddress(address)||p==0)return null
        val user=if(protocol=="trojan")null else server.optJSONArray("users")?.optJSONObject(0)
        val secret=if(protocol=="trojan")server.optString("password") else user?.optString("id").orEmpty()
        if(secret.isBlank() || (protocol!="trojan" && !uuid.matches(secret)))return null

        val stream=outbound.optJSONObject("streamSettings")?:JSONObject()
        val network=stream.optString("network","tcp").ifBlank{"tcp"}.lowercase(Locale.ROOT)
        if(network !in setOf("tcp","ws","grpc"))return null
        val security=stream.optString("security","none").ifBlank{"none"}.lowercase(Locale.ROOT)
        if(security !in setOf("none","tls"))return null
        if(protocol=="trojan" && security!="tls")return null
        val tls=stream.optJSONObject("tlsSettings")
        val sni=tls?.optString("serverName").orEmpty()
        val allowInsecure=tls?.optBoolean("allowInsecure",false)?:false
        if(allowInsecure && protocol!="vmess")return null
        val ws=stream.optJSONObject("wsSettings")
        val grpc=stream.optJSONObject("grpcSettings")
        val tcp=stream.optJSONObject("tcpSettings")
        val disguise=if(network=="tcp")
            tcp?.optJSONObject("header")?.optString("type","none")?.lowercase(Locale.ROOT) ?: "none"
            else "none"
        if(disguise !in setOf("none","http"))return null
        val host=if(network=="ws")ws?.optJSONObject("headers")?.optString("Host").orEmpty()
            else ""
        val path=when(network){
            "ws"->ws?.optString("path","/").orEmpty().ifBlank{"/"}
            "grpc"->grpc?.optString("serviceName").orEmpty()
            else -> ""
        }
        if(network=="grpc" && path.isBlank())return null
        val name=outbound.optString("tag").ifBlank{protocol.uppercase(Locale.ROOT)}
        if(protocol=="vmess"){
            val data=JSONObject().apply{
                put("v","2");put("ps",name);put("add",address);put("port",p.toString())
                put("id",secret);put("aid",user?.optInt("alterId",0)?.toString()?:"0")
                put("scy",user?.optString("security","auto").orEmpty().ifBlank{"auto"})
                put("net",network);put("type",disguise);put("host",host)
                put("path",path);put("tls",if(security=="tls")"tls" else "")
                if(sni.isNotBlank())put("sni",sni)
                if(allowInsecure)put("insecure","1")
            }
            return Link(protocol,"vmess://"+Base64.encodeToString(
                data.toString().toByteArray(Charsets.UTF_8),Base64.NO_WRAP))
        }
        val query=ArrayList<Pair<String,String>>()
        if(protocol=="vless")query.add("encryption" to "none")
        query.add("security" to security)
        query.add("type" to network)
        if(sni.isNotBlank())query.add("sni" to sni)
        if(network=="ws"){
            if(host.isNotBlank())query.add("host" to host)
            query.add("path" to path)
        }else if(network=="grpc")query.add("serviceName" to path)
        else if(disguise=="http")query.add("headerType" to "http")
        val flow=user?.optString("flow").orEmpty()
        if(protocol=="vless" && flow.isNotBlank())query.add("flow" to flow)
        val encoded=query.joinToString("&"){Uri.encode(it.first)+"="+Uri.encode(it.second)}
        val credentials=Uri.encode(secret)
        return Link(protocol,protocol+"://"+credentials+"@"+endpoint(address)+":"+p+
            "?"+encoded+"#"+Uri.encode(name))
    }
}
