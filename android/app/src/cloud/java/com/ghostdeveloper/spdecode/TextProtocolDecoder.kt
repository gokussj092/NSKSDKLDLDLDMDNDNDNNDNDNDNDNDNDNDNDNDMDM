package com.ghostdeveloper.spdecode

import android.content.Context
import android.util.Base64
import com.google.gson.JsonParser
import java.util.Locale

/**
 * C5 source-identification only. Original text decoders and keys live solely
 * in the server. This class NEVER performs local decryption.
 */
object TextProtocolDecoder {
    const val MAX_CHARS=250_000
    data class Input(val protocol:String,val app:String,val suffix:String,val content:String)
    private val link=Regex("""(?i)(?<![a-z0-9._-])([a-z0-9._-]+)://([^\s\x60]+)""")
    private val known=mapOf(
        "tls" to ("TLS Tunnel" to "tls"),
        "ssc" to ("SSC Custom" to "ssc"),
        "dt" to ("Dark Tunnel" to "dark"),
        "dtunnel" to ("Dark Tunnel" to "dark"),
        "dark" to ("Dark Tunnel" to "dark"),
        "vmess" to ("VMess" to "vmess"),
        "zivpn" to ("ZIVPN" to "zivpn"),
        "howdy" to ("Howdy" to "howdy"),
        "n7pr" to ("Howdy" to "howdy"),
        "mark" to ("Howdy" to "howdy"),
        "v2box" to ("V2Box" to "v2box"),
        "falcontunnel" to ("Falcon Tunnel" to "falcon"),
        "npvt-ssh" to ("NPVT / DNS" to "npvt-ssh"),
        "slipnet-enc" to ("SlipNet" to "slipnet"),
        "renz" to ("RENZ / 7NET" to "renz"),
        "izph" to ("IZPH VPN Pro" to "izph"),
        "wyrlite" to ("WyrLite" to "wyrlite"),
        "wyrvpn" to ("WyrVPN" to "wyrvpn"),
        "intvpn" to ("IntVPN" to "intvpn"),
        "juanscript" to ("JuanScript" to "juanscript"),
        "mobi" to ("JuanScript" to "mobi"),
        "eut-settings" to ("EUT" to "eut-settings"),
        "kivuvpn" to ("Kivu VPN" to "kivuvpn"),
        "httptweak" to ("HTTP Tweak" to "httptweak"),
        "creeb" to ("Creeb Bundle" to "creeb"),
    )
    fun appNameForSuffix(suffix:String):String? =
        known.values.firstOrNull { it.second==suffix.lowercase(Locale.ROOT) }?.first
    fun identify(raw:String):Input? {
        if(raw.length>MAX_CHARS || raw.isBlank()) return null
        val clean=raw.trim().replace("\u200b","").replace("\ufeff","")
        if(clean.startsWith("/decssh ",ignoreCase=true))
            return Input("decssh","SSH","decssh",clean)
        val matches=link.findAll(clean).firstOrNull()
        if(matches!=null) {
            val scheme=matches.groupValues[1].lowercase(Locale.ROOT)
            val body=matches.groupValues[2].trim()
            if(body.isNotBlank()) {
                val kind=when {
                    scheme.startsWith("nm-")->"NetMod" to "netmod"
                    scheme.startsWith("ar-")->"ARMod" to "armod"
                    scheme.startsWith("pb-")->"XrayPB" to "xraypb"
                    scheme.contains("dark")->"Dark Tunnel" to "dark"
                    else->known[scheme] ?: ("Cloud text" to scheme.take(24))
                }
                return Input(scheme,kind.first,kind.second,clean)
            }
        }
        // Inspect only a well-known unencrypted JSON envelope, not its
        // encrypted fields or any other unrelated secrets.
        if(clean.length in 24..MAX_CHARS && clean.matches(Regex("[A-Za-z0-9+/_=-]+"))) {
            try {
                val padded=clean.replace('-','+').replace('_','/')
                val bytes=Base64.decode(padded,Base64.DEFAULT)
                if(bytes.size in 24..(1024*1024)) {
                    val obj=JsonParser.parseString(String(bytes,Charsets.UTF_8))
                    if(obj.isJsonObject && obj.asJsonObject.has("encryptedLockedConfig"))
                        return Input("dark","Dark Tunnel","dark",clean)
                }
            }catch(_:Exception){}
            return Input("netmod","NetMod","netmod",clean)
        }
        return null
    }
    @Suppress("UNUSED_PARAMETER")
    fun decode(context:Context,input:Input):String? = null
}
