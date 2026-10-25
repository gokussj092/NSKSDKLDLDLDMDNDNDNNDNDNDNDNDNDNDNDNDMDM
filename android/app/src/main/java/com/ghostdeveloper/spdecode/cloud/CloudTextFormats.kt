package com.ghostdeveloper.spdecode.cloud

import com.ghostdeveloper.spdecode.TextProtocolDecoder

/** Versioned public Cloud metadata, never executable routes or decryption keys. */
data class CloudTextRoute(
    val prefix:String,val name:String,val suffix:String,val kind:String
)

/** Explicit Cloud schemes: no format guessing or cross-decoder fallbacks. */
internal object CloudTextFormats {
    private const val MNR_ALPHABET="¹²³⁴⁵⁶⁷⁸⁹⁰·,‽:'′"
    fun identify(raw:String,routes:List<CloudTextRoute> = emptyList()):TextProtocolDecoder.Input? {
        val value=raw.trim()
        // Longest prefix first: e.g. npvt-vless:// before npvt://.
        // The worker independently checks whether a method is really supported.
        val remote=routes.asSequence()
            .filter { value.length>it.prefix.length &&
                value.startsWith(it.prefix,ignoreCase=true) }
            .maxByOrNull { it.prefix.length }
        if(remote!=null && value.length<=TextProtocolDecoder.MAX_CHARS)
            return TextProtocolDecoder.Input("cloud:"+remote.suffix,
                remote.name,remote.suffix,value)
        if(value.length !in 6..TextProtocolDecoder.MAX_CHARS)return null
        return when {
            Regex("^mnrtunneludp://[A-Za-z0-9]{10}$").matches(value) ||
                (value.length>=64 && value.length%2==0 && value.all { it in MNR_ALPHABET }) ->
                TextProtocolDecoder.Input("mnr-tunnel-plus","MNR TUNNEL PLUS","stp",value)
            listOf("npvt://","npvt-ssh://","npvt-vless://","npvt-vmess://","npv://")
                .any { value.startsWith(it,ignoreCase=true) && value.length>it.length } ->
                TextProtocolDecoder.Input("npv-tunnel","NPV Tunnel","npvs",value)
            listOf("1FTnl.","1FT1.","1ftunnel://1FTnl/","1ftunnel://1FT1/")
                .any { value.startsWith(it) && value.length>it.length } ->
                TextProtocolDecoder.Input("oneftunnel","1FTunnel","1ftnl",value)
            // Only full vendor-prefixed exports; Cloud performs all decoding.
            value.length>"mytunnelproxy://".length &&
                value.startsWith("mytunnelproxy://",ignoreCase=true) ->
                TextProtocolDecoder.Input("mytunnelproxy","My Tunnel Proxy","mtp",value)
            value.length>"actunnelvpn://".length &&
                value.startsWith("actunnelvpn://",ignoreCase=true) ->
                TextProtocolDecoder.Input("actunnelvpn","AC TUNNEL VPN","actun",value)
            value.startsWith("ua://",ignoreCase=true) ->
                TextProtocolDecoder.Input("ua","Ultra Custom","ua",value)
            value.startsWith("mkk://",ignoreCase=true) ->
                TextProtocolDecoder.Input("mkk","MKK Hyper VPN","mkk",value)
            value.startsWith("vpn://",ignoreCase=true) ->
                TextProtocolDecoder.Input("vpn","DTunnel Mod","vpn",value)
            else -> null
        }
    }
}
