package com.ghostdeveloper.spdecode.cloud

import com.ghostdeveloper.spdecode.TextProtocolDecoder

/** Explicit Cloud schemes: no format guessing or cross-decoder fallbacks. */
internal object CloudTextFormats {
    fun identify(raw:String):TextProtocolDecoder.Input? {
        val value=raw.trim()
        if(value.length !in 6..TextProtocolDecoder.MAX_CHARS)return null
        return when {
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
