package com.ghostdeveloper.spdecode

import android.content.Context
import android.util.Base64
import java.net.URI

/**
 * C5 only validates references for the unchanged input panel. Vendor network,
 * signing, response authentication and actual EHI decryption run on the VPS.
 */
internal object HttpInjectorCloudPort {
    internal enum class Reason { REFERENCE, NETWORK, SERVER, INTEGRITY, DECODER }
    internal class CloudException(val reason:Reason):Exception("Cloud import: $reason")
    private val keyPattern=Regex("[A-Za-z0-9_]{1,128}")
    fun parseReference(input:String):String {
        val value=input.trim().removePrefix("\uFEFF")
        if(value.length>1024 || value.isBlank())throw CloudException(Reason.REFERENCE)
        if(keyPattern.matches(value))return value
        val codes=value.codePoints().toArray()
        if(codes.size>=3 && codes.first()==0x1F489 && codes.last()==0x1F680){
            val alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            val encoded=StringBuilder()
            for(code in codes.slice(1 until codes.size-1)){
                val v=code-128467
                if(v !in 0..127 || v.toChar() !in alphabet)
                    throw CloudException(Reason.REFERENCE)
                encoded.append(v.toChar())
            }
            val decoded=try {
                String(Base64.decode(encoded.toString(),Base64.DEFAULT),Charsets.UTF_8)
            }catch(_:Exception){throw CloudException(Reason.REFERENCE)}
            if(!keyPattern.matches(decoded))throw CloudException(Reason.REFERENCE)
            return decoded
        }
        val url=try{URI(value)}catch(_:Exception){throw CloudException(Reason.REFERENCE)}
        if(url.scheme !in listOf("https","ehi") ||
            url.host!="ehi.link" || url.port!=-1 || url.rawUserInfo!=null ||
            url.rawQuery!=null || url.rawFragment!=null)
            throw CloudException(Reason.REFERENCE)
        val key=url.rawPath?.removePrefix("/") ?: ""
        if(!keyPattern.matches(key))throw CloudException(Reason.REFERENCE)
        return key
    }
    @Suppress("UNUSED_PARAMETER")
    fun decodeOnline(context:Context,reference:String):String =
        throw CloudException(Reason.NETWORK)
}
