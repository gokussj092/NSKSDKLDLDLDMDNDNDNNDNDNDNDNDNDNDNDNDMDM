package com.ghostdeveloper.spdecode.cloud

import android.util.Base64
import org.json.JSONObject

/**
 * Bounded, structural-only V2Box password prompt detection. AES-GCM
 * authentication must still succeed in the selected local/Cloud decoder.
 */
internal object V2BoxPasswordProbe {
    private const val MAX_BYTES = 2 * 1024 * 1024

    fun requiresPassword(data:ByteArray):Boolean {
        if(data.isEmpty() || data.size>MAX_BYTES)return false
        return try {
            var raw=String(data,Charsets.UTF_8).trim()
            for(prefix in listOf("v2box://","locked="))
                if(prefix in raw)raw=raw.substringAfter(prefix)
            val obj=runCatching { JSONObject(raw) }.getOrNull()
                ?: JSONObject(String(Base64.decode(raw.filterNot{it.isWhitespace()},
                    Base64.DEFAULT),Charsets.UTF_8))
            if(obj.optString("magic")!="v2box_export")return false
            val protected=when(obj.optInt("version",-1)){
                1 -> obj.optBoolean("isPasswordProtected",false)
                2 -> {
                    val encoded=obj.optString("header")
                    if(encoded.length !in 1..4096)return false
                    val header=JSONObject(String(Base64.decode(encoded,Base64.DEFAULT),
                        Charsets.UTF_8))
                    val salt=Base64.decode(header.optString("salt"),Base64.DEFAULT)
                    header.optInt("v",-1)==2 &&
                        header.optString("kdf")=="pbkdf2-sha256" &&
                        header.optInt("iterations",0) in 100_000..1_200_000 &&
                        salt.size in 16..32
                }
                else -> false
            }
            if(!protected)return false
            val nonce=Base64.decode(obj.getString("nonce"),Base64.DEFAULT)
            val tag=Base64.decode(obj.getString("tag"),Base64.DEFAULT)
            val ciphertext=Base64.decode(obj.getString("ciphertext"),Base64.DEFAULT)
            nonce.size==12 && tag.size==16 && ciphertext.isNotEmpty()
        }catch(_:Exception){false}
    }
}
