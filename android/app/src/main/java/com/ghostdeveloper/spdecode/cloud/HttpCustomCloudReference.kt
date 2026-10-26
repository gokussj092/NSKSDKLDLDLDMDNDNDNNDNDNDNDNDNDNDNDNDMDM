package com.ghostdeveloper.spdecode.cloud

/** Fixed public hosting references only; never interpreted as network destinations locally. */
internal object HttpCustomCloudReference {
    val prefixes=setOf("https://cloudvpn.mrfrankofc.com/","https://link.playsmarty.uk/")
    fun matches(raw:String):Boolean {
        val value=raw.trim()
        return Regex("^https://cloudvpn\\.mrfrankofc\\.com/[A-Za-z0-9_-]{6}$").matches(value) ||
            Regex("^https://link\\.playsmarty\\.uk/[A-Za-z0-9_-]{1,64}$").matches(value)
    }
}
