package com.ghostdeveloper.spdecode.parity

import android.content.Context

/**
 * C5 compile-only compatibility shapes. They contain NO keys, crypto
 * implementations or offline decoding and are excluded from legacy builds.
 * Android cloud runtime always uses libspdecode.so and the private backend.
 */
internal object AndroidOfflineDecoderRouter {
    fun decode(context:Context,filename:String,input:ByteArray):String? = null
    fun decodeWithUserPassword(context:Context,filename:String,input:ByteArray,password:ByteArray):String? = null
    fun decodeWithCredentials(context:Context,filename:String,input:ByteArray,password:ByteArray?,hwid:String?):String? = null
}
internal object GenericVpnPort { const val MAX_INPUT_BYTES = 2*1024*1024 }
internal object UltraSandokPort { const val MAX_INPUT_BYTES = 2*1024*1024 }
internal object RenzPort { const val MAX_INPUT_BYTES = 2*1024*1024 }
internal object LinkLayerPort { const val MAX_INPUT = 2*1024*1024 }
internal object NpvsPort { const val MAX_INPUT = 2*1024*1024 }
internal object NurTunnelPort { const val MAX_INPUT = 2*1024*1024 }

/**
 * HCCFG metadata is obtained from the authenticated Cloud API in C5, never
 * by embedding any protected cryptographic material in the APK.
 */
internal object HcHccfgPort {
    data class Requirements(
        val passwordRequired:Boolean,
        val hwidRequired:Boolean,
        val headerAuthenticated:Boolean,
        val schema:Int,
        val schedule:String,
    ) {
        val requiresCredentials:Boolean get() = passwordRequired || hwidRequired
    }
    fun inspectRequirements(input:ByteArray):Requirements? = null
    fun requiresExternalPassword(input:ByteArray):Boolean = false
}
