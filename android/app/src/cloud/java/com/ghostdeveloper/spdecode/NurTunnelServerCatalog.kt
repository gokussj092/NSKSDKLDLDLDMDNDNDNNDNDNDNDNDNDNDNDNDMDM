package com.ghostdeveloper.spdecode

import android.content.Context
import java.io.IOException

/** C5 compatibility shape with NO embedded catalog endpoint or decoder. */
internal object NurTunnelServerCatalog {
    @Suppress("UNUSED_PARAMETER")
    fun defaultUrl(context:Context):String = throw IOException("CLOUD_REQUIRED")
    @Suppress("UNUSED_PARAMETER")
    fun download(url:String):ByteArray = throw IOException("CLOUD_REQUIRED")
    @Suppress("UNUSED_PARAMETER")
    fun decodeDownloaded(context:Context,data:ByteArray):String =
        throw IOException("CLOUD_REQUIRED")
}
