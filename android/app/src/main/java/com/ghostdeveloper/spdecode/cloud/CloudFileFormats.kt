package com.ghostdeveloper.spdecode.cloud

import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import java.util.Locale

/**
 * Cloud-only additions; never imply that a native APK decoder exists.
 * These extension identifiers match the explicitly registered C8 server engines.
 */
internal object CloudFileFormats {
    private val names=mapOf(
        "rt" to "REESE TUNNEL",
        "gol" to "VPN PLUS PERÚ",
        "ua" to "Ultra Custom",
        "nvpnc" to "Neutro VPN",
        "green" to "24clan VPN Green",
        "hxt" to "HX Tunnel VPN",
    )
    fun detect(filename:String):AndroidDecoderCatalog.Format? {
        val basename=filename.substringAfterLast('/').substringAfterLast('\\')
            .lowercase(Locale.ROOT)
        val suffix=names.keys.filter { basename.endsWith(".$it") }
            .maxByOrNull { it.length }?:return null
        return AndroidDecoderCatalog.Format(
            suffix=suffix,
            appName=names.getValue(suffix),
            portStatus="cloud_server_only",
            androidVerified=false,
            script="server-only",
            originalRuntime="python",
            migrationPhase="C8",
            sourceCatalog="cloud-c8",
        )
    }
}
