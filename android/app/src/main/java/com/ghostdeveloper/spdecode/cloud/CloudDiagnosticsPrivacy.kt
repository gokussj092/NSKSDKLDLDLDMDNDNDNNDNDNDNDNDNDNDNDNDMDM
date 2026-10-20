package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import java.security.SecureRandom
import java.time.LocalDate
import java.time.ZoneOffset

/** Privacy-first: telemetry starts disabled. No Android ID, device HWID, email or fingerprint. */
internal object CloudDiagnosticsPrivacy {
    private const val ENABLED="usage-optin"
    private const val INSTALL_ID="usage-install"
    private const val DAY="usage-last-day"
    private fun vault(context:Context)=ServerVpnSecureCache(context)

    fun enabled(context:Context):Boolean =
        vault(context).read(ENABLED)?.toString(Charsets.UTF_8)=="yes"

    @Synchronized fun setEnabled(context:Context,allowed:Boolean){
        if(allowed){
            if(!enabled(context)){
                val bytes=ByteArray(16).also{SecureRandom().nextBytes(it)}
                val id=bytes.joinToString(""){"%02x".format(it.toInt() and 0xff)}
                vault(context).write(INSTALL_ID,id.toByteArray(Charsets.US_ASCII))
                vault(context).delete(DAY)
                vault(context).write(ENABLED,"yes".toByteArray(Charsets.UTF_8))
                bytes.fill(0)
            }
        }else{
            // Clear the stored random identifier to prevent future association.
            vault(context).delete(ENABLED)
            vault(context).delete(INSTALL_ID)
            vault(context).delete(DAY)
        }
    }
    fun installationIdIfDue(context:Context):String? {
        if(!enabled(context))return null
        val today=LocalDate.now(ZoneOffset.UTC).toString()
        if(vault(context).read(DAY)?.toString(Charsets.UTF_8)==today)return null
        return vault(context).read(INSTALL_ID)?.toString(Charsets.US_ASCII)
            ?.takeIf{it.matches(Regex("[0-9a-f]{32}"))}
    }
    fun markSent(context:Context){
        if(enabled(context))vault(context).write(DAY,
            LocalDate.now(ZoneOffset.UTC).toString().toByteArray(Charsets.UTF_8))
    }
}
