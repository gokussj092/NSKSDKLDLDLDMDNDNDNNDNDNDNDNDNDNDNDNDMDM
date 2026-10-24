package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** Approximate active installations after the user accepts Cloud privacy terms.
 * No Android ID, HWID, advertising ID, location, filename or decoded content.
 * The random per-installation ID stays in encrypted local storage; the server
 * accepts it once per day and stores only a keyed HyperLogLog cardinality.
 */
internal object CloudDiagnosticsPrivacy {
    private const val INSTALL_ID="usage-install"
    private const val DAY="usage-last-day"
    private fun vault(context:Context)=ServerVpnSecureCache(context)

    fun enabled(context:Context):Boolean=CloudLegalConsent.accepted(context)

    /** Called on withdrawal of Cloud terms. Do not allow a separate usage toggle. */
    @Synchronized fun setEnabled(context:Context,allowed:Boolean){
        if(!allowed){
            vault(context).delete(INSTALL_ID)
            vault(context).delete(DAY)
        }
    }
    @Synchronized private fun installationId(context:Context):String {
        val previous=vault(context).read(INSTALL_ID)?.toString(Charsets.US_ASCII)
        if(previous!=null && previous.matches(Regex("[0-9a-f]{32}")))return previous
        val bytes=ByteArray(16).also{SecureRandom().nextBytes(it)}
        val id=bytes.joinToString(""){"%02x".format(it.toInt() and 0xff)}
        vault(context).write(INSTALL_ID,id.toByteArray(Charsets.US_ASCII))
        bytes.fill(0)
        return id
    }
    private fun utcDay():String=SimpleDateFormat("yyyy-MM-dd",Locale.ROOT).apply{timeZone=TimeZone.getTimeZone("UTC")}.format(Date())
    fun installationIdIfDue(context:Context):String? {
        if(!enabled(context))return null
        val today=utcDay()
        if(vault(context).read(DAY)?.toString(Charsets.UTF_8)==today)return null
        return installationId(context)
    }
    fun markSent(context:Context){
        if(enabled(context))vault(context).write(DAY,
            utcDay().toByteArray(Charsets.UTF_8))
    }
}
