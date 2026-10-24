package com.ghostdeveloper.spdecode

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

/**
 * Defense in depth for official GitHub release APKs. The expected certificate
 * digest is injected by the production CI from the permanent signing keystore.
 * This detects APKs re-signed using a different certificate on normal Android
 * installs. It does NOT defeat a determined patcher, or protect static keys
 * from inspection, and Play App Signing requires its own allowlisted SHA-256 certificate.
 */
internal object ReleaseIntegrity {
    fun isTrusted(context: Context): Boolean {
        if (BuildConfig.DEBUG) return true
        // Rechecked at startup and on activity resume; no network required.
        // Release debuggability and attached instrumentation are unexpected.
        if (context.packageName != BuildConfig.APPLICATION_ID) return false
        if ((context.applicationInfo.flags and
                android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) return false
        if (android.os.Debug.isDebuggerConnected() ||
            android.os.Debug.waitingForDebugger()) return false
        // Distinguish the upload/APK signer from Play App Signing. Accept only
        // explicit fingerprints injected by trusted release CI (never arbitrary certs).
        val expected = listOfNotNull(
            hex(BuildConfig.TRUSTED_SIGNER_SHA256),
            hex(BuildConfig.PLAY_APP_SIGNER_SHA256)
        ).distinctBy { it.toList() }
        if (expected.isEmpty()) return false
        return try {
            val pm = context.packageManager
            if (Build.VERSION.SDK_INT >= 28) {
                expected.any { digest ->
                    pm.hasSigningCertificate(context.packageName, digest, PackageManager.CERT_INPUT_SHA256)
                }
            } else {
                @Suppress("DEPRECATION")
                val packageInfo = pm.getPackageInfo(context.packageName,
                    PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                val signatures = packageInfo.signatures.orEmpty()
                signatures.size == 1 && expected.any { digest ->
                    MessageDigest.isEqual(MessageDigest.getInstance("SHA-256")
                        .digest(signatures[0].toByteArray()),digest)
                }
            }
        } catch (_: Exception) {
            false // fail closed on production, never accept an unknown signer
        }
    }

    private fun hex(raw: String): ByteArray? {
        val value = raw.trim()
        if(value.length != 64 || !value.all { it in "0123456789abcdefABCDEF" }) return null
        return ByteArray(32) { index ->
            value.substring(index*2,index*2+2).toInt(16).toByte()
        }
    }
}
