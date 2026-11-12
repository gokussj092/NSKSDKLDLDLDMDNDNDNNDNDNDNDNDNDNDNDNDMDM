package com.ghostdeveloper.spdecode

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.CancellationSignal
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import androidx.compose.runtime.*
import java.util.concurrent.atomic.AtomicBoolean

/** Optional device-side privacy gate for an already authenticated server session.
 * This is not an independent server MFA factor. No biometric data is stored. */
internal object NativeDeviceAccountGuard {
    private const val PREF="spdecode-device-account-gate"
    var unlocked by mutableStateOf(false)
        private set
    fun enabled(context:Context):Boolean =
        context.getSharedPreferences(PREF,Context.MODE_PRIVATE).getBoolean("enabled",false)
    fun supported(context:Context):Boolean {
        if(Build.VERSION.SDK_INT<30)return false
        val keyguard=context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        return keyguard?.isDeviceSecure==true
    }
    fun lock(){unlocked=false}
    fun setEnabled(context:Context,enabled:Boolean){
        if(enabled&&!supported(context))return
        context.getSharedPreferences(PREF,Context.MODE_PRIVATE)
            .edit().putBoolean("enabled",enabled).apply()
        unlocked=!enabled
    }
    private fun activity(context:Context):Activity?{
        var current=context
        repeat(8){
            if(current is Activity)return current
            current=(current as? ContextWrapper)?.baseContext?:return null
        }
        return null
    }
    fun authenticate(context:Context,title:String,onFinished:(Boolean)->Unit){
        val host=activity(context)
        if(host==null||!supported(context)){onFinished(false);return}
        if(Build.VERSION.SDK_INT>=30){
            val once=AtomicBoolean(false)
            fun deliver(success:Boolean){
                if(once.compareAndSet(false,true)){
                    if(success)unlocked=true
                    onFinished(success)
                }
            }
            val prompt=BiometricPrompt.Builder(host)
                .setTitle(title)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()
            prompt.authenticate(CancellationSignal(),host.mainExecutor,
                object:BiometricPrompt.AuthenticationCallback(){
                    override fun onAuthenticationSucceeded(result:BiometricPrompt.AuthenticationResult){
                        deliver(true)
                    }
                    override fun onAuthenticationError(errorCode:Int,errString:CharSequence){
                        deliver(false)
                    }
                })
        }else onFinished(false)
    }
}
