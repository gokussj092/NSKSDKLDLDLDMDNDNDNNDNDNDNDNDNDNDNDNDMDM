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
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID
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
    data class DeviceKey(val keyId:String,val publicKey:String)
    private fun hashAccount(id:String):String =
        MessageDigest.getInstance("SHA-256").digest(id.toByteArray(Charsets.UTF_8))
            .take(12).joinToString(""){"%02x".format(it)}
    private fun alias(id:String)="spdecode_account_ec_v1_"+hashAccount(id)
    private fun keyPrefs(context:Context)=context.getSharedPreferences(
        "spdecode_account_device_key_ids",Context.MODE_PRIVATE)
    fun ensureDeviceKey(context:Context,accountId:String):DeviceKey {
        require(supported(context)&&accountId.isNotBlank())
        val keyName=alias(accountId)
        val store=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
        var entry=store.getEntry(keyName,null) as? KeyStore.PrivateKeyEntry
        if(entry==null){
            val generator=KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,"AndroidKeyStore")
            generator.initialize(KeyGenParameterSpec.Builder(keyName,KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(30,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                .build())
            generator.generateKeyPair()
            entry=store.getEntry(keyName,null) as? KeyStore.PrivateKeyEntry
                ?:throw IllegalStateException("DEVICE_KEY_UNAVAILABLE")
            keyPrefs(context).edit().putString(keyName,UUID.randomUUID().toString()).commit()
        }
        val id=keyPrefs(context).getString(keyName,null)
            ?:UUID.randomUUID().toString().also{
                keyPrefs(context).edit().putString(keyName,it).commit()
            }
        return DeviceKey(id,Base64.encodeToString(entry.certificate.publicKey.encoded,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
    }
    fun signedChallenge(context:Context,accountId:String,phrase:String):String {
        require(supported(context)&&phrase.length in 20..240)
        val store=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
        val entry=store.getEntry(alias(accountId),null) as? KeyStore.PrivateKeyEntry
            ?:throw IllegalStateException("DEVICE_KEY_UNAVAILABLE")
        // AndroidKeyStore enforces authentication on every signature operation,
        // with the device-confirmed 30-second authorization window.
        val signing=Signature.getInstance("SHA256withECDSA")
        signing.initSign(entry.privateKey)
        signing.update(phrase.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(signing.sign(),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
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
