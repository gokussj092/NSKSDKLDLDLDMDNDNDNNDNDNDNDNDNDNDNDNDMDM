package com.ghostdeveloper.spdecode

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialInterruptedException
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.exceptions.NoCredentialException
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Native Android account connector. Google verifies identity through Android
 * Credential Manager, Better Auth verifies the signed ID token server-side.
 * No in-app WebView, no Google password interception and no API keys in prefs.
 */
internal class NativeCommerceAuth(private val context:Context) {
    /** A diagnostic identifier, never a bearer or Google ID token. */
    internal class AuthFailure(val code:String):IllegalStateException(code)
    companion object {
        internal fun diagnostic(error:Throwable):String {
            val code=(error as? AuthFailure)?.code
                ?: (error as? IllegalStateException)?.message.orEmpty()
            return code.takeIf{it.matches(Regex("[A-Z][A-Z0-9_]{2,64}"))}
                ?: "NATIVE_AUTH_FAILED"
        }
    }
    private fun hostActivity():Activity {
        var current:Context=context
        repeat(8) {
            val activity=current as? Activity
            if(activity!=null)return activity
            current=(current as? ContextWrapper)?.baseContext
                ?:throw AuthFailure("ACTIVITY_REQUIRED")
        }
        throw AuthFailure("ACTIVITY_REQUIRED")
    }
    private val origin="https://spdecode.xyz"
    private val prefs=context.getSharedPreferences("spdecode-native-commerce-session",Context.MODE_PRIVATE)
    private val keyAlias="spdecode_commerce_session_v1"
    private fun encrypt(value:String):String {
        val storage=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
        val key=(storage.getKey(keyAlias,null) as? SecretKey)?:run {
            val generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore")
            generator.init(KeyGenParameterSpec.Builder(keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).build())
            generator.generateKey()
        }
        val cipher=Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE,key)
        val iv=cipher.iv
        return Base64.encodeToString(iv+cipher.doFinal(value.toByteArray(Charsets.UTF_8)),
            Base64.NO_WRAP)
    }
    private fun decrypt(value:String):String {
        val bytes=Base64.decode(value,Base64.NO_WRAP)
        if(bytes.size<29)throw IllegalStateException("SESSION_INVALID")
        val storage=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
        val key=storage.getKey(keyAlias,null) as? SecretKey
            ?:throw IllegalStateException("SESSION_KEY_MISSING")
        val cipher=Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE,key,GCMParameterSpec(128,bytes.copyOfRange(0,12)))
        return String(cipher.doFinal(bytes.copyOfRange(12,bytes.size)),Charsets.UTF_8)
    }
    fun sessionToken():String? {
        val stored=prefs.getString("session",null)?:return null
        return try{decrypt(stored).takeIf{it.length in 24..1024}}
        catch(_:Exception){prefs.edit().remove("session").apply();null}
    }
    private fun save(token:String) {
        require(token.length in 24..1024 && !token.any{it.isWhitespace()})
        if(!prefs.edit().putString("session",encrypt(token)).commit())
            throw IllegalStateException("SESSION_NOT_PERSISTED")
    }
    private suspend fun http(path:String,method:String="GET",body:JSONObject?=null,
        authenticated:Boolean=false):Pair<JSONObject,String?> = withContext(Dispatchers.IO){
        require(path.startsWith("/api/") && !path.contains("..") && !path.contains("://"))
        val url=URL(origin+path)
        val connection=url.openConnection() as HttpURLConnection
        try{
            connection.instanceFollowRedirects=false
            connection.connectTimeout=8000
            connection.readTimeout=8000
            connection.requestMethod=method
            connection.setRequestProperty("Accept","application/json")
            connection.setRequestProperty("Cache-Control","no-store")
            if(authenticated){
                val token=sessionToken()?:throw IllegalStateException("SIGN_IN_REQUIRED")
                connection.setRequestProperty("Authorization","Bearer "+token)
            }
            if(method!="GET"){
                connection.doOutput=true
                connection.setRequestProperty("Origin",origin)
                connection.setRequestProperty("Content-Type","application/json")
                if(path=="/api/auth/sign-in/social")
                    connection.setRequestProperty("X-SPDECODE-Mobile-Auth","android-v1")
                val bytes=(body?:JSONObject()).toString().toByteArray(Charsets.UTF_8)
                require(bytes.size<=if(path=="/api/account/profile")119_000 else 16*1024)
                connection.outputStream.use{it.write(bytes)}
            }
            val status=connection.responseCode
            if(status !in 200..299){
                // Parse bounded, non-sensitive API error codes. Never expose tokens
                // or arbitrary server response bodies in the user interface.
                val returned=runCatching{
                    connection.errorStream?.use{stream->
                        val buffer=ByteArray(2048)
                        val count=stream.read(buffer)
                        if(count>0)JSONObject(String(buffer,0,count,Charsets.UTF_8))
                            .optJSONObject("error")?.optString("code") else null
                    }
                }.getOrNull()
                val known=returned?.takeIf{it.matches(Regex("[A-Z][A-Z0-9_]{2,64}"))}
                val error=known?:when(status){
                    400->"MOBILE_AUTH_BAD_REQUEST"
                    401->"SIGN_IN_REQUIRED"
                    403->"NOT_AUTHORIZED"
                    404->"MOBILE_AUTH_ENDPOINT_MISSING"
                    409->"AUTH_CONFLICT"
                    503->"SERVICE_UNAVAILABLE"
                    else->"MOBILE_AUTH_HTTP_"+status
                }
                throw AuthFailure(error)
            }
            if(!connection.contentType.orEmpty().startsWith("application/json"))
                throw IllegalStateException("INVALID_RESPONSE")
            val output=ByteArrayOutputStream()
            connection.inputStream.use{input->
                val buffer=ByteArray(4096)
                while(true){
                    val n=input.read(buffer)
                    if(n<0)break
                    if(output.size()+n>256*1024)throw IllegalStateException("RESPONSE_TOO_LARGE")
                    output.write(buffer,0,n)
                }
            }
            Pair(JSONObject(output.toString(Charsets.UTF_8.name())),
                connection.getHeaderField("set-auth-token"))
        } finally {connection.disconnect()}
    }
    suspend fun signInWithGoogle(acceptedPolicies:Boolean):JSONObject {
        if(!acceptedPolicies)throw IllegalStateException("CONSENT_REQUIRED")
        val config=try { http("/api/auth/native-config").first }
            catch(e:AuthFailure){throw AuthFailure(
                if(e.code=="MOBILE_AUTH_ENDPOINT_MISSING")"NATIVE_AUTH_NOT_DEPLOYED"
                else e.code)}
        if(!config.optBoolean("enabled",false))
            throw AuthFailure("NATIVE_AUTH_DISABLED_ON_SERVER")
        val clientId=config.optString("googleWebClientId")
        if(!clientId.endsWith(".apps.googleusercontent.com") || clientId.length>256)
            throw AuthFailure("GOOGLE_WEB_CLIENT_ID_UNAVAILABLE")
        // This is an explicit "Continue with Google" button; Google specifies
        // GetSignInWithGoogleOption here, rather than the silent/bottom-sheet
        // GetGoogleIdOption intended for sign-in suggestions.
        val options=GetSignInWithGoogleOption.Builder(clientId).build()
        // Credential Manager needs the foreground Activity, not an application
        // or locale-wrapped non-Activity context.
        val activity=hostActivity()
        val credential=try {
            CredentialManager.create(activity).getCredential(
                activity,GetCredentialRequest.Builder()
                    .addCredentialOption(options).build()
            ).credential
        }catch(e:GetCredentialCancellationException){
            throw AuthFailure("GOOGLE_SIGN_IN_CANCELLED")
        }catch(e:NoCredentialException){
            throw AuthFailure("GOOGLE_NO_AVAILABLE_CREDENTIAL")
        }catch(e:GetCredentialProviderConfigurationException){
            throw AuthFailure("GOOGLE_CREDENTIAL_PROVIDER_MISCONFIGURED")
        }catch(e:GetCredentialUnsupportedException){
            throw AuthFailure("GOOGLE_CREDENTIAL_PROVIDER_UNSUPPORTED")
        }catch(e:GetCredentialInterruptedException){
            throw AuthFailure("GOOGLE_CREDENTIAL_INTERRUPTED")
        }catch(e:GetCredentialException){
            throw AuthFailure("GOOGLE_CREDENTIAL_PICKER_FAILED")
        }
        if(credential !is CustomCredential ||
            credential.type!=GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL)
            throw AuthFailure("GOOGLE_CREDENTIAL_REQUIRED")
        val idToken=try{GoogleIdTokenCredential.createFrom(credential.data).idToken}
            catch(_:Exception){throw AuthFailure("GOOGLE_ID_TOKEN_INVALID")}
        val body=JSONObject().put("provider","google").put("idToken",
            JSONObject().put("token",idToken))
            .put("acceptedTerms","2026-11-10")
            .put("acceptedPrivacy","2026-11-10")
        val response=http("/api/auth/sign-in/social","POST",body)
        if(response.first.optBoolean("redirect",false))
            throw AuthFailure("GOOGLE_NATIVE_TOKEN_FLOW_UNSUPPORTED")
        val session=response.second?.takeIf{it.isNotBlank()}
            ?:response.first.optString("token").takeIf{it.isNotBlank()}
            ?:throw AuthFailure("SESSION_NOT_ISSUED")
        save(session)
        return try {
            account()?:throw AuthFailure("SESSION_NOT_CONFIRMED")
        }catch(e:AuthFailure){throw e}
        catch(_:Exception){throw AuthFailure("ACCOUNT_SESSION_UNAVAILABLE")}
    }
    suspend fun account():JSONObject?{
        if(sessionToken()==null){CommerceSession.clear();return null}
        val response=runCatching{http("/api/account",authenticated=true).first}.getOrNull()
        return response?.takeIf{!it.isNull("user") && it.optJSONObject("user")!=null}
            ?.also{CommerceSession.update(it)}
    }
    /** Public profile edits. A fresh authenticated server session is required. */
    suspend fun editProfile(name:String,username:String,avatarData:String?,
        replaceAvatar:Boolean):JSONObject {
        val normalizedName=name.trim()
        val normalizedHandle=username.trim().lowercase(java.util.Locale.ROOT)
        if(!NativeProfileRules.validDisplayName(normalizedName) ||
            !NativeProfileRules.validUsername(normalizedHandle))
            throw AuthFailure("INVALID_PROFILE")
        if(replaceAvatar && avatarData!=null &&
            (avatarData.length>115000 || !avatarData.startsWith("data:image/jpeg;base64,")))
            throw AuthFailure("INVALID_AVATAR")
        val body=JSONObject().put("name",normalizedName).put("username",normalizedHandle)
        if(replaceAvatar)body.put("avatarData",avatarData ?: JSONObject.NULL)
        http("/api/account/profile","PATCH",body,true)
        return account()?:throw AuthFailure("ACCOUNT_SESSION_UNAVAILABLE")
    }
    /** Server-authoritative quote; amounts and taxes are never calculated here. */
    suspend fun quoteAdFree(provider:String,country:String):JSONObject {
        if(provider !in setOf("stripe","paypal") || !Regex("[A-Z]{2}").matches(country))
            throw AuthFailure("INVALID_CHECKOUT")
        val data=JSONObject().put("product","ads-free").put("provider",provider)
            .put("currency","USD").put("country",country).put("region","")
            .put("term","base")
        return http("/api/store/quote","POST",data,true).first
    }
    suspend fun checkoutAdFree(provider:String,country:String,version:Int):String {
        if(version<1 || provider !in setOf("stripe","paypal") ||
            !Regex("[A-Z]{2}").matches(country))throw AuthFailure("INVALID_CHECKOUT")
        val body=JSONObject().put("product","ads-free")
            .put("provider",provider).put("currency","USD")
            .put("country",country).put("region","")
            .put("term","base").put("version",version)
            .put("idempotencyKey",java.util.UUID.randomUUID().toString())
            .put("acceptedTerms","2026-11-10")
        val response=http("/api/store/checkout","POST",body,true).first
        val checkout=response.optString("url")
        val url=runCatching{URL(checkout)}.getOrNull()
        val host=if(provider=="stripe")setOf("checkout.stripe.com") else
            setOf("www.paypal.com","www.sandbox.paypal.com")
        if(url==null || url.protocol!="https" || url.host !in host ||
            url.userInfo!=null || url.port!=-1)
            throw AuthFailure("INVALID_CHECKOUT_URL")
        return checkout
    }
    suspend fun editApiIp(entitlementId:String,ip:String):JSONObject {
        if(!CommercialServerIp.isPublicLiteral(ip))throw IllegalArgumentException("INVALID_PUBLIC_IP")
        return http("/api/account/api-ip","PATCH",
            JSONObject().put("id",entitlementId).put("allowedIp",ip),true).first
    }
    suspend fun signOut(){
        try{
            if(sessionToken()!=null)http("/api/auth/sign-out","POST",JSONObject(),true)
        }finally{
            prefs.edit().remove("session").commit()
            CommerceSession.clear()
        }
    }
}
