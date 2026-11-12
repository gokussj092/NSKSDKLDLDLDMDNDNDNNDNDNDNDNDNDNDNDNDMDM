package com.ghostdeveloper.spdecode

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
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
                require(bytes.size<=16*1024)
                connection.outputStream.use{it.write(bytes)}
            }
            val status=connection.responseCode
            if(status !in 200..299)throw IllegalStateException(
                when(status){401->"SIGN_IN_REQUIRED";403->"NOT_AUTHORIZED";409->"CONFLICT";503->"SERVICE_UNAVAILABLE";else->"REQUEST_FAILED"})
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
    suspend fun signInWithGoogle():JSONObject {
        val config=http("/api/auth/native-config").first
        if(!config.optBoolean("enabled",false))
            throw IllegalStateException("ACCOUNTS_NOT_CONFIGURED")
        val clientId=config.optString("googleWebClientId")
        if(!clientId.endsWith(".apps.googleusercontent.com") || clientId.length>256)
            throw IllegalStateException("GOOGLE_OAUTH_NOT_CONFIGURED")
        val options=GetGoogleIdOption.Builder()
            .setFilterByAuthorizedAccounts(false)
            .setServerClientId(clientId)
            .setAutoSelectEnabled(false)
            .build()
        val credential=CredentialManager.create(context).getCredential(
            context,GetCredentialRequest.Builder().addCredentialOption(options).build()
        ).credential
        if(credential !is CustomCredential ||
            credential.type!=GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL)
            throw IllegalStateException("GOOGLE_CREDENTIAL_REQUIRED")
        val idToken=GoogleIdTokenCredential.createFrom(credential.data).idToken
        val body=JSONObject().put("provider","google").put("idToken",
            JSONObject().put("token",idToken))
            .put("acceptedTerms","2026-11-10")
            .put("acceptedPrivacy","2026-11-10")
        val response=http("/api/auth/sign-in/social","POST",body)
        val session=response.second?:response.first.optString("token")
        if(session.isNullOrBlank())throw IllegalStateException("SESSION_NOT_ISSUED")
        save(session)
        return account()?:throw IllegalStateException("SESSION_NOT_CONFIRMED")
    }
    suspend fun account():JSONObject?{
        if(sessionToken()==null)return null
        val response=runCatching{http("/api/account",authenticated=true).first}.getOrNull()
        return response?.takeIf{!it.isNull("user") && it.optJSONObject("user")!=null}
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
        }
    }
}
