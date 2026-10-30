package com.ghostdeveloper.spdecode.cloud

import com.ghostdeveloper.spdecode.BuildConfig
import android.content.Context
import java.security.PrivateKey
import org.json.JSONObject
import java.io.IOException

/**
 * Only libspdecode.so establishes HTTPS connections. Payload and response
 * remain opaque binary ciphertext until they reach the trusted endpoints.
 */
internal object CloudNativeTransport {
    init { System.loadLibrary("spdecode") }

    // All HPKE key agreement, message framing, AEAD and reply authentication
    // execute in libspdecode.so. Kotlin handles only JSON/Android integration.
    @JvmStatic private external fun nativePrepareHpke(
        operation: Int, metadata: ByteArray, attachment: ByteArray?
    ): ByteArray
    @JvmStatic private external fun nativeOpenHpke(
        handle: Long, status: Int, wire: ByteArray, response: ByteArray
    ): ByteArray
    @JvmStatic private external fun nativeDiscardHpke(handle: Long)

    fun prepareHpke(operation: Int, metadata: ByteArray, attachment: ByteArray?): ByteArray =
        nativePrepareHpke(operation, metadata, attachment)
    fun openHpke(handle: Long, status: Int, wire: ByteArray, response: ByteArray): ByteArray =
        nativeOpenHpke(handle, status, wire, response)
    fun discardHpke(handle: Long) = nativeDiscardHpke(handle)

    // Native RAM-only session cache; temporary bearer copies still cross JNI.
    @JvmStatic private external fun nativeCacheSession(token: String, seconds: Long, actionRequired: Boolean)
    @JvmStatic private external fun nativeGetSession(): String
    @JvmStatic private external fun nativeRequiresActionIntegrity(): Boolean
    @JvmStatic private external fun nativeClearSession()
    @JvmStatic private external fun nativeInvalidateSession(token: String)
    fun cacheSession(token: String, seconds: Long, actionRequired: Boolean) =
        nativeCacheSession(token, seconds, actionRequired)
    fun cachedSession(): String = nativeGetSession()
    fun actionIntegrityRequired(): Boolean = nativeRequiresActionIntegrity()
    fun clearCachedSession() = nativeClearSession()
    private fun invalidateCachedSession(token: String) = nativeInvalidateSession(token)

    @JvmStatic private external fun nativeSignHardware(key: PrivateKey, message: ByteArray): ByteArray
    @JvmStatic private external fun nativeAliasSuffix(): String
    fun signWithKeystore(key: PrivateKey, message: ByteArray): ByteArray =
        nativeSignHardware(key, message)
    fun hardwareAliasSuffix(): String = nativeAliasSuffix()

    @JvmStatic private external fun nativeVerifyReleaseSigner(
        context: Context, expectedPackage: String, uploadCert: String, playCert: String, debugBuild: Boolean
    ): Boolean
    fun verifyReleaseSigner(context: Context, expectedPackage: String,
                            uploadCert: String, playCert: String, debugBuild: Boolean): Boolean =
        nativeVerifyReleaseSigner(context, expectedPackage, uploadCert, playCert, debugBuild)

    @JvmStatic private external fun nativePlayNonce(
        nonce: String, challengeId: String, publicKey: String
    ): String
    @JvmStatic private external fun nativeValidClassicChallenge(
        nonce: String, challengeId: String, apiVersion: String
    ): Boolean
    @JvmStatic private external fun nativeValidActionChallenge(
        requestHash: String, challengeId: String, cloudProjectNumber: Long
    ): Boolean
    @JvmStatic private external fun nativeValidPlayNonce(nonce: String): Boolean
    fun validClassicChallenge(nonce: String, challengeId: String, apiVersion: String): Boolean =
        nativeValidClassicChallenge(nonce, challengeId, apiVersion)
    fun validActionChallenge(requestHash: String, challengeId: String, project: Long): Boolean =
        nativeValidActionChallenge(requestHash, challengeId, project)
    fun validPlayNonce(nonce: String): Boolean = nativeValidPlayNonce(nonce)
    @JvmStatic private external fun nativePrepareProof(
        operation: Int, version: String, wire: ByteArray, bearer: String
    ): Array<String>
    @JvmStatic private external fun nativeFormatProof(
        operation: Int, version: String, wire: ByteArray, bearer: String,
        timestamp: String, nonce: String
    ): String
    @JvmStatic private external fun nativeHashWire(wire: ByteArray): String

    fun playIntegrityNonce(nonce: String, challengeId: String, publicKey: String): String =
        nativePlayNonce(nonce, challengeId, publicKey)
    fun prepareRequestProof(operation: Int, version: String, wire: ByteArray, bearer: String): Array<String> =
        nativePrepareProof(operation, version, wire, bearer)
    fun formatRequestProof(operation: Int, version: String, wire: ByteArray, bearer: String,
                           timestamp: String, nonce: String): String =
        nativeFormatProof(operation, version, wire, bearer, timestamp, nonce)
    fun requestHashHex(wire: ByteArray): String = nativeHashWire(wire)

    @JvmStatic private external fun postNativeEncrypted(
        operation: Int,
        wire: ByteArray,
        bearer: String,
        clientVersion: String,
        timestamp: String,
        nonce: String,
        proof: String,
        actionChallenge: String,
        actionIntegrity: String,
    ): ByteArray

    data class Reply(val status: Int, val body: JSONObject)
    fun prepare(operation:Int,payload:JSONObject,attachment:ByteArray?=null):V2HpkeEnvelope.Prepared {
        require(BuildConfig.SPDECODE_CLOUD_ENABLED) { "CLOUD_DISABLED" }
        require(operation in 1..17 && operation!=3) { "CLOUD_ROUTE_DENIED" }
        return V2HpkeEnvelope.prepare(operation,payload,attachment)
    }

    fun post(operation: Int, payload: JSONObject, bearer: String = "",
             actionChallenge: String = "", actionIntegrity: String = "",
             attachment:ByteArray?=null,
             prepared:V2HpkeEnvelope.Prepared?=null): Reply {
        val encrypted=prepared?:prepare(operation,payload,attachment)
        try {
            // Request proof covers exactly the bytes passed to native HTTPS.
            val proof=CloudRequestProof.signBytes(operation,BuildConfig.VERSION_NAME,encrypted.wire,bearer)
            val returned=postNativeEncrypted(operation,encrypted.wire,bearer,BuildConfig.VERSION_NAME,
                proof.timestamp,proof.nonce,proof.signature,actionChallenge,actionIntegrity)
            val newline=returned.indexOf('\n'.code.toByte())
            if(newline !in 3..4)throw IOException("CLOUD_INVALID_HTTP_ENVELOPE")
            val status=String(returned,0,newline,Charsets.US_ASCII).toIntOrNull()
                ?:throw IOException("CLOUD_INVALID_HTTP_STATUS")
            if(status !in 100..599)throw IOException("CLOUD_INVALID_HTTP_STATUS")
            val body=returned.copyOfRange(newline+1,returned.size)
            if(body.size>=4 && body.copyOfRange(0,4).contentEquals("SPR2".toByteArray(Charsets.US_ASCII))) {
                val opened=encrypted.open(status,body)
                if(status==401) invalidateCachedSession(bearer)
                return Reply(status,opened)
            }
            // The edge can reject a request before HPKE authentication. No plaintext
            // SUCCESS, tokens, decoded results, or application data are accepted.
            if(status in 200..299)throw IOException("CLOUD_HPKE_REPLY_REQUIRED")
            val code=try {
                JSONObject(String(body,Charsets.UTF_8)).optJSONObject("error")
                    ?.optString("code").orEmpty().takeIf {it.matches(Regex("[A-Z_]{3,50}"))}
            }catch(_:Exception){null}
            if(status==401) invalidateCachedSession(bearer)
            return Reply(status,JSONObject().put("error",JSONObject()
                .put("code",code?:"SERVICE_UNAVAILABLE")))
        }finally {encrypted.discard()}
    }
}
