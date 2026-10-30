package com.ghostdeveloper.spdecode.cloud

import com.ghostdeveloper.spdecode.BuildConfig
import org.json.JSONObject
import java.io.IOException

/**
 * Only libspdecode.so establishes HTTPS connections. Payload and response
 * remain opaque binary ciphertext until they reach the trusted endpoints.
 */
internal object CloudNativeTransport {
    init { System.loadLibrary("spdecode") }

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
            if(body.size>=4 && body.copyOfRange(0,4).contentEquals("SPR2".toByteArray(Charsets.US_ASCII)))
                return Reply(status,encrypted.open(status,body))
            // The edge can reject a request before HPKE authentication. No plaintext
            // SUCCESS, tokens, decoded results, or application data are accepted.
            if(status in 200..299)throw IOException("CLOUD_HPKE_REPLY_REQUIRED")
            val code=try {
                JSONObject(String(body,Charsets.UTF_8)).optJSONObject("error")
                    ?.optString("code").orEmpty().takeIf {it.matches(Regex("[A-Z_]{3,50}"))}
            }catch(_:Exception){null}
            return Reply(status,JSONObject().put("error",JSONObject()
                .put("code",code?:"SERVICE_UNAVAILABLE")))
        }finally {encrypted.discard()}
    }
}
