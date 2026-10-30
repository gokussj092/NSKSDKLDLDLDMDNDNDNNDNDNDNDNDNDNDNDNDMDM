package com.ghostdeveloper.spdecode.cloud

import com.ghostdeveloper.spdecode.BuildConfig
import org.json.JSONObject
import java.io.IOException

/**
 * Only JNI C++ issues the HTTPS requests. Kotlin never handles network sockets,
 * backend signing or provider secrets. No decoder is implemented in this client.
 */
internal object CloudNativeTransport {
    init { System.loadLibrary("spdecode") }

    @JvmStatic private external fun postNative(
        operation: Int,
        body: ByteArray,
        bearer: String,
        clientVersion: String,
        timestamp: String,
        nonce: String,
        proof: String,
        actionChallenge: String,
        actionIntegrity: String,
    ): ByteArray

    data class Reply(val status: Int, val body: JSONObject)

    fun post(operation: Int, payload: JSONObject, bearer: String = "",
             actionChallenge: String = "", actionIntegrity: String = ""): Reply {
        require(BuildConfig.SPDECODE_CLOUD_ENABLED) { "CLOUD_DISABLED" }
        require(operation in 1..17 && operation != 3) { "CLOUD_ROUTE_DENIED" }
        val plaintext=payload.toString().toByteArray(Charsets.UTF_8)
        val version=BuildConfig.VERSION_NAME
        // Operation 1 is a public bootstrap challenge. Everything else in
        // V2 must be sealed and an unknown recipient key is a hard failure.
        val timestamp=(System.currentTimeMillis()/1000).toString()
        val nonce=android.util.Base64.encodeToString(ByteArray(24).also {
            java.security.SecureRandom().nextBytes(it)
        },android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
        val exchange=if(operation==CloudOperation.CHALLENGE) null else
            CloudV2Hpke.seal(operation,version,timestamp,nonce,bearer,plaintext)
        val wire=exchange?.first?:plaintext
        val proof=CloudRequestProof.signBytesWithMetadata(operation,version,wire,bearer,timestamp,nonce)
        val returned=postNative(operation,wire,bearer,version,
            proof.timestamp,proof.nonce,proof.signature,actionChallenge,actionIntegrity)
        val newline=returned.indexOf(10.toByte())
        if(newline !in 3..4)throw IOException("CLOUD_INVALID_HTTP_ENVELOPE")
        val status=String(returned,0,newline,Charsets.US_ASCII).toIntOrNull()
            ?:throw IOException("CLOUD_INVALID_HTTP_STATUS")
        if(status !in 100..599)throw IOException("CLOUD_INVALID_HTTP_STATUS")
        val bytes=returned.copyOfRange(newline+1,returned.size)
        val clear=if(operation==CloudOperation.CHALLENGE)bytes
            else exchange!!.second.openReply(status,bytes)
        val document=try {JSONObject(String(clear,Charsets.UTF_8))}
            catch(_:Exception){throw IOException("CLOUD_INVALID_JSON")}
        return Reply(status,document)
    }
}

