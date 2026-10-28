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
        json: String,
        bearer: String,
        clientVersion: String,
        timestamp: String,
        nonce: String,
        proof: String,
        actionChallenge: String,
        actionIntegrity: String,
    ): String

    data class Reply(val status: Int, val body: JSONObject)

    fun post(operation: Int, payload: JSONObject, bearer: String = "",
             actionChallenge: String = "", actionIntegrity: String = ""): Reply {
        require(BuildConfig.SPDECODE_CLOUD_ENABLED) { "CLOUD_DISABLED" }
        require(operation in 1..16 && operation != 3) { "CLOUD_ROUTE_DENIED" }
        val json = payload.toString()
        val proof = CloudRequestProof.sign(operation, BuildConfig.VERSION_NAME, json, bearer)
        val returned = postNative(operation, json, bearer, BuildConfig.VERSION_NAME,
            proof.timestamp, proof.nonce, proof.signature, actionChallenge, actionIntegrity)
        val newline = returned.indexOf('\n')
        if (newline !in 3..4) throw IOException("CLOUD_INVALID_HTTP_ENVELOPE")
        val status = returned.substring(0, newline).toIntOrNull()
            ?: throw IOException("CLOUD_INVALID_HTTP_STATUS")
        if (status !in 100..599) throw IOException("CLOUD_INVALID_HTTP_STATUS")
        val document = try { JSONObject(returned.substring(newline + 1)) }
            catch (_: Exception) { throw IOException("CLOUD_INVALID_JSON") }
        return Reply(status, document)
    }
}

