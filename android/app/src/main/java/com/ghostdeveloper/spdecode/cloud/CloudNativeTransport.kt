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
        endpoint: String,
        json: String,
        bearer: String,
    ): String

    data class Reply(val status: Int, val body: JSONObject)

    fun post(endpoint: String, payload: JSONObject, bearer: String = ""): Reply {
        require(BuildConfig.SPDECODE_CLOUD_ENABLED) { "CLOUD_DISABLED" }
        // Fixed route allowlist; do not let the UI provide a full URL.
        require(endpoint in setOf(
            "/api/v1/session/challenge", "/api/v1/session",
            "/api/v1/session/qa",
            "/api/v1/decode/file", "/api/v1/decode/text",
            "/api/v1/decode/import/cloud",
            "/api/v1/decode/import/catalog/remote",
            "/api/v1/server-vpn/catalog", "/api/v1/server-vpn/icon",
            "/api/v1/server-vpn/decode", "/api/v1/server-vpn/watch", "/api/v1/telemetry",
        )) { "CLOUD_ROUTE_DENIED" }
        val returned = postNative(
            endpoint, payload.toString(), bearer
        )
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
