package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import android.util.Base64
import com.ghostdeveloper.spdecode.BuildConfig
import com.ghostdeveloper.spdecode.parity.HcHccfgPort
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.json.JSONObject
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.coroutineContext
import java.io.IOException

/**
 * C4 composition adapter only. HTTPS I/O runs inside libspdecode.so.
 * Play Integrity's official Android SDK provides the classic nonce verdict.
 * Secrets of the actual decoders are NEVER compiled into this client.
 */
internal class CloudDecodeClient(context: Context) {
    private val app = context.applicationContext
    private var token = ""
    private var expiresAtMs = 0L
    private val lock = Any()
    private val integrityManager by lazy { IntegrityManagerFactory.create(app) }

    data class Decoded(val rawText: String, val sourceBytes: Int? = null)

    class Failure(val code: String, val httpStatus: Int) :
        IOException("SP-DECODE CLOUD: $code")

    companion object {
        const val MAX_INPUT = 8 * 1024 * 1024
        private const val SAFE_TOKEN_MARGIN_MS = 30_000L
    }

    private fun extract(reply: CloudNativeTransport.Reply): JSONObject {
        if (reply.status !in 200..299) {
            val code = reply.body.optJSONObject("error")?.optString("code")
                ?.takeIf { it.matches(Regex("[A-Z_]{3,50}")) } ?: "SERVICE_UNAVAILABLE"
            throw Failure(code, reply.status)
        }
        return reply.body
    }

    private suspend fun requestIntegrityToken(nonce: String): String =
        suspendCancellableCoroutine { cont ->
            if (nonce.length !in 16..500 || !nonce.matches(Regex("[A-Za-z0-9_-]+"))) {
                cont.resumeWithException(IOException("CLOUD_INVALID_NONCE"))
                return@suspendCancellableCoroutine
            }
            try {
                integrityManager.requestIntegrityToken(
                    IntegrityTokenRequest.builder().setNonce(nonce).build()
                ).addOnSuccessListener { response ->
                    if (cont.isActive) cont.resume(response.token())
                }.addOnFailureListener {
                    if (cont.isActive) cont.resumeWithException(IOException("CLOUD_INTEGRITY_UNAVAILABLE"))
                }
            } catch (_: Exception) {
                if (cont.isActive) cont.resumeWithException(IOException("CLOUD_INTEGRITY_UNAVAILABLE"))
            }
        }

    private suspend fun session(): String {
        synchronized(lock) {
            if (token.isNotBlank() && System.currentTimeMillis() + SAFE_TOKEN_MARGIN_MS < expiresAtMs)
                return token
        }
        // No fallback to local decryptors when attestation or networking fails.
        val challenge = withContext(Dispatchers.IO) {
            extract(CloudNativeTransport.post("/api/v1/session/challenge", JSONObject()))
        }
        val nonce = challenge.getString("nonce")
        val challengeId = challenge.getString("challengeId")
        coroutineContext.ensureActive()
        val code=if(BuildConfig.SPDECODE_QA_BUILD)CloudQaMemory.get() else ""
        val (endpoint,body)=if(code.isNotEmpty()) {
            "/api/v1/session/qa" to
                JSONObject().put("challengeId",challengeId).put("qaCode",code)
        } else {
            val verdict=requestIntegrityToken(nonce)
            coroutineContext.ensureActive()
            "/api/v1/session" to
                JSONObject().put("challengeId",challengeId).put("integrityToken",verdict)
        }
        val reply=withContext(Dispatchers.IO) {
            extract(CloudNativeTransport.post(endpoint,body))
        }
        val access = reply.getString("accessToken")
        val seconds = reply.getLong("expiresIn")
        if (!access.matches(Regex("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")) ||
            seconds !in 1L..300L) throw IOException("CLOUD_INVALID_SESSION")
        synchronized(lock) {
            token = access
            expiresAtMs = System.currentTimeMillis() + seconds * 1000
        }
        return access
    }

    private suspend fun decode(endpoint: String, payload: JSONObject): Decoded {
        require(BuildConfig.SPDECODE_CLOUD_ENABLED) { "CLOUD_DISABLED" }
        coroutineContext.ensureActive()
        val bearer = session()
        coroutineContext.ensureActive()
        val response = withContext(Dispatchers.IO) {
            extract(CloudNativeTransport.post(endpoint,payload,bearer))
        }
        coroutineContext.ensureActive()
        if (response.optString("status") != "success" || response.optBoolean("isPartial",true))
            throw IOException("CLOUD_PARTIAL_RESULT_REJECTED")
        if (!response.has("rawText") || response.isNull("rawText"))
            throw IOException("CLOUD_MISSING_RESULT")
        val text = response.getString("rawText")
        if (text.isBlank()) throw IOException("CLOUD_EMPTY_RESULT")
        if (text.length > 4 * 1024 * 1024) throw IOException("CLOUD_RESULT_TOO_LARGE")
        return Decoded(text,response.optInt("sourceBytes",0).takeIf { it > 0 })
    }

    /**
     * Server-side requirement probe: never decrypt HCCFG headers locally.
     * Existing password/HWID dialog is opened only when the real Cloud worker
     * returns a sanitized lock requirement; no result is stored for this probe.
     */
    suspend fun inspectHcRequirements(bytes:ByteArray):HcHccfgPort.Requirements? =
        try {
            decodeFile("hc",bytes)
            null
        }catch(failure:Failure) {
            val flags=when(failure.code) {
                "PASSWORD_REQUIRED"->true to false
                "HWID_REQUIRED"->false to true
                "HWID_PASSWORD_REQUIRED"->true to true
                else->throw failure
            }
            HcHccfgPort.Requirements(
                passwordRequired=flags.first,
                hwidRequired=flags.second,
                headerAuthenticated=false,
                schema=0,
                schedule="cloud",
            )
        }

    suspend fun decodeFile(format: String, bytes: ByteArray,
                           password: ByteArray? = null, hwid: String? = null): String {
        if (bytes.isEmpty() || bytes.size > MAX_INPUT) throw IOException("CLOUD_INVALID_INPUT")
        if (format.isBlank() || (!format.matches(Regex("[a-z0-9._-]{1,64}")) && format != "fɴ"))
            throw IOException("CLOUD_INVALID_FORMAT")
        if ((password != null || hwid != null) && format != "hc")
            throw IOException("CLOUD_CREDENTIALS_NOT_ALLOWED")
        val body = JSONObject()
            .put("format", format)
            .put("dataBase64", Base64.encodeToString(bytes, Base64.NO_WRAP))
        if (password != null || hwid != null) {
            val credentials = JSONObject()
            if (password != null) credentials.put("password", String(password,Charsets.UTF_8))
            if (hwid != null) credentials.put("hwid",hwid)
            body.put("credentials",credentials)
        }
        return decode("/api/v1/decode/file",body).rawText
    }

    suspend fun decodeText(text: String): String =
        decode("/api/v1/decode/text",JSONObject().put("text",text)).rawText

    suspend fun decodeHttpInjectorCloud(reference: String): String =
        decode("/api/v1/decode/import/cloud",
            JSONObject().put("reference",reference).put("consent",true)).rawText

    suspend fun decodeNurCatalog(): Decoded =
        decode("/api/v1/decode/import/catalog/remote",JSONObject().put("consent",true))

    /** Public presentation metadata only; never contains provider endpoints. */
    suspend fun serverVpnCatalog(knownVersion:Int): JSONObject =
        withContext(Dispatchers.IO) {
            extract(CloudNativeTransport.post("/api/v1/server-vpn/catalog",
                JSONObject().put("knownVersion",knownVersion)))
        }

    suspend fun decodeServerVpnProvider(id:String): Decoded {
        require(id.matches(Regex("[a-z0-9-]{1,48}")))
        return decode("/api/v1/server-vpn/decode",
            JSONObject().put("id",id).put("consent",true))
    }

    suspend fun serverVpnIcon(id:String): JSONObject {
        require(id.matches(Regex("[a-z0-9-]{1,48}")))
        return withContext(Dispatchers.IO) {
            extract(CloudNativeTransport.post("/api/v1/server-vpn/icon",
                JSONObject().put("id",id)))
        }
    }

}
