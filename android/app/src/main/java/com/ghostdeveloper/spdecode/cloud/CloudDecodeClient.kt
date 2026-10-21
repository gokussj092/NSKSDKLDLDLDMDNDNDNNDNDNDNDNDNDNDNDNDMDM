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

    /** Client-side defense-in-depth; server sessions still require Play Integrity. */
    private fun requireLegalConsent() {
        if(!CloudLegalConsent.accepted(app)) throw Failure("LEGAL_CONSENT_REQUIRED",403)
    }

    data class Diagnostic(val service:String,val format:String,val code:String)
    @Volatile var lastDiagnostic:Diagnostic?=null
        private set
    fun clearLastDiagnostic(){lastDiagnostic=null}

    data class Decoded(val rawText: String, val sourceBytes: Int? = null)

    class Failure(val code: String, val httpStatus: Int) :
        IOException("SP-DECODE CLOUD: $code")

    fun clearSession() {
        synchronized(lock) {
            token=""
            expiresAtMs=0L
        }
    }

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
        // The server decides; the client cannot override enforcement.
        val integrityRequired=challenge.optBoolean("integrityRequired",true)
        val challengeId = challenge.getString("challengeId")
        coroutineContext.ensureActive()
        val code=if(BuildConfig.SPDECODE_QA_BUILD)CloudQaMemory.get() else ""
        // Private QA must never silently attempt Play Integrity after the
        // volatile test code is lost (e.g., Android killed the process).
        if(BuildConfig.SPDECODE_QA_BUILD && code.isEmpty())
            throw IOException("CLOUD_QA_CODE_REQUIRED")
        val (endpoint,body)=if(code.isNotEmpty()) {
            "/api/v1/session/qa" to
                JSONObject().put("challengeId",challengeId).put("qaCode",code)
        } else if(integrityRequired) {
            val verdict=requestIntegrityToken(nonce)
            coroutineContext.ensureActive()
            "/api/v1/session" to
                JSONObject().put("challengeId",challengeId).put("integrityToken",verdict)
        } else {
            // Strictly short-lived operator-approved beta; no integrity token is forged.
            "/api/v1/session" to JSONObject().put("challengeId",challengeId)
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

    /**
     * MKK aggregates four independent sources. A complete RESPONSE can carry
     * explicit source failures. Permit only this documented partial shape;
     * never accept arbitrary incomplete file/NUR/EHI results.
     */
    private fun allowsMkkHyperPartial(
        endpoint:String,payload:JSONObject,response:JSONObject
    ):Boolean {
        if(endpoint!="/api/v1/server-vpn/decode" ||
            payload.optString("id")!="mkk-hyper" ||
            response.optString("kind")!="vpn_catalog" ||
            response.optString("providerId")!="mkk-hyper")return false
        val report=response.optJSONObject("structuredJson")?:return false
        if(report.optString("provider")!="mkk-hyper" ||
            report.optBoolean("complete",true) ||
            report.optInt("sourceCount",-1)!=4)return false
        val warnings=response.optJSONArray("warnings")?:return false
        if((0 until warnings.length()).none {
                warnings.optString(it)=="PARTIAL_SOURCE_FAILURE"
            })return false
        val sources=report.optJSONArray("sources")?:return false
        val expected=listOf("servers","static","subscriptions","legacy-subscriptions")
        if(sources.length()!=expected.size)return false
        var succeeded=0
        var failed=0
        for(i in expected.indices){
            val source=sources.optJSONObject(i)?:return false
            if(source.optString("name")!=expected[i])return false
            when(source.optString("status")){
                "ok"->succeeded++
                "error"->failed++
                else->return false
            }
        }
        return succeeded>0 && failed>0 && succeeded==report.optInt("successfulSources",-1)
    }

    private suspend fun decode(endpoint: String, payload: JSONObject): Decoded {
        require(BuildConfig.SPDECODE_CLOUD_ENABLED) { "CLOUD_DISABLED" }
        withContext(Dispatchers.IO) { requireLegalConsent() }
        coroutineContext.ensureActive()
        lastDiagnostic=null
        val bearer = session()
        coroutineContext.ensureActive()
        val response = try {
            withContext(Dispatchers.IO) {
                // Never store request payloads or credentials in a diagnostic.
                requireLegalConsent()
                extract(CloudNativeTransport.post(endpoint,payload,bearer))
            }
        }catch(failure:Failure) {
            // Only whitelisted enum-like codes and known format labels are retained in RAM.
            if(failure.httpStatus>=400 && failure.code.matches(Regex("[A-Z][A-Z0-9_]{2,49}"))) {
                val service=when(endpoint){
                    "/api/v1/decode/import/cloud"->"httpInjector"
                    "/api/v1/server-vpn/decode","/api/v1/decode/import/catalog/remote"->"serverVpn"
                    else->"files"
                }
                val raw=when(service){
                    "httpInjector"->"ehi"
                    "serverVpn"->payload.optString("id","nur-catalog")
                    else->payload.optString("format",if(endpoint.endsWith("/text"))"text" else "other")
                }
                val safe=raw.takeIf{it.matches(Regex("[a-z0-9][a-z0-9._-]{0,31}"))}?:"other"
                lastDiagnostic=Diagnostic(service,safe,failure.code)
            }
            throw failure
        }
        coroutineContext.ensureActive()
        if (response.optString("status") != "success" ||
            (response.optBoolean("isPartial",true) &&
             !allowsMkkHyperPartial(endpoint,payload,response)))
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

    /** Public What's New. No auth, device identifiers or decoded payloads. */
    suspend fun whatsNew(knownVersion:Int,locale:String):JSONObject = withContext(Dispatchers.IO) {
        requireLegalConsent()
        require(knownVersion in 0..999999999)
        require(locale.matches(Regex("[A-Za-z-]{2,16}")))
        extract(CloudNativeTransport.post("/api/v1/whats-new",
            JSONObject().put("knownVersion",knownVersion).put("locale",locale)))
    }

    /** Public presentation metadata only; never contains provider endpoints. */
    suspend fun serverVpnCatalog(knownVersion:Int): JSONObject =
        withContext(Dispatchers.IO) {
            requireLegalConsent()
            extract(CloudNativeTransport.post("/api/v1/server-vpn/catalog",
                JSONObject().put("knownVersion",knownVersion)))
        }

    /** Only the VPS version number is returned; no provider URLs or decoded files. */
    suspend fun watchCatalogVersion(knownVersion:Int):Int = withContext(Dispatchers.IO) {
        requireLegalConsent()
        require(knownVersion in 0..999999999)
        val reply=extract(CloudNativeTransport.post("/api/v1/server-vpn/watch",
            JSONObject().put("knownVersion",knownVersion)))
        val version=reply.optInt("catalogVersion",0)
        if(version !in 1..999999999)throw IOException("CLOUD_INVALID_CATALOG_VERSION")
        version
    }

    suspend fun decodeServerVpnProvider(id:String): Decoded {
        require(id.matches(Regex("[a-z0-9-]{1,48}")))
        return decode("/api/v1/server-vpn/decode",
            JSONObject().put("id",id).put("consent",true))
    }

    suspend fun serverVpnIcon(id:String): JSONObject {
        require(id.matches(Regex("[a-z0-9-]{1,48}")))
        return withContext(Dispatchers.IO) {
            requireLegalConsent()
            extract(CloudNativeTransport.post("/api/v1/server-vpn/icon",
                JSONObject().put("id",id)))
        }
    }

    /** Explicit user action only: never uploads the source file or a free-text note. */
    suspend fun reportFailure(details:Diagnostic):String {
        requireLegalConsent()
        val data=JSONObject().put("type","report")
            .put("service",details.service).put("format",details.format)
            .put("code",details.code).put("appVersion",BuildConfig.VERSION_NAME)
        val response=withContext(Dispatchers.IO){
            extract(CloudNativeTransport.post("/api/v1/telemetry",data,session()))
        }
        val id=response.optString("reportId")
        if(!id.matches(Regex("[0-9a-f-]{36}")))throw IOException("CLOUD_REPORT_RESPONSE_INVALID")
        return id
    }

    /** Optional count of installations; random ID created only after user opts in. */
    suspend fun registerOptInActivity(installationId:String) {
        requireLegalConsent()
        require(installationId.matches(Regex("[0-9a-f]{32}")))
        val data=JSONObject().put("type","activity")
            .put("installationId",installationId).put("consent",true)
        withContext(Dispatchers.IO){
            extract(CloudNativeTransport.post("/api/v1/telemetry",data,session()))
        }
    }

}
