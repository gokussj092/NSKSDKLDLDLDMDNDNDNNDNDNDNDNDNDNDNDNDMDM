package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import android.util.Base64
import com.ghostdeveloper.spdecode.BuildConfig
import com.ghostdeveloper.spdecode.ReleaseIntegrity
import com.ghostdeveloper.spdecode.parity.HcHccfgPort
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.android.gms.tasks.Task
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
    private val sessionMutex = CloudRequestProof.enrollmentMutex
    @Volatile private var exportCatalog:CompatibleExportCatalog?=null
    @Volatile private var exportCatalogCheckedAt:Long=0
    private val standardLock = Mutex()
    private var standardProject = 0L
    private var standardProvider: StandardIntegrityManager.StandardIntegrityTokenProvider? = null
    private val standardManager by lazy { IntegrityManagerFactory.createStandard(app) }
    private val integrityManager by lazy { IntegrityManagerFactory.create(app) }

    /** Client-side defense-in-depth; server sessions still require Play Integrity. */
    private fun requireLegalConsent() {
        if(!ReleaseIntegrity.isTrusted(app)) throw Failure("INTEGRITY_REJECTED",403)
        if(!CloudLegalConsent.accepted(app)) throw Failure("LEGAL_CONSENT_REQUIRED",403)
    }

    data class Diagnostic(val service:String,val format:String,val code:String)
    @Volatile var lastDiagnostic:Diagnostic?=null
        private set
    fun clearLastDiagnostic(){lastDiagnostic=null}

    data class Decoded(val rawText: String, val sourceBytes: Int? = null, val compatibleExport:JSONObject?=null)

    class Failure(val code: String, val httpStatus: Int,
        val passwordSubmitted:Boolean=false,val hwidSubmitted:Boolean=false) :
        IOException("SP-DECODE CLOUD: $code")

    fun clearSession() {
        synchronized(lock) {
            token=""
            expiresAtMs=0L
        }
    }

    companion object {
        // All foreground/background clients use the same device key and short-lived session.
        // Sharing avoids repeated Classic Integrity admissions for concurrent workers.
        private var token = ""
        private var expiresAtMs = 0L
        private val lock = Any()
        @Volatile private var actionIntegrityRequired = true
        const val MAX_INPUT = 8 * 1024 * 1024
        private const val SAFE_TOKEN_MARGIN_MS = 30_000L
    }

    private fun extract(reply: CloudNativeTransport.Reply): JSONObject {
        if (reply.status == 401) clearSession()
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

    private suspend fun session(): String = sessionMutex.withLock {
        synchronized(lock) {
            if (token.isNotBlank() && System.currentTimeMillis() + SAFE_TOKEN_MARGIN_MS < expiresAtMs)
                return@withLock token
        }
        // No fallback to local decryptors when attestation or networking fails.
        val challenge = withContext(Dispatchers.IO) {
            extract(CloudNativeTransport.post(CloudOperation.CHALLENGE,
                JSONObject().put("publicKey", CloudRequestProof.publicKey())))
        }
        val nonce = challenge.getString("nonce")
        val challengeId = challenge.getString("challengeId")
        val playRequired = challenge.optBoolean("integrityRequired", true)
        if (!nonce.matches(Regex("[A-Za-z0-9_-]{43}")) ||
            !challengeId.matches(Regex("[0-9a-f-]{36}")) ||
            challenge.optString("apiVersion") != "v2")
            throw IOException("CLOUD_INVALID_NONCE")
        // An external beta may omit Play tokens ONLY when server policy explicitly allows it.
        // Hardware attestation remains mandatory for all beta sessions.
        if (playRequired && BuildConfig.SPDECODE_QA_BUILD)
            throw IOException("CLOUD_INTEGRITY_UNAVAILABLE")
        val certificates = if (challenge.optBoolean("keyAttestationRequired", false)) {
            withContext(Dispatchers.IO) { CloudRequestProof.attest(
                challenge.getString("attestationChallenge"), challenge.getString("hardwareLevel")) }
        } else null
        val verdict = if (playRequired)
            requestIntegrityToken(CloudRequestProof.integrityNonce(nonce, challengeId))
        else ""
        coroutineContext.ensureActive()
        val operation = CloudOperation.SESSION
        val body = JSONObject().put("challengeId",challengeId).put("integrityToken",verdict)
        if (certificates != null) body.put("publicKey", CloudRequestProof.publicKey()).put("certificateChain", certificates)
        val reply=withContext(Dispatchers.IO) {
            extract(CloudNativeTransport.post(operation,body))
        }
        actionIntegrityRequired = reply.optBoolean("actionIntegrityRequired", false)
        val access = reply.getString("accessToken")
        val seconds = reply.getLong("expiresIn")
        if (!access.matches(Regex("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")) ||
            seconds !in 1L..300L) throw IOException("CLOUD_INVALID_SESSION")
        synchronized(lock) {
            token = access
            expiresAtMs = System.currentTimeMillis() + seconds * 1000
        }
        access
    }

    private suspend fun <T> awaitPlay(task: Task<T>): T = suspendCancellableCoroutine { cont ->
        task.addOnSuccessListener { if (cont.isActive) cont.resume(it) }
            .addOnFailureListener { if (cont.isActive) cont.resumeWithException(IOException("CLOUD_INTEGRITY_UNAVAILABLE")) }
    }

    private suspend fun protectedPost(operation: Int, payload: JSONObject, bearer: String,
                                      attachment:ByteArray?=null): CloudNativeTransport.Reply {
        val exact = JSONObject(payload.toString())
        val prepared=CloudNativeTransport.prepare(operation,exact,attachment)
        if (!actionIntegrityRequired) return CloudNativeTransport.post(operation,exact,bearer,prepared=prepared)
        // Standard Integrity is bound to the final encrypted bytes, NOT to a
        // separately serialized plaintext JSON document. The same prepared
        // ciphertext is reused after the challenge; never seal it twice.
        val hash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(prepared.wire).joinToString("") { "%02x".format(it.toInt() and 255) }
        val challenge = extract(CloudNativeTransport.post(CloudOperation.ACTION_CHALLENGE,
            JSONObject().put("operation", operation).put("bodySha256", hash), bearer))
        val project = challenge.getString("cloudProjectNumber").toLongOrNull()
            ?.takeIf { it > 0L } ?: throw IOException("CLOUD_INTEGRITY_UNAVAILABLE")
        val requestHash = challenge.getString("requestHash")
        val id = challenge.getString("challengeId")
        if (!requestHash.matches(Regex("[A-Za-z0-9_-]{43}")) || !id.matches(Regex("[0-9a-f-]{36}")))
            throw IOException("CLOUD_INVALID_NONCE")
        val provider = standardLock.withLock {
            if (standardProvider == null || standardProject != project) {
                standardProvider = withTimeout(60_000L) { awaitPlay(standardManager.prepareIntegrityToken(
                    StandardIntegrityManager.PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(project).build())) }
                standardProject = project
            }
            checkNotNull(standardProvider)
        }
        val integrity = try { withTimeout(30_000L) { awaitPlay(provider.request(
            StandardIntegrityManager.StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build())).token() } }
        catch (error: Exception) {
            standardLock.withLock { standardProvider = null }
            throw error
        }
        coroutineContext.ensureActive()
        return CloudNativeTransport.post(operation, exact, bearer, id, integrity, prepared=prepared)
    }

    /**
     * MKK aggregates four independent sources. A complete RESPONSE can carry
     * explicit source failures. Permit only this documented partial shape;
     * never accept arbitrary incomplete file/NUR/EHI results.
     */
    private fun allowsMkkHyperPartial(
        operation:Int,payload:JSONObject,response:JSONObject
    ):Boolean {
        if(operation!=CloudOperation.DECODE_SERVER ||
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

    private suspend fun decode(operation: Int, payload: JSONObject, attachment:ByteArray?=null): Decoded {
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
                extract(protectedPost(operation,payload,bearer,attachment))
            }
        }catch(failure:Failure) {
            // Only whitelisted enum-like codes and known format labels are retained in RAM.
            if(!CloudCredentialPolicy.expectedCredentialResponse(failure.code) &&
                failure.httpStatus>=400 &&
                failure.code.matches(Regex("[A-Z][A-Z0-9_]{2,49}"))) {
                val service=when(operation){
                    CloudOperation.IMPORT_CLOUD->"httpInjector"
                    CloudOperation.DECODE_SERVER,CloudOperation.IMPORT_CATALOG->"serverVpn"
                    else->"files"
                }
                val raw=when(service){
                    "httpInjector"->"ehi"
                    "serverVpn"->payload.optString("id","nur-catalog")
                    else->payload.optString("format",if(operation == CloudOperation.TEXT)"text" else "other")
                }
                val safe=raw.takeIf{it.matches(Regex("[a-z0-9][a-z0-9._-]{0,31}"))}?:"other"
                lastDiagnostic=Diagnostic(service,safe,failure.code)
            }
            throw failure
        }
        coroutineContext.ensureActive()
        if (response.optString("status") != "success" ||
            (response.optBoolean("isPartial",true) &&
             !allowsMkkHyperPartial(operation,payload,response)))
            throw IOException("CLOUD_PARTIAL_RESULT_REJECTED")
        if (!response.has("rawText") || response.isNull("rawText"))
            throw IOException("CLOUD_MISSING_RESULT")
        val text = response.getString("rawText")
        if (text.isBlank()) throw IOException("CLOUD_EMPTY_RESULT")
        val isMkk=operation==CloudOperation.DECODE_SERVER &&
            payload.optString("id")=="mkk-hyper"
        val maximum=if(isMkk)32*1024*1024 else 4*1024*1024
        if(text.length>maximum || text.toByteArray(Charsets.UTF_8).size>maximum)
            throw IOException("CLOUD_RESULT_TOO_LARGE")
        if(isMkk) {
            // A large MKK result must be a complete JSON document, never an
            // HTML response, truncated result or arbitrary diagnostic string.
            val document=try{JSONObject(text)}
                catch(_:Exception){throw IOException("CLOUD_INVALID_JSON")}
            if(document.optString("provider")!="mkk-hyper" ||
                document.optJSONArray("sources")?.length()!=4 ||
                response.optJSONObject("structuredJson")?.optString("provider")!="mkk-hyper")
                throw IOException("CLOUD_INVALID_JSON")
        }
        return Decoded(text,response.optInt("sourceBytes",0).takeIf { it > 0 },response.optJSONObject("compatibleExport"))
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
                           password: ByteArray? = null, hwid: String? = null,
                           allowPasswordFromCatalog: Boolean = false,
                           onCompatibleExport:((CompatibleExportArtifact?)->Unit)?=null): String {
        if (bytes.isEmpty() || bytes.size > MAX_INPUT) throw IOException("CLOUD_INVALID_INPUT")
        // Match the validated Unicode suffix contract, not a frozen ASCII list.
        // The server still decides whether a decoder for the suffix exists.
        if (format.isBlank() || !format.matches(Regex("[\\p{L}\\p{N}._-]{1,64}")))
            throw IOException("CLOUD_INVALID_FORMAT")
        // Future password-capable engines may be announced by a validated remote
        // format snapshot. The worker independently enforces its own allowlist.
        if ((password != null && (!(CloudCredentialPolicy.fileAcceptsPassword(format) ||
                allowPasswordFromCatalog) || password.isEmpty() || password.size>4096)) ||
            (hwid != null && format != "hc"))
            throw IOException("CLOUD_CREDENTIALS_NOT_ALLOWED")
        val body = JSONObject()
            .put("format", format)
        val isRecipientNpvs=format=="npvs" &&
            NpvsRecipientProbe.fingerprints(bytes).isNotEmpty()
        // The signed NPVS recipient envelope is mutually exclusive with
        // passphrase protection. Never silently overwrite recipientKey.
        if(isRecipientNpvs && (password!=null || hwid!=null))
            throw IOException("CLOUD_CREDENTIALS_NOT_ALLOWED")
        val recipient=if(isRecipientNpvs) NpvsRecipientPicker.choose(app,bytes) else null
        val credentials=JSONObject()
        if(recipient!=null)credentials.put("recipientKey",recipient)
        if(password!=null)credentials.put("password",String(password,Charsets.UTF_8))
        if(hwid!=null)credentials.put("hwid",hwid)
        if(credentials.length()>0)body.put("credentials",credentials)
        if(onCompatibleExport!=null && format in CompatibleExportArtifact.targets) {
            val now=android.os.SystemClock.elapsedRealtime()
            if(exportCatalogCheckedAt==0L||now-exportCatalogCheckedAt>15*60_000L) {
                try {serverVpnCatalog(0)}
                catch(e:CancellationException){throw e}
                catch(_:Exception){exportCatalog=null;exportCatalogCheckedAt=now}
            }
            if(exportCatalog?.suffixes?.contains(format)==true) {
                val locale=app.resources.configuration.locales[0].language
                body.put("compatibleExport",JSONObject().put("profile",CompatibleExportArtifact.PROFILE)
                    .put("language",if(locale=="es")"es" else "en"))
            }
        }
        val decoded=decode(CloudOperation.FILE,body,bytes)
        val artifact=if(onCompatibleExport!=null)runCatching {
            CompatibleExportArtifact.parse(decoded.compatibleExport,format,decoded.rawText,
                CompatibleExportArtifact.digest(bytes))
        }.getOrNull() else null
        onCompatibleExport?.invoke(artifact)
        return decoded.rawText
    }

    suspend fun generateNpvsIdentity():JSONObject {
        require(BuildConfig.SPDECODE_CLOUD_ENABLED)
        requireLegalConsent()
        val bearer=session()
        val result=withContext(Dispatchers.IO){
            requireLegalConsent()
            extract(protectedPost(CloudOperation.IDENTITY,
                JSONObject().put("consent",true),bearer)).getJSONObject("identity")
        }
        NpvsIdentityVault.validate(result)
        require(result.optString("source")=="generated" && result.optString("kind")=="keypair")
        return result
    }

    suspend fun decodeText(text: String, password: ByteArray? = null): String {
        if(HttpCustomCloudReference.matches(text)) {
            if(password!=null)throw IOException("CLOUD_CREDENTIALS_NOT_ALLOWED")
            return HttpCustomOnlineFlow.run(
                download={downloadHttpCustom(text)},
                decode={bytes,pw,id->decodeFile("hc",bytes,pw,id)},
                prompt={pw,id->HttpCustomCloudPrompt.ask(pw,id)},
            )
        }
        if(password != null && (!CloudCredentialPolicy.textAcceptsPassword(text) ||
                password.isEmpty() || password.size > 4096))
            throw IOException("CLOUD_CREDENTIALS_NOT_ALLOWED")
        val body=JSONObject().put("text",text)
        if(password!=null)body.put("credentials",
            JSONObject().put("password",String(password,Charsets.UTF_8)))
        return decode(CloudOperation.TEXT,body).rawText
    }

    private suspend fun downloadHttpCustom(reference:String):ByteArray {
        lastDiagnostic=null
        require(BuildConfig.SPDECODE_CLOUD_ENABLED)
        requireLegalConsent()
        val bearer=session()
        val reply=withContext(Dispatchers.IO){
            requireLegalConsent()
            extract(protectedPost(CloudOperation.IMPORT_HTTP_CUSTOM,
                JSONObject().put("reference",reference.trim()).put("consent",true),bearer))
        }
        coroutineContext.ensureActive()
        if(reply.optString("status")!="success" || reply.optString("kind")!="encrypted_file" ||
            reply.optString("format")!="hc")throw IOException("CLOUD_INVALID_JSON")
        val encoded=reply.getString("dataBase64")
        if(encoded.isEmpty() || encoded.length>4*((MAX_INPUT+2)/3) ||
            encoded.length%4!=0 || !encoded.matches(Regex("[A-Za-z0-9+/]+={0,2}")))
            throw IOException("CLOUD_INVALID_INPUT")
        val bytes=try{Base64.decode(encoded,Base64.NO_WRAP)}
            catch(_:IllegalArgumentException){throw IOException("CLOUD_INVALID_INPUT")}
        if(bytes.isEmpty() || bytes.size>MAX_INPUT || reply.optInt("sourceBytes")!=bytes.size ||
            Base64.encodeToString(bytes,Base64.NO_WRAP)!=encoded){
            bytes.fill(0);throw IOException("CLOUD_INVALID_INPUT")
        }
        return bytes
    }

    suspend fun decodeHttpInjectorCloud(reference: String): String =
        decode(CloudOperation.IMPORT_CLOUD,
            JSONObject().put("reference",reference).put("consent",true)).rawText

    suspend fun decodeNurCatalog(): Decoded =
        decode(CloudOperation.IMPORT_CATALOG,JSONObject().put("consent",true))

    /** Release notes use the authenticated V2 transport. */
    suspend fun whatsNew(knownVersion:Int,locale:String):JSONObject = withContext(Dispatchers.IO) {
        requireLegalConsent()
        require(knownVersion in 0..999999999)
        require(locale.matches(Regex("[A-Za-z-]{2,16}")))
        extract(CloudNativeTransport.post(CloudOperation.WHATS_NEW,
            JSONObject().put("knownVersion",knownVersion).put("locale",locale),session()))
    }

    /** Public presentation metadata only; never contains provider operations. */
    suspend fun serverVpnCatalog(knownVersion:Int): JSONObject =
        withContext(Dispatchers.IO) {
            requireLegalConsent()
            val envelope=CatalogEnvelope()
            envelope.open(extract(CloudNativeTransport.post(CloudOperation.CATALOG,
                JSONObject().put("knownVersion",knownVersion).put("catalogKey",envelope.publicKey),session())),"catalog").also { reply ->
                if(!reply.optBoolean("unchanged",false)) {
                    exportCatalog=runCatching {CompatibleExportCatalog.parse(reply.optJSONObject("compatibleExports"))}.getOrNull()
                    exportCatalogCheckedAt=android.os.SystemClock.elapsedRealtime()
                }
            }
        }

    suspend fun notifications():JSONObject = withContext(Dispatchers.IO) {
        requireLegalConsent()
        extract(CloudNativeTransport.post(CloudOperation.NOTIFICATIONS,JSONObject(),session()))
    }

    /** Only the VPS version number is returned; no provider URLs or decoded files. */
    suspend fun watchCatalogVersion(knownVersion:Int):Int = withContext(Dispatchers.IO) {
        requireLegalConsent()
        require(knownVersion in 0..999999999)
        val reply=extract(CloudNativeTransport.post(CloudOperation.WATCH,
            JSONObject().put("knownVersion",knownVersion),session()))
        val version=reply.optInt("catalogVersion",0)
        if(version !in 1..999999999)throw IOException("CLOUD_INVALID_CATALOG_VERSION")
        version
    }

    suspend fun decodeServerVpnProvider(id:String): Decoded {
        require(id.matches(Regex("[a-z0-9-]{1,48}")))
        return decode(CloudOperation.DECODE_SERVER,
            JSONObject().put("id",id).put("consent",true))
    }

    suspend fun serverVpnIcon(id:String): JSONObject {
        require(id.matches(Regex("[a-z0-9-]{1,48}")))
        return withContext(Dispatchers.IO) {
            requireLegalConsent()
            val envelope=CatalogEnvelope()
            envelope.open(extract(CloudNativeTransport.post(CloudOperation.ICON,
                JSONObject().put("id",id).put("catalogKey",envelope.publicKey),session())),"icon")
        }
    }

    /** Explicit user action only: never uploads the source file or a free-text note. */
    suspend fun reportFailure(details:Diagnostic):String {
        requireLegalConsent()
        val data=JSONObject().put("type","report")
            .put("service",details.service).put("format",details.format)
            .put("code",details.code).put("appVersion",BuildConfig.VERSION_NAME)
        val response=withContext(Dispatchers.IO){
            extract(CloudNativeTransport.post(CloudOperation.TELEMETRY,data,session()))
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
            extract(CloudNativeTransport.post(CloudOperation.TELEMETRY,data,session()))
        }
    }

}

