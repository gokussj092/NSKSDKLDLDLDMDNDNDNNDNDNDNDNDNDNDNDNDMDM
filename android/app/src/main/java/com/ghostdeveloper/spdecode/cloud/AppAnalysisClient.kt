package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.SystemClock
import android.provider.OpenableColumns
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.ghostdeveloper.spdecode.NativeCommerceAuth
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.coroutineContext

/**
 * SP-DECODE Arnes: paid APK analysis over direct authenticated HTTPS
 * (NativeCommerceAuth Bearer session). One credit-backed job at a time.
 *
 * Transport is chunk-JSON-base64 (2 MB), the same shape as APK-QA, but the
 * routes are the app-analysis ones (/api/v1/app-analysis/...) and the server —
 * never the client — decides price, balance and whether the button is
 * enabled. No consent checkbox exists in this flow, so start() never sends
 * one and the server never requires it.
 *
 * The checkpoint (job id, upload token, SAF uri) and the device label are
 * encrypted with AndroidKeyStore AES-256-GCM. The finished result.zip is
 * saved under filesDir/app-analysis/ so the user can re-export it without
 * the server link. WorkManager (AppAnalysisWorker) drives executeQueued();
 * the Activity only observes the local snapshot.
 */
internal class AppAnalysisClient(context: Context) {
    internal class Failure(val code: String, val status: Int = 0) : IOException(code)

    data class Preflight(
        val creditsAvailable: Int, val balance: Int, val held: Int,
        val creditPriceCents: Int, val currency: String,
        val creditsPerAnalysis: Int = 1,
    )
    data class JobView(
        val jobId: String, val status: String, val phaseCode: String?,
        val progressPercent: Int?, val receivedBytes: Long, val totalBytes: Long,
        val filename: String, val packageName: String?, val appName: String?,
        val creditState: String, val errorCode: String?, val needsToken: Boolean,
        val isNewCatalogCandidate: Boolean,
        val resultBytes: Long?, val resultSha256: String?, val downloadUrl: String?,
        val expiresAt: String?, val createdAt: String?,
        val updatedAt: String?,
    ) {
        val active: Boolean get() = status !in setOf(
            "COMPLETED", "COMPLETED_PARTIAL", "FAILED", "REJECTED", "EXPIRED")
        val terminal: Boolean get() = !active
    }
    data class Snapshot(
        val active: Boolean, val job: JobView?, val error: String?,
        val filename: String, val preflight: Preflight?,
    )

    companion object {
        const val MAX_BYTES = 150L * 1000L * 1000L
        private const val MAX_CHUNK = 2 * 1024 * 1024
        private const val MAX_RESULT_BYTES = 32 * 1024 * 1024
        private const val WORK_BUDGET_MS = 6L * 60L * 1000L
        private const val ORIGIN = "https://spdecode.xyz"
        private const val KEY_ALIAS = "spdecode_app_analysis_v1"
        private const val PREFS = "spdecode-app-analysis"
    }

    private val app = context.applicationContext
    private val resolver = app.contentResolver
    private val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val resultsDir = File(app.filesDir, "app-analysis")
        .also { if (!it.isDirectory && !it.mkdirs()) throw IOException("APP_ANALYSIS_STORAGE_UNAVAILABLE") }

    // -- Encrypted local state (same AES/GCM pattern as NativeCommerceAuth). --
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true).build())
        return generator.generateKey()
    }
    private fun encrypt(value: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        return Base64.encodeToString(cipher.iv + cipher.doFinal(value.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
    }
    private fun decrypt(value: String): String {
        val bytes = Base64.decode(value, Base64.NO_WRAP)
        if (bytes.size < 29) throw IOException("APP_ANALYSIS_LOCAL_STATE_INVALID")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        return String(cipher.doFinal(bytes.copyOfRange(12, bytes.size)), Charsets.UTF_8)
    }
    private fun readState(): JSONObject? {
        val raw = prefs.getString("checkpoint", null) ?: return null
        return runCatching { JSONObject(decrypt(raw)) }.getOrNull()
    }
    private fun writeState(state: JSONObject) {
        if (!prefs.edit().putString("checkpoint", encrypt(state.toString())).commit())
            throw IOException("APP_ANALYSIS_LOCAL_STATE_UNAVAILABLE")
    }
    private fun clearState() {
        prefs.edit().remove("checkpoint").apply()
    }

    /** Opaque per-device label (SHA-256 of a random id). The Bearer session is
     * the real authentication; this only binds the job to one device. */
    fun deviceKeyHash(): String {
        val stored = prefs.getString("device", null)
        val id = if (stored != null) runCatching { decrypt(stored) }.getOrNull() else null
        val value = id ?: ByteArray(32).also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        if (id == null) prefs.edit().putString("device", encrypt(value)).apply()
        return MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun token(): String =
        NativeCommerceAuth(app).sessionToken() ?: throw Failure("SIGN_IN_REQUIRED", 401)

    // -- Direct HTTPS (mirrors NativeCommerceAuth.http, with a body cap that
    // fits one 2 MB base64 chunk). Never sends tokens anywhere else. --
    private fun httpJson(
        method: String, path: String, body: JSONObject?, bodyCapBytes: Int = 256 * 1024,
    ): JSONObject {
        require(path.startsWith("/api/") && !path.contains("..") && !path.contains("://"))
        val connection = URL(ORIGIN + path).openConnection() as HttpURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 8000
            connection.readTimeout = if (method == "POST" && bodyCapBytes > 256 * 1024) 60000 else 8000
            connection.requestMethod = method
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Cache-Control", "no-store")
            connection.setRequestProperty("Authorization", "Bearer " + token())
            if (method != "GET") {
                connection.doOutput = true
                connection.setRequestProperty("Origin", ORIGIN)
                connection.setRequestProperty("Content-Type", "application/json")
                val bytes = (body ?: JSONObject()).toString().toByteArray(Charsets.UTF_8)
                require(bytes.size <= bodyCapBytes)
                connection.outputStream.use { it.write(bytes) }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.use { it.readBytes().decodeToString() }.orEmpty()
            if (status !in 200..299) {
                val code = runCatching { JSONObject(text).optJSONObject("error")?.optString("code") }
                    .getOrNull()?.takeIf { it.matches(Regex("[A-Z][A-Z0-9_]{2,64}")) }
                    ?: when (status) {
                        400 -> "APP_ANALYSIS_BAD_REQUEST"
                        401 -> "SIGN_IN_REQUIRED"
                        402 -> "INSUFFICIENT_CREDITS"
                        403 -> "APP_ANALYSIS_ACCESS_DENIED"
                        404 -> "APP_ANALYSIS_JOB_NOT_FOUND"
                        409 -> "APP_ANALYSIS_CONFLICT"
                        413 -> "INPUT_TOO_LARGE"
                        429 -> "APP_ANALYSIS_BUSY"
                        503 -> "SERVICE_UNAVAILABLE"
                        else -> "APP_ANALYSIS_HTTP_$status"
                    }
                throw Failure(code, status)
            }
            if (!connection.contentType.orEmpty().startsWith("application/json"))
                throw Failure("INVALID_RESPONSE", status)
            if (text.toByteArray(Charsets.UTF_8).size > 256 * 1024)
                throw Failure("RESPONSE_TOO_LARGE", status)
            return JSONObject(text)
        } finally {
            connection.disconnect()
        }
    }

    fun jobViewOf(raw: JSONObject): JobView = JobView(
        jobId = raw.optString("jobId"),
        status = raw.optString("status"),
        phaseCode = raw.optString("phaseCode").takeIf { it.isNotBlank() },
        progressPercent = if (raw.has("progressPercent") && !raw.isNull("progressPercent"))
            raw.optInt("progressPercent") else null,
        receivedBytes = raw.optLong("receivedBytes"),
        totalBytes = raw.optLong("totalBytes"),
        filename = raw.optString("filename"),
        packageName = raw.optString("packageName").takeIf { it.isNotBlank() },
        appName = raw.optString("appName").takeIf { it.isNotBlank() },
        creditState = raw.optString("creditState"),
        errorCode = raw.optString("errorCode").takeIf { it.isNotBlank() },
        needsToken = raw.optBoolean("needsToken", false),
        isNewCatalogCandidate = raw.optBoolean("isNewCatalogCandidate", false),
        resultBytes = if (raw.has("resultBytes") && !raw.isNull("resultBytes"))
            raw.optLong("resultBytes") else null,
        resultSha256 = raw.optString("resultSha256").takeIf { it.isNotBlank() },
        downloadUrl = raw.optString("downloadUrl").takeIf { it.isNotBlank() },
        expiresAt = raw.optString("expiresAt").takeIf { it.isNotBlank() },
        createdAt = raw.optString("createdAt").takeIf { it.isNotBlank() },
        updatedAt = raw.optString("updatedAt").takeIf { it.isNotBlank() },
    )

    /** Server-authoritative preflight: credits + price. Never cached long. */
    suspend fun preflight(): Preflight = withContext(Dispatchers.IO) {
        val raw = httpJson("POST", "/api/v1/app-analysis/preflight", JSONObject())
        val preflight = Preflight(
            creditsAvailable = raw.optInt("creditsAvailable"),
            balance = raw.optInt("balance"),
            held = raw.optInt("held"),
            creditPriceCents = raw.optInt("creditPriceCents"),
            currency = raw.optString("currency").takeIf { it.isNotBlank() } ?: "USD",
            creditsPerAnalysis = raw.optInt("creditsPerAnalysis", 1),
        )
        val state = readState() ?: JSONObject()
        writeState(state.put("preflight", JSONObject()
            .put("creditsAvailable", preflight.creditsAvailable)
            .put("balance", preflight.balance).put("held", preflight.held)
            .put("creditPriceCents", preflight.creditPriceCents)
            .put("currency", preflight.currency)
            .put("creditsPerAnalysis", preflight.creditsPerAnalysis)))
        preflight
    }

    fun hasActiveJob(): Boolean {
        val state = readState() ?: return false
        val job = state.optJSONObject("job") ?: return false
        return jobViewOf(job).active
    }

    /** Local snapshot for the observer: no network, never a progress estimate. */
    fun snapshot(): Snapshot? {
        val state = readState() ?: return null
        val job = state.optJSONObject("job")?.let { runCatching { jobViewOf(it) }.getOrNull() }
        val stored = state.optJSONObject("preflight")
        val preflight = stored?.let {
            Preflight(it.optInt("creditsAvailable"), it.optInt("balance"),
                it.optInt("held"), it.optInt("creditPriceCents"),
                it.optString("currency").takeIf { s -> s.isNotBlank() } ?: "USD",
                it.optInt("creditsPerAnalysis", 1))
        }
        return Snapshot(
            active = job?.active ?: false, job = job,
            error = state.optString("error").takeIf { it.isNotBlank() },
            filename = state.optString("filename"),
            preflight = preflight,
        )
    }

    private fun filename(uri: Uri): String {
        var raw = ""
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val column = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (column >= 0) raw = c.getString(column).orEmpty()
            }
        }
        val extension = raw.substringAfterLast('.', missingDelimiterValue = "").lowercase()
        if (extension !in setOf("apk", "apks")) throw IOException("APP_ANALYSIS_FORMAT_UNSUPPORTED")
        val base = raw.substringBeforeLast('.')
            .replace(Regex("[^A-Za-z0-9_. -]"), "_")
            .trim('.', ' ').take(88)
        return (base.ifEmpty { "spdecode-sample" }) + "." + extension
    }

    /** Called only after the user taps "Importar aplicación". */
    fun queue(uri: Uri) {
        if (hasActiveJob()) throw IOException("APP_ANALYSIS_ALREADY_ACTIVE")
        try {
            resolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } catch (_: SecurityException) {
            throw IOException("APP_ANALYSIS_PERSISTENT_FILE_PERMISSION_REQUIRED")
        }
        val startId = ByteArray(32).also { SecureRandom().nextBytes(it) }.let { hex(it) }
        writeState(JSONObject().put("uri", uri.toString()).put("filename", filename(uri))
            .put("startId", startId).put("job", JSONObject.NULL))
    }

    private suspend fun hashFile(uri: Uri): Pair<Long, String> = withContext(Dispatchers.IO) {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(256 * 1024)
        var total = 0L
        try {
            (resolver.openInputStream(uri) ?: throw IOException("APP_ANALYSIS_FILE_UNAVAILABLE")).use { src ->
                while (true) {
                    coroutineContext.ensureActive()
                    val count = src.read(buffer)
                    if (count < 0) break
                    if (count == 0) continue
                    total += count
                    if (total > MAX_BYTES) throw IOException("APP_ANALYSIS_INPUT_TOO_LARGE")
                    digest.update(buffer, 0, count)
                }
            }
            if (total == 0L) throw IOException("APP_ANALYSIS_EMPTY_FILE")
            total to hex(digest.digest())
        } finally {
            buffer.fill(0)
        }
    }

    private fun saveJob(state: JSONObject, job: JobView, error: String = ""): JSONObject {
        val raw = JSONObject()
            .put("jobId", job.jobId).put("status", job.status)
            .put("phaseCode", job.phaseCode)
            .put("receivedBytes", job.receivedBytes).put("totalBytes", job.totalBytes)
            .put("filename", job.filename).put("packageName", job.packageName)
            .put("appName", job.appName).put("creditState", job.creditState)
            .put("errorCode", job.errorCode).put("needsToken", job.needsToken)
            .put("resultSha256", job.resultSha256).put("downloadUrl", job.downloadUrl)
            .put("expiresAt", job.expiresAt).put("createdAt", job.createdAt)
        if (job.progressPercent != null) raw.put("progressPercent", job.progressPercent)
        if (job.resultBytes != null) raw.put("resultBytes", job.resultBytes)
        return state.put("job", raw).put("error", error)
    }

    private suspend fun sendRemaining(state: JSONObject): JSONObject {
        var current = state
        val job = jobViewOf(current.getJSONObject("job"))
        val uri = Uri.parse(current.optString("uri"))
        val (total, digest) = hashFile(uri)
        if (total != job.totalBytes) throw IOException("APP_ANALYSIS_FILE_CHANGED")
        val chunkBytes = current.optInt("chunkBytes", MAX_CHUNK)
        var sent = job.receivedBytes
        var next = (sent / chunkBytes).toInt()
        val block = ByteArray(chunkBytes)
        val discard = ByteArray(256 * 1024)
        try {
            (resolver.openInputStream(uri) ?: throw IOException("APP_ANALYSIS_FILE_UNAVAILABLE")).use { src ->
                var remaining = sent
                while (remaining > 0L) {
                    coroutineContext.ensureActive()
                    val count = src.read(discard, 0, minOf(remaining, discard.size.toLong()).toInt())
                    if (count < 0) throw IOException("APP_ANALYSIS_FILE_CHANGED")
                    if (count == 0) continue
                    remaining -= count
                }
                while (sent < total) {
                    coroutineContext.ensureActive()
                    var count = 0
                    val expectedSize = minOf(chunkBytes.toLong(), total - sent).toInt()
                    while (count < expectedSize) {
                        coroutineContext.ensureActive()
                        val n = src.read(block, count, expectedSize - count)
                        if (n < 0) throw IOException("APP_ANALYSIS_FILE_CHANGED")
                        if (n == 0) continue
                        count += n
                    }
                    val piece = block.copyOf(count)
                    try {
                        val payload = JSONObject()
                            .put("jobId", job.jobId)
                            .put("uploadToken", current.optString("uploadToken"))
                            .put("index", next)
                            .put("chunkSha256", hex(MessageDigest.getInstance("SHA-256").digest(piece)))
                            .put("dataBase64", android.util.Base64.encodeToString(piece, android.util.Base64.NO_WRAP))
                            .put("deviceKeyHash", deviceKeyHash())
                        val ack = httpJson("POST", "/api/v1/app-analysis/chunk", payload,
                            bodyCapBytes = 4 * 1024 * 1024)
                        if (ack.optLong("receivedBytes", -1L) != sent + count ||
                            ack.optInt("nextChunk", -1) != next + 1)
                            throw IOException("APP_ANALYSIS_CHUNK_ACK_INVALID")
                        sent += count
                        next++
                        current = saveJob(current, job.copy(receivedBytes = sent))
                        writeState(current)
                        if (sent < total) delay(4500L)
                    } finally {
                        piece.fill(0)
                    }
                }
            }
        } finally {
            block.fill(0); discard.fill(0)
        }
        return current
    }

    /** Downloads result.zip for a completed job and saves it locally so the
     * user can re-export it without the server link. Best-effort: a failed
     * save never fails the (already terminal) job. Returns true when the
     * local copy is present and its SHA-256 matches. */
    private suspend fun saveLocalResult(job: JobView): Boolean = withContext(Dispatchers.IO) {
        if (job.resultSha256.isNullOrBlank() || job.status !in setOf("COMPLETED", "COMPLETED_PARTIAL"))
            return@withContext false
        val file = File(resultsDir, job.jobId + ".zip")
        if (file.exists() && file.length() == (job.resultBytes ?: -1L)) return@withContext true
        try {
            val connection = URL(ORIGIN + "/api/v1/app-analysis/" + job.jobId + "/download")
                .openConnection() as HttpURLConnection
            try {
                connection.instanceFollowRedirects = false
                connection.connectTimeout = 8000
                connection.readTimeout = 60000
                connection.setRequestProperty("Accept", "application/zip")
                connection.setRequestProperty("Authorization", "Bearer " + token())
                if (connection.responseCode !in 200..299) return@withContext false
                val digest = MessageDigest.getInstance("SHA-256")
                val buffer = ByteArray(256 * 1024)
                var total = 0L
                val tmp = File(resultsDir, job.jobId + ".zip.tmp")
                tmp.outputStream().use { out ->
                    connection.inputStream.use { src ->
                        while (true) {
                            coroutineContext.ensureActive()
                            val count = src.read(buffer)
                            if (count < 0) break
                            if (count == 0) continue
                            total += count
                            if (total > MAX_RESULT_BYTES) throw IOException("APP_ANALYSIS_RESULT_TOO_LARGE")
                            digest.update(buffer, 0, count)
                            out.write(buffer, 0, count)
                        }
                    }
                }
                if (hex(digest.digest()) != job.resultSha256) {
                    tmp.delete()
                    return@withContext false
                }
                if (!tmp.renameTo(file)) {
                    tmp.delete()
                    return@withContext false
                }
                val index = readLocalIndex().filter { it.jobId != job.jobId } +
                    LocalResult(job.jobId, job.filename, job.resultSha256,
                        job.packageName, job.appName, System.currentTimeMillis())
                writeLocalIndex(index)
                true
            } finally {
                connection.disconnect()
            }
        } catch (_: Exception) {
            false
        }
    }

    data class LocalResult(
        val jobId: String, val filename: String, val sha256: String,
        val packageName: String?, val appName: String?, val savedAt: Long,
    )
    private fun readLocalIndex(): List<LocalResult> {
        val raw = prefs.getString("localResults", null) ?: return emptyList()
        return runCatching {
            val plain = decrypt(raw)
            val array = JSONArray(plain)
            (0 until array.length()).mapNotNull { n ->
                val item = array.optJSONObject(n) ?: return@mapNotNull null
                LocalResult(item.optString("jobId"), item.optString("filename"),
                    item.optString("sha256"),
                    item.optString("packageName").takeIf { it.isNotBlank() },
                    item.optString("appName").takeIf { it.isNotBlank() },
                    item.optLong("savedAt"))
            }
        }.getOrDefault(emptyList())
    }
    private fun writeLocalIndex(items: List<LocalResult>) {
        val array = JSONArray()
        items.take(50).forEach {
            array.put(JSONObject().put("jobId", it.jobId).put("filename", it.filename)
                .put("sha256", it.sha256).put("packageName", it.packageName)
                .put("appName", it.appName).put("savedAt", it.savedAt))
        }
        prefs.edit().putString("localResults", encrypt(array.toString())).apply()
    }
    fun localResults(): List<LocalResult> = readLocalIndex()

    /** Re-export a saved result.zip to a SAF document, verifying SHA-256. */
    suspend fun exportResult(jobId: String, uri: Uri): Boolean = withContext(Dispatchers.IO) {
        val local = readLocalIndex().find { it.jobId == jobId }
            ?: return@withContext false
        val file = File(resultsDir, jobId + ".zip")
        if (!file.exists()) return@withContext false
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(256 * 1024)
        resolver.openOutputStream(uri, "w")?.use { out ->
            file.inputStream().use { src ->
                while (true) {
                    coroutineContext.ensureActive()
                    val count = src.read(buffer)
                    if (count < 0) break
                    if (count == 0) continue
                    digest.update(buffer, 0, count)
                    out.write(buffer, 0, count)
                }
            }
        } ?: return@withContext false
        hex(digest.digest()) == local.sha256
    }

    /**
     * Download result.zip from the server (Bearer session, no signed link
     * needed in-app) to a SAF document, verifying SHA-256. The file is also
     * kept locally so the next export does not need the server.
     */
    suspend fun downloadResult(job: JobView, uri: Uri): Boolean = withContext(Dispatchers.IO) {
        if (job.resultSha256.isNullOrBlank()) return@withContext false
        if (saveLocalResult(job)) return@withContext exportResult(job.jobId, uri)
        false
    }

    /** Server history ("Aplicaciones"): the account's own jobs. */
    suspend fun refreshHistory(): List<JobView> = withContext(Dispatchers.IO) {
        val raw = httpJson("GET", "/api/v1/app-analysis", null)
        val array = raw.optJSONArray("jobs") ?: JSONArray()
        (0 until array.length()).mapNotNull { n ->
            array.optJSONObject(n)?.let { runCatching { jobViewOf(it) }.getOrNull() }
        }
    }

    fun noteRecoverableError(code: String) {
        val state = readState() ?: return
        val safe = code.takeIf { it.matches(Regex("[A-Z_]{3,60}")) } ?: "APP_ANALYSIS_RECONNECTING"
        writeState(state.put("error", safe))
    }
    fun noteTerminalError(code: String) {
        val state = readState() ?: return
        val safe = code.takeIf { it.matches(Regex("[A-Z_]{3,60}")) } ?: "APP_ANALYSIS_FAILED"
        val job = state.optJSONObject("job")?.let { runCatching { jobViewOf(it) }.getOrNull() }
        if (job != null) writeState(saveJob(state, job.copy(status = "FAILED", errorCode = safe), safe))
        else writeState(state.put("error", safe))
    }

    /** Single durable unit: start (reserves the credit) -> upload -> finish
     * (VPN gate + queue) -> poll until terminal -> save the result locally.
     * Reentrant: every retry re-verifies server-authoritative progress. */
    suspend fun executeQueued(): Unit = withContext(Dispatchers.IO) {
        var state = readState() ?: return@withContext
        if (state.optJSONObject("job")?.let { runCatching { jobViewOf(it) }.getOrNull()?.terminal } == true)
            return@withContext
        val deadline = SystemClock.elapsedRealtime() + WORK_BUDGET_MS
        val uri = Uri.parse(state.optString("uri"))
        if (state.optString("sha256").isBlank()) {
            val (total, digest) = hashFile(uri)
            state = state.put("sha256", digest).put("totalBytes", total)
            writeState(state)
        }
        if (state.optString("jobId").isBlank()) {
            val started = httpJson("POST", "/api/v1/app-analysis/start", JSONObject()
                .put("filename", state.optString("filename"))
                .put("totalBytes", state.optLong("totalBytes"))
                .put("sha256", state.optString("sha256"))
                .put("deviceKeyHash", deviceKeyHash()))
            val id = started.optString("jobId")
            val uploadToken = started.optString("uploadToken")
            val step = started.optInt("chunkBytes")
            if (!Regex("[0-9a-f-]{36}").matches(id) ||
                !Regex("[A-Za-z0-9_-]{43}").matches(uploadToken) ||
                step !in 1..MAX_CHUNK) throw IOException("APP_ANALYSIS_INVALID_SESSION")
            state = state.put("jobId", id).put("uploadToken", uploadToken)
                .put("chunkBytes", step)
            val job = JobView(id, started.optString("status", "UPLOADING"), null, null,
                0L, state.optLong("totalBytes"), state.optString("filename"), null, null,
                "held", null, false, false, null, null, null, null, null, null)
            state = saveJob(state, job)
            writeState(state)
        }
        while (SystemClock.elapsedRealtime() < deadline) {
            coroutineContext.ensureActive()
            val current = readState() ?: return@withContext
            val job = current.optJSONObject("job")?.let { jobViewOf(it) } ?: return@withContext
            val remote = jobViewOf(httpJson("GET",
                "/api/v1/app-analysis/" + job.jobId, null))
            state = saveJob(current, remote)
            writeState(state)
            when (remote.status) {
                "COMPLETED", "COMPLETED_PARTIAL" -> {
                    saveLocalResult(remote)
                    return@withContext
                }
                "FAILED", "REJECTED", "EXPIRED" -> return@withContext
                "UPLOADING" -> {
                    state = sendRemaining(state)
                    val finished = jobViewOf(httpJson("POST",
                        "/api/v1/app-analysis/finish", JSONObject()
                            .put("jobId", job.jobId)
                            .put("uploadToken", state.optString("uploadToken"))
                            .put("deviceKeyHash", deviceKeyHash())))
                    state = saveJob(readState() ?: state, finished)
                    writeState(state)
                    if (finished.terminal) return@withContext
                }
                "UPLOADED", "QUEUED_FOR_ANALYSIS", "ANALYZING", "AWAITING_HUMAN" -> delay(12_000L)
                else -> throw IOException("APP_ANALYSIS_INVALID_STATE")
            }
        }
        throw IOException("APP_ANALYSIS_RETRY_SCHEDULED")
    }
}
