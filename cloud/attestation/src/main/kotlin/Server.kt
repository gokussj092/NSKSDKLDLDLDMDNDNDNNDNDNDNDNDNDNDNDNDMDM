package com.ghostdeveloper.attestation

import com.android.keyattestation.verifier.*
import com.android.keyattestation.verifier.challengecheckers.ChallengeMatcher
import com.google.gson.Gson
import com.google.gson.JsonParser
import com.google.protobuf.ByteString
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.time.YearMonth
import java.util.Base64
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

data class Policy(val packageName: String, val digests: Set<ByteString>, val minimumVersion: BigInteger,
                  val level: String, val patchMonths: Long)
data class Evidence(val chain: List<String>, val challenge: String, val publicKey: String)
data class Decision(val valid: Boolean, val publicKey: String? = null,
                    val level: String? = null, val versionCode: Long? = null)

// Log bounded, non-identifying rejection categories only. Never log certificates,
// package names, public keys, challenges, serials, URLs or exception messages.
private fun reject(reason: String): Decision {
    System.err.println("SP_ATTEST_REJECT=$reason")
    return Decision(false)
}

internal fun parseRevocations(text: String): Set<String> {
    val root = JsonParser.parseString(text).asJsonObject
    val entries = checkNotNull(root.getAsJsonObject("entries"))
    return entries.entrySet().map { (serial, entry) ->
        require(serial.matches(Regex("[a-f0-9]+")))
        require(entry.asJsonObject["status"].asString in setOf("REVOKED", "SUSPENDED"))
        serial.lowercase().trimStart('0').ifEmpty { "0" }
    }.toSet()
}

/** Fresh CRL required. A failed refresh never extends the lifetime of an old list. */
class GoogleRevocations {
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4))
        .followRedirects(HttpClient.Redirect.NEVER).build()
    private var expires = Instant.MIN
    private var serials: Set<String> = emptySet()
    @Synchronized fun current(): Set<String> {
        if (Instant.now().isBefore(expires)) return serials
        val request = HttpRequest.newBuilder(URI.create("https://android.googleapis.com/attestation/status"))
            .timeout(Duration.ofSeconds(7)).GET().build()
        val response = client.send(request, HttpResponse.BodyHandlers.ofInputStream())
        val text = response.body().use {
            val bytes = it.readNBytes(4 * 1024 * 1024 + 1)
            require(bytes.size <= 4 * 1024 * 1024 && response.statusCode() == 200)
            String(bytes, Charsets.UTF_8)
        }
        val next = parseRevocations(text)
        val cacheSeconds = Regex("(?:^|,)\\s*max-age=([0-9]+)")
            .find(response.headers().firstValue("Cache-Control").orElse(""))
            ?.groupValues?.get(1)?.toLongOrNull()?.coerceIn(0,3600) ?: 300
        serials = next
        expires = Instant.now().plusSeconds(cacheSeconds)
        return serials
    }
}

fun decide(evidence: Evidence, policy: Policy, verifier: Verifier): Decision {
    require(evidence.chain.size in 2..8)
    require(evidence.challenge.matches(Regex("[A-Za-z0-9_-]{43}")))
    require(evidence.publicKey.matches(Regex("[A-Za-z0-9_-]{120,128}")))
    val factory = CertificateFactory.getInstance("X.509")
    val chain = evidence.chain.map {
        require(it.length <= 8192)
        val stream = ByteArrayInputStream(Base64.getDecoder().decode(it))
        val certificate = factory.generateCertificate(stream) as X509Certificate
        require(stream.available() == 0)
        certificate
    }
    val result = verifier.verify(chain, ChallengeMatcher(Base64.getUrlDecoder().decode(evidence.challenge)))
    if (result !is VerificationResult.Success) {
        val category = when (result) {
            is VerificationResult.ChallengeMismatch -> "CHALLENGE"
            is VerificationResult.PathValidationFailure -> "CERT_PATH"
            is VerificationResult.ChainParsingFailure -> "CHAIN_FORMAT"
            is VerificationResult.ExtensionParsingFailure -> "CERT_EXTENSION"
            is VerificationResult.ConstraintViolation -> "CERT_CONSTRAINT"
            else -> "CERT_INVALID"
        }
        return reject(category)
    }
    if (!result.deviceLocked || result.verifiedBootState != VerifiedBootState.VERIFIED)
        return reject("VERIFIED_BOOT")
    val level = when (result.securityLevel) {
        SecurityLevel.STRONG_BOX -> "strongbox"
        SecurityLevel.TRUSTED_ENVIRONMENT -> "tee"
        else -> return reject("SECURITY_LEVEL")
    }
    if (policy.level == "strongbox" && level != "strongbox") return reject("SECURITY_LEVEL")
    val key = Base64.getUrlEncoder().withoutPadding().encodeToString(result.publicKey.encoded)
    if (key != evidence.publicKey) return reject("KEY_MISMATCH")
    // Parse only after the library validated the chain and its extension placement.
    val description = checkNotNull(KeyDescription.parseFrom(chain.first()))
    val app = description.softwareEnforced.attestationApplicationId ?: return reject("APP_ID_MISSING")
    if (app.packages.size != 1 || app.packages.none { it.name == policy.packageName && it.version >= policy.minimumVersion } ||
        app.signatures.isEmpty() || app.signatures.any { it !in policy.digests }) return reject("APP_ID_MISMATCH")
    val floor = YearMonth.now(java.time.ZoneOffset.UTC).minusMonths(policy.patchMonths)
    val ceiling = YearMonth.now(java.time.ZoneOffset.UTC).plusMonths(1)
    val attributes = description.hardwareEnforced
    // Android's attestation schema marks vendorPatchLevel and bootPatchLevel OPTIONAL.
    // A missing optional field is not evidence of an old or untrusted device.
    // Require a current hardware-enforced OS patch, and reject any present
    // vendor/boot patch if it is outside the established security window.
    val osPatch = attributes.osPatchLevel ?: return reject("OS_PATCH_MISSING")
    if (osPatch.yearMonth.isBefore(floor) || osPatch.yearMonth.isAfter(ceiling))
        return reject("OS_PATCH_OUTDATED")
    if (listOfNotNull(attributes.vendorPatchLevel, attributes.bootPatchLevel)
        .any { it.yearMonth.isBefore(floor) || it.yearMonth.isAfter(ceiling) })
        return reject("VENDOR_BOOT_PATCH_OUTDATED")
    // App package version is taken only from Google's hardware-validated attestationApplicationId.
    return Decision(true, key, level, app.packages.single().version.longValueExact())
}

private fun reply(exchange: HttpExchange, status: Int, value: Any) {
    val bytes = Gson().toJson(value).toByteArray(Charsets.UTF_8)
    exchange.responseHeaders.set("Content-Type", "application/json")
    exchange.responseHeaders.set("Cache-Control", "no-store")
    exchange.sendResponseHeaders(status, bytes.size.toLong())
    exchange.responseBody.use { it.write(bytes) }
}

fun main() {
    val env = System.getenv()
    val token = env["CLOUD_KEY_ATTESTATION_TOKEN"] ?: ""
    val packageName = env["CLOUD_GOOGLE_PLAY_PACKAGE"] ?: ""
    val certificates = (env["CLOUD_PLAY_CERT_SHA256"] ?: "").split(',').map { it.trim().lowercase() }
    val minimumVersion = (env["CLOUD_MIN_ANDROID_VERSION_CODE"] ?: "33").toBigInteger()
    val level = env["CLOUD_KEY_ATTESTATION_LEVEL"] ?: "tee"
    val months = (env["CLOUD_KEY_MAX_PATCH_AGE_MONTHS"] ?: "12").toLong()
    require(token.length >= 32 && packageName.matches(Regex("[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+")))
    require(certificates.size in 1..4 && certificates.all { it.matches(Regex("[a-f0-9]{64}")) })
    require(minimumVersion >= BigInteger.valueOf(33) && level in setOf("tee", "strongbox") && months in 1..24)
    val policy = Policy(packageName, certificates.map { ByteString.copyFrom(it.chunked(2).map { x -> x.toInt(16).toByte() }.toByteArray()) }.toSet(), minimumVersion, level, months)
    val revocations = GoogleRevocations()
    val expected = AttestationApplicationId(setOf(AttestationPackageInfo(packageName, minimumVersion)), policy.digests)
    val verifier = Verifier(GoogleTrustAnchors, { revocations.current() }, { Instant.now() }, expected,
        ConstraintConfig(attestationApplicationId = AttestationApplicationIdConstraint.STRICT))
    val server = HttpServer.create(InetSocketAddress("0.0.0.0", 8788), 8)
    server.executor = ThreadPoolExecutor(2, 2, 0L, TimeUnit.SECONDS, ArrayBlockingQueue(8))
    server.createContext("/ready") { exchange ->
        try { revocations.current(); reply(exchange, 200, mapOf("ready" to true)) }
        catch (_: Exception) { reply(exchange, 503, mapOf("ready" to false)) }
        finally { exchange.close() }
    }
    server.createContext("/verify") { exchange ->
        try {
            val supplied = exchange.requestHeaders.getFirst("X-SP-Attestation-Token") ?: ""
            if (!MessageDigest.isEqual(token.toByteArray(), supplied.toByteArray())) reply(exchange, 403, Decision(false))
            else if (exchange.requestMethod != "POST" || exchange.requestURI.rawPath != "/verify" ||
                exchange.requestURI.rawQuery != null || exchange.requestHeaders.getFirst("Content-Type") != "application/json") reply(exchange,400,Decision(false))
            else {
                val bytes = exchange.requestBody.readNBytes(65537)
                require(bytes.size <= 65536)
                val evidence = Gson().fromJson(String(bytes, Charsets.UTF_8), Evidence::class.java)
                reply(exchange, 200, decide(evidence, policy, verifier))
            }
        } catch (_: Exception) {
            // Never return or log exception messages: they can contain device details.
            reply(exchange, 403, reject("VERIFICATION_EXCEPTION"))
        }
        finally { exchange.close() }
    }
    server.start()
}
