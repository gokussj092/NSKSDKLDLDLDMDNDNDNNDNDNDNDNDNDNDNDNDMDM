package com.ghostdeveloper.spdecode.cloud

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import kotlinx.coroutines.sync.Mutex
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** Hardware-attested installation keys and signed requests. Trust is decided by the backend. */
internal object CloudRequestProof {
    private const val ALIAS = "spdecode.transport.v2"
    private val random = SecureRandom()
    val enrollmentMutex = Mutex()
    private const val HARDWARE_PREFIX = "spdecode.transport.v3."
    private val store: KeyStore by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }
    private var activeAlias: String? = null
    private fun aliases(): List<String> = store.aliases().toList().filter {
        it == ALIAS || it.startsWith(HARDWARE_PREFIX)
    }
    @Synchronized private fun entry(bearer: String = ""): KeyStore.PrivateKeyEntry {
        // Existing sessions keep using their original hardware key during rotation.
        val requested = if (bearer.isNotEmpty() && bearer.length <= 2048) try {
            JSONObject(String(Base64.decode(bearer.substringBefore('.'), Base64.URL_SAFE), Charsets.UTF_8))
                .optString("key").takeIf { it.matches(Regex("[A-Za-z0-9_-]{120,128}")) }
        } catch (_: Exception) { null } else null
        if (requested != null) {
            for (alias in aliases()) {
                val candidate = store.getEntry(alias, null) as? KeyStore.PrivateKeyEntry ?: continue
                if (encode(candidate.certificate.publicKey.encoded) == requested) return candidate
            }
            throw java.io.IOException("CLOUD_KEY_UNAVAILABLE")
        }
        if (activeAlias == null) activeAlias = aliases().filter { it.startsWith(HARDWARE_PREFIX) }.maxOrNull()
        if (activeAlias == null) {
            if (!store.containsAlias(ALIAS)) {
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                    initialize(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256).build())
                }.generateKeyPair()
            }
            activeAlias = ALIAS
        }
        return store.getEntry(activeAlias, null) as KeyStore.PrivateKeyEntry
    }
    /** Server validates the chain; this function never treats a local boolean as evidence. */
    @Synchronized fun attest(challenge: String, requiredLevel: String): JSONArray {
        require(challenge.matches(Regex("[A-Za-z0-9_-]{43}")))
        require(requiredLevel == "tee" || requiredLevel == "strongbox")
        val now = System.currentTimeMillis()
        for (alias in aliases().filter { it.startsWith(HARDWARE_PREFIX) }) {
            val created = alias.removePrefix(HARDWARE_PREFIX).substringBefore('.').toLongOrNull() ?: 0L
            if (now - created > 600_000L && alias != activeAlias) store.deleteEntry(alias)
        }
        if (aliases().size >= 8) throw java.io.IOException("CLOUD_KEY_ENROLLMENT_LIMIT")
        val alias = HARDWARE_PREFIX + now + "." + encode(ByteArray(6).also(random::nextBytes))
        fun generate(strong: Boolean) {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(Base64.decode(challenge, Base64.URL_SAFE))
            if (Build.VERSION.SDK_INT >= 28) spec.setIsStrongBoxBacked(strong)
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(spec.build())
            }.generateKeyPair()
        }
        if (requiredLevel == "strongbox" && Build.VERSION.SDK_INT < 28)
            throw java.io.IOException("CLOUD_STRONGBOX_UNAVAILABLE")
        try {
            if (Build.VERSION.SDK_INT >= 28) {
                try { generate(true) }
                catch (error: StrongBoxUnavailableException) {
                    if (requiredLevel == "strongbox") throw java.io.IOException("CLOUD_STRONGBOX_UNAVAILABLE", error)
                    store.deleteEntry(alias)
                    generate(false)
                }
            } else generate(false)
            val chain = store.getCertificateChain(alias) ?: throw java.io.IOException("CLOUD_ATTESTATION_UNAVAILABLE")
            if (chain.size !in 2..8) throw java.io.IOException("CLOUD_ATTESTATION_UNAVAILABLE")
            activeAlias = alias
            return JSONArray().apply { chain.forEach { put(Base64.encodeToString(it.encoded, Base64.NO_WRAP)) } }
        } catch (error: Exception) {
            store.deleteEntry(alias)
            throw error
        }
    }
    private fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes,
        Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    private fun digest(value: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
    private fun hex(value: String): String = digest(value).joinToString("") { "%02x".format(it.toInt() and 255) }
    fun publicKey(): String = encode(entry().certificate.publicKey.encoded)
    fun integrityNonce(nonce: String, challengeId: String): String =
        encode(digest(listOf("SPDECODE-KEY-V2", nonce, challengeId, publicKey()).joinToString("\n")))

    data class Proof(val timestamp: String, val nonce: String, val signature: String)
    internal fun message(operation: Int, version: String, body: String, bearer: String,
                         timestamp: String, nonce: String): String =
        listOf("SPDECODE-POP-V2", "POST", operation.toString(), version,
            timestamp, nonce, hex(bearer), hex(body)).joinToString("\n")

    fun sign(operation: Int, version: String, body: String, bearer: String): Proof =
        signBytes(operation, version, body.toByteArray(Charsets.UTF_8), bearer)

    /** Sign exactly what crosses HTTPS: HPKE ciphertext, not sensitive JSON. */
    fun signBytes(operation: Int, version: String, body: ByteArray, bearer: String): Proof {
        val timestamp = (System.currentTimeMillis() / 1000).toString()
        val nonce = encode(ByteArray(24).also(random::nextBytes))
        return signBytesWithMetadata(operation,version,body,bearer,timestamp,nonce)
    }

    fun signBytesWithMetadata(operation:Int,version:String,body:ByteArray,bearer:String,
                              timestamp:String,nonce:String):Proof {
        val message = listOf("SPDECODE-POP-V2", "POST", operation.toString(),version,
            timestamp,nonce,hex(bearer),MessageDigest.getInstance("SHA-256").digest(body)
            .joinToString("") { "%02x".format(it.toInt() and 255) }).joinToString("\n")
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(entry(bearer).privateKey)
            update(message.toByteArray(Charsets.UTF_8))
            sign()
        }
        return Proof(timestamp, nonce, encode(signature))
    }
}

