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
import java.security.spec.ECGenParameterSpec

/** Hardware-attested installation keys and signed requests. Trust is decided by the backend. */
internal object CloudRequestProof {
    private const val ALIAS = "spdecode.transport.v2"
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
        val alias = HARDWARE_PREFIX + now + "." + CloudNativeTransport.hardwareAliasSuffix()
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
    fun publicKey(): String = encode(entry().certificate.publicKey.encoded)
    fun integrityNonce(nonce: String, challengeId: String): String =
        CloudNativeTransport.playIntegrityNonce(nonce, challengeId, publicKey())

    data class Proof(val timestamp: String, val nonce: String, val signature: String)
    internal fun message(operation: Int, version: String, body: String, bearer: String,
                         timestamp: String, nonce: String): String =
        CloudNativeTransport.formatRequestProof(operation, version,
            body.toByteArray(Charsets.UTF_8), bearer, timestamp, nonce)

    /** Hardware-backed signature over exact native-formatted ciphertext proof. */
    fun signBytes(operation: Int, version: String, bytes: ByteArray, bearer: String): Proof {
        val parts = CloudNativeTransport.prepareRequestProof(operation, version, bytes, bearer)
        if(parts.size != 3)throw java.io.IOException("CLOUD_NATIVE_PROOF_INVALID")
        val input = parts[2].toByteArray(Charsets.UTF_8)
        val signature = try {
            CloudNativeTransport.signWithKeystore(entry(bearer).privateKey, input)
        } finally {
            input.fill(0)
        }
        return Proof(parts[0], parts[1], encode(signature))
    }

    fun sign(operation: Int, version: String, body: String, bearer: String): Proof =
        signBytes(operation, version, body.toByteArray(Charsets.UTF_8), bearer)
}
