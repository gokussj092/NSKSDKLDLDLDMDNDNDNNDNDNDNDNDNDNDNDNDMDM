package com.ghostdeveloper.spdecode.cloud

import kotlinx.coroutines.sync.Mutex
import org.json.JSONArray
import java.io.IOException

/**
 * Minimal Kotlin facade. Key selection, alias lifecycle and enrollment policy
 * are implemented in C++; Android Keystore private keys never leave the OS.
 * The server independently validates hardware certificate chains.
 */
internal object CloudRequestProof {
    val enrollmentMutex = Mutex()

    fun publicKey(): String = CloudNativeTransport.hardwarePublicKey()

    fun attest(challenge: String, requiredLevel: String): JSONArray =
        JSONArray().apply {
            CloudNativeTransport.attestHardwareKey(challenge, requiredLevel).forEach { put(it) }
        }

    fun integrityNonce(nonce: String, challengeId: String): String =
        CloudNativeTransport.playIntegrityNonce(nonce, challengeId, publicKey())

    data class Proof(val timestamp: String, val nonce: String, val signature: String)

    internal fun message(operation: Int, version: String, body: String, bearer: String,
                         timestamp: String, nonce: String): String =
        CloudNativeTransport.formatRequestProof(operation, version,
            body.toByteArray(Charsets.UTF_8), bearer, timestamp, nonce)

    fun signBytes(operation: Int, version: String, bytes: ByteArray, bearer: String): Proof {
        val parts=CloudNativeTransport.signRequestProof(operation,version,bytes,bearer)
        if(parts.size!=3) throw IOException("CLOUD_NATIVE_PROOF_INVALID")
        return Proof(parts[0],parts[1],parts[2])
    }

    fun sign(operation: Int, version: String, body: String, bearer: String): Proof =
        signBytes(operation,version,body.toByteArray(Charsets.UTF_8),bearer)
}
