package com.ghostdeveloper.spdecode.cloud

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** Non-exportable installation key. Server key attestation is a separate policy. */
internal object CloudRequestProof {
    private const val ALIAS = "spdecode.transport.v2"
    private val random = SecureRandom()
    private val entry: KeyStore.PrivateKeyEntry by lazy {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!store.containsAlias(ALIAS)) {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256).build())
            }.generateKeyPair()
        }
        store.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
    }
    private fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes,
        Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    private fun digest(value: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
    private fun hex(value: String): String = digest(value).joinToString("") { "%02x".format(it.toInt() and 255) }
    fun publicKey(): String = encode(entry.certificate.publicKey.encoded)
    fun integrityNonce(nonce: String, challengeId: String): String =
        encode(digest(listOf("SPDECODE-KEY-V2", nonce, challengeId, publicKey()).joinToString("\n")))

    data class Proof(val timestamp: String, val nonce: String, val signature: String)
    internal fun message(operation: Int, version: String, body: String, bearer: String,
                         timestamp: String, nonce: String): String =
        listOf("SPDECODE-POP-V2", "POST", operation.toString(), version,
            timestamp, nonce, hex(bearer), hex(body)).joinToString("\n")

    fun sign(operation: Int, version: String, body: String, bearer: String): Proof {
        val timestamp = (System.currentTimeMillis() / 1000).toString()
        val nonce = encode(ByteArray(24).also(random::nextBytes))
        val message = message(operation, version, body, bearer, timestamp, nonce)
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.privateKey)
            update(message.toByteArray(Charsets.UTF_8))
            sign()
        }
        return Proof(timestamp, nonce, encode(signature))
    }
}
