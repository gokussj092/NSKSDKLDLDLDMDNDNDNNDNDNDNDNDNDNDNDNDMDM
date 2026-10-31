package com.ghostdeveloper.spdecode.cloud

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec

/**
 * Mandatory Android platform calls only. Alias lifecycle, key selection and
 * attestation policy live in C++ and are verified again by the Cloud server.
 * Never exports an AndroidKeyStore private key.
 */
internal object CloudKeystorePlatform {
    private val store: KeyStore by lazy {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }

    @JvmStatic fun aliases(): Array<String> = store.aliases().toList().toTypedArray()
    @JvmStatic fun contains(alias: String): Boolean = store.containsAlias(alias)
    @JvmStatic fun delete(alias: String) = store.deleteEntry(alias)
    @JvmStatic fun publicKey(alias: String): String {
        val entry = store.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        return Base64.encodeToString(entry.certificate.publicKey.encoded,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }
    @JvmStatic fun privateKey(alias: String): PrivateKey =
        (store.getEntry(alias, null) as KeyStore.PrivateKeyEntry).privateKey

    @JvmStatic fun chain(alias: String): Array<String>? =
        store.getCertificateChain(alias)?.map {
            Base64.encodeToString(it.encoded, Base64.NO_WRAP)
        }?.toTypedArray()

    @JvmStatic fun generate(alias: String, challenge: ByteArray?, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (challenge != null) spec.setAttestationChallenge(challenge)
        if (Build.VERSION.SDK_INT >= 28) spec.setIsStrongBoxBacked(strongBox)
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            .apply { initialize(spec.build()) }.generateKeyPair()
    }
}
