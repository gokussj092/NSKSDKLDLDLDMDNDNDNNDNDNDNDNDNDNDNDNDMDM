package com.ghostdeveloper.spdecode.cloud

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.zip.GZIPInputStream

/**
 * Per-request ephemeral P-256 recipient. All ECDH, HKDF-SHA256, AES-256-GCM
 * authentication and decryption execute in libspdecode.so using Mbed TLS.
 *
 * Android supplies an ephemeral JCA KeyPair (also used for test fixtures);
 * PKCS#8 bytes are temporary and cleared after JNI. This is not the
 * non-exportable installation signing key from AndroidKeyStore.
 */
internal class CatalogEnvelope(
    private val pair: KeyPair=KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
) {
    val publicKey: String=Base64.encodeToString(pair.public.encoded,
        Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    fun open(body: JSONObject, purpose: String): JSONObject {
        require(body.getInt("envelope")==1 && body.getString("purpose")==purpose)
        require(purpose=="catalog" || purpose=="icon")
        val size=body.getInt("plainBytes")
        require(size in 1..MAX_PLAIN)
        val privatePkcs8=pair.private.encoded ?: throw java.io.IOException("CLOUD_CATALOG_KEY_UNAVAILABLE")
        val packed=try {
            CloudNativeTransport.openCatalog(privatePkcs8,publicKey,purpose,
                body.getString("serverKey"),body.getString("salt"),body.getString("iv"),
                size,body.getString("data"))
        }finally{ privatePkcs8.fill(0) }
        val plain=try { inflate(packed,size).also{require(it.size==size)} }
                  finally{packed.fill(0)}
        return try {JSONObject(String(plain,Charsets.UTF_8))}
               finally {plain.fill(0)}
    }
    companion object {
        const val MAX_PLAIN=4*1024*1024
        internal fun inflate(bytes:ByteArray,limit:Int):ByteArray {
            // Existing encrypted cache records allow 6 MiB; catalog wire remains 4 MiB.
            require(limit in 1..maxOf(MAX_PLAIN,ServerVpnIconPolicy.CACHE_RECORD_BYTES))
            val out=ByteArrayOutputStream()
            GZIPInputStream(ByteArrayInputStream(bytes)).use {stream->
                val buffer=ByteArray(8192)
                while(true) {val n=stream.read(buffer);if(n<0)break
                    require(out.size()+n<=limit);out.write(buffer,0,n)}
            }
            return out.toByteArray()
        }
    }
}
