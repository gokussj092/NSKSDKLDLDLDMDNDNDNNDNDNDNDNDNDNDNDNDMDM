package com.ghostdeveloper.spdecode.cloud

import org.json.JSONObject
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal Android JSON/JNI facade. RFC 9180 HPKE, X25519, HKDF, AES-GCM,
 * nonce generation, server pin verification, response authentication and
 * per-request state execute exclusively in libspdecode.so.
 *
 * Android Keystore, Play Integrity and signed proof registration remain
 * Android platform services and are migrated separately.
 */
internal object V2HpkeEnvelope {
    class Prepared internal constructor(
        val wire: ByteArray,
        private val handle: Long
    ) {
        fun open(status: Int, response: ByteArray): JSONObject {
            val plaintext = CloudNativeTransport.openHpke(handle, status, wire, response)
            return try {
                JSONObject(String(plaintext, Charsets.UTF_8))
            } finally {
                plaintext.fill(0)
            }
        }

        fun discard() {
            CloudNativeTransport.discardHpke(handle)
            wire.fill(0)
        }
    }

    fun prepare(operation: Int, metadata: JSONObject, attachment: ByteArray? = null): Prepared {
        val json = metadata.toString().toByteArray(Charsets.UTF_8)
        val combined = try {
            CloudNativeTransport.prepareHpke(operation, json, attachment)
        } finally {
            json.fill(0)
        }
        try {
            if (combined.size !in 8 + 71 + 16..8 + 11 * 1024 * 1024)
                throw IOException("CLOUD_HPKE_NATIVE_INVALID")
            val handle = ByteBuffer.wrap(combined, 0, 8)
                .order(ByteOrder.BIG_ENDIAN).long
            if (handle == 0L)
                throw IOException("CLOUD_HPKE_NATIVE_INVALID")
            return Prepared(combined.copyOfRange(8, combined.size), handle)
        } finally {
            combined.fill(0)
        }
    }
}
