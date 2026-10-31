package com.ghostdeveloper.spdecode

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.cloud.CloudNativeTransport
import com.ghostdeveloper.spdecode.cloud.CloudOperation
import com.ghostdeveloper.spdecode.cloud.CloudRequestProof
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

@RunWith(AndroidJUnit4::class)
class CloudTransportProofInstrumentedTest {
    private fun decode(text: String): ByteArray = Base64.decode(text, Base64.URL_SAFE or Base64.NO_WRAP)
    private fun verify(key: String, message: String, proof: String): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(decode(key))))
            update(message.toByteArray(Charsets.UTF_8))
            verify(decode(proof))
        }
    @Test fun sharedServerVectorPreservesUnicodeAndExactSignedBytes() {
        val text=InstrumentationRegistry.getInstrumentation().context.assets
            .open("v2-proof-vector.json").bufferedReader().use { it.readText() }
        val v=JSONObject(text)
        val message=CloudRequestProof.message(v.getInt("operation"),v.getString("version"),
            v.getString("body"),v.getString("bearer"),v.getString("timestamp"),v.getString("nonce"))
        val digest=MessageDigest.getInstance("SHA-256").digest(message.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        assertEquals(v.getString("messageSha256"),digest)
        assertTrue(verify(v.getString("publicKey"),message,v.getString("signature")))
    }
    @Test fun installationKeySignsExactRequestAndPrivateMaterialIsNonExportable() {
        val key=CloudRequestProof.publicKey()
        val body=JSONObject().put("text","México 👻 漢字").toString()
        val proof=CloudRequestProof.sign(CloudOperation.TEXT,"1.1.22",body,"synthetic.bearer")
        val message=CloudRequestProof.message(CloudOperation.TEXT,"1.1.22",body,"synthetic.bearer",proof.timestamp,proof.nonce)
        assertTrue(verify(key,message,proof.signature))
        assertFalse(verify(key,message+" ",proof.signature))
        assertEquals(key,CloudRequestProof.publicKey())
        assertNotEquals(proof.nonce,CloudRequestProof.sign(CloudOperation.TEXT,"1.1.22",body,"synthetic.bearer").nonce)
        val store=KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val matching=store.aliases().toList().filter {
            it=="spdecode.transport.v2" || it.startsWith("spdecode.transport.v3.")
        }.mapNotNull { store.getEntry(it,null) as? KeyStore.PrivateKeyEntry }
            .singleOrNull { Base64.encodeToString(it.certificate.publicKey.encoded,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)==key }
        assertNotNull("The native-selected alias must resolve to a real AndroidKeyStore entry",matching)
        assertNull(matching!!.privateKey.encoded)
    }
    @Test fun invalidAttestationChallengeIsRejectedBeforeGeneratingKeys() {
        try {
            CloudRequestProof.attest("invalid-challenge","strongbox")
            fail("Invalid native challenge was accepted")
        } catch (expected: java.io.IOException) {
            assertTrue(expected.message!!.startsWith("CLOUD_ATTESTATION_"))
        }
    }

    @Test fun nativeLibraryRegistersBridgeAndInvalidOperationFailsBeforeNetwork() {
        try { CloudNativeTransport.post(3,JSONObject());fail("Reserved operation accepted") }
        catch (_: IllegalArgumentException) { /* object initialization loaded real JNI */ }
    }
}
