package com.ghostdeveloper.spdecode

import android.content.Context
import android.content.ContextWrapper
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.cloud.NpvsIdentityVault
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/** Real AndroidKeyStore/GCM and PKCS8 import. Isolated directory; never deletes a user's alias. */
@RunWith(AndroidJUnit4::class)
class NpvsIdentityVaultInstrumentedTest {
    private lateinit var root:File
    private lateinit var context:Context
    @Before fun setup(){
        val app=InstrumentationRegistry.getInstrumentation().targetContext
        root=File(app.cacheDir,"npv-identity-test-"+UUID.randomUUID()).apply{mkdirs()}
        context=object:ContextWrapper(app){
            override fun getApplicationContext():Context=this
            override fun getNoBackupFilesDir():File=root
        }
    }
    @After fun cleanup(){root.deleteRecursively()}
    private fun b64(raw:ByteArray)=Base64.encodeToString(raw,Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    private fun sha(raw:ByteArray)=NpvsIdentityVault.hex(MessageDigest.getInstance("SHA-256").digest(raw))
    private fun identity():JSONObject {
        val pair=KeyPairGenerator.getInstance("EC").apply{initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        val pub=pair.public as ECPublicKey
        val x=pub.w.affineX.toByteArray().takeLast(32).toByteArray()
        val public=byteArrayOf(if(pub.w.affineY.testBit(0))3 else 2)+ByteArray(32-x.size)+x
        return JSONObject().put("schema","spdecode.npvs.recipient.v1").put("kind","keypair")
            .put("source","generated").put("curve","P-256").put("fingerprint",sha(public))
            .put("publicKey",b64(public)).put("privateKey",b64(pair.private.encoded))
    }
    private fun frame(fingerprint:String):ByteArray=ByteArray(320).also {
        "NPVS".toByteArray().copyInto(it);it[4]=5;it[8]=198.toByte();it[9]=1;it[61]=1
        fingerprint.chunked(2).map{value->value.toInt(16).toByte()}.toByteArray().copyInto(it,62)
    }
    @Test fun pkcs8PairPersistsEncryptedAndIsInactiveUntilOptIn(){
        val value=identity();val vault=NpvsIdentityVault(context);val entry=vault.save(value)
        val raw=frame(value.getString("fingerprint"))
        assertFalse(vault.enabled());assertTrue(vault.matching(raw).isEmpty())
        val stored=File(root,"npvs-identities-v1/${entry.id}.npvk").readBytes()
        assertFalse(String(stored,Charsets.ISO_8859_1).contains(value.getString("privateKey")))
        val reopened=NpvsIdentityVault(context)
        assertEquals(value.getString("privateKey"),reopened.entries().single().material.getString("privateKey"))
        reopened.enable(true);assertEquals(entry.id,reopened.matching(raw).single().id)
        reopened.enable(false);assertTrue(reopened.matching(raw).isEmpty())
        reopened.delete(entry.id);assertTrue(reopened.entries().isEmpty())
    }
    @Test fun hardwareAgreementMatchesOnlyItsExactFile(){
        val value=identity();val raw=frame(value.getString("fingerprint"));val vault=NpvsIdentityVault(context)
        val capture=JSONObject().put("schema","spdecode.npvs.recipient.v1").put("kind","agreement")
            .put("source","captured").put("curve","P-256").put("fingerprint",value.getString("fingerprint"))
            .put("peer",value.getString("publicKey")).put("sharedSecret",b64(ByteArray(32){1}))
            .put("fileSha256",sha(raw))
        val entry=vault.save(capture);vault.enable(true)
        assertEquals(entry.id,vault.matching(raw).single().id)
        val other=raw.copyOf().also{it[it.lastIndex]=1}
        assertTrue(vault.matching(other).isEmpty())
    }
    @Test fun mixedPairsDuplicateJsonAndModifiedCiphertextFailClosed(){
        val value=identity();val mixed=JSONObject(value.toString()).put("privateKey",identity().getString("privateKey"))
        assertTrue(runCatching{NpvsIdentityVault.validate(mixed)}.isFailure)
        val duplicate=value.toString().dropLast(1)+",\"kind\":\"keypair\"}"
        assertTrue(runCatching{NpvsIdentityVault.parse(duplicate)}.isFailure)
        val vault=NpvsIdentityVault(context);val entry=vault.save(value)
        val path=File(root,"npvs-identities-v1/${entry.id}.npvk")
        val raw=path.readBytes();raw[raw.lastIndex]=(raw.last().toInt() xor 1).toByte();path.writeBytes(raw)
        assertTrue(runCatching{vault.entries()}.isFailure)
    }
}
