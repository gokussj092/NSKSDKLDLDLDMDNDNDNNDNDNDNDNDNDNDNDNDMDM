package com.ghostdeveloper.spdecode

import android.content.Context
import android.util.Base64
import androidx.compose.foundation.layout.Column
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.cloud.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.*
import java.security.spec.*
import javax.crypto.Cipher
import javax.crypto.SecretKey

@RunWith(AndroidJUnit4::class)
class CatalogFeaturesInstrumentedTest {
    @get:Rule val compose=createComposeRule()
    private val context get()=InstrumentationRegistry.getInstrumentation().targetContext
    private fun bytes(s:String)=Base64.decode(s,Base64.URL_SAFE or Base64.NO_WRAP)
    @Test fun serverEnvelopeOpensOnAndroidAndTamperingFails() {
        val fixture=InstrumentationRegistry.getInstrumentation().context.assets.open("catalog-envelope-vector.json").bufferedReader().use {JSONObject(it.readText())}
        val factory=KeyFactory.getInstance("EC")
        val pair=KeyPair(factory.generatePublic(X509EncodedKeySpec(bytes(fixture.getString("publicKey")))),
            factory.generatePrivate(PKCS8EncodedKeySpec(bytes(fixture.getString("privateKey")))))
        val envelope=fixture.getJSONObject("envelope")
        fun openFixture(source:JSONObject,purpose:String):JSONObject {
            val packed=CloudNativeTransport.openCatalog(pair.private.encoded,
                fixture.getString("publicKey"),purpose,source.getString("serverKey"),
                source.getString("salt"),source.getString("iv"),source.getInt("plainBytes"),
                source.getString("data"))
            return JSONObject(String(CatalogEnvelope.inflate(packed,source.getInt("plainBytes"))))
        }
        val result=openFixture(envelope,"catalog")
        assertEquals("México 👻 漢字",result.getJSONArray("apps").getJSONObject(0).getString("name"))
        assertEquals(73,result.getInt("catalogVersion"))
        for(kind in listOf("length","ciphertext","purpose")) {
            val bad=JSONObject(envelope.toString())
            if(kind=="length")bad.put("plainBytes",bad.getInt("plainBytes")+1)
            if(kind=="ciphertext") {val data=bytes(bad.getString("data"));data[0]=(data[0].toInt() xor 1).toByte();
                bad.put("data",Base64.encodeToString(data,Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))}
            try{openFixture(bad,if(kind=="purpose")"icon" else "catalog");fail("Tampered envelope accepted")}
            catch(_:Exception){ /* Expected authenticated rejection. AssertionError is not swallowed. */ }
        }
        CatalogEnvelope().use { recipient ->
            try{recipient.open(envelope,"catalog");fail("Wrong recipient accepted")}
            catch(_:Exception){ /* Native-generated key must not authenticate saved fixture. */ }
        }
    }
    @Test fun cacheReadsLegacyRecordsAndWritesCompressedAuthenticatedRecords() {
        val cache=ServerVpnSecureCache(context);val name="instrument-notice-catalog"
        val source="catalog 👻".repeat(500).toByteArray()
        val file=File(context.noBackupFilesDir,"server_vpn_cache/v1/$name")
        try {
            cache.write(name,source);assertArrayEquals("Compressed SVC2 round trip",source,cache.read(name))
            assertEquals(0x32,file.readBytes()[3].toInt());assertTrue(file.length()<source.size)
            val ks=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
            val key=ks.getKey("spdecode.server-vpn.device-cache.v1",null) as SecretKey
            val cipher=Cipher.getInstance("AES/GCM/NoPadding").apply {init(Cipher.ENCRYPT_MODE,key)
                updateAAD("spdecode:server-vpn:v1:$name".toByteArray())}
            file.writeBytes(byteArrayOf(0x53,0x56,0x43,0x31)+cipher.iv+cipher.doFinal(source))
            assertArrayEquals("Legacy SVC1 round trip",source,cache.read(name))
            val maximum=ByteArray(ServerVpnIconPolicy.CACHE_RECORD_BYTES) { (it % 31).toByte() }
            cache.write(name,maximum)
            assertArrayEquals("Existing 6 MiB cache budget remains readable",maximum,cache.read(name))
            val packed=java.io.ByteArrayOutputStream().also {out->
                java.util.zip.GZIPOutputStream(out).use {it.write(maximum)}
            }.toByteArray()
            try {CatalogEnvelope.inflate(packed,CatalogEnvelope.MAX_PLAIN);fail("Wire decompression exceeded 4 MiB")}
            catch(_:IllegalArgumentException) { /* Wire and cache retain independent bounded budgets. */ }
            cache.write(name,source)
            val damaged=file.readBytes();damaged[damaged.lastIndex]=(damaged.last().toInt() xor 1).toByte();file.writeBytes(damaged)
            assertNull(cache.read(name))
        }finally{cache.delete(name)}
    }
    @Test fun compactRefreshAndEmptyLoadingRenderWithoutChangingPalette() {
        compose.setContent {SpDecodeAmoledTheme {Column {
            CatalogRefreshControl(false,true,{})
            CatalogEmptyLoading(73)
        }}}
        compose.onNodeWithTag("server_vpn_manual_refresh").assertIsEnabled()
        compose.onNodeWithText(context.getString(R.string.catalog_check_action)).assertExists()
        compose.onNodeWithTag("catalog_empty_loading").assertExists()
        compose.onNodeWithText(context.getString(R.string.catalog_progress,73)).assertExists()
    }
    @Test fun donationsShowBothPaymentMethodsAndTheExactAccount() {
        compose.setContent {SpDecodeAmoledTheme {DonationSettingsCard()}}
        compose.onNodeWithText("Binance").assertExists()
        compose.onNodeWithText("Ghost Developer\nID: 1233239512").assertExists()
        compose.onNodeWithText("PayPal").assertExists()
        compose.onNodeWithText(context.getString(R.string.donation_coming_soon)).assertExists()
    }
    @Test fun exportsPreserveBasenamesAndRemoveUnsafePathCharacters() {
        assertEquals("Mi archivo (Unlocked).hc",CompatibleExportFilename.forSource("Mi archivo.hc","hc"))
        assertEquals("Servidor 👻 (Unlocked).ehi",CompatibleExportFilename.forSource("Servidor 👻.ehi","ehi"))
        assertEquals("config (Unlocked).dark",CompatibleExportFilename.forSource("/../../.dark","dark"))
        assertEquals("Mi archivo (Unlocked).npvs",CompatibleExportFilename.forSource("Mi archivo (Unlocked).npvs","npvs"))
        assertFalse(CompatibleExportFilename.forSource("../\u202esecreto\n.ehi","ehi").contains('\u202e'))
    }
    @Test fun notificationOptInIsNeverImplicit() {
        CloudNotifications.setEnabled(context,false)
        assertFalse(CloudNotifications.enabled(context))
    }
}
