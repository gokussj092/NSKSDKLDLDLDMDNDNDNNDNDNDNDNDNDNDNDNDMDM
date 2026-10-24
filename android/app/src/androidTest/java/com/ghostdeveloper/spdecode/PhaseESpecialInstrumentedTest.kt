package com.ghostdeveloper.spdecode

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.google.gson.JsonParser
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** E.1–E.3: actual API35 routing of original Python source-encrypted fixtures. */
@RunWith(AndroidJUnit4::class)
class PhaseESpecialInstrumentedTest {
    private val inst get()=InstrumentationRegistry.getInstrumentation()
    private val context get()=inst.targetContext
    private val inventory by lazy {AndroidDecoderCatalog.read(context)}
    private val evidence by lazy {
        JSONObject(inst.context.assets.open("parity/e-special-fixtures.json")
            .bufferedReader(Charsets.UTF_8).use{it.readText()})
    }
    private val vectors by lazy{evidence.getJSONArray("vectors")}
    private fun reference(row:JSONObject) {
        val suffix=row.getString("suffix")
        val mode=row.getString("mode")
        val input=Base64.decode(row.getString("encodedInput"),Base64.DEFAULT)
        val actual=AndroidOfflineDecoderRouter.decode(context,"example.$suffix",input)
        assertNotNull("Phase E $suffix mode=$mode",actual)
        val expected=row.getString("expected")
        val parsed=try {JsonParser.parseString(expected)}catch(_:Exception){null}
        if(parsed!=null && !parsed.isJsonPrimitive)
            assertEquals("Complete Python JSON parity: $suffix mode=$mode",
                parsed,JsonParser.parseString(actual!!))
        else assertEquals("Python text output: $suffix mode=$mode",
                expected.trim(),actual!!.trim())
    }
    private fun verify(group:Set<String>,size:Int) {
        val seen=mutableSetOf<String>()
        for(i in 0 until vectors.length()){
            val row=vectors.getJSONObject(i)
            if(row.getString("mode")!="outer" || row.getString("suffix") !in group)continue
            reference(row);seen.add(row.getString("suffix"))
        }
        assertEquals(group,seen)
        assertEquals(size,seen.size)
        for(suffix in seen){
            val f=AndroidDecoderCatalog.detect("file.$suffix",inventory)
            assertEquals("E",f?.migrationPhase)
            assertTrue(f!!.hasNativeDecoder)
        }
    }
    @Test fun E1AllEightNativeFormats(){
        verify(setOf("st","itv","eut","v2box","slipnet","juanscript","juan","mobi"),8)
    }
    @Test fun E2AllTenNativeFormats(){
        verify(setOf("wyrvpnlite","wyrlite","wyrl","wyr","int","fthp","ftp","ar","msy","ec"),10)
    }
    @Test fun E3AllNineXorFormats(){
        verify(setOf("apnalite","apnatnl","bdnet","hxt","fnf","4ulite","omanova","ursa","hsome"),9)
    }
    @Test fun optionalCryptographicVariants(){
        val modes=mutableSetOf<String>()
        for(i in 0 until vectors.length()){
            val row=vectors.getJSONObject(i)
            if(row.getString("mode")=="outer")continue
            if(row.getString("mode")=="password_required" &&
                row.getString("suffix")=="v2box") {
                // A protected V2Box synthetic fixture intentionally has no user
                // password. The guarded path must request credentials, never
                // silently claim a successful decryption.
                val input=Base64.decode(row.getString("encodedInput"),Base64.DEFAULT)
                assertTrue(com.ghostdeveloper.spdecode.cloud.V2BoxPasswordProbe.requiresPassword(input))
                assertNull(AndroidOfflineDecoderRouter.decode(context,"sample.v2box",input))
            }else reference(row)
            modes.add(row.getString("mode"))
        }
        assertEquals(setOf("aes_gcm","optional_header","secondary_key","password_required"),modes)
    }
    @Test fun inventoryIsExactAndOtherFamiliesPreserved(){
        assertEquals(27,evidence.getInt("suffixCount"))
        assertEquals(31,evidence.getInt("caseCount"))
        assertEquals(13,evidence.getJSONArray("modules").length())
        assertEquals(239,inventory.size)
        assertEquals(239,inventory.count{it.hasNativeDecoder})
        assertEquals(0,inventory.count{it.isPending})
        assertEquals(27,inventory.count{it.migrationPhase=="E"&&it.hasNativeDecoder})
        assertEquals(13,inventory.count{it.migrationPhase=="F"&&it.hasNativeDecoder})
        for(name in listOf("vlx","ost","7net","npvs")){
            val f=AndroidDecoderCatalog.detect("file.$name",inventory)
            assertNotNull(f);assertTrue(f!!.hasNativeDecoder)
            assertTrue(f.migrationPhase!="E")
        }
        assertTrue(AndroidDecoderCatalog.detect("file.izph",inventory)!!.hasNativeDecoder)
    }
    @Test fun failClosedForUnknownAndWrongFamilies(){
        for(suffix in listOf("st","slipnet","mobi","fthp","int","ec","apnalite","wyr")){
            assertNull("Malformed input must fail: $suffix",
                AndroidOfflineDecoderRouter.decode(context,"bad.$suffix",byteArrayOf(0,1,2,3)))
        }
        assertNull(AndroidOfflineDecoderRouter.decode(context,"bad.izph",
            "not a native configuration".toByteArray()))
        assertNull(AndroidOfflineDecoderRouter.decode(context,"bad.v2box",
            "{\"magic\":\"v2box_export\"}".toByteArray()))
        assertNull(AndroidOfflineDecoderRouter.decode(context,"bad.st",ByteArray(0)))
    }
}
