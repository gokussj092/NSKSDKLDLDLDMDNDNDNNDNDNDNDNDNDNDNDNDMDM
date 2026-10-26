package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.ghostdeveloper.spdecode.parity.NpvsJson
import com.ghostdeveloper.spdecode.parity.NpvsWhitebox
import com.ghostdeveloper.spdecode.parity.NpvsWhiteboxEvaluator
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** SHA-pinned NPVS v5 Python/Kotlin white-box vectors, plus fail-closed routing. */
@RunWith(AndroidJUnit4::class)
class NpvsV5InstrumentedTest {
    private val context get()=InstrumentationRegistry.getInstrumentation().targetContext
    private fun hex(text:String):ByteArray=ByteArray(text.length/2){
        text.substring(it*2,it*2+2).toInt(16).toByte()
    }
    @Test fun fourWhiteboxVectorsMatchUnmodifiedPython() {
        val evaluator=NpvsWhiteboxEvaluator(NpvsWhitebox.tables(context))
        for((sample,expected) in listOf(
            "00000000000000000000000000000000" to "4878126b14231f6f522f310686001524",
            "000102030405060708090a0b0c0d0e0f" to "f659c73d8c0fa5150e3254dfe0a1106d",
            "00112233445566778899aabbccddeeff" to "47e6155a8b2588d855972b60d123ce94",
            "ffffffffffffffffffffffffffffffff" to "65c2e1759568da2929e357d637c33664"
        )){
            assertArrayEquals(sample,hex(expected),evaluator.encrypt(hex(sample)))
        }
    }
    @Test fun tamperedOrUnsupportedNPVSNeverSucceeds() {
        val router=AndroidOfflineDecoderRouter
        assertNull(router.decode(context,"broken.npvs",ByteArray(0)))
        assertNull(router.decode(context,"broken.npvs",ByteArray(89)))
        val invalid=ByteArray(135){0}
        "NPVS".toByteArray().copyInto(invalid)
        invalid[4]=4
        assertNull(router.decode(context,"unsupported.npvs",invalid))
        assertNull(router.decode(context,"wrong.npvs",ByteArray(4*1024*1024+1)))
        assertNull(router.decode(context,"wrong.txt",invalid))
    }
    @Test fun sourceCanonicalizationMatchesApkMinimalEscaping() {
        // The APK preserves HTML and JavaScript separators in signed contexts.
        assertEquals("{\"a\":[false,null,\"日本語\"],\"b\":\"<>&\u2028\u2029\"}",
            NpvsJson.canonical(org.json.JSONObject()
                .put("b","<>&\u2028\u2029").put("a",org.json.JSONArray().put(false)
                    .put(org.json.JSONObject.NULL).put("日本語"))))
        assertEquals("\"\\n\\\"\\\\\\u0001\"",NpvsJson.canonical("\n\"\\\u0001"))
    }
}
