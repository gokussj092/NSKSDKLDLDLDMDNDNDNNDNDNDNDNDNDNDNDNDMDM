package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ghostdeveloper.spdecode.cloud.NpvsPasswordProbe
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NpvsPasswordProbeInstrumentedTest {
    private fun write32(array:ByteArray,index:Int,value:Int) {
        array[index]=(value ushr 24).toByte()
        array[index+1]=(value ushr 16).toByte()
        array[index+2]=(value ushr 8).toByte()
        array[index+3]=value.toByte()
    }

    private fun example(mode:Int=1,version:Int=5):ByteArray {
        val headerLength=53+80+4+228
        val bodyLength=200
        val bytes=ByteArray(9+headerLength+16+bodyLength+64)
        "NPVS".toByteArray().copyInto(bytes)
        bytes[4]=version.toByte()
        write32(bytes,5,headerLength)
        bytes[9]=1
        bytes[9+50]=mode.toByte()
        write32(bytes,9+53,600000)
        write32(bytes,9+133,228)
        write32(bytes,9+headerLength+12,bodyLength)
        return bytes
    }

    @Test fun passwordV5NeedsDialogAndNormalV5DoesNot() {
        assertTrue(NpvsPasswordProbe.requiresPassword(example()))
        assertFalse(NpvsPasswordProbe.requiresPassword(example(mode=0)))
        assertFalse(NpvsPasswordProbe.requiresPassword(example(mode=2)))
        assertFalse(NpvsPasswordProbe.requiresPassword(example(version=6)))
    }

    @Test fun malformedAndTruncatedInputsDoNotTriggerPasswordDialog() {
        val original=example()
        assertFalse(NpvsPasswordProbe.requiresPassword(ByteArray(5)))
        assertFalse(NpvsPasswordProbe.requiresPassword(original.copyOf(original.size-1)))
        val wrongHeader=original.copyOf()
        wrongHeader[9+53]=0
        wrongHeader[9+54]=0
        wrongHeader[9+55]=0
        wrongHeader[9+56]=0
        assertFalse(NpvsPasswordProbe.requiresPassword(wrongHeader))
        val badMetadata=original.copyOf()
        write32(badMetadata,9+133,2)
        assertFalse(NpvsPasswordProbe.requiresPassword(badMetadata))
    }
}
