package com.ghostdeveloper.spdecode.cloud

/**
 * Structural-only NPVS v5 passphrase hint for the existing Android password
 * dialog. No decryption, recipient fallback, keys or network operations.
 *
 * The signed file and credentials are ALWAYS authenticated by the Cloud
 * NPVS worker. An invalid signature may match this framing and must still be
 * rejected by the worker; this helper never grants a success result.
 */
internal object NpvsPasswordProbe {
    private const val MAX_FILE_BYTES = 4 * 1024 * 1024
    private const val MIN_ITERATIONS = 600_000L
    private const val MAX_ITERATIONS = 10_000_000L

    private fun uint16(data:ByteArray,offset:Int):Int =
        ((data[offset].toInt() and 0xff) shl 8) or
            (data[offset+1].toInt() and 0xff)

    private fun uint32(data:ByteArray,offset:Int):Long =
        ((data[offset].toLong() and 0xff) shl 24) or
            ((data[offset+1].toLong() and 0xff) shl 16) or
            ((data[offset+2].toLong() and 0xff) shl 8) or
            (data[offset+3].toLong() and 0xff)

    fun requiresPassword(data:ByteArray):Boolean {
        if(data.size !in 89..MAX_FILE_BYTES ||
            data[0]!=0x4e.toByte() || data[1]!=0x50.toByte() ||
            data[2]!=0x56.toByte() || data[3]!=0x53.toByte() ||
            data[4]!=5.toByte())return false
        val headerLength=uint32(data,5)
        if(headerLength !in 135L..262144L || 9L+headerLength+80L>data.size)
            return false
        val start=9
        if(data[start]!=1.toByte() || data[start+50]!=1.toByte())
            return false
        val recipients=uint16(data,start+51)
        if(recipients>1024)return false
        val descriptorOffset=53L+recipients*125L
        val descriptorEnd=descriptorOffset+80L
        if(descriptorEnd+4L>headerLength)return false
        val descriptorPos=start+descriptorOffset.toInt()
        val iterations=uint32(data,descriptorPos)
        if(iterations !in MIN_ITERATIONS..MAX_ITERATIONS)return false
        val metadataLength=uint32(data,start+descriptorEnd.toInt())
        if(metadataLength<16L || descriptorEnd+4L+metadataLength!=headerLength)
            return false
        val encryptedBodyLength=uint32(data,start+headerLength.toInt()+12)
        if(encryptedBodyLength<70L ||
            9L+headerLength+16L+encryptedBodyLength+64L!=data.size.toLong())
            return false
        return true
    }
}
