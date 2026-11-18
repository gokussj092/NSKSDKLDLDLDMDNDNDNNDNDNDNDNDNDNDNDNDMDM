package com.ghostdeveloper.spdecode.cloud

import org.junit.Assert.*
import org.junit.Test

/** No live Firestore call: verify that Android routes a valid Hex Custom key
 * to the approved cloud broker without first requiring a provider picker. */
class CloudOnlineReferenceTest {
    @Test fun automaticHexCustomDetection() {
        val found=CloudOnlineReference.resolve("HexCustom-AbCd1234Ef","auto",emptyList())
        assertNotNull(found)
        assertEquals("hexcustom",found!!.provider)
        assertEquals("hexcm",found.suffix)
        assertEquals("hex-custom-cloud.hexcm",found.filename)
    }

    @Test fun malformedHexCustomIdsDoNotCallTheServer() {
        assertNull(CloudOnlineReference.resolve("HexCustom-AbCd1234E","auto",emptyList()))
        assertNull(CloudOnlineReference.resolve("HexCustom-AbCd1234Ef!","auto",emptyList()))
        assertNull(CloudOnlineReference.resolve("hexcustom-AbCd1234Ef","auto",emptyList()))
    }
}
