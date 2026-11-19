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

    @Test fun detectTunneltweakCloudUuidAndExplicitReference() {
        val id="00000000-0000-4000-8000-000000000001"
        for(input in listOf(id,"tunneltweak://"+id,"TUNNELTWEAK://"+id.uppercase())) {
            val result=CloudOnlineReference.resolve(input,"auto",emptyList())
            assertNotNull(result)
            assertEquals("tunneltweak",result!!.provider)
            assertEquals(id,result.reference)
            assertEquals("tut",result.suffix)
            assertEquals("tunneltweak-cloud.tut",result.filename)
        }
        val explicit=CloudOnlineReference.resolve(id,"tunneltweak",emptyList())
        assertEquals("tunneltweak",explicit!!.provider)
        assertTrue(CloudOnlineReference.options(emptyList()).any{
            it.id=="tunneltweak" && it.name=="Tunneltweak Cloud"
        })
    }

    @Test fun malformedAndUnknownCloudUuidsDoNotSelectOtherProviders() {
        val id="00000000-0000-4000-8000-000000000001"
        for(input in listOf(id.dropLast(1),id+"?next=http://127.0.0.1",
            "https://tunneltweak.com/api/cloudconfig/"+id,
            "tunneltweak://../"+id,"tunneltweak://"+id+"/secret",
            "00000000-0000-0000-0000-00000000000g")) {
            assertNull(CloudOnlineReference.resolve(input,"auto",emptyList()))
        }
        assertNull(CloudOnlineReference.resolve(id,"ehi",emptyList()))
        assertNull(CloudOnlineReference.resolve(id,"hc",emptyList()))
    }

    @Test fun malformedHexCustomIdsDoNotCallTheServer() {
        assertNull(CloudOnlineReference.resolve("HexCustom-AbCd1234E","auto",emptyList()))
        assertNull(CloudOnlineReference.resolve("HexCustom-AbCd1234Ef!","auto",emptyList()))
        assertNull(CloudOnlineReference.resolve("hexcustom-AbCd1234Ef","auto",emptyList()))
    }
}
