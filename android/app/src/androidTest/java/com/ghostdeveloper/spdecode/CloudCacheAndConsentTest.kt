package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.cloud.CloudDecodeClient
import com.ghostdeveloper.spdecode.cloud.CloudLegalConsent
import com.ghostdeveloper.spdecode.cloud.ServerVpnSecureCache
import java.io.File
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Device tests use the real Android Keystore. No test production credentials
 * or historical decoder material are included in these inputs.
 */
@RunWith(AndroidJUnit4::class)
class CloudCacheAndConsentTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val cacheDir get() = File(context.noBackupFilesDir,"server_vpn_cache/v1")

    @Test fun roundTripHasUniqueNoncesAndNoPlaintextOnDisk() {
        val name="probe-"+UUID.randomUUID().toString().replace("-","")
        val content="""{"catalogVersion":2,"private":"never-in-plaintext"}""".toByteArray()
        val file=File(cacheDir,name)
        try {
            val vault=ServerVpnSecureCache(context)
            vault.write(name,content)
            val first=file.readBytes()
            assertFalse(first.toString(Charsets.UTF_8).contains("never-in-plaintext"))
            assertArrayEquals(content,vault.read(name))
            vault.write(name,content)
            val second=file.readBytes()
            assertFalse(first.contentEquals(second))
            assertArrayEquals(content,ServerVpnSecureCache(context).read(name))
        } finally { file.delete() }
    }

    @Test fun tamperingOrRenamingEncryptedRecordsFailsAuthentication() {
        val id=UUID.randomUUID().toString().replace("-","")
        val name="probe-$id"
        val other="other-$id"
        val original=File(cacheDir,name)
        val renamed=File(cacheDir,other)
        try {
            val vault=ServerVpnSecureCache(context)
            vault.write(name,"authenticated".toByteArray())
            val mutated=original.readBytes()
            mutated[mutated.lastIndex]=(mutated.last().toInt() xor 1).toByte()
            original.writeBytes(mutated)
            assertNull(vault.read(name))
            vault.write(name,"authenticated".toByteArray())
            original.copyTo(renamed,overwrite=true)
            assertNull(vault.read(other))
        } finally {
            original.delete()
            renamed.delete()
        }
    }

    @Test fun illegalIdentifiersAreRejected() {
        val vault=ServerVpnSecureCache(context)
        for(name in listOf("../legal","catalog.json","/tmp/file","ICON_UPPER","")) {
            try {
                vault.write(name,byteArrayOf(1))
                fail("Unsafe cache filename accepted: $name")
            } catch(_:IllegalArgumentException) { /* expected */ }
        }
    }

    @Test fun withdrawalBlocksCloudWithoutErasingEncryptedCatalog() {
        val legal=File(cacheDir,"legal")
        val backup=legal.takeIf { it.isFile }?.readBytes()
        val catalog=File(cacheDir,"probe-consent-${UUID.randomUUID().toString().replace("-","")}")
        try {
            val store=ServerVpnSecureCache(context)
            store.write(catalog.name,"local-cached-icon".toByteArray())
            CloudLegalConsent.accept(context)
            assertTrue(CloudLegalConsent.accepted(context))
            CloudLegalConsent.revoke(context)
            assertFalse(CloudLegalConsent.accepted(context))
            assertArrayEquals("local-cached-icon".toByteArray(),store.read(catalog.name))
        }finally {
            catalog.delete()
            if(backup==null)legal.delete()else legal.writeBytes(backup)
        }
    }

    @Test fun publicCatalogNetworkIsBlockedWithoutAcceptedTerms() {
        val legal=File(cacheDir,"legal")
        val previous=legal.takeIf { it.isFile }?.readBytes()
        try {
            CloudLegalConsent.revoke(context)
            assertFalse(CloudLegalConsent.accepted(context))
            try {
                runBlocking { CloudDecodeClient(context).serverVpnCatalog(0) }
                fail("Catalog accessed without legal consent")
            }catch(error:CloudDecodeClient.Failure) {
                assertEquals("LEGAL_CONSENT_REQUIRED",error.code)
                assertEquals(403,error.httpStatus)
            }
        }finally {
            if(previous==null) legal.delete() else legal.writeBytes(previous)
        }
    }

    @Test fun consentIsEncryptedAndBoundToCurrentLegalVersion() {
        val file=File(cacheDir,"legal")
        val before=file.takeIf { it.isFile }?.readBytes()
        try {
            CloudLegalConsent.accept(context)
            assertTrue(CloudLegalConsent.accepted(context))
            assertFalse(file.readBytes().toString(Charsets.UTF_8).contains("accepted"))
            val data=file.readBytes()
            data[data.lastIndex]=(data.last().toInt() xor 1).toByte()
            file.writeBytes(data)
            assertFalse(CloudLegalConsent.accepted(context))
        } finally {
            if(before==null) file.delete() else file.writeBytes(before)
        }
    }
}
