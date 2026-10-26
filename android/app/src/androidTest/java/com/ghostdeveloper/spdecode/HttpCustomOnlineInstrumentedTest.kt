package com.ghostdeveloper.spdecode.cloud

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class HttpCustomOnlineInstrumentedTest {
    @Test fun oneDownloadSurvivesDualCredentialChallengeAndErasesBytes()=runBlocking {
        val input=byteArrayOf(1,2,3,4)
        val password="test-only".toByteArray()
        var downloads=0;var calls=0;var prompts=0
        val result=HttpCustomOnlineFlow.run(
            download={downloads++;input},
            decode={bytes,pw,hwid->
                assertSame(input,bytes);assertArrayEquals(byteArrayOf(1,2,3,4),bytes)
                calls++
                if(calls==1)throw CloudDecodeClient.Failure("HWID_PASSWORD_REQUIRED",422)
                assertSame(password,pw);assertEquals("A".repeat(32),hwid)
                "{\"complete\":true}"
            },prompt={pw,id->
                prompts++;assertTrue(pw);assertTrue(id)
                HttpCustomOnlineFlow.Credentials(password,"A".repeat(32))
            })
        assertEquals("{\"complete\":true}",result)
        assertEquals(1,downloads);assertEquals(2,calls);assertEquals(1,prompts)
        assertTrue(input.all{it==0.toByte()});assertTrue(password.all{it==0.toByte()})
    }

    @Test fun unavailableReferenceNeverInvokesDecoderOrCredentialPrompt()=runBlocking {
        try {
            HttpCustomOnlineFlow.run(
                download={throw CloudDecodeClient.Failure("REMOTE_CONFIG_UNAVAILABLE",410)},
                decode={_,_,_->error("must not decrypt missing data")},
                prompt={_,_->error("must not ask credentials for expired link")})
            fail("expected typed expired-link error")
        }catch(e:CloudDecodeClient.Failure){assertEquals("REMOTE_CONFIG_UNAVAILABLE",e.code)}
    }

    @Test fun wrongPasswordAndCancellationEraseInputWithoutRedownloading()=runBlocking {
        for(cancel in listOf(false,true)) {
            val input=byteArrayOf(7,8,9);val password=byteArrayOf(4,5)
            var downloads=0;var calls=0
            try {
                HttpCustomOnlineFlow.run(download={downloads++;input},
                    decode={_,_,_->calls++;throw CloudDecodeClient.Failure(
                        if(calls==1)"PASSWORD_REQUIRED" else "AUTH_FAILED",422)},
                    prompt={_,_->if(cancel)null else HttpCustomOnlineFlow.Credentials(password,null)})
                fail("expected cancellation/authentication failure")
            }catch(e:CancellationException){assertTrue(cancel)}
             catch(e:CloudDecodeClient.Failure){
                assertFalse(cancel);assertEquals("AUTH_FAILED",e.code)
                assertTrue(e.passwordSubmitted);assertFalse(e.hwidSubmitted)
            }
            assertEquals(1,downloads);assertTrue(input.all{it==0.toByte()})
            if(!cancel)assertTrue(password.all{it==0.toByte()})
        }
    }

    @Test fun fixedReferencesAreRecognizedWithStrictDestinationSyntax(){
        for(link in listOf("https://cloudvpn.mrfrankofc.com/Ab12Cd","https://link.playsmarty.uk/test-link")){
            assertTrue(HttpCustomCloudReference.matches(link))
            assertEquals("hc",CloudTextFormats.identify(link)?.suffix)
        }
        for(link in listOf("http://link.playsmarty.uk/Ab12Cd","https://link.playsmarty.uk@evil.test/Ab12Cd",
            "https://link.playsmarty.uk/../admin","https://cloudvpn.mrfrankofc.com/Ab12Cd?redirect=http://127.0.0.1"))
            assertFalse(HttpCustomCloudReference.matches(link))
    }
}
