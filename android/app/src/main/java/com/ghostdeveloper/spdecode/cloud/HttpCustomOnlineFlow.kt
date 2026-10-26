package com.ghostdeveloper.spdecode.cloud

import kotlinx.coroutines.CancellationException

/** One download, the existing file decoder, volatile encrypted bytes only. */
internal object HttpCustomOnlineFlow {
    data class Credentials(val password:ByteArray?,val hwid:String?)
    suspend fun run(
        download:suspend ()->ByteArray,
        decode:suspend (ByteArray,ByteArray?,String?)->String,
        prompt:suspend (Boolean,Boolean)->Credentials?,
    ):String {
        val bytes=download()
        try {
            try { return decode(bytes,null,null) }
            catch(error:CloudDecodeClient.Failure) {
                val locks=when(error.code){
                    "PASSWORD_REQUIRED"->true to false
                    "HWID_REQUIRED"->false to true
                    "HWID_PASSWORD_REQUIRED"->true to true
                    else->throw error
                }
                val credentials=prompt(locks.first,locks.second)
                    ?:throw CancellationException("Cloud import cancelled")
                try { return decode(bytes,credentials.password,credentials.hwid) }
                catch(failure:CloudDecodeClient.Failure){
                    throw CloudDecodeClient.Failure(failure.code,failure.httpStatus,
                        credentials.password!=null,credentials.hwid!=null)
                } finally { credentials.password?.fill(0) }
            }
        } finally { bytes.fill(0) }
    }
}
