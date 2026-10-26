package com.ghostdeveloper.spdecode.cloud

import androidx.compose.runtime.*
import com.ghostdeveloper.spdecode.HcProtectedImportDialog
import com.ghostdeveloper.spdecode.parity.HcHccfgPort
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Reuse the secure HC dialog; no URI, payload, password or HWID is persisted. */
internal object HttpCustomCloudPrompt {
    private data class Pending(val password:Boolean,val hwid:Boolean,
        val result:CompletableDeferred<HttpCustomOnlineFlow.Credentials?>)
    private val mutex=Mutex()
    private var active by mutableStateOf<Pending?>(null)
    val isShowing:Boolean get()=active!=null

    suspend fun ask(password:Boolean,hwid:Boolean):HttpCustomOnlineFlow.Credentials?=mutex.withLock {
        val pending=Pending(password,hwid,CompletableDeferred())
        withContext(Dispatchers.Main.immediate){active=pending}
        try { pending.result.await() }
        finally {
            withContext(NonCancellable+Dispatchers.Main.immediate){
                if(active===pending)active=null
            }
        }
    }

    @Composable fun Content(){
        val pending=active?:return
        key(pending) {
            HcProtectedImportDialog("HTTP Custom Cloud.hc",
                HcHccfgPort.Requirements(passwordRequired=pending.password,
                    hwidRequired=pending.hwid,headerAuthenticated=false,schema=0,schedule="cloud"),
                onSubmit={password,hwid->
                    val value=HttpCustomOnlineFlow.Credentials(password?.toByteArray(Charsets.UTF_8),hwid)
                    if(!pending.result.complete(value))value.password?.fill(0)
                },onCancel={pending.result.complete(null)})
        }
    }
}
