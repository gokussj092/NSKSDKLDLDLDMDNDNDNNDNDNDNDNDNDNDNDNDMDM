package com.ghostdeveloper.spdecode.cloud

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import com.ghostdeveloper.spdecode.R
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** Non-exported, secure chooser. Intent carries an opaque ticket, never key material. */
internal class NpvsRecipientActivity:Activity() {
    private var ticket:String?=null
    private var dialog:AlertDialog?=null
    override fun onCreate(savedInstanceState:Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        ticket=intent.getStringExtra("ticket")
        val pending=ticket?.let{requests[it]}?:run{finish();return}
        var selected=0
        dialog=AlertDialog.Builder(this).setTitle(getString(R.string.npv_choose_title)+"\n"+getString(R.string.npv_send_notice))
            .setSingleChoiceItems(pending.labels.toTypedArray(),0){_,which->selected=which}
            .setPositiveButton(R.string.npv_use){_,_->pending.result.complete(pending.ids[selected]);finish()}
            .setNegativeButton(android.R.string.cancel){_,_->pending.result.complete(null);finish()}
            .setOnCancelListener{pending.result.complete(null);finish()}.create()
        pending.activity=this
        dialog?.show()
    }
    override fun onDestroy(){
        ticket?.let{requests[it]?.result?.complete(null)}
        dialog?.dismiss();super.onDestroy()
    }
    private data class Pending(val ids:List<String>,val labels:List<String>,
        val result:CompletableDeferred<String?>,var activity:NpvsRecipientActivity?=null)
    companion object {
        private val requests=ConcurrentHashMap<String,Pending>()
        suspend fun choose(context:Context,bytes:ByteArray):String? {
            val vault=NpvsIdentityVault(context)
            val choices=withContext(Dispatchers.IO){vault.matching(bytes)}
            if(choices.isEmpty())return null
            val ticket=UUID.randomUUID().toString()
            val labels=choices.map {
                context.getString(if(it.source=="generated")R.string.npv_generated else R.string.npv_captured)+
                    " · "+it.fingerprint.take(16)+
                    if(it.kind=="agreement")" · "+context.getString(R.string.npv_file_only) else ""
            }
            val pending=Pending(choices.map{it.id},labels,CompletableDeferred())
            requests[ticket]=pending
            try {
                withContext(Dispatchers.Main) {
                    context.startActivity(Intent(context,NpvsRecipientActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).putExtra("ticket",ticket))
                }
                val selected=pending.result.await()?:throw CloudDecodeClient.Failure("PRIVATE_KEY_REQUIRED",422)
                // Recheck opt-in and identity/file binding immediately before sending.
                return withContext(Dispatchers.IO){vault.matching(bytes).firstOrNull{it.id==selected}
                    ?.material?.toString()?:throw CloudDecodeClient.Failure("PRIVATE_KEY_REQUIRED",422)}
            }finally{
                requests.remove(ticket)
                withContext(kotlinx.coroutines.NonCancellable+Dispatchers.Main){pending.activity?.finish()}
            }
        }
    }
}
