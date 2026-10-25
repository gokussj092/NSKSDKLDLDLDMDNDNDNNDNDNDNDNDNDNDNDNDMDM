package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import com.ghostdeveloper.spdecode.R
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.UUID

/** In-app Compose selection. No Activity, task, intent, or key material in UI state. */
internal object NpvsRecipientPicker {
    private data class Choice(val id:String,val label:String)
    private data class Pending(val ticket:String,val choices:List<Choice>,
        val decision:CompletableDeferred<String?>)
    private val mutex=Mutex()
    private var active by mutableStateOf<Pending?>(null)
    val isShowing:Boolean get()=active!=null

    suspend fun choose(context:Context,bytes:ByteArray):String?=mutex.withLock {
        val vault=NpvsIdentityVault(context)
        val choices=withContext(Dispatchers.IO){vault.matching(bytes)}
        if(choices.isEmpty())return@withLock null
        val labels=choices.map { entry ->
            val source=context.getString(if(entry.source=="generated")R.string.npv_generated
                else R.string.npv_captured)
            val suffix=if(entry.kind=="agreement")" · "+context.getString(R.string.npv_file_only) else ""
            Choice(entry.id,source+" · "+entry.fingerprint.take(16)+suffix)
        }
        val pending=Pending(UUID.randomUUID().toString(),labels,CompletableDeferred())
        withContext(Dispatchers.Main.immediate){active=pending}
        try {
            val selected=pending.decision.await()
                ?:throw CloudDecodeClient.Failure("PRIVATE_KEY_REQUIRED",422)
            // Validate the original file, current opt-in, and persisted identity
            // again immediately before material is sent over the existing TLS channel.
            return@withLock withContext(Dispatchers.IO) {
                vault.matching(bytes).firstOrNull{it.id==selected}
                    ?.material?.toString()
                    ?:throw CloudDecodeClient.Failure("PRIVATE_KEY_REQUIRED",422)
            }
        } finally {
            withContext(NonCancellable+Dispatchers.Main.immediate) {
                if(active===pending)active=null
            }
        }
    }

    @Composable
    fun Content() {
        val pending=active?:return
        key(pending.ticket) {
            var selectedId by remember {mutableStateOf(pending.choices.first().id)}
            AlertDialog(
                onDismissRequest={pending.decision.complete(null)},
                properties=DialogProperties(securePolicy=SecureFlagPolicy.SecureOn),
                icon={Icon(Icons.Outlined.Shield,null,tint=Color(0xFF38A36D))},
                title={Text(stringResource(R.string.npv_choose_title),fontWeight=FontWeight.Bold)},
                text={
                    Column(verticalArrangement=Arrangement.spacedBy(12.dp)) {
                        Text(stringResource(R.string.npv_send_notice),
                            color=Color(0xFFABABAB))
                        Column(Modifier.heightIn(max=340.dp).verticalScroll(rememberScrollState()),
                            verticalArrangement=Arrangement.spacedBy(8.dp)) {
                            pending.choices.forEach { choice ->
                                val selected=choice.id==selectedId
                                Surface(
                                    color=if(selected)Color(0xFF242424)else Color(0xFF171717),
                                    shape=RoundedCornerShape(14.dp),
                                    border=BorderStroke(1.dp,
                                        if(selected)Color(0xFF38A36D)else Color(0xFF333333)),
                                    modifier=Modifier.fillMaxWidth().clickable { selectedId=choice.id }
                                ) {
                                    Row(Modifier.padding(12.dp),verticalAlignment=Alignment.CenterVertically) {
                                        RadioButton(selected=selected,onClick={selectedId=choice.id},
                                            colors=RadioButtonDefaults.colors(
                                                selectedColor=Color(0xFF38A36D),
                                                unselectedColor=Color(0xFFABABAB)))
                                        Spacer(Modifier.width(8.dp))
                                        Text(choice.label,color=Color.White,
                                            style=MaterialTheme.typography.bodyMedium)
                                    }
                                }
                            }
                        }
                    }
                },
                confirmButton={TextButton(onClick={pending.decision.complete(selectedId)}) {
                    Text(stringResource(R.string.npv_use),color=Color.White)
                }},
                dismissButton={TextButton(onClick={pending.decision.complete(null)}) {
                    Text(stringResource(R.string.npv_cancel),color=Color(0xFFABABAB))
                }},
                containerColor=Color.Black,
                titleContentColor=Color.White,
                textContentColor=Color(0xFFABABAB),
                shape=RoundedCornerShape(22.dp)
            )
        }
    }
}
