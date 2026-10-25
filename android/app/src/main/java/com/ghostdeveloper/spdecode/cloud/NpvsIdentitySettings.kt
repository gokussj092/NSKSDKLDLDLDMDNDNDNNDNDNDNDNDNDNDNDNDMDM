package com.ghostdeveloper.spdecode.cloud

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import com.ghostdeveloper.spdecode.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun NpvsIdentitySettings() {
    val context=LocalContext.current
    val vault=remember{NpvsIdentityVault(context)}
    val client=remember{CloudDecodeClient(context)}
    val scope=rememberCoroutineScope()
    var entries by remember{mutableStateOf(emptyList<NpvsIdentityVault.Entry>())}
    var enabled by remember{mutableStateOf(false)}
    var working by remember{mutableStateOf(false)}
    var message by remember{mutableStateOf<String?>(null)}
    var shown by remember{mutableStateOf<NpvsIdentityVault.Entry?>(null)}
    var revealPrivate by remember{mutableStateOf(false)}
    var consent by remember{mutableStateOf(false)}
    fun refresh(){entries=vault.entries();enabled=vault.enabled()}
    LaunchedEffect(Unit){try{withContext(Dispatchers.IO){refresh()}}catch(_:Exception){message=context.getString(R.string.npv_invalid)}}
    val importer=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()){uri->
        if(uri!=null)scope.launch {
            working=true
            try {
                withContext(Dispatchers.IO){
                    val raw=context.contentResolver.openInputStream(uri)?.use{stream->
                        val output=java.io.ByteArrayOutputStream();val buffer=ByteArray(2048)
                        try{while(true){val n=stream.read(buffer);if(n<0)break
                            require(output.size()+n<=16384);output.write(buffer,0,n)};output.toByteArray()}
                        finally{buffer.fill(0)}
                    }?:error("input")
                    try{vault.save(NpvsIdentityVault.parse(String(raw,Charsets.UTF_8)));refresh()}
                    finally{raw.fill(0)}
                }
                message=context.getString(R.string.npv_saved)
            }catch(_:Exception){message=context.getString(R.string.npv_invalid)}finally{working=false}
        }
    }
    Surface(color=Color(0xFF242424),shape=RoundedCornerShape(16.dp),modifier=Modifier.fillMaxWidth()){
        Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.npv_title),style=MaterialTheme.typography.titleMedium,color=Color.White)
            Text(stringResource(R.string.npv_detail),color=Color(0xFFABABAB),style=MaterialTheme.typography.bodySmall)
            Row {
                Text(stringResource(R.string.npv_enabled),modifier=Modifier.weight(1f),color=Color.White)
                Switch(checked=enabled,enabled=!working,onCheckedChange={value->scope.launch {
                    try{withContext(Dispatchers.IO){vault.enable(value)};enabled=value}
                    catch(_:Exception){message=context.getString(R.string.npv_invalid)}
                }})
            }
            OutlinedButton(onClick={consent=true},enabled=!working,modifier=Modifier.fillMaxWidth()){
                Text(stringResource(R.string.npv_generate))}
            OutlinedButton(onClick={importer.launch(arrayOf("application/json","text/plain","application/octet-stream"))},
                enabled=!working,modifier=Modifier.fillMaxWidth()) {Text(stringResource(R.string.npv_import))}
            for(entry in entries){
                Text((if(entry.source=="generated")stringResource(R.string.npv_generated) else stringResource(R.string.npv_captured))+
                    " · "+entry.fingerprint.take(16),color=Color.White)
                Row {
                    TextButton(onClick={shown=entry;revealPrivate=false},enabled=!working){Text(stringResource(R.string.npv_view))}
                    TextButton(onClick={scope.launch{try{withContext(Dispatchers.IO){vault.delete(entry.id);refresh()}}
                        catch(_:Exception){message=context.getString(R.string.npv_invalid)}}},enabled=!working){Text(stringResource(R.string.npv_delete))}
                }
            }
            if(working)CircularProgressIndicator()
            message?.let{Text(it,color=Color.White,style=MaterialTheme.typography.bodySmall)}
        }
    }
    if(consent)AlertDialog(onDismissRequest={consent=false},title={Text(stringResource(R.string.npv_generate))},
        text={Text(stringResource(R.string.npv_generation_notice))},confirmButton={TextButton(onClick={
            consent=false;working=true;scope.launch {
                try{
                    val value=client.generateNpvsIdentity()
                    val entry=withContext(Dispatchers.IO){vault.save(value).also{refresh()}}
                    shown=entry;revealPrivate=false;message=null
                }catch(error:Exception){message=CloudUserErrors.message(context,error)}finally{working=false}
            }
        }){Text(stringResource(R.string.npv_generate))}},dismissButton={TextButton(onClick={consent=false}){Text(stringResource(android.R.string.cancel))}})
    shown?.let{entry->
        fun copy(value:String,sensitive:Boolean){
            val clip=ClipData.newPlainText("NPV",value)
            if(sensitive && android.os.Build.VERSION.SDK_INT>=24)clip.description.extras=PersistableBundle().apply {
                putBoolean("android.content.extra.IS_SENSITIVE",true)
            }
            (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(clip)
        }
        AlertDialog(onDismissRequest={shown=null;revealPrivate=false},
            properties=DialogProperties(securePolicy=SecureFlagPolicy.SecureOn),
            title={Text(stringResource(R.string.npv_title))},text={Column(verticalArrangement=Arrangement.spacedBy(10.dp)){
                if(entry.kind=="keypair"){
                    val public=entry.material.getString("publicKey");val private=entry.material.getString("privateKey")
                    OutlinedTextField(value=public,onValueChange={},readOnly=true,label={Text("Public key · P-256")})
                    TextButton(onClick={copy(public,false)}){Text(stringResource(R.string.npv_copy_public))}
                    OutlinedTextField(value=private,onValueChange={},readOnly=true,label={Text("Private key · PKCS#8")},
                        visualTransformation=if(revealPrivate)androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation())
                    TextButton(onClick={revealPrivate=!revealPrivate}){Text(stringResource(R.string.npv_reveal))}
                    TextButton(onClick={copy(private,true)}){Text(stringResource(R.string.npv_copy_private))}
                }else Text(stringResource(R.string.npv_hardware_notice))
                Text(entry.fingerprint,style=MaterialTheme.typography.bodySmall)
            }},confirmButton={TextButton(onClick={shown=null;revealPrivate=false}){Text(stringResource(android.R.string.ok))}})
    }
}
