package com.ghostdeveloper.spdecode

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.DeleteOutline
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** S.4 offline opt-in provisioning; never display, log, copy or export secret bytes. */
@Composable
internal fun DeviceCredentialSettingsSection() {
    val context=LocalContext.current.applicationContext
    val vault=remember(context){DevicePrivateCredentialVault(context)}
    val scope=rememberCoroutineScope()
    var inventory by remember {mutableStateOf<DevicePrivateCredentialVault.Inventory?>(null)}
    var showAdd by remember {mutableStateOf(false)}
    var deleteId by remember {mutableStateOf<String?>(null)}
    var label by remember {mutableStateOf("")}
    var secret by remember {mutableStateOf("")}
    var working by remember {mutableStateOf(false)}
    var error by remember {mutableStateOf(false)}
    var updated by remember {mutableStateOf(false)}

    LaunchedEffect(vault) {
        inventory=try {withContext(Dispatchers.IO){vault.inventory()}}
        catch(_:Exception){error=true;null}
    }
    val foreground=Color(0xFFF7F7F7)
    val subdued=Color(0xFFABABAB)
    Surface(color=Color(0xFF242424),shape=RoundedCornerShape(16.dp),
        modifier=Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment=Alignment.CenterVertically) {
                Icon(Icons.Outlined.Key,null,tint=foreground)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.s4_vault_title),color=foreground,
                    style=MaterialTheme.typography.titleMedium)
            }
            Text(stringResource(R.string.s4_vault_detail),color=subdued,
                style=MaterialTheme.typography.bodySmall)
            val items=inventory?.entries.orEmpty()
            if(items.isEmpty()) {
                Text(stringResource(R.string.s4_vault_empty),color=subdued,
                    style=MaterialTheme.typography.bodySmall)
            }
            for(entry in items){
                Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(entry.label,color=foreground)
                        Text(stringResource(R.string.s4_vault_stored),
                            color=subdued,style=MaterialTheme.typography.bodySmall)
                    }
                    IconButton(onClick={deleteId=entry.id},enabled=!working) {
                        Icon(Icons.Outlined.DeleteOutline,
                            stringResource(R.string.s4_vault_delete),tint=subdued)
                    }
                }
            }
            val unreadable=inventory?.unreadable?:0
            if(unreadable>0) Text(stringResource(R.string.s4_vault_unreadable,unreadable),
                color=subdued,style=MaterialTheme.typography.bodySmall)
            if(error) Text(stringResource(R.string.s4_vault_error),color=foreground,
                style=MaterialTheme.typography.bodySmall)
            if(updated) Text(stringResource(R.string.s4_vault_success),color=foreground,
                style=MaterialTheme.typography.bodySmall)
            OutlinedButton(
                onClick={
                    error=false
                    updated=false
                    label=""
                    secret=""
                    showAdd=true
                },
                enabled=!working,
                modifier=Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Outlined.Add,null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.s4_vault_add))
            }
        }
    }
    if(showAdd){
        AlertDialog(
            onDismissRequest={
                if(!working){secret="";label="";showAdd=false}
            },
            title={Text(stringResource(R.string.s4_vault_add))},
            text={
                Column(verticalArrangement=Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(value=label,onValueChange={if(it.length<=64)label=it},
                        label={Text(stringResource(R.string.s4_vault_label))},
                        maxLines=1,singleLine=true)
                    OutlinedTextField(value=secret,onValueChange={if(it.length<=4096)secret=it},
                        label={Text(stringResource(R.string.s4_vault_secret))},
                        visualTransformation=PasswordVisualTransformation(),
                        keyboardOptions=KeyboardOptions(keyboardType=KeyboardType.Password),
                        maxLines=1,singleLine=true)
                    Text(stringResource(R.string.s4_vault_warning),
                        style=MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton={
                TextButton(enabled=!working&&label.isNotBlank()&&
                    secret.isNotEmpty()&&secret.toByteArray(Charsets.UTF_8).size<=4096,
                    onClick={
                        val candidateLabel=label.trim()
                        val material=secret.toByteArray(Charsets.UTF_8)
                        secret=""
                        label=""
                        working=true
                        showAdd=false
                        scope.launch {
                            try {
                                inventory=withContext(Dispatchers.IO) {
                                    vault.provision(candidateLabel,material)
                                    vault.inventory()
                                }
                                error=false
                                updated=true
                            } catch(_:Exception) {
                                error=true
                                updated=false
                            } finally {
                                material.fill(0)
                                working=false
                            }
                        }
                    }) {Text(stringResource(R.string.s4_vault_save))}
            },
            dismissButton={
                TextButton(enabled=!working,onClick={
                    secret=""
                    label=""
                    showAdd=false
                }){Text(stringResource(R.string.cancel))}
            },
            properties=DialogProperties(securePolicy=SecureFlagPolicy.SecureOn),
            containerColor=Color.Black,
            titleContentColor=Color(0xFFF7F7F7),
            textContentColor=Color(0xFFF7F7F7),
            tonalElevation=0.dp,
        )
    }
    if(deleteId!=null){
        AlertDialog(
            onDismissRequest={if(!working)deleteId=null},
            title={Text(stringResource(R.string.s4_vault_delete))},
            text={Text(stringResource(R.string.s4_vault_delete_confirm))},
            confirmButton={
                TextButton(enabled=!working,onClick={
                    val id=deleteId?:return@TextButton
                    deleteId=null
                    working=true
                    scope.launch {
                        try {
                            inventory=withContext(Dispatchers.IO){
                                vault.delete(id)
                                vault.inventory()
                            }
                            error=false
                            updated=true
                        } catch(_:Exception){
                            error=true
                            updated=false
                        }finally{working=false}
                    }
                }){Text(stringResource(R.string.s4_vault_delete))}
            },
            dismissButton={
                TextButton(enabled=!working,onClick={deleteId=null}){
                    Text(stringResource(R.string.cancel))
                }
            },
            containerColor=Color.Black,
            titleContentColor=Color(0xFFF7F7F7),
            textContentColor=Color(0xFFF7F7F7),
            tonalElevation=0.dp,
        )
    }
}
