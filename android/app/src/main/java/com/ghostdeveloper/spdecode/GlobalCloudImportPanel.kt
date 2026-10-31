package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostdeveloper.spdecode.cloud.CloudOnlineReference
import com.ghostdeveloper.spdecode.cloud.CloudTextRoute

/** Unified external-hosted configuration import. No direct vendor requests. */
@Composable
internal fun GlobalCloudImportPanel(
    enabled:Boolean,
    routes:List<CloudTextRoute>,
    onDecode:(String,String)->Unit,
) {
    var reference by remember { mutableStateOf("") }
    var selected by remember { mutableStateOf("auto") }
    val providers=remember(routes){CloudOnlineReference.options(routes)}
    if(selected!="auto" && providers.none{it.id==selected})selected="auto"
    Surface(modifier=Modifier.fillMaxWidth(),shape=RoundedCornerShape(15.dp),
        color=Color(0xFF242424),border=BorderStroke(1.dp,Color(0xFF303030))) {
        Column(Modifier.padding(12.dp),verticalArrangement=Arrangement.spacedBy(9.dp)) {
            Text(stringResource(R.string.cloud_global_title),
                color=Color.White,fontSize=14.sp)
            Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                horizontalArrangement=Arrangement.spacedBy(6.dp)) {
                FilterChip(selected=selected=="auto",enabled=enabled,
                    onClick={selected="auto"},
                    label={Text(stringResource(R.string.cloud_global_auto))})
                providers.forEach { provider ->
                    FilterChip(selected=selected==provider.id,enabled=enabled,
                        onClick={selected=provider.id},label={Text(provider.name)})
                }
            }
            OutlinedTextField(
                value=reference,
                onValueChange={if(it.length<=1024)reference=it},
                modifier=Modifier.fillMaxWidth(),minLines=2,maxLines=4,
                enabled=enabled,
                placeholder={Text(stringResource(R.string.cloud_global_hint))},
                keyboardOptions=KeyboardOptions(capitalization=KeyboardCapitalization.None,
                    autoCorrectEnabled=false),
                colors=OutlinedTextFieldDefaults.colors(
                    focusedTextColor=Color.White,unfocusedTextColor=Color.White,
                    focusedPlaceholderColor=Color(0xFFABABAB),
                    unfocusedPlaceholderColor=Color(0xFFABABAB)),
                trailingIcon={
                    if(reference.isNotEmpty())IconButton(onClick={reference=""},enabled=enabled) {
                        Icon(Icons.Outlined.Close,stringResource(R.string.close))
                    }
                }
            )
            Button(onClick={onDecode(selected,reference)},enabled=enabled&&reference.isNotBlank(),
                modifier=Modifier.fillMaxWidth().heightIn(min=44.dp),
                shape=RoundedCornerShape(12.dp),
                colors=ButtonDefaults.buttonColors(
                    containerColor=Color(0xFFF1F1F1),contentColor=Color(0xFF111111))) {
                Icon(Icons.Outlined.Cloud,null,modifier=Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.cloud_global_action),fontSize=14.sp)
            }
            Text(stringResource(R.string.cloud_global_detail),
                color=Color(0xFFABABAB),fontSize=11.sp,lineHeight=16.sp)
        }
    }
}
