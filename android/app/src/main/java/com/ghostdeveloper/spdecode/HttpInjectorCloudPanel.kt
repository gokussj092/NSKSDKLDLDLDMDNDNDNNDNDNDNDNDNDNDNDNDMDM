package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
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

/** Separate online import form; never routed through the offline text editor. */
@Composable
internal fun HttpInjectorCloudPanel(
    enabled: Boolean,
    onDecode: (String) -> Unit,
) {
    var reference by remember { mutableStateOf("") }
    Surface(
        modifier=Modifier.fillMaxWidth(),
        shape=RoundedCornerShape(15.dp),
        color=Color(0xFF242424),
        border=BorderStroke(1.dp,Color(0xFF303030)),
    ) {
        Column(
            modifier=Modifier.padding(12.dp),
            verticalArrangement=Arrangement.spacedBy(9.dp),
        ) {
            Text(stringResource(R.string.cloud_http_injector_title),
                color=Color(0xFFF7F7F7),fontSize=14.sp)
            OutlinedTextField(
                value=reference,
                onValueChange={if(it.length<=1024)reference=it},
                modifier=Modifier.fillMaxWidth(),
                minLines=2,
                maxLines=4,
                enabled=enabled,
                placeholder={Text(stringResource(R.string.cloud_http_injector_hint))},
                keyboardOptions=KeyboardOptions(
                    capitalization=KeyboardCapitalization.None,
                    autoCorrectEnabled=false,
                ),
                trailingIcon={
                    if(reference.isNotEmpty()) IconButton(onClick={reference=""},enabled=enabled) {
                        Icon(Icons.Outlined.Close,stringResource(R.string.close))
                    }
                },
            )
            Button(
                onClick={if(reference.isNotBlank())onDecode(reference)},
                enabled=enabled && reference.isNotBlank(),
                modifier=Modifier.fillMaxWidth().heightIn(min=44.dp),
                shape=RoundedCornerShape(12.dp),
                colors=ButtonDefaults.buttonColors(
                    containerColor=Color(0xFFF1F1F1),
                    contentColor=Color(0xFF111111)),
            ) {
                Icon(Icons.Outlined.Cloud,null,modifier=Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.cloud_http_injector_action),fontSize=14.sp)
            }
            Text(stringResource(R.string.cloud_http_injector_privacy),
                fontSize=11.sp,lineHeight=16.sp,color=Color(0xFF999999))
        }
    }
}
