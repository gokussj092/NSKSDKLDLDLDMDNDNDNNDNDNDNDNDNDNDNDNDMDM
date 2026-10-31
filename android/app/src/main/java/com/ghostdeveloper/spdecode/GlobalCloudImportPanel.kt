package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostdeveloper.spdecode.cloud.CloudOnlineReference
import com.ghostdeveloper.spdecode.cloud.CloudTextRoute

/** Approved Cloud providers only. The backend validates every submitted reference. */
@Composable
internal fun GlobalCloudImportPanel(
    enabled:Boolean,
    routes:List<CloudTextRoute>,
    onDecode:(String,String)->Unit,
) {
    var reference by rememberSaveable { mutableStateOf("") }
    var selected by rememberSaveable { mutableStateOf("auto") }
    val providers=remember(routes){CloudOnlineReference.options(routes)}
    LaunchedEffect(providers) {
        if(selected!="auto" && providers.none{it.id==selected})selected="auto"
    }
    Surface(
        modifier=Modifier.fillMaxWidth(),
        shape=RoundedCornerShape(16.dp),
        color=Color(0xFF242424),
        border=BorderStroke(1.dp,Color(0xFF343434)),
    ) {
        Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(14.dp)) {
            Row(verticalAlignment=Alignment.CenterVertically,
                horizontalArrangement=Arrangement.spacedBy(10.dp)) {
                Icon(Icons.Outlined.Cloud,null,tint=Color.White,modifier=Modifier.size(24.dp))
                Text(stringResource(R.string.cloud_global_title),
                    color=Color.White,fontSize=17.sp,fontWeight=FontWeight.SemiBold)
            }
            Text(stringResource(R.string.cloud_global_detail),
                color=Color(0xFFABABAB),fontSize=12.sp,lineHeight=18.sp)
            // One fully visible radio list, including remote providers from the
            // signed catalog. No clipped horizontal chips or ambiguous selection.
            Column(verticalArrangement=Arrangement.spacedBy(7.dp)) {
                CloudProviderOption(
                    label=stringResource(R.string.cloud_global_auto),
                    selected=selected=="auto",enabled=enabled,onSelect={selected="auto"})
                providers.forEach { provider ->
                    CloudProviderOption(
                        label=provider.name,
                        selected=selected==provider.id,
                        enabled=enabled,
                        onSelect={selected=provider.id},
                    )
                }
            }
            OutlinedTextField(
                value=reference,
                onValueChange={if(it.length<=1024)reference=it},
                modifier=Modifier.fillMaxWidth(),
                minLines=2,maxLines=4,
                enabled=enabled,
                shape=RoundedCornerShape(12.dp),
                placeholder={Text(stringResource(R.string.cloud_global_hint))},
                keyboardOptions=KeyboardOptions(
                    capitalization=KeyboardCapitalization.None,autoCorrectEnabled=false),
                colors=OutlinedTextFieldDefaults.colors(
                    focusedContainerColor=Color(0xFF1D1D1D),
                    unfocusedContainerColor=Color(0xFF1D1D1D),
                    disabledContainerColor=Color(0xFF1D1D1D),
                    focusedBorderColor=Color(0xFFB7A6D1),
                    unfocusedBorderColor=Color(0xFF505050),
                    focusedTextColor=Color.White,
                    unfocusedTextColor=Color.White,
                    focusedPlaceholderColor=Color(0xFFABABAB),
                    unfocusedPlaceholderColor=Color(0xFFABABAB),
                ),
                trailingIcon={
                    if(reference.isNotEmpty())IconButton(
                        onClick={reference=""},enabled=enabled) {
                        Icon(Icons.Outlined.Close,stringResource(R.string.close))
                    }
                }
            )
            Button(
                onClick={onDecode(selected,reference)},
                enabled=enabled&&reference.isNotBlank(),
                modifier=Modifier.fillMaxWidth().heightIn(min=48.dp),
                shape=RoundedCornerShape(12.dp),
                colors=ButtonDefaults.buttonColors(
                    containerColor=Color(0xFFF1F1F1),
                    contentColor=Color(0xFF111111),
                    disabledContainerColor=Color(0xFF3E3E3E),
                    disabledContentColor=Color(0xFF909090)),
            ) {
                Icon(Icons.Outlined.Cloud,null,modifier=Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.cloud_global_action),fontSize=14.sp)
            }
        }
    }
}

@Composable
private fun CloudProviderOption(
    label:String,
    selected:Boolean,
    enabled:Boolean,
    onSelect:()->Unit,
) {
    Surface(
        color=if(selected)Color(0xFF35303E) else Color(0xFF292929),
        shape=RoundedCornerShape(12.dp),
        border=BorderStroke(1.dp,
            if(selected)Color(0xFF9E90B4) else Color(0xFF424242)),
    ) {
        Row(
            modifier=Modifier.fillMaxWidth()
                .selectable(
                    selected=selected,
                    enabled=enabled,
                    role=Role.RadioButton,
                    onClick=onSelect,
                ).padding(horizontal=12.dp,vertical=10.dp),
            verticalAlignment=Alignment.CenterVertically,
        ) {
            Text(label,color=if(enabled)Color.White else Color(0xFF929292),
                fontWeight=if(selected)FontWeight.SemiBold else FontWeight.Normal,
                fontSize=14.sp,modifier=Modifier.weight(1f))
            Spacer(Modifier.width(8.dp))
            RadioButton(
                selected=selected,onClick=null,enabled=enabled,
                colors=RadioButtonDefaults.colors(
                    selectedColor=Color(0xFFD5C7EC),
                    unselectedColor=Color(0xFF989898),
                )
            )
        }
    }
}
