package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import java.util.Locale

/** Chunk mode measures verified payload bytes; legacy mode measures HTTP bytes. */
data class CatalogTransferUiState(
    val receivedBytes:Long=0L,
    val totalBytes:Long=-1L,
    val completed:Boolean=false,
    val paused:Boolean=false,
    val resumable:Boolean=false,
    val displayVersion:String?=null,
)

@Composable
internal fun CatalogTransferDialog(
    state:CatalogTransferUiState,
    onCancel:()->Unit,
    onFinish:()->Unit,
    onResume:()->Unit={},
    onDiscard:()->Unit={},
) {
    val colors=MaterialTheme.colorScheme
    val total=state.totalBytes.takeIf { it>=0 }
    val percent=total?.let { if(it==0L)100 else (state.receivedBytes.coerceIn(0L,it)*100L/it).toInt() }
    val mb:(Long)->String={ bytes -> String.format(Locale.getDefault(),"%.2f",bytes/1048576.0) }
    androidx.compose.ui.window.Dialog(
        onDismissRequest={},
        properties=androidx.compose.ui.window.DialogProperties(
            dismissOnBackPress=false,dismissOnClickOutside=false)
    ) {
        Surface(
            modifier=Modifier.fillMaxWidth().testTag("catalog_transfer_dialog"),
            color=SpDecodeAmoledColors.background,
            shape=RoundedCornerShape(17.dp),
            border=BorderStroke(1.dp,colors.outline),
            tonalElevation=0.dp,
        ) {
            Column(
                modifier=Modifier.padding(22.dp),
                horizontalAlignment=Alignment.CenterHorizontally,
                verticalArrangement=Arrangement.spacedBy(16.dp),
            ) {
                if(state.completed) {
                    Text(stringResource(R.string.catalog_transfer_completed)+(state.displayVersion?.let{" v$it"}?:""),
                        color=colors.onSurface,
                        style=MaterialTheme.typography.titleMedium,
                        fontWeight=FontWeight.SemiBold,
                        textAlign=TextAlign.Center)
                    Text(stringResource(R.string.catalog_transfer_saved),
                        color=colors.onSurfaceVariant,
                        style=MaterialTheme.typography.bodyMedium,
                        textAlign=TextAlign.Center)
                    Button(onClick=onFinish,modifier=Modifier.fillMaxWidth()
                        .testTag("catalog_transfer_finish")) {
                        Text(stringResource(R.string.catalog_transfer_finish))
                    }
                } else {
                    if(state.paused) {
                        Text(stringResource(R.string.catalog_transfer_paused),color=colors.onSurface)
                        Button(onClick=onResume){Text(stringResource(R.string.catalog_transfer_resume))}
                        if(state.resumable)OutlinedButton(onClick=onDiscard){Text(stringResource(R.string.catalog_transfer_discard))}
                    }
                    if(state.resumable)Text(stringResource(R.string.catalog_transfer_retention),color=colors.onSurfaceVariant)
                    Text(stringResource(if(percent==100)R.string.catalog_transfer_verifying else R.string.catalog_transfer_downloading),
                        color=colors.onSurface,
                        style=MaterialTheme.typography.titleMedium,
                        fontWeight=FontWeight.SemiBold,
                        textAlign=TextAlign.Center)
                    Column(verticalArrangement=Arrangement.spacedBy(8.dp)) {
                        if(percent!=null) {
                            if(percent<100)Text("$percent%",modifier=Modifier.fillMaxWidth(),
                                textAlign=TextAlign.End,color=colors.onSurface,
                                style=MaterialTheme.typography.labelMedium)
                            LinearProgressIndicator(
                                progress={percent/100f},
                                modifier=Modifier.fillMaxWidth().height(7.dp),
                                color=colors.onSurface,
                                trackColor=colors.surfaceVariant,
                            )
                        }else{
                            LinearProgressIndicator(
                                modifier=Modifier.fillMaxWidth().height(7.dp),
                                color=colors.onSurface,
                                trackColor=colors.surfaceVariant,
                            )
                        }
                        Text(
                            if(total!=null)
                                stringResource(R.string.catalog_transfer_bytes_total,
                                    mb(state.receivedBytes),mb(total))
                            else stringResource(R.string.catalog_transfer_bytes_unknown,
                                mb(state.receivedBytes)),
                            modifier=Modifier.fillMaxWidth(),
                            textAlign=TextAlign.Center,color=colors.onSurfaceVariant,
                            style=MaterialTheme.typography.bodyMedium,
                        )
                    }
                    OutlinedButton(onClick=onCancel,modifier=Modifier.fillMaxWidth()
                        .testTag("catalog_transfer_cancel")) {
                        Text(stringResource(R.string.cancel))
                    }
                }
            }
        }
    }
}
