package com.ghostdeveloper.spdecode.cloud

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.ghostdeveloper.spdecode.R

@Composable
internal fun CatalogRefreshControl(updating:Boolean,enabled:Boolean,onClick:()->Unit) {
    FilledTonalButton(onClick=onClick,enabled=enabled,
        modifier=Modifier.testTag("server_vpn_manual_refresh").heightIn(min=48.dp),
        shape=RoundedCornerShape(14.dp),
        colors=ButtonDefaults.filledTonalButtonColors(
            containerColor=MaterialTheme.colorScheme.surfaceVariant,
            contentColor=MaterialTheme.colorScheme.onSurface,
            disabledContainerColor=MaterialTheme.colorScheme.surfaceVariant,
            disabledContentColor=MaterialTheme.colorScheme.onSurfaceVariant),
        contentPadding=PaddingValues(horizontal=12.dp,vertical=8.dp)) {
        if(updating) CircularProgressIndicator(Modifier.size(17.dp),strokeWidth=2.dp,
            color=MaterialTheme.colorScheme.onSurface)
        else Icon(Icons.Outlined.Refresh,null,Modifier.size(19.dp))
        Spacer(Modifier.width(6.dp))
        Text(stringResource(if(updating)R.string.catalog_checking else R.string.catalog_check_action),
            style=MaterialTheme.typography.labelMedium,maxLines=1)
    }
}

/** Percent measures verified catalog records (including their icons), never a timer. */
@Composable
internal fun CatalogEmptyLoading(percent:Int?,modifier:Modifier=Modifier) {
    Column(modifier.fillMaxWidth().testTag("catalog_empty_loading"),
        verticalArrangement=Arrangement.Center,horizontalAlignment=Alignment.CenterHorizontally) {
        Box(contentAlignment=Alignment.Center) {
            CircularProgressIndicator(Modifier.size(64.dp),strokeWidth=3.dp,
                color=MaterialTheme.colorScheme.onSurface)
            if(percent!=null) Text(stringResource(R.string.catalog_progress,percent.coerceIn(0,100)),
                style=MaterialTheme.typography.labelSmall)
        }
        Spacer(Modifier.height(16.dp))
        Text(stringResource(R.string.catalog_loading_short),style=MaterialTheme.typography.bodyMedium,
            color=MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
