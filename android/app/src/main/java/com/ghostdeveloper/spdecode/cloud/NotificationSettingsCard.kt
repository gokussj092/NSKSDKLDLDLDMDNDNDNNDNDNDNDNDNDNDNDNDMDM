package com.ghostdeveloper.spdecode.cloud

import android.Manifest
import android.os.Build
import android.content.Intent
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.ghostdeveloper.spdecode.R

@Composable
internal fun NotificationSettingsCard() {
    val context=LocalContext.current
    var enabled by remember {mutableStateOf(CloudNotifications.enabled(context))}
    val permission=rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {granted->
        if(granted){CloudNotifications.setEnabled(context,true);enabled=CloudNotifications.enabled(context)}
    }
    Card(shape=RoundedCornerShape(18.dp),colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant)) {
        ListItem(headlineContent={Text(stringResource(R.string.notifications_title))},
            supportingContent={Text(stringResource(R.string.notifications_description))},
            leadingContent={Icon(Icons.Outlined.Notifications,null)},
            trailingContent={Switch(checked=enabled,onCheckedChange={value->
                if(value && Build.VERSION.SDK_INT>=33 && !CloudNotifications.allowed(context))
                    permission.launch(Manifest.permission.POST_NOTIFICATIONS)
                else {CloudNotifications.setEnabled(context,value);enabled=CloudNotifications.enabled(context)}
            })},colors=ListItemDefaults.colors(containerColor=MaterialTheme.colorScheme.surfaceVariant))
        TextButton(onClick={
            context.startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE,context.packageName))
        },modifier=Modifier.padding(horizontal=16.dp)){Text(stringResource(R.string.notifications_system_settings))}
    }
}

/** Offered once after a successful export; denial never blocks saving the file. */
@Composable
internal fun ExportNotificationPrompt(onDone:()->Unit) {
    val context=LocalContext.current
    val permission=rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {granted->
        if(granted)CloudNotifications.setEnabled(context,true)
        onDone()
    }
    fun finish(){CloudNotifications.markExportPrompt(context);onDone()}
    AlertDialog(onDismissRequest={finish()},title={Text(stringResource(R.string.notifications_title))},
        text={Text(stringResource(R.string.notifications_description))},
        confirmButton={TextButton(onClick={
            CloudNotifications.markExportPrompt(context)
            if(Build.VERSION.SDK_INT>=33&&!CloudNotifications.allowed(context))permission.launch(Manifest.permission.POST_NOTIFICATIONS)
            else {CloudNotifications.setEnabled(context,true);onDone()}
        }){Text(stringResource(R.string.notifications_enable))}},
        dismissButton={TextButton(onClick={finish()}){Text(stringResource(R.string.notifications_later))}})
}
