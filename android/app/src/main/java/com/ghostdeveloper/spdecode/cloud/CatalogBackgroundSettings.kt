package com.ghostdeveloper.spdecode.cloud

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.core.app.NotificationManagerCompat
import com.ghostdeveloper.spdecode.R

@Composable
internal fun CatalogBackgroundSettings() {
    val context = LocalContext.current
    var enabled by remember { mutableStateOf(CloudCatalogUpdates.backgroundEnabled(context)) }
    var showGuide by rememberSaveable { mutableStateOf(false) }
    val notificationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}

    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(stringResource(R.string.catalog_background_title))
            Text(stringResource(R.string.catalog_background_description),
                style = MaterialTheme.typography.bodySmall)
        }
        Switch(checked = enabled, onCheckedChange = { value ->
            CloudCatalogUpdates.setBackgroundEnabled(context, value)
            enabled = CloudCatalogUpdates.backgroundEnabled(context)
            if (enabled) showGuide = true
        })
    }

    if (enabled) {
        TextButton(onClick = { showGuide = true }) {
            Text(stringResource(R.string.catalog_background_guide_title))
        }
    }
    if (showGuide) {
        AlertDialog(
            onDismissRequest = { showGuide = false },
            title = { Text(stringResource(R.string.catalog_background_guide_title)) },
            text = { Text(stringResource(R.string.catalog_background_guide_body)) },
            confirmButton = {
                TextButton(onClick = {
                    context.openSystemSettings(applicationSettings(context))
                }) { Text(stringResource(R.string.catalog_background_open_settings)) }
            },
            dismissButton = {
                TextButton(onClick = {
                    showGuide = false
                    if (Build.VERSION.SDK_INT >= 33 && !NotificationManagerCompat.from(context).areNotificationsEnabled()) {
                        notificationPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                    }
                }) { Text(stringResource(android.R.string.ok)) }
            },
        )
    }
}

private fun applicationSettings(context: Context) =
    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))

private fun Context.openSystemSettings(intent: Intent) {
    try { startActivity(intent) }
    catch (_: ActivityNotFoundException) { /* The explanatory card is still usable on customized Android. */ }
    catch (_: SecurityException) { /* Some managed devices disallow app settings. */ }
}
