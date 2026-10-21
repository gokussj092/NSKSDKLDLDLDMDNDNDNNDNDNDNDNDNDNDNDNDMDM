package com.ghostdeveloper.spdecode

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy

/**
 * S.4: an explicit one-file authorization gesture. Only public label/UUID
 * metadata reaches Compose. Secret bytes never enter UI state or callbacks.
 */
@Composable
internal fun PrivateCredentialImportDialog(
    filename: String,
    credentials: List<DevicePrivateCredentialVault.Metadata>,
    onChoose: (String?) -> Unit,
    onCancel: () -> Unit,
    onManual: () -> Unit = onCancel,
) {
    AlertDialog(
        onDismissRequest = onCancel,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text(stringResource(R.string.s4_import_title)) },
        text = {
            Column {
                Text(stringResource(R.string.s4_import_description,filename))
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    credentials.forEach { entry ->
                        TextButton(
                            onClick = { onChoose(entry.id) },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(entry.label) }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onManual) {
                Text(stringResource(R.string.hc_auth_enter_manually))
            }
            TextButton(onClick = { onChoose(null) }) {
                Text(stringResource(R.string.s4_import_without_password))
            }
        },
        dismissButton = {
            TextButton(onClick = onCancel) { Text(stringResource(R.string.cancel)) }
        },
        containerColor = Color.Black,
        tonalElevation = 0.dp,
        titleContentColor = Color(0xFFF7F7F7),
        textContentColor = Color(0xFFABABAB),
        shape = RoundedCornerShape(17.dp),
    )
}
