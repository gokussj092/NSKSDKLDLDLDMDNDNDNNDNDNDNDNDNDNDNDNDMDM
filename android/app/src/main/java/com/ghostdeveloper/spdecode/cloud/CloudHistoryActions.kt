package com.ghostdeveloper.spdecode.cloud

import androidx.compose.foundation.layout.Box
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.DeleteOutline
import androidx.compose.material.icons.outlined.FileDownload
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import com.ghostdeveloper.spdecode.DecodeView
import com.ghostdeveloper.spdecode.R
import com.ghostdeveloper.spdecode.ResultExport
import com.ghostdeveloper.spdecode.ResultPresentation

/**
 * Cloud-only, small replacement for the trash action within existing history
 * cards. No changes to dimensions, card background, list layout or navigation.
 */
@Composable
fun CloudHistoryEntryActions(onExport: () -> Unit, onDelete: () -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        IconButton(onClick = { expanded = true }) {
            Icon(Icons.Outlined.MoreVert,
                contentDescription = stringResource(R.string.cloud_history_actions),
                tint = Color(0xFFABABAB))
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            containerColor = Color(0xFF242424),
        ) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.export)) },
                leadingIcon = { Icon(Icons.Outlined.FileDownload, null) },
                onClick = {
                    expanded = false
                    onExport()
                },
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.history_delete_one)) },
                leadingIcon = { Icon(Icons.Outlined.DeleteOutline, null) },
                onClick = {
                    expanded = false
                    onDelete()
                },
            )
        }
    }
}

/**
 * A large catalog stays in encrypted history. Viewing it requires explicit
 * navigation afterwards and can be slow on memory-constrained devices.
 */
@Composable
fun CloudLargeResultNotice(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Outlined.Info, null, tint = Color(0xFFE0B563)) },
        title = { Text(stringResource(R.string.cloud_large_result_title)) },
        text = { Text(stringResource(R.string.cloud_large_result_body),
            color = Color(0xFFABABAB)) },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cloud_large_result_acknowledge))
            }
        },
        containerColor = Color(0xFF242424),
        titleContentColor = Color(0xFFF7F7F7),
        textContentColor = Color(0xFFABABAB),
    )
}

/** Export complete NUR JSON without building the costly 1,500-field preview. */
object CloudHistoryJsonExport {
    fun content(entry: DecodeView): String =
        if (entry.extension == "nurservers") entry.rawText
        else ResultPresentation.formatted(entry.document, ResultExport.JSON)
}
