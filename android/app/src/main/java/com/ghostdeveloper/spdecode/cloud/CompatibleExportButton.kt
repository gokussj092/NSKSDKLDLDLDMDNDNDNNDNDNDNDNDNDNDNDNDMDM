package com.ghostdeveloper.spdecode.cloud

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.FileDownload
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.ghostdeveloper.spdecode.DecodeView
import com.ghostdeveloper.spdecode.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** This composable stays mounted until the destination callback finishes. */
@Composable
fun CompatibleExportButton(entry:DecodeView,onDone:()->Unit={}) {
    val context=LocalContext.current
    val scope=rememberCoroutineScope()
    val artifact=entry.compatibleExport
    var writing by remember(entry.id){mutableStateOf(false)}
    val launcher=rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")){uri->
        if(uri==null){writing=false;onDone()}
        else if(artifact!=null)scope.launch {
            val ok=try {
                withContext(Dispatchers.IO) {
                    require(artifact.matches(entry.rawText))
                    val bytes=artifact.bytes()
                    try {
                        context.contentResolver.openOutputStream(uri,"w")?.use {out->out.write(bytes);out.flush()}
                            ?:error("Destination unavailable")
                    } finally {bytes.fill(0)}
                }
                true
            } catch(cancelled:CancellationException) {
                writing=false
                throw cancelled
            } catch(_:Exception) { false }
            Toast.makeText(context,if(ok)R.string.saved else R.string.compatible_export_failed,Toast.LENGTH_SHORT).show()
            writing=false
            onDone()
        }
    }
    if(artifact!=null) {
        OutlinedButton(modifier=Modifier.fillMaxWidth(),enabled=!writing,onClick={
            writing=true
            try {launcher.launch(artifact.filenameFor(entry.filename))}
            catch(_:Exception){writing=false;Toast.makeText(context,R.string.compatible_export_failed,Toast.LENGTH_SHORT).show()}
        }) {
            Icon(Icons.Outlined.FileDownload,null)
            Spacer(Modifier.width(9.dp))
            Text(stringResource(R.string.compatible_export_for,artifact.targetAppName))
        }
    } else if(entry.extension in CompatibleExportArtifact.targets) {
        Text(stringResource(R.string.compatible_export_redecode,CompatibleExportArtifact.targets.getValue(entry.extension).second),style=MaterialTheme.typography.bodySmall)
    }
}

