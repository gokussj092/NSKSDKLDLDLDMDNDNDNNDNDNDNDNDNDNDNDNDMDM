package com.ghostdeveloper.spdecode.cloud

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.view.WindowManager
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.ghostdeveloper.spdecode.R

private fun Context.hostActivity(): Activity? = when(this) {
    is Activity -> this
    is ContextWrapper -> if(baseContext!==this) baseContext.hostActivity() else null
    else -> null
}

@Composable
internal fun PrivateScreenSettings() {
    val context=LocalContext.current
    val prefs=remember { context.getSharedPreferences("spdecode-ui-preferences",Context.MODE_PRIVATE) }
    var enabled by remember { mutableStateOf(prefs.getBoolean("private-screen",false)) }
    Column(Modifier.fillMaxWidth().padding(16.dp)) {
        Row {
            Text(stringResource(R.string.private_screen_title),Modifier.weight(1f),color=Color.White)
            Switch(checked=enabled,onCheckedChange={ value ->
                enabled=value
                prefs.edit().putBoolean("private-screen",value).apply()
                context.hostActivity()?.window?.let { window ->
                    if(value) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                }
            })
        }
        Text(stringResource(R.string.private_screen_detail),style=MaterialTheme.typography.bodySmall,color=Color(0xFFABABAB))
    }
}
