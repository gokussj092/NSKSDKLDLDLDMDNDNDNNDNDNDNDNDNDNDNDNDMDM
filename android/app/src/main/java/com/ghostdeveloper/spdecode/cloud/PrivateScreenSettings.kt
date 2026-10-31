package com.ghostdeveloper.spdecode.cloud

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.view.WindowManager
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostdeveloper.spdecode.R

private fun Context.hostActivity(): Activity? = when(this) {
    is Activity -> this
    is ContextWrapper -> if(baseContext!==this) baseContext.hostActivity() else null
    else -> null
}

/** Uses the same AMOLED SettingsCard geometry as the other Settings sections. */
@Composable
internal fun PrivateScreenSettings() {
    val context=LocalContext.current
    val prefs=remember(context) {
        context.getSharedPreferences("spdecode-ui-preferences",Context.MODE_PRIVATE)
    }
    var enabled by remember { mutableStateOf(prefs.getBoolean("private-screen",false)) }
    Surface(
        modifier=Modifier.fillMaxWidth(),
        color=Color(0xFF242424),
        shape=RoundedCornerShape(16.dp),
    ) {
        Column(
            Modifier.padding(16.dp),
            verticalArrangement=Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier=Modifier.fillMaxWidth(),
                verticalAlignment=Alignment.CenterVertically,
            ) {
                Icon(Icons.Outlined.Lock,null,tint=Color.White,
                    modifier=Modifier.size(24.dp))
                Spacer(Modifier.width(12.dp))
                Text(stringResource(R.string.private_screen_title),
                    modifier=Modifier.weight(1f),
                    color=Color.White,fontWeight=FontWeight.SemiBold,fontSize=17.sp)
                Switch(
                    checked=enabled,
                    onCheckedChange={ value ->
                        enabled=value
                        prefs.edit().putBoolean("private-screen",value).apply()
                        context.hostActivity()?.window?.let { window ->
                            if(value)window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                            else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                        }
                    },
                    colors=SwitchDefaults.colors(
                        checkedThumbColor=Color.Black,
                        checkedTrackColor=Color.White,
                    )
                )
            }
            Text(stringResource(R.string.private_screen_detail),
                color=Color(0xFFABABAB),fontSize=13.sp,lineHeight=19.sp)
        }
    }
}
