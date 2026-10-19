package com.ghostdeveloper.spdecode.cloud

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostdeveloper.spdecode.BuildConfig

/**
 * Visible in Settings only in a dedicated QA build.
 * No code is bundled or stored persistently; the operator enters it at runtime.
 * The original pinned Settings source remains untouched in Git.
 */
@Composable
internal fun CloudQaSettingsCard() {
    if (!BuildConfig.SPDECODE_QA_BUILD) return

    var entry by remember { mutableStateOf("") }
    var configured by remember { mutableStateOf(CloudQaMemory.get().isNotEmpty()) }
    val bg = Color(0xFF242424)
    val title = Color(0xFFF7F7F7)
    val muted = Color(0xFFABABAB)

    Surface(color = bg, shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.VpnKey, contentDescription = null, tint = title)
                Spacer(Modifier.width(10.dp))
                Text("Cloud QA · Pruebas privadas", color = title,
                    fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
            }
            Text(
                "Introduce el código temporal generado con 'sudo spdecode qa start' " +
                    "en tu VPS. Este modo permite probar los descifradores antes de " +
                    "publicar la aplicación en Google Play.",
                fontSize = 13.sp, color = muted, lineHeight = 19.sp
            )
            OutlinedTextField(
                value = entry,
                onValueChange = { if (it.length <= 80) entry = it.trim() },
                singleLine = true,
                label = { Text("Código temporal QA") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
            Button(
                onClick = {
                    CloudQaMemory.set(entry)
                    entry = ""
                    configured = true
                },
                enabled = entry.matches(Regex("spqa-[A-Za-z0-9_-]{40,64}")),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (configured) "Cambiar código QA" else "Activar acceso QA")
            }
            if (configured) {
                Text("Código cargado en memoria. Ya puedes descifrar archivos.",
                    color = title, fontSize = 12.sp)
                OutlinedButton(
                    onClick = {
                        CloudQaMemory.clear()
                        entry = ""
                        configured = false
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Borrar código QA") }
            }
            Text("El código no se guarda en el dispositivo. Caduca en el servidor " +
                "y solo permite sesiones temporales.", color = muted, fontSize = 12.sp)
        }
    }
}
