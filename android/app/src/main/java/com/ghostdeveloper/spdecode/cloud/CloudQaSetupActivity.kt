package com.ghostdeveloper.spdecode.cloud

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.ghostdeveloper.spdecode.BuildConfig
import com.ghostdeveloper.spdecode.MainActivity

/** QA-only secondary launcher; never changes the C0-locked main interface. */
class CloudQaSetupActivity:ComponentActivity() {
    override fun onCreate(savedInstanceState:Bundle?) {
        super.onCreate(savedInstanceState)
        if(!BuildConfig.SPDECODE_QA_BUILD) { finish(); return }
        setContent {
            var code by remember { mutableStateOf("") }
            var configured by remember { mutableStateOf(CloudQaMemory.get().isNotEmpty()) }
            MaterialTheme(colorScheme=darkColorScheme()) {
                Surface(modifier=Modifier.fillMaxSize()) {
                    Column(modifier=Modifier.fillMaxSize().padding(24.dp),
                        verticalArrangement=Arrangement.spacedBy(16.dp)) {
                        Text("SP-DECODE · Cloud QA",style=MaterialTheme.typography.headlineSmall)
                        Text("Acceso privado para pruebas de descifrado antes de publicar en Google Play. " +
                            "Usa el código de cuatro horas generado por 'sudo spdecode qa start' en tu VPS.")
                        OutlinedTextField(
                            value=code,onValueChange={if(it.length<=80)code=it.trim()},
                            label={Text("Código temporal QA")},singleLine=true,
                            visualTransformation=PasswordVisualTransformation(),
                            modifier=Modifier.fillMaxWidth()
                        )
                        Button(
                            onClick={
                                CloudQaMemory.set(code)
                                code=""
                                configured=true
                            },
                            enabled=code.matches(Regex("spqa-[A-Za-z0-9_-]{40,64}")),
                            modifier=Modifier.fillMaxWidth()
                        ) { Text("Activar QA en este dispositivo") }
                        if(configured) {
                            Text("Código cargado en memoria. No se guarda en disco.")
                            OutlinedButton(
                                onClick={
                                    startActivity(Intent(this@CloudQaSetupActivity,
                                        MainActivity::class.java))
                                    finish()
                                },modifier=Modifier.fillMaxWidth()
                            ) { Text("Abrir SP-DECODE") }
                            TextButton(onClick={CloudQaMemory.clear();code="";configured=false}) {
                                Text("Borrar código")
                            }
                        }
                    }
                }
            }
        }
    }
}
