package com.ghostdeveloper.spdecode.offline

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.database.Cursor
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.InputType
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * UI and Android SAF only. Kotlin contains no decryption, crypto KDF,
 * key generation, provider catalog or network transport.
 */
class MainActivity : ComponentActivity() {
    private lateinit var status: TextView
    private lateinit var output: TextView
    private lateinit var password: EditText
    private lateinit var hwid: EditText
    private var resultText = ""
    private var exportName = "spdecode-offline.json"

    private val importer = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) process(uri)
    }
    private val exporter = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        if (uri != null && resultText.isNotEmpty()) {
            try {
                contentResolver.openOutputStream(uri)?.use {
                    it.write(resultText.toByteArray(Charsets.UTF_8))
                } ?: error("No export stream")
                status.text = "JSON exportado."
            } catch (_: Exception) {
                status.text = "No se pudo exportar el JSON."
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.statusBarColor = Color.BLACK
        window.navigationBarColor = Color.BLACK
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
            setBackgroundColor(Color.BLACK)
        }
        setContentView(ScrollView(this).apply { addView(root) })
        fun label(value: String, fontSize: Float = 14f) = TextView(this).apply {
            text = value
            textSize = fontSize
            setTextColor(Color.WHITE)
            setPadding(0, 10, 0, 10)
        }
        fun action(value: String, callback: () -> Unit) {
            root.addView(Button(this).apply {
                text = value
                isAllCaps = false
                setOnClickListener { callback() }
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        root.addView(label("SP-DECODE Offline", 25f))
        root.addView(label("Sin Internet · Motor C++/JNI · Alfa de integración"))
        root.addView(label("Descifrado disponible: NetMod Syna (.nm) y HTTP Custom (.hc) "
            + "HCCFG/HCX4 compatible con contraseña, HWID y ambos.\n"
            + "Generación de identidad NPV P-256: disponible.\n"
            + "HTTP Custom antiguo (no HCCFG), HTTP Injector y descifrado NPV: pendientes. "
            + "Sin descifrado Kotlin ni servicios Cloud."))
        password = EditText(this).apply {
            hint = "Contraseña HTTP Custom (si está protegida)"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setTextColor(Color.WHITE); setHintTextColor(Color.LTGRAY)
        }
        hwid = EditText(this).apply {
            hint = "HWID HTTP Custom (si está vinculado)"
            inputType = InputType.TYPE_CLASS_TEXT
            setTextColor(Color.WHITE); setHintTextColor(Color.LTGRAY)
        }
        root.addView(password)
        root.addView(hwid)
        action("Importar archivo de configuración") { importer.launch(arrayOf("*/*")) }
        action("Generar clave pública y privada NPV") {
            status.text = "Generando claves P-256 localmente…"
            Thread {
                val value = runCatching { NativeOffline.generateIdentityNative() }
                runOnUiThread {
                    value.onSuccess {
                        show(it, "npv-identity.json")
                        status.text = "Claves P-256 generadas. Conserva la clave privada en un lugar seguro."
                    }.onFailure { status.text = "No se pudieron generar las claves NPV." }
                }
            }.start()
        }
        action("Copiar resultado completo") {
            if (resultText.isNotEmpty()) {
                val clip = ClipData.newPlainText("SP-DECODE Offline", resultText)
                (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(clip)
                status.text = "Copiado: el resultado puede contener secretos."
            }
        }
        action("Exportar JSON") {
            if (resultText.isNotEmpty()) exporter.launch(exportName)
        }
        status = label("Selecciona un archivo o genera una identidad.")
        root.addView(status)
        output = label("", 12f).apply {
            setTextIsSelectable(true)
            typeface = android.graphics.Typeface.MONOSPACE
        }
        root.addView(output)
    }

    private fun process(uri: Uri) {
        var fileName = "documento"
        var cursor: Cursor? = null
        try {
            cursor = contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            if (cursor?.moveToFirst() == true) {
                val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (index >= 0) fileName = cursor.getString(index) ?: fileName
            }
        } catch (_: Exception) { } finally { cursor?.close() }
        val extension = fileName.substringAfterLast('.', "").lowercase()
        if (extension !in setOf("nm", "hc", "ehi", "npv4", "npvt", "npvs")) {
            status.text = "Este formato no está incluido en la edición nativa."
            return
        }
        val pass = password.text.toString()
        val hardwareId = hwid.text.toString()
        status.text = "Analizando localmente: " + fileName
        Thread {
            val result = runCatching {
                val bytes = contentResolver.openInputStream(uri)?.use { input ->
                    val output = ByteArrayOutputStream()
                    val buffer = ByteArray(8192)
                    while (true) {
                        val n = input.read(buffer)
                        if (n < 0) break
                        if (output.size() + n > 4 * 1024 * 1024) error("Archivo mayor de 4 MiB")
                        output.write(buffer, 0, n)
                    }
                    output.toByteArray()
                } ?: error("Archivo inaccesible")
                try {
                    val nativeBytes = NativeOffline.decodeNative(bytes, extension, pass, hardwareId)
                    val text = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(nativeBytes)).toString()
                    JSONObject(text) // Validate JSON structure; no cryptographic work here.
                    nativeBytes.fill(0)
                    text
                } finally {
                    bytes.fill(0)
                }
            }
            runOnUiThread {
                result.onSuccess {
                    show(it, fileName.substringBeforeLast('.') + ".json")
                    status.text = "Descifrado C++ completo: " + fileName
                }.onFailure {
                    status.text = "Sin resultado: " + (it.message ?: "error")
                }
            }
        }.start()
    }
    private fun show(value: String, name: String) {
        resultText = value
        exportName = name
        output.text = value
    }
}
