package com.ghostdeveloper.spdecode.admin

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONArray
import org.json.JSONObject

@Composable
internal fun SecurityScreen(go: (Page) -> Unit) {
    var info by rememberSaveable { mutableStateOf<String?>(null) }
    ScreenList {
        item {
            Tile(Modifier.fillMaxWidth(), GreenPanel) {
                Column(
                    Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Icon(Icons.Outlined.VerifiedUser, null, Modifier.size(48.dp), Mint)
                    Text(
                        "Seguridad administrativa",
                        color = Ink,
                        fontSize = 23.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Small("Conexión autenticada pendiente", color = Amber)
                }
            }
        }
        item {
            ActionRow("Acceso biométrico", Icons.Outlined.Fingerprint, "Pendiente de integración") {
                info = "Acceso biométrico"
            }
        }
        item {
            ActionRow(
                "Autenticación 2FA",
                Icons.Outlined.PhonelinkLock,
                "Pendiente de integración",
            ) {
                info = "Autenticación 2FA"
            }
        }
        item {
            ActionRow("Cambiar contraseña", Icons.Outlined.Lock, "Requiere una sesión real") {
                info = "Cambiar contraseña"
            }
        }
        item { ActionRow("Dispositivos y sesiones", Icons.Outlined.Devices) { go(Page.Sessions) } }
        item { ActionRow("Roles y permisos", Icons.Outlined.AdminPanelSettings) { go(Page.Roles) } }
        item { ActionRow("Auditoría administrativa", Icons.Outlined.History) { go(Page.Logs) } }
        item {
            Small(
                "Esta versión permite revisar los flujos de administración. El acceso real, la reautenticación y las sesiones revocables se validarán con el servidor."
            )
        }
    }
    info?.let { title ->
        AlertDialog(
            onDismissRequest = { info = null },
            containerColor = Panel,
            title = { Text(title) },
            text = {
                Text(
                    "Esta función requiere la integración de autenticación administrativa. No se solicitarán ni almacenarán contraseñas reales en la demostración.",
                    color = Muted,
                )
            },
            confirmButton = { TextButton(onClick = { info = null }) { Text("Entendido") } },
        )
    }
}

@Composable
internal fun SessionsScreen(state: PreviewState, feedback: (String) -> Unit) {
    var confirm by rememberSaveable { mutableStateOf(false) }
    ScreenList {
        item {
            Tile(Modifier.fillMaxWidth()) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Avatar(Icons.Outlined.PhoneAndroid)
                    Column {
                        Text("Este dispositivo", color = Ink, fontWeight = FontWeight.SemiBold)
                        Small("SP-DECODE Admin · demostración")
                        Small("Sesión visual de prueba", color = Mint)
                    }
                }
            }
        }
        if (state.otherSessions > 0) {
            item {
                Text("Otras sesiones de ejemplo", color = Ink, fontWeight = FontWeight.SemiBold)
            }
            items(state.otherSessions) { i ->
                Tile(Modifier.fillMaxWidth()) {
                    Text(if (i == 0) "Windows · Chrome" else "Android 15", color = Ink)
                    Small(if (i == 0) "Hace 2 horas" else "Ayer")
                    Small("Registro de demostración")
                }
            }
            item { SecondaryAction("Cerrar las demás sesiones", true) { confirm = true } }
        } else
            item {
                EmptyState(
                    "Solo este dispositivo",
                    "No quedan otras sesiones en los datos de prueba.",
                    Icons.Outlined.Devices,
                )
            }
    }
    if (confirm)
        ConfirmationDialog(
            "Cerrar otras sesiones",
            "Se eliminarán solo los registros de sesión de esta demostración.",
            "Cerrar sesiones",
            true,
            { confirm = false },
        ) {
            state.otherSessions = 0
            state.log("Otras sesiones de prueba cerradas")
            confirm = false
            feedback("Registros de sesión de prueba actualizados")
        }
}

@Composable
internal fun MaintenanceScreen(
    state: PreviewState,
    feedback: (String) -> Unit,
    export: (String, String) -> Unit,
    go: (Page) -> Unit,
) {
    var action by rememberSaveable { mutableStateOf("") }
    ScreenList {
        item {
            Tile(Modifier.fillMaxWidth()) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Avatar(Icons.Outlined.Storage)
                    Column {
                        Text("Caché del sistema", color = Ink, fontWeight = FontWeight.SemiBold)
                        Small("${state.cacheMb} MB utilizados · ejemplo")
                    }
                }
                SecondaryAction("Limpiar caché de prueba") { action = "cache" }
            }
        }
        item {
            Tile(Modifier.fillMaxWidth()) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Avatar(Icons.Outlined.Backup, Blue)
                    Column {
                        Text(
                            "Datos de administración",
                            color = Ink,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Small("Cuentas, operaciones y licencias de prueba")
                    }
                }
                SecondaryAction("Exportar datos de prueba") {
                    export("SP-DECODE-Admin-Datos-DEMO.json", previewData(state))
                }
            }
        }
        item {
            Tile(Modifier.fillMaxWidth()) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Avatar(Icons.Outlined.Dns)
                    Column {
                        Text("Servicios", color = Ink, fontWeight = FontWeight.SemiBold)
                        Small("5 servicios en la instantánea de ejemplo")
                    }
                }
                SecondaryAction("Ver estado de los servicios") { go(Page.Server) }
            }
        }
        item {
            Tile(Modifier.fillMaxWidth()) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Modo mantenimiento", color = Ink, fontWeight = FontWeight.SemiBold)
                        Small(
                            if (state.maintenance) "Activado en la demostración" else "Desactivado"
                        )
                    }
                    Switch(state.maintenance, { action = "maintenance" })
                }
                Small("Este control no interrumpe el servicio real.", color = Amber)
            }
        }
    }
    if (action.isNotEmpty())
        ConfirmationDialog(
            if (action == "cache") "Limpiar caché de prueba" else "Cambiar mantenimiento",
            "El cambio se aplicará solo a los datos y estados de esta vista previa.",
            onDismiss = { action = "" },
        ) {
            if (action == "cache") {
                state.cacheMb = 0
                state.log("Caché de prueba limpiada")
            } else {
                state.maintenance = !state.maintenance
                state.log("Mantenimiento de prueba: ${state.maintenance}")
            }
            action = ""
            feedback("Estado de prueba actualizado")
        }
}

private fun previewData(state: PreviewState): String =
    JSONObject()
        .apply {
            put("mode", "preview")
            put("warning", "Datos ficticios. No es un respaldo de producción.")
            put("generatedAt", state.now())
            put(
                "users",
                JSONArray().apply {
                    state.users.forEach { u ->
                        put(
                            JSONObject()
                                .put("id", u.id)
                                .put("name", u.name)
                                .put("email", u.email)
                                .put("status", u.status)
                                .put("credits", u.credits)
                        )
                    }
                },
            )
            put(
                "orders",
                JSONArray().apply {
                    state.orders.forEach { o ->
                        put(
                            JSONObject()
                                .put("id", o.id)
                                .put("userId", o.userId)
                                .put("product", o.productName)
                                .put("amountCents", o.cents)
                                .put("status", o.status.label)
                        )
                    }
                },
            )
            put(
                "licenses",
                JSONArray().apply {
                    state.licenses.forEach { l ->
                        put(
                            JSONObject()
                                .put("code", l.code)
                                .put("userId", l.userId)
                                .put("deviceLimit", l.devices)
                                .put("revoked", l.revoked)
                        )
                    }
                },
            )
            put("catalogVersion", state.catalogVersion)
        }
        .toString(2)

@Composable
internal fun SettingsScreen(state: PreviewState, go: (Page) -> Unit) {
    var about by rememberSaveable { mutableStateOf(false) }
    ScreenList {
        item {
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Avatar(Icons.Outlined.VerifiedUser, Mint, 56)
                Column {
                    Text("Administrador", color = Ink, fontWeight = FontWeight.SemiBold)
                    Small("SP-DECODE · vista previa", color = Mint)
                }
            }
        }
        item { Small("APARIENCIA", color = Mint) }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Appearance.entries.forEach { appearance ->
                    val selected = state.appearance == appearance
                    val background =
                        when (appearance) {
                            Appearance.Amoled -> Color.Black
                            Appearance.Dark -> Color(0xFF17231E)
                            Appearance.Light -> Color(0xFFF3F6F4)
                        }
                    Column(
                        Modifier.weight(1f).clickable { state.updateAppearance(appearance) },
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Box(
                            Modifier.fillMaxWidth()
                                .height(90.dp)
                                .background(
                                    if (selected) Mint else Border,
                                    RoundedCornerShape(14.dp),
                                )
                                .padding(2.dp)
                        ) {
                            Column(
                                Modifier.fillMaxSize()
                                    .background(background, RoundedCornerShape(12.dp))
                                    .padding(10.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Box(
                                    Modifier.fillMaxWidth(.6f)
                                        .height(5.dp)
                                        .background(Color(0xFF34D9A4), RoundedCornerShape(3.dp))
                                )
                                repeat(2) {
                                    Box(
                                        Modifier.fillMaxWidth()
                                            .height(18.dp)
                                            .background(
                                                if (appearance == Appearance.Light) Color.White
                                                else Color(0xFF2A3931),
                                                RoundedCornerShape(5.dp),
                                            )
                                    )
                                }
                            }
                        }
                        Small(
                            when (appearance) {
                                Appearance.Amoled -> "AMOLED"
                                Appearance.Dark -> "Oscuro"
                                Appearance.Light -> "Claro"
                            },
                            color = if (selected) Mint else Muted,
                        )
                    }
                }
            }
        }
        item {
            Tile(Modifier.fillMaxWidth()) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Indicadores de avisos", color = Ink)
                        Small("Muestra el contador de avisos en la barra")
                    }
                    Switch(state.notificationsEnabled, { state.setNotifications(it) })
                }
            }
        }
        item {
            DetailLine("Idioma de la interfaz", "Español")
            Small("Los avisos para clientes admiten los 14 idiomas de SP-DECODE.")
        }
        item { ActionRow("Notificaciones", Icons.Outlined.Notifications) { go(Page.Notices) } }
        item { ActionRow("Privacidad y seguridad", Icons.Outlined.Security) { go(Page.Security) } }
        item {
            ActionRow(
                "Acerca de",
                Icons.Outlined.Info,
                "SP-DECODE Admin · ${BuildConfig.VERSION_NAME}",
            ) {
                about = true
            }
        }
    }
    if (about)
        AlertDialog(
            onDismissRequest = { about = false },
            containerColor = Panel,
            icon = { Icon(Icons.Outlined.VerifiedUser, null, tint = Mint) },
            title = { Text("SP-DECODE Admin") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Ghost Nexora Studio")
                    Small("Versión ${BuildConfig.VERSION_NAME}")
                    Small(
                        "Vista previa de administración para Android. Datos locales de demostración.",
                        color = Amber,
                    )
                }
            },
            confirmButton = { TextButton(onClick = { about = false }) { Text("Cerrar") } },
        )
}
