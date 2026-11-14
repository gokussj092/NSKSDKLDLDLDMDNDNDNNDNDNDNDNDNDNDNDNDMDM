package com.ghostdeveloper.spdecode.admin

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
internal fun ServerScreen(state: PreviewState, feedback: (String) -> Unit) {
    var service by rememberSaveable { mutableStateOf<String?>(null) }
    ScreenList {
        item {
            Tile(Modifier.fillMaxWidth(), GreenPanel) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Icon(
                        if (state.maintenance) Icons.Outlined.Build
                        else Icons.Outlined.MonitorHeart,
                        null,
                        tint = if (state.maintenance) Amber else Mint,
                    )
                    Text(
                        if (state.maintenance) "Mantenimiento de prueba" else "Operativo",
                        color = if (state.maintenance) Amber else Mint,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
                Small("Tiempo en línea · ejemplo")
                Text("14d 08h 32m", color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 30.sp)
            }
        }
        item { Meter("Procesador", 24, Mint) }
        item { Meter("Memoria RAM", 38, Blue) }
        item { Meter("Almacenamiento", 18, Purple) }
        item { Text("Servicios", color = Ink, fontWeight = FontWeight.SemiBold) }
        items(listOf("Nginx", "Web API", "Worker", "PostgreSQL", "Redis")) { name ->
            Row(
                Modifier.fillMaxWidth().clickable { service = name }.padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Icon(Icons.Outlined.CheckCircle, null, Modifier.size(18.dp), Mint)
                Text(name, Modifier.weight(1f), color = Ink, fontSize = 14.sp)
                Small("Online", color = Mint)
            }
        }
        item {
            Small("Instantánea local: ${state.refreshedAt}")
            SecondaryAction("Actualizar vista de prueba") {
                state.refreshedAt = state.now()
                feedback("Instantánea de demostración actualizada")
            }
        }
    }
    service?.let { name ->
        AlertDialog(
            onDismissRequest = { service = null },
            containerColor = Panel,
            title = { Text(name) },
            text = {
                Text(
                    "Servicio operativo en los datos de ejemplo. La supervisión y las acciones del VPS requieren conectar la API administrativa.",
                    color = Muted,
                )
            },
            confirmButton = { TextButton(onClick = { service = null }) { Text("Cerrar") } },
        )
    }
}

@Composable
private fun Meter(label: String, value: Int, tint: androidx.compose.ui.graphics.Color) {
    Tile(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label, color = Ink)
            Text("$value%", color = tint)
        }
        LinearProgressIndicator(
            progress = { value / 100f },
            modifier = Modifier.fillMaxWidth().height(7.dp),
            color = tint,
            trackColor = Border,
        )
    }
}

@Composable
internal fun CatalogScreen(state: PreviewState, feedback: (String) -> Unit) {
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf("Todas") }
    var draft by
        rememberSaveable(state.catalogVersion) {
            mutableStateOf(state.catalog.associate { it.id to it.enabled })
        }
    var confirm by rememberSaveable { mutableStateOf(false) }
    val changed = state.catalog.any { draft[it.id] != it.enabled }
    val rows =
        state.catalog.filter {
            it.name.contains(query.trim(), true) &&
                (filter == "Todas" ||
                    filter == "Activas" && draft[it.id] == true ||
                    filter == "Desactivadas" && draft[it.id] == false)
        }
    ScreenList {
        item {
            Tile(Modifier.fillMaxWidth(), GreenPanel) {
                Small("Versión del catálogo")
                Text(
                    state.catalogVersion.toString(),
                    color = Mint,
                    fontWeight = FontWeight.Bold,
                    fontSize = 32.sp,
                )
                Small("${state.catalog.size} aplicaciones de demostración")
            }
        }
        item { SearchField(query, { query = it }, "Buscar aplicación...") }
        item { FilterRow(listOf("Todas", "Activas", "Desactivadas"), filter) { filter = it } }
        if (rows.isEmpty())
            item {
                EmptyState(
                    "Sin aplicaciones",
                    "Prueba otro nombre o filtro.",
                    Icons.Outlined.Storage,
                )
            }
        items(rows, key = { it.id }) { app ->
            val enabled = draft[app.id] == true
            Column {
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Avatar(Icons.Outlined.Shield, if (enabled) Mint else Amber, 48)
                    Column(Modifier.weight(1f)) {
                        Text(app.name, color = Ink, fontWeight = FontWeight.SemiBold)
                        Small(
                            if (enabled)
                                if (app.id in listOf("hc", "hi")) "Método activo"
                                else "Catálogo activo"
                            else "Catálogo desactivado",
                            color = if (enabled) Mint else Amber,
                        )
                    }
                    Switch(enabled, { draft = draft + (app.id to it) })
                }
                HorizontalDivider(color = Border)
            }
        }
        if (changed) item { Small("Hay cambios sin publicar", color = Amber) }
        item { PrimaryAction("Publicar actualización", changed) { confirm = true } }
        if (changed)
            item {
                TextButton(
                    onClick = { draft = state.catalog.associate { it.id to it.enabled } },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Descartar cambios")
                }
            }
    }
    if (confirm)
        ConfirmationDialog(
            "Publicar actualización",
            "Se actualizará la versión y se añadirá un aviso únicamente en esta demostración. Los métodos y servicios reales no se modificarán.",
            "Publicar prueba",
            onDismiss = { confirm = false },
        ) {
            state.publishCatalog(draft)
            confirm = false
            feedback("Catálogo de prueba actualizado")
        }
}

@Composable
internal fun BroadcastScreen(state: PreviewState, feedback: (String) -> Unit) {
    var language by rememberSaveable { mutableStateOf("es") }
    var selected by rememberSaveable { mutableStateOf(noticeLanguages.map { it.code }) }
    var languagesOpen by rememberSaveable { mutableStateOf(false) }
    var preview by rememberSaveable { mutableStateOf(false) }
    var confirm by rememberSaveable { mutableStateOf(false) }
    val content = state.broadcastDraft.getValue(language)
    val valid =
        selected.isNotEmpty() &&
            selected.all { code ->
                state.broadcastDraft.getValue(code).let {
                    it.title.trim().length in 1..80 && it.message.trim().length in 1..1000
                }
            }
    ScreenList {
        item {
            SelectField(
                "Destinatarios",
                state.broadcastAudience,
                listOf("Todos los usuarios", "Usuarios activos", "Usuarios Premium"),
                { it },
            ) {
                state.broadcastAudience = it
            }
        }
        item {
            SelectField(
                "Tipo de aviso",
                state.broadcastType,
                listOf("Actualización de catálogo", "Aviso general", "Mantenimiento"),
                { it },
            ) {
                state.broadcastType = it
            }
        }
        item {
            SelectField(
                "Idioma que estás editando",
                language,
                noticeLanguages.map { it.code },
                { code -> noticeLanguages.first { it.code == code }.name },
            ) {
                language = it
            }
        }
        item {
            CompositionLocalProvider(
                LocalLayoutDirection provides
                    if (noticeLanguages.first { it.code == language }.rtl) LayoutDirection.Rtl
                    else LayoutDirection.Ltr
            ) {
                EditorField(
                    "Título",
                    content.title,
                    {
                        state.broadcastDraft =
                            state.broadcastDraft + (language to content.copy(title = it))
                    },
                    max = 80,
                )
            }
        }
        item {
            CompositionLocalProvider(
                LocalLayoutDirection provides
                    if (noticeLanguages.first { it.code == language }.rtl) LayoutDirection.Rtl
                    else LayoutDirection.Ltr
            ) {
                EditorField(
                    "Mensaje",
                    content.message,
                    {
                        state.broadcastDraft =
                            state.broadcastDraft + (language to content.copy(message = it))
                    },
                    max = 1000,
                    lines = 5,
                )
            }
        }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "Mostrar aviso dentro de la app",
                    Modifier.weight(1f),
                    color = Ink,
                    fontSize = 14.sp,
                )
                Switch(state.broadcastInApp, { state.broadcastInApp = it })
            }
        }
        item {
            Tile(Modifier.fillMaxWidth().clickable { languagesOpen = true }, GreenPanel) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Icon(Icons.Outlined.Translate, null, Modifier.size(20.dp), Mint)
                    Text(
                        "${selected.size} idiomas · Multiidioma",
                        Modifier.weight(1f),
                        color = Mint,
                        fontSize = 14.sp,
                    )
                    Icon(Icons.Outlined.ChevronRight, null, tint = Mint)
                }
            }
        }
        item {
            Small(
                "Edita y revisa el texto de cada idioma seleccionado. No se traducen automáticamente los cambios."
            )
        }
        if (!valid)
            item { Small("Selecciona al menos un idioma y completa sus campos.", color = Amber) }
        item { SecondaryAction("Vista previa del aviso") { preview = true } }
        item { PrimaryAction("Enviar notificación", valid) { confirm = true } }
    }
    if (languagesOpen)
        AlertDialog(
            onDismissRequest = { languagesOpen = false },
            containerColor = Panel,
            title = { Text("Idiomas del aviso") },
            text = {
                Column(Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState())) {
                    noticeLanguages.forEach { lang ->
                        Row(
                            Modifier.fillMaxWidth().clickable {
                                selected =
                                    if (lang.code in selected) selected - lang.code
                                    else selected + lang.code
                            },
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(
                                lang.code in selected,
                                { enabled ->
                                    selected =
                                        if (enabled) selected + lang.code else selected - lang.code
                                },
                            )
                            Text(lang.name, fontSize = 14.sp)
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { languagesOpen = false }) { Text("Listo") } },
        )
    if (preview)
        NoticePreview(
            content,
            noticeLanguages.first { it.code == language }.rtl,
            state.broadcastType == "Actualización de catálogo",
            { preview = false },
        )
    if (confirm)
        ConfirmationDialog(
            "Enviar notificación de prueba",
            "Se guardará una simulación para ${state.broadcastAudience.lowercase()} en ${selected.size} idiomas. No se enviarán notificaciones push ni avisos a clientes reales.",
            "Guardar simulación",
            onDismiss = { confirm = false },
        ) {
            state.publishNotice(
                state.broadcastAudience,
                state.broadcastType,
                state.broadcastDraft.filterKeys { it in selected },
                state.broadcastInApp,
            )
            confirm = false
            feedback("Aviso añadido a la demostración")
        }
}

@Composable
internal fun NoticePreview(
    content: LocalizedNotice,
    rtl: Boolean,
    catalog: Boolean,
    dismiss: () -> Unit,
) {
    CompositionLocalProvider(
        LocalLayoutDirection provides if (rtl) LayoutDirection.Rtl else LayoutDirection.Ltr
    ) {
        AlertDialog(
            onDismissRequest = dismiss,
            containerColor = Panel,
            icon = {
                Icon(
                    if (catalog) Icons.Outlined.Storage else Icons.Outlined.Notifications,
                    null,
                    tint = Mint,
                )
            },
            title = { Text(content.title) },
            text = { Text(content.message, color = Muted) },
            confirmButton = {
                TextButton(onClick = dismiss) {
                    Text(if (catalog) content.confirm else content.acknowledge)
                }
            },
            dismissButton = { TextButton(onClick = dismiss) { Text(content.cancel) } },
        )
    }
}

@Composable
internal fun SavedBroadcast(state: PreviewState, id: String, dismiss: () -> Unit) {
    val notice = state.broadcasts.firstOrNull { it.id == id }
    if (notice == null) {
        LaunchedEffect(Unit) { dismiss() }
        return
    }
    var language by remember {
        mutableStateOf(if ("es" in notice.messages) "es" else notice.messages.keys.first())
    }
    var preview by rememberSaveable { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = dismiss,
        containerColor = Panel,
        title = { Text("Aviso de prueba") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
                Small("${notice.audience} · ${notice.messages.size} idiomas")
                Small(
                    if (notice.inApp) "Aviso dentro de la app activado"
                    else "Aviso dentro de la app desactivado"
                )
                SelectField(
                    "Idioma",
                    language,
                    notice.messages.keys.toList(),
                    { code -> noticeLanguages.first { it.code == code }.name },
                ) {
                    language = it
                }
                Text(
                    notice.messages.getValue(language).title,
                    color = Ink,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(notice.messages.getValue(language).message, color = Muted)
            }
        },
        confirmButton = { TextButton(onClick = { preview = true }) { Text("Vista previa") } },
        dismissButton = { TextButton(onClick = dismiss) { Text("Cerrar") } },
    )
    if (preview)
        NoticePreview(
            notice.messages.getValue(language),
            noticeLanguages.first { it.code == language }.rtl,
            notice.type == "Actualización de catálogo",
            { preview = false },
        )
}

@Composable
internal fun LogsScreen(state: PreviewState, export: (String, String) -> Unit) {
    var filter by rememberSaveable { mutableStateOf("Todos") }
    var query by rememberSaveable { mutableStateOf("") }
    val rows =
        state.logs.filter {
            (filter == "Todos" ||
                filter == "Advertencias" && it.level == "WARN" ||
                filter == "Errores" && it.level == "ERROR") && it.text.contains(query.trim(), true)
        }
    ScreenList {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Metric(
                    "Operaciones",
                    state.logs.size.toString(),
                    Icons.Outlined.History,
                    modifier = Modifier.weight(1f),
                )
                Metric(
                    "Sin error",
                    "${if (state.logs.isEmpty()) 100 else state.logs.count { it.level != "ERROR" } * 100 / state.logs.size}%",
                    Icons.Outlined.CheckCircle,
                    modifier = Modifier.weight(1f),
                )
            }
        }
        item { SearchField(query, { query = it }, "Buscar actividad...") }
        item { FilterRow(listOf("Todos", "Advertencias", "Errores"), filter) { filter = it } }
        if (rows.isEmpty())
            item {
                EmptyState(
                    "Sin actividad",
                    "No hay registros que coincidan con el filtro.",
                    Icons.Outlined.History,
                )
            }
        items(rows, key = { it.id }) { LogCard(it) }
        item {
            SecondaryAction("Exportar registros") {
                export("SP-DECODE-Admin-Registros.csv", state.exportLogs())
            }
        }
    }
}

@Composable
internal fun LogCard(log: PreviewLog) {
    val color =
        when (log.level) {
            "WARN" -> Amber
            "ERROR" -> Red
            else -> Mint
        }
    Tile(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(log.level, color = color, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            Small(log.time)
        }
        Text(log.text, color = Ink, fontSize = 14.sp)
    }
}
