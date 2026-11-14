package com.ghostdeveloper.spdecode.admin

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Send
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.filter

@Composable
internal fun SupportScreen(state: PreviewState, open: (String) -> Unit) {
    var filter by rememberSaveable { mutableStateOf("Todos") }
    var query by rememberSaveable { mutableStateOf("") }
    val rows =
        state.tickets.filter {
            (filter == "Todos" ||
                filter == "Pendientes" && !it.closed ||
                filter == "Cerrados" && it.closed) &&
                (state.user(it.userId).name.contains(query.trim(), true) ||
                    it.lastMessage.contains(query.trim(), true) ||
                    it.id.contains(query.trim()))
        }
    ScreenList {
        item { SearchField(query, { query = it }, "Buscar conversación...") }
        item {
            Row(
                Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                listOf(
                        "Todos" to state.tickets.size,
                        "Pendientes" to state.tickets.count { !it.closed },
                        "Cerrados" to state.tickets.count { it.closed },
                    )
                    .forEach { (label, count) ->
                        FilterChip(
                            filter == label,
                            { filter = label },
                            { Text("$label $count", fontSize = 13.sp) },
                            shape = CircleShape,
                            border = null,
                            colors =
                                FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = GreenPanel,
                                    selectedLabelColor = Mint,
                                ),
                        )
                    }
            }
        }
        if (rows.isEmpty())
            item {
                EmptyState(
                    "Sin conversaciones",
                    "No hay tickets que coincidan con esta búsqueda.",
                    Icons.Outlined.Forum,
                )
            }
        items(rows, key = { it.id }) { ticket ->
            Column {
                Row(
                    Modifier.fillMaxWidth().clickable { open(ticket.id) }.padding(vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    UserAvatar(state.user(ticket.userId), 52)
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(
                            state.user(ticket.userId).name,
                            color = Ink,
                            fontWeight =
                                if (ticket.unread > 0) FontWeight.Bold else FontWeight.Medium,
                        )
                        Text(
                            ticket.lastMessage,
                            color = Muted,
                            fontSize = 14.sp,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        if (ticket.closed) Small("Cerrado")
                    }
                    Column(
                        horizontalAlignment = Alignment.End,
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Small(ticket.time, color = if (ticket.unread > 0) Mint else Muted)
                        CountBadge(ticket.unread)
                    }
                }
                HorizontalDivider(color = Border)
            }
        }
    }
}

@Composable
internal fun ChatScreen(state: PreviewState, id: String, feedback: (String) -> Unit) {
    val keyboardOpen = WindowInsets.ime.getBottom(LocalDensity.current) > 0
    val ticket = state.ticket(id)
    var draft by rememberSaveable(id) { mutableStateOf("") }
    var assignment by rememberSaveable { mutableStateOf(false) }
    var attach by rememberSaveable { mutableStateOf(false) }
    val list = rememberLazyListState()
    LaunchedEffect(id, ticket.messages.size, keyboardOpen) {
        val expectedItems = ticket.messages.size + 1
        if (ticket.messages.isNotEmpty()) {
            snapshotFlow { list.layoutInfo.totalItemsCount to list.layoutInfo.viewportSize.height }
                .filter { (count, height) -> count == expectedItems && height > 0 }
                .collectLatest {
                    // Both the keyboard and clearing a multiline draft can resize the viewport.
                    // Follow each size change so the final layout still shows the sent message.
                    withFrameNanos {}
                    list.scrollToItem(expectedItems - 1)
                }
        }
    }
    Box(Modifier.fillMaxSize().imePadding(), contentAlignment = Alignment.TopCenter) {
        Column(Modifier.widthIn(max = 840.dp).fillMaxSize().padding(horizontal = 16.dp)) {
            if (!keyboardOpen)
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Small("Ticket #${ticket.id}")
                    Small(
                        if (ticket.closed) "● Cerrado" else "● Abierto",
                        color = if (ticket.closed) Muted else Mint,
                    )
                }
            HorizontalDivider(color = Border)
            LazyColumn(
                Modifier.weight(1f).fillMaxWidth(),
                state = list,
                contentPadding = PaddingValues(vertical = 18.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                item(key = "day") {
                    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        Small(
                            "Hoy",
                            Modifier.background(Panel, CircleShape)
                                .padding(horizontal = 12.dp, vertical = 6.dp),
                        )
                    }
                }
                items(ticket.messages, key = { it.id }) { MessageBubble(it, keyboardOpen) }
            }
            HorizontalDivider(color = Border)
            if (!keyboardOpen)
                Row(
                    Modifier.fillMaxWidth()
                        .clickable { assignment = true }
                        .padding(vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Small(
                        "Asignado a: ${state.staff.firstOrNull { it.id == ticket.agentId }?.name ?: "Sin asignar"}",
                        Modifier.weight(1f),
                    )
                    Icon(
                        Icons.Outlined.ManageAccounts,
                        "Cambiar agente",
                        Modifier.size(20.dp),
                        Mint,
                    )
                }
            if (ticket.closed)
                PrimaryAction("Reabrir ticket") {
                    state.updateTicket(ticket.copy(closed = false))
                    feedback("Ticket reabierto en la demostración")
                }
            else
                Row(
                    Modifier.fillMaxWidth().padding(bottom = 10.dp),
                    verticalAlignment = Alignment.Bottom,
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    IconButton(onClick = { attach = true }, modifier = Modifier.size(48.dp)) {
                        Icon(
                            Icons.Outlined.AttachFile,
                            "Adjuntar archivo",
                            Modifier.size(21.dp),
                            Muted,
                        )
                    }
                    TextField(
                        draft,
                        { draft = it.take(2000) },
                        placeholder = {
                            Text(
                                "Escribir mensaje...",
                                fontSize = 14.sp,
                                lineHeight = 20.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                        textStyle =
                            MaterialTheme.typography.bodyMedium.copy(
                                fontSize = 15.sp,
                                lineHeight = 20.sp,
                            ),
                        shape = RoundedCornerShape(25.dp),
                        maxLines = if (keyboardOpen) 2 else 4,
                        colors = fieldColors(),
                        modifier = Modifier.weight(1f),
                    )
                    FilledIconButton(
                        onClick = {
                            state.send(id, draft)
                            draft = ""
                        },
                        enabled = draft.isNotBlank(),
                        modifier = Modifier.size(48.dp),
                        colors =
                            IconButtonDefaults.filledIconButtonColors(
                                containerColor = Mint,
                                contentColor = MaterialTheme.colorScheme.onPrimary,
                                disabledContainerColor = Panel,
                                disabledContentColor = Muted,
                            ),
                    ) {
                        Icon(
                            Icons.AutoMirrored.Outlined.Send,
                            "Añadir mensaje local",
                            Modifier.size(21.dp),
                        )
                    }
                }
        }
    }
    if (assignment)
        AlertDialog(
            onDismissRequest = { assignment = false },
            containerColor = Panel,
            title = { Text("Asignar agente") },
            text = {
                Column {
                    Small("Asignación de prueba", color = Amber)
                    val agents =
                        state.staff.filter {
                            Permission.SupportReply in state.role(it.roleId).permissions
                        }
                    agents.forEach { agent ->
                        Row(
                            Modifier.fillMaxWidth().clickable {
                                state.updateTicket(ticket.copy(agentId = agent.id))
                                assignment = false
                            },
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(
                                agent.id == ticket.agentId,
                                {
                                    state.updateTicket(ticket.copy(agentId = agent.id))
                                    assignment = false
                                },
                            )
                            Text(agent.name, fontSize = 14.sp)
                        }
                    }
                    if (agents.isEmpty()) Small("No hay agentes con permiso de respuesta.")
                }
            },
            confirmButton = { TextButton(onClick = { assignment = false }) { Text("Cerrar") } },
        )
    if (attach)
        AlertDialog(
            onDismissRequest = { attach = false },
            containerColor = Panel,
            title = { Text("Archivos adjuntos") },
            text = {
                Text(
                    "La carga de archivos se habilitará al conectar el soporte con el servidor.",
                    color = Muted,
                )
            },
            confirmButton = { TextButton(onClick = { attach = false }) { Text("Entendido") } },
        )
}

@Composable
private fun MessageBubble(message: PreviewMessage, compact: Boolean) {
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        val width = maxWidth * .86f
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = if (message.outgoing) Arrangement.End else Arrangement.Start,
        ) {
            Column(
                Modifier.widthIn(max = width)
                    .background(
                        if (message.outgoing) GreenPanel else Panel,
                        RoundedCornerShape(
                            topStart = 17.dp,
                            topEnd = 17.dp,
                            bottomStart = if (message.outgoing) 17.dp else 4.dp,
                            bottomEnd = if (message.outgoing) 4.dp else 17.dp,
                        ),
                    )
                    .padding(horizontal = 14.dp, vertical = if (compact) 8.dp else 11.dp),
                verticalArrangement = Arrangement.spacedBy(if (compact) 4.dp else 6.dp),
            ) {
                if (message.outgoing)
                    Text(message.author, color = Mint, fontSize = 12.sp, lineHeight = 16.sp)
                Text(message.text, color = Ink, fontSize = 15.sp, lineHeight = 20.sp)
                Row(
                    Modifier.align(Alignment.End),
                    horizontalArrangement = Arrangement.spacedBy(5.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(message.time, color = Muted, fontSize = 12.sp, lineHeight = 16.sp)
                    if (message.outgoing) {
                        Icon(
                            if (message.local) Icons.Outlined.Schedule else Icons.Outlined.DoneAll,
                            if (message.local) "Mensaje local, no enviado"
                            else "Mensaje de ejemplo",
                            Modifier.size(14.dp),
                            Mint,
                        )
                        if (message.local)
                            Text("Local", color = Mint, fontSize = 12.sp, lineHeight = 16.sp)
                    }
                }
            }
        }
    }
}

@Composable
internal fun NoticesScreen(
    state: PreviewState,
    open: (PreviewNotice) -> Unit,
    compose: () -> Unit,
) {
    var filter by rememberSaveable { mutableStateOf("Todas") }
    val rows = state.notices.filter { filter == "Todas" || !it.read }
    ScreenList {
        item { SecondaryAction("Enviar notificación", onClick = compose) }
        item { FilterRow(listOf("Todas", "Sin leer"), filter) { filter = it } }
        item { Small("HOY") }
        if (rows.isEmpty())
            item {
                EmptyState(
                    "Todo al día",
                    "No hay notificaciones sin leer.",
                    Icons.Outlined.NotificationsNone,
                )
            }
        items(rows, key = { it.id }) { notice ->
            val tint =
                when (notice.kind) {
                    "support" -> Blue
                    "user" -> Purple
                    "service" -> Amber
                    else -> Mint
                }
            val icon =
                when (notice.kind) {
                    "support" -> Icons.Outlined.Forum
                    "user" -> Icons.Outlined.PersonAdd
                    "service" -> Icons.Outlined.WarningAmber
                    "catalog" -> Icons.Outlined.Storage
                    "broadcast" -> Icons.Outlined.Campaign
                    else -> Icons.Outlined.ShoppingBag
                }
            Column {
                Row(
                    Modifier.fillMaxWidth()
                        .clickable {
                            state.markNoticeRead(notice.id)
                            open(notice)
                        }
                        .padding(vertical = 14.dp),
                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    Avatar(icon, tint)
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(
                            notice.title,
                            color = Ink,
                            fontWeight =
                                if (notice.read) FontWeight.Medium else FontWeight.SemiBold,
                            fontSize = 15.sp,
                        )
                        Text(notice.text, color = Muted, fontSize = 14.sp)
                        Small(notice.time)
                    }
                    if (!notice.read)
                        Box(Modifier.padding(top = 6.dp).size(6.dp).background(tint, CircleShape))
                }
                HorizontalDivider(color = Border)
            }
        }
    }
}
