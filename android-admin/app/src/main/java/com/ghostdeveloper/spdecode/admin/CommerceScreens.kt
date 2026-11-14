package com.ghostdeveloper.spdecode.admin

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ReceiptLong
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.time.LocalDate
import kotlin.math.abs

@Composable
internal fun FinanceScreen(state: PreviewState, go: (Page) -> Unit) {
    var days by rememberSaveable { mutableIntStateOf(30) }
    val rows = state.orders.filter { it.ageDays < days }
    val total = state.revenue(days)
    val previous = state.revenue(days * 2) - total
    val comparison =
        if (previous == 0L) "Operaciones de demostración"
        else
            String.format(
                java.util.Locale.ROOT,
                "%+.1f%% respecto al periodo anterior",
                (total - previous) * 100.0 / abs(previous),
            )
    ScreenList {
        item {
            FilterRow(listOf("7 días", "30 días", "90 días"), "$days días") {
                days = it.substringBefore(' ').toInt()
            }
        }
        item {
            Tile(Modifier.fillMaxWidth(), GreenPanel) {
                Small("Ingresos netos")
                Text(money(total), color = Mint, fontSize = 36.sp, fontWeight = FontWeight.Bold)
                Small(comparison, color = Mint)
                Spacer(Modifier.height(10.dp))
                Trend(financePoints(rows, days))
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Metric(
                    "Ventas",
                    rows.count { it.status == OrderStatus.Completed }.toString(),
                    Icons.AutoMirrored.Outlined.ReceiptLong,
                    modifier = Modifier.weight(1f),
                )
                Metric(
                    "Por confirmar",
                    rows.count { it.status == OrderStatus.Pending }.toString(),
                    Icons.Outlined.Schedule,
                    Amber,
                    Modifier.weight(1f),
                )
            }
        }
        item { Text("Métodos de pago", color = Ink, fontWeight = FontWeight.SemiBold) }
        items(listOf("PayPal", "Stripe", "Mercado Pago")) { provider ->
            val net =
                rows
                    .filter { it.provider == provider }
                    .sumOf { if (it.status == OrderStatus.Completed) it.cents else 0L }
            val positive =
                rows
                    .filter { it.status == OrderStatus.Completed }
                    .sumOf { it.cents }
                    .coerceAtLeast(1)
            val tint =
                when (provider) {
                    "PayPal" -> Blue
                    "Stripe" -> Purple
                    else -> Mint
                }
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(provider, color = Ink, fontSize = 14.sp)
                    Text(money(net), color = Ink, fontSize = 14.sp)
                }
                LinearProgressIndicator(
                    progress = { (net.toFloat() / positive).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth().height(6.dp),
                    color = tint,
                    trackColor = Border,
                )
            }
        }
        item { SecondaryAction("Ver historial de operaciones") { go(Page.Purchases) } }
        item { Small("Los pedidos reembolsados y pendientes no cuentan como ingresos.") }
    }
}

private fun financePoints(rows: List<PreviewOrder>, days: Int): List<Float> {
    var sum = 0L
    val values =
        (6 downTo 0).map { bucket ->
            sum +=
                rows
                    .filter { (it.ageDays * 7 / days).coerceIn(0, 6) == bucket }
                    .sumOf { if (it.status == OrderStatus.Completed) it.cents else 0L }
            sum
        }
    val min = minOf(0L, values.min())
    val range = (values.max() - min).coerceAtLeast(1)
    return values.map { .9f - ((it - min).toFloat() / range) * .8f }
}

@Composable
internal fun PurchasesScreen(state: PreviewState, open: (String) -> Unit) {
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf("Todos") }
    val rows =
        state.orders.filter {
            (filter == "Todos" || it.status.label == filter) &&
                listOf(it.id, it.productName, state.user(it.userId).name, it.provider).any { text ->
                    text.contains(query.trim(), true)
                }
        }
    ScreenList {
        item { SearchField(query, { query = it }, "Buscar pedido...") }
        item {
            FilterRow(listOf("Todos") + OrderStatus.entries.map { it.label }, filter) {
                filter = it
            }
        }
        if (rows.isEmpty())
            item {
                EmptyState(
                    "Sin operaciones",
                    "Prueba otro pedido, usuario o estado.",
                    Icons.Outlined.ShoppingBag,
                )
            }
        items(rows, key = { it.id }) { OrderCard(state, it) { open(it.id) } }
        item { Small("${rows.size} operaciones de prueba") }
    }
}

@Composable
internal fun OrderCard(state: PreviewState, order: PreviewOrder, open: () -> Unit) {
    Tile(Modifier.fillMaxWidth().clickable(onClick = open)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Small("#${order.id}")
            Text(
                (if (order.status == OrderStatus.Completed) "+"
                else if (order.status == OrderStatus.Refunded) "−" else "") + money(order.cents),
                color = statusColor(order.status.label),
                fontWeight = FontWeight.SemiBold,
                fontSize = 14.sp,
            )
        }
        Text(order.productName, color = Ink, fontWeight = FontWeight.SemiBold)
        Small("${state.user(order.userId).name} · ${order.provider}")
        Small(order.status.label, color = statusColor(order.status.label))
    }
}

@Composable
internal fun OrderDetailScreen(state: PreviewState, id: String, feedback: (String) -> Unit) {
    val order = state.orders.first { it.id == id }
    var action by remember { mutableStateOf<OrderStatus?>(null) }
    ScreenList {
        item {
            Tile(Modifier.fillMaxWidth(), GreenPanel) {
                Small("Pedido #${order.id}")
                Text(
                    money(order.cents),
                    color = Mint,
                    fontSize = 34.sp,
                    fontWeight = FontWeight.Bold,
                )
                Text(order.productName, color = Ink)
                Small(order.status.label, color = statusColor(order.status.label))
            }
        }
        item {
            DetailLine("Usuario", state.user(order.userId).name)
            DetailLine("Correo", state.user(order.userId).email)
            DetailLine("Método de pago", order.provider)
            DetailLine(
                "Fecha de ejemplo",
                LocalDate.now().minusDays(order.ageDays.toLong()).toString(),
            )
            DetailLine("Moneda", "USD")
        }
        if (order.status == OrderStatus.Pending)
            item {
                PrimaryAction("Completar operación de prueba") { action = OrderStatus.Completed }
            }
        if (order.status != OrderStatus.Refunded)
            item {
                SecondaryAction("Registrar reembolso de prueba", true) {
                    action = OrderStatus.Refunded
                }
            }
        item {
            Small(
                "Los cambios de esta vista no procesan cobros ni reembolsos reales.",
                color = Amber,
            )
        }
    }
    if (action != null)
        ConfirmationDialog(
            "Actualizar operación",
            "Se registrará el estado ${action!!.label.lowercase()} solo en la demostración. No se contactará con ${order.provider}.",
            danger = action == OrderStatus.Refunded,
            onDismiss = { action = null },
        ) {
            state.changeOrder(id, action!!)
            action = null
            feedback("Operación de prueba actualizada")
        }
}

@Composable
internal fun DetailLine(label: String, value: String) {
    Column(
        Modifier.fillMaxWidth().padding(vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(5.dp),
    ) {
        Small(label)
        Text(value, color = Ink, fontSize = 15.sp)
        HorizontalDivider(Modifier.padding(top = 8.dp), color = Border)
    }
}

@Composable
private fun productIcon(kind: ProductKind) =
    when (kind) {
        ProductKind.Offline -> Icons.Outlined.Memory
        ProductKind.Api -> Icons.Outlined.Code
        ProductKind.Credits -> Icons.Outlined.Inventory2
    }

@Composable
private fun productTint(kind: ProductKind) =
    when (kind) {
        ProductKind.Offline -> Mint
        ProductKind.Api -> Purple
        ProductKind.Credits -> Amber
    }

@Composable
internal fun ProductsScreen(state: PreviewState, feedback: (String) -> Unit) {
    var editId by rememberSaveable { mutableStateOf<String?>(null) }
    val edit = state.products.firstOrNull { it.id == editId }
    ScreenList {
        items(state.products, key = { it.id }) { product ->
            Tile(Modifier.fillMaxWidth()) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Avatar(productIcon(product.kind), productTint(product.kind), 52)
                    Column(Modifier.weight(1f)) {
                        Text(product.name, color = Ink, fontWeight = FontWeight.SemiBold)
                        Small(product.description)
                    }
                }
                Row(
                    Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        money(product.cents),
                        color = Ink,
                        fontSize = 28.sp,
                        fontWeight = FontWeight.Bold,
                    )
                    Small(
                        if (product.available) "● Disponible" else "● No disponible",
                        color = if (product.available) Mint else Muted,
                    )
                }
                SecondaryAction("Editar producto") { editId = product.id }
            }
        }
    }
    edit?.let { product ->
        ProductForm(state, product, { editId = null }) {
            editId = null
            feedback("Producto de prueba actualizado")
        }
    }
}

@Composable
private fun ProductForm(
    state: PreviewState,
    product: PreviewProduct,
    dismiss: () -> Unit,
    saved: () -> Unit,
) {
    var name by rememberSaveable(product.id) { mutableStateOf(product.name) }
    var description by rememberSaveable(product.id) { mutableStateOf(product.description) }
    var price by
        rememberSaveable(product.id) { mutableStateOf(money(product.cents).removePrefix("$")) }
    var available by rememberSaveable(product.id) { mutableStateOf(product.available) }
    val cents = parsePrice(price)
    FormDialog(
        "Editar producto",
        name.trim().length >= 3 && description.isNotBlank() && cents != null,
        onDismiss = dismiss,
        onConfirm = {
            state.saveProduct(
                product.copy(
                    name = name,
                    description = description,
                    cents = cents!!,
                    available = available,
                )
            )
            saved()
        },
    ) {
        EditorField("Producto", name, { name = it }, max = 80)
        EditorField("Descripción", description, { description = it })
        EditorField("Precio en USD", price, { price = it }, KeyboardType.Decimal, max = 10)
        if (cents == null)
            Small("Usa un precio entre 0.01 y 99,999.99 con hasta dos decimales.", color = Amber)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Disponible", Modifier.weight(1f), color = Ink)
            Switch(available, { available = it })
        }
    }
}

@Composable
internal fun LicensesScreen(state: PreviewState, create: () -> Unit, open: (String) -> Unit) {
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf("Todas") }
    val rows =
        state.licenses.filter {
            (filter == "Todas" ||
                filter == "Activas" && !it.revoked ||
                filter == "Revocadas" && it.revoked) &&
                (state.user(it.userId).name.contains(query.trim(), true) ||
                    it.code.contains(query.trim(), true))
        }
    ScreenList {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Metric(
                    "Activas",
                    state.licenses.count { !it.revoked }.toString(),
                    Icons.Outlined.VpnKey,
                    modifier = Modifier.weight(1f),
                )
                Metric(
                    "Revocadas",
                    state.licenses.count { it.revoked }.toString(),
                    Icons.Outlined.Block,
                    Red,
                    Modifier.weight(1f),
                )
            }
        }
        item { SearchField(query, { query = it }, "Buscar licencia...") }
        item { FilterRow(listOf("Todas", "Activas", "Revocadas"), filter) { filter = it } }
        if (rows.isEmpty())
            item {
                EmptyState(
                    "Sin licencias",
                    "No hay licencias para esta búsqueda.",
                    Icons.Outlined.VpnKey,
                )
            }
        items(rows, key = { it.id }) { LicenseCard(state, it) { open(it.id) } }
        item { PrimaryAction("+ Generar licencia", onClick = create) }
    }
}

@Composable
internal fun LicenseCard(state: PreviewState, license: PreviewLicense, open: () -> Unit) {
    Tile(Modifier.fillMaxWidth().clickable(onClick = open)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(Icons.Outlined.VpnKey, null, Modifier.size(18.dp), Mint)
            Text(
                state.user(license.userId).name,
                Modifier.weight(1f),
                color = Ink,
                fontWeight = FontWeight.Medium,
            )
            Small(
                if (license.revoked) "Revocada" else "Activa",
                color = if (license.revoked) Red else Mint,
            )
        }
        Small("DEMO-SPD-••••-${license.code.takeLast(4)}")
        Small("${license.used} de ${license.devices} dispositivos")
    }
}

@Composable
internal fun LicenseForm(state: PreviewState, dismiss: () -> Unit, created: (String) -> Unit) {
    var userId by rememberSaveable { mutableStateOf(state.users.first().id) }
    var devices by rememberSaveable { mutableIntStateOf(3) }
    var expiry by rememberSaveable { mutableIntStateOf(0) }
    FormDialog(
        "Generar licencia",
        true,
        "Generar",
        dismiss,
        { created(state.generateLicense(userId, devices, expiry).id) },
    ) {
        Small(
            "La clave generada incluye DEMO y solo sirve para revisar esta interfaz.",
            color = Amber,
        )
        SelectField("Usuario", userId, state.users.map { it.id }, { state.user(it).name }) {
            userId = it
        }
        SelectField("Dispositivos", devices, listOf(1, 2, 3, 5, 10), { "$it dispositivos" }) {
            devices = it
        }
        SelectField(
            "Vigencia",
            expiry,
            listOf(0, 7, 30, 90, 365),
            { if (it == 0) "Sin vencimiento" else "$it días" },
        ) {
            expiry = it
        }
    }
}

@Composable
internal fun LicenseDetailScreen(state: PreviewState, id: String, feedback: (String) -> Unit) {
    val value = state.licenses.first { it.id == id }
    var confirm by rememberSaveable { mutableStateOf(false) }
    val copy = rememberCopyToClipboard()
    ScreenList {
        item {
            Tile(Modifier.fillMaxWidth(), GreenPanel) {
                Avatar(Icons.Outlined.VpnKey)
                Text(
                    "SP-DECODE Offline",
                    color = Ink,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Small(state.user(value.userId).name)
                Small(
                    if (value.revoked) "● Revocada" else "● Activa",
                    color = if (value.revoked) Red else Mint,
                )
            }
        }
        item {
            DetailLine("Clave de demostración", value.code)
            SecondaryAction("Copiar clave de prueba") {
                copy(value.code)
                feedback("Clave de prueba copiada")
            }
        }
        item {
            DetailLine("Dispositivos", "${value.used} de ${value.devices}")
            DetailLine(
                "Vigencia",
                if (value.expiryDays == 0) "Sin vencimiento"
                else "${value.expiryDays} días desde su creación",
            )
        }
        if (value.used > 0) {
            item { Text("Dispositivos de ejemplo", color = Ink, fontWeight = FontWeight.SemiBold) }
            items(value.used) { i ->
                Tile(Modifier.fillMaxWidth()) {
                    Text("Android · dispositivo ${i + 1}", color = Ink)
                    Small("Registro de demostración")
                }
            }
        }
        item {
            SecondaryAction(
                if (value.revoked) "Restaurar licencia" else "Revocar licencia",
                !value.revoked,
            ) {
                confirm = true
            }
        }
    }
    if (confirm)
        ConfirmationDialog(
            if (value.revoked) "Restaurar licencia" else "Revocar licencia",
            "Se cambiará únicamente esta licencia de prueba.",
            danger = !value.revoked,
            onDismiss = { confirm = false },
        ) {
            state.toggleLicense(id)
            confirm = false
            feedback("Licencia de prueba actualizada")
        }
}

@Composable
internal fun GiftsScreen(state: PreviewState, history: () -> Unit, feedback: (String) -> Unit) {
    val available = state.products.filter { it.available }
    var productId by rememberSaveable { mutableStateOf("offline") }
    var uses by rememberSaveable { mutableIntStateOf(1) }
    var expiry by rememberSaveable { mutableIntStateOf(0) }
    var devices by rememberSaveable { mutableIntStateOf(3) }
    var result by remember { mutableStateOf<PreviewGift?>(null) }
    val selected = available.firstOrNull { it.id == productId } ?: available.firstOrNull()
    ScreenList {
        item {
            Tile(Modifier.fillMaxWidth(), GreenPanel) {
                Column(
                    Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Icon(Icons.Outlined.CardGiftcard, null, Modifier.size(46.dp), Mint)
                    Text(
                        "Crear código",
                        color = Ink,
                        fontSize = 26.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text("Genera recompensas para tus usuarios.", color = Muted, fontSize = 14.sp)
                }
            }
        }
        if (selected != null)
            item {
                SelectField(
                    "Recompensa",
                    selected.id,
                    available.map { it.id },
                    { state.product(it).name },
                ) {
                    productId = it
                }
            }
        else
            item {
                EmptyState(
                    "Sin productos disponibles",
                    "Activa un producto antes de generar un código.",
                    Icons.Outlined.ShoppingBag,
                )
            }
        item {
            SelectField(
                "Cantidad de usos",
                uses,
                listOf(1, 5, 10, 25, 100),
                { if (it == 1) "1 usuario" else "$it usuarios" },
            ) {
                uses = it
            }
        }
        item {
            SelectField(
                "Caducidad",
                expiry,
                listOf(0, 7, 30, 90, 365),
                { if (it == 0) "Sin vencimiento" else "$it días" },
            ) {
                expiry = it
            }
        }
        if (selected?.kind == ProductKind.Offline)
            item {
                SelectField(
                    "Dispositivos",
                    devices,
                    listOf(1, 2, 3, 5, 10),
                    { "$it dispositivos" },
                ) {
                    devices = it
                }
            }
        item {
            PrimaryAction("Generar gift code", selected != null) {
                result = state.generateGift(selected!!.id, uses, expiry, devices)
                feedback("Código añadido al historial de prueba")
            }
        }
        item { SecondaryAction("Ver historial de códigos", onClick = history) }
    }
    result?.let { gift ->
        val copy = rememberCopyToClipboard()
        AlertDialog(
            onDismissRequest = { result = null },
            containerColor = Panel,
            icon = { Icon(Icons.Outlined.CardGiftcard, null, tint = Mint) },
            title = { Text("Código de prueba generado") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(gift.code, color = Mint, fontWeight = FontWeight.SemiBold)
                    Small("Este código DEMO no puede canjearse en el servidor.", color = Amber)
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        copy(gift.code)
                        feedback("Código de prueba copiado")
                    }
                ) {
                    Text("Copiar")
                }
            },
            dismissButton = { TextButton(onClick = { result = null }) { Text("Cerrar") } },
        )
    }
}

@Composable
internal fun GiftHistoryScreen(state: PreviewState, feedback: (String) -> Unit) {
    var query by rememberSaveable { mutableStateOf("") }
    var selected by remember { mutableStateOf<PreviewGift?>(null) }
    val copy = rememberCopyToClipboard()
    val rows =
        state.gifts.filter {
            it.code.contains(query.trim(), true) ||
                state.product(it.productId).name.contains(query.trim(), true)
        }
    ScreenList {
        item { SearchField(query, { query = it }, "Buscar código...") }
        if (rows.isEmpty())
            item {
                EmptyState(
                    "Sin códigos",
                    "Los códigos de prueba que generes aparecerán aquí.",
                    Icons.Outlined.CardGiftcard,
                )
            }
        items(rows, key = { it.id }) { gift ->
            Tile(Modifier.fillMaxWidth()) {
                Text(
                    state.product(gift.productId).name,
                    color = Ink,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(gift.code, color = Mint, fontSize = 13.sp)
                Small(
                    "${gift.used} de ${gift.maxUses} usos · ${if (gift.expiryDays == 0) "sin vencimiento" else "vigencia de ${gift.expiryDays} días"}"
                )
                Small(
                    if (gift.revoked) "Revocado" else "Disponible",
                    color = if (gift.revoked) Red else Mint,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    TextButton(
                        onClick = {
                            copy(gift.code)
                            feedback("Código de prueba copiado")
                        }
                    ) {
                        Text("Copiar")
                    }
                    TextButton(onClick = { selected = gift }) {
                        Text(
                            if (gift.revoked) "Restaurar" else "Revocar",
                            color = if (gift.revoked) Mint else Red,
                        )
                    }
                }
            }
        }
    }
    selected?.let { gift ->
        ConfirmationDialog(
            "Cambiar estado del código",
            "El cambio se aplicará solo al código de prueba seleccionado.",
            danger = !gift.revoked,
            onDismiss = { selected = null },
        ) {
            state.toggleGift(gift.id)
            selected = null
            feedback("Código de prueba actualizado")
        }
    }
}

@Composable
internal fun ApiScreen(state: PreviewState, create: () -> Unit, open: (String) -> Unit) {
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf("Todos") }
    val rows =
        state.apiClients.filter {
            (filter == "Todos" ||
                filter == "Activos" && !it.revoked ||
                filter == "Revocados" && it.revoked) &&
                (it.name.contains(query.trim(), true) || it.ip.contains(query.trim()))
        }
    ScreenList {
        item {
            Tile(Modifier.fillMaxWidth(), GreenPanel) {
                Small("Solicitudes realizadas hoy")
                Text(
                    String.format(
                        java.util.Locale.US,
                        "%,d",
                        state.apiClients.sumOf { it.requests },
                    ),
                    color = Mint,
                    fontSize = 36.sp,
                    fontWeight = FontWeight.Bold,
                )
                Small("${state.apiClients.count { !it.revoked }} clientes con acceso activo")
            }
        }
        item { SearchField(query, { query = it }, "Buscar cliente o IP...") }
        item { FilterRow(listOf("Todos", "Activos", "Revocados"), filter) { filter = it } }
        if (rows.isEmpty())
            item {
                EmptyState("Sin clientes", "Prueba otro nombre, IP o filtro.", Icons.Outlined.Code)
            }
        items(rows, key = { it.id }) { client ->
            Tile(Modifier.fillMaxWidth().clickable { open(client.id) }) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Icon(Icons.Outlined.Code, null, Modifier.size(18.dp), Mint)
                    Text(
                        client.name,
                        Modifier.weight(1f),
                        color = Ink,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Small(
                        if (client.revoked) "Revocada" else "Activa",
                        color = if (client.revoked) Red else Mint,
                    )
                }
                Small("IP: ${client.ip}")
                Small("Solicitudes: ${String.format(java.util.Locale.US, "%,d", client.requests)}")
            }
        }
        item { PrimaryAction("Crear acceso API", onClick = create) }
    }
}

@Composable
internal fun ApiForm(
    state: PreviewState,
    clientId: String? = null,
    dismiss: () -> Unit,
    saved: (String) -> Unit,
) {
    val client = clientId?.let { id -> state.apiClients.first { it.id == id } }
    var name by rememberSaveable(clientId) { mutableStateOf(client?.name.orEmpty()) }
    var ip by rememberSaveable(clientId) { mutableStateOf(client?.ip.orEmpty()) }
    val address = canonicalIp(ip)
    FormDialog(
        if (client == null) "Crear acceso API" else "Editar acceso API",
        name.trim().length >= 3 && address != null,
        onDismiss = dismiss,
        onConfirm = { saved(state.saveApi(name, ip, clientId)) },
    ) {
        Small("Una única IP por clave de prueba. No se emiten credenciales reales.", color = Amber)
        EditorField("Cliente", name, { name = it }, max = 50)
        EditorField("IP autorizada", ip, { ip = it }, max = 45)
        if (ip.isNotEmpty() && address == null)
            Small("Escribe una dirección IPv4 o IPv6 válida, sin puertos ni dominios.", color = Red)
    }
}

@Composable
internal fun ApiDetailScreen(state: PreviewState, id: String, feedback: (String) -> Unit) {
    val client = state.apiClients.first { it.id == id }
    var edit by rememberSaveable { mutableStateOf(false) }
    var action by rememberSaveable { mutableStateOf("") }
    val copy = rememberCopyToClipboard()
    ScreenList {
        item {
            Tile(Modifier.fillMaxWidth(), GreenPanel) {
                Avatar(Icons.Outlined.Code)
                Text(client.name, color = Ink, fontSize = 24.sp, fontWeight = FontWeight.SemiBold)
                Small(
                    if (client.revoked) "● Revocada" else "● Activa",
                    color = if (client.revoked) Red else Mint,
                )
            }
        }
        item {
            DetailLine("IP autorizada", client.ip)
            DetailLine("Solicitudes de prueba", client.requests.toString())
            DetailLine("Clave de demostración", client.key)
        }
        item {
            SecondaryAction("Copiar clave de prueba") {
                copy(client.key)
                feedback("Clave de prueba copiada")
            }
        }
        item { SecondaryAction("Editar cliente e IP") { edit = true } }
        item { SecondaryAction("Renovar clave de prueba") { action = "rotate" } }
        item {
            SecondaryAction(
                if (client.revoked) "Restaurar acceso" else "Revocar acceso",
                !client.revoked,
            ) {
                action = "status"
            }
        }
    }
    if (edit)
        ApiForm(state, id, { edit = false }) {
            edit = false
            feedback("Acceso de prueba actualizado")
        }
    if (action.isNotEmpty())
        ConfirmationDialog(
            if (action == "rotate") "Renovar clave" else "Cambiar acceso",
            "Este cambio solo afecta al cliente de prueba seleccionado.",
            danger = action == "status" && !client.revoked,
            onDismiss = { action = "" },
        ) {
            if (action == "rotate") state.rotateApi(id) else state.toggleApi(id)
            action = ""
            feedback("Acceso de prueba actualizado")
        }
}

@Composable
internal fun CreditsScreen(state: PreviewState, history: () -> Unit, feedback: (String) -> Unit) {
    var query by rememberSaveable { mutableStateOf("") }
    var selected by remember { mutableStateOf<PreviewUser?>(null) }
    val rows =
        state.users.filter {
            it.name.contains(query.trim(), true) || it.email.contains(query.trim(), true)
        }
    ScreenList {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Metric(
                    "Créditos en cuentas",
                    state.users.sumOf { it.credits }.toString(),
                    Icons.Outlined.Payments,
                    modifier = Modifier.weight(1f),
                )
                Metric(
                    "Movimientos",
                    state.creditHistory.size.toString(),
                    Icons.Outlined.History,
                    modifier = Modifier.weight(1f),
                )
            }
        }
        item { SearchField(query, { query = it }, "Buscar usuario...") }
        if (rows.isEmpty()) item { EmptyState("Sin resultados", "Prueba otro usuario o correo.") }
        items(rows, key = { it.id }) { user ->
            Tile(Modifier.fillMaxWidth().clickable { selected = user }) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    UserAvatar(user)
                    Column(Modifier.weight(1f)) {
                        Text(user.name, color = Ink, fontWeight = FontWeight.SemiBold)
                        Small("Saldo de créditos")
                    }
                    Text(
                        user.credits.toString(),
                        color = if (user.credits == 0) Amber else Mint,
                        fontWeight = FontWeight.Bold,
                        fontSize = 24.sp,
                    )
                }
                SecondaryAction("Ajustar créditos") { selected = user }
            }
        }
        item { SecondaryAction("Ver movimientos", onClick = history) }
    }
    selected?.let { user ->
        var quantity by rememberSaveable(user.id) { mutableStateOf("") }
        var reason by rememberSaveable(user.id) { mutableStateOf("") }
        val amount = quantity.toIntOrNull()
        val balance = state.user(user.id).credits
        val valid =
            amount != null &&
                amount != 0 &&
                amount in -10000..10000 &&
                balance + amount in 0..1_000_000 &&
                reason.trim().length >= 3
        FormDialog(
            "Ajustar créditos · ${user.name}",
            valid,
            onDismiss = { selected = null },
            onConfirm = {
                state.adjustCredits(user.id, amount!!, reason)
                selected = null
                feedback("Saldo de prueba actualizado")
            },
        ) {
            Small("Saldo actual: $balance")
            EditorField("Cantidad (+ o −)", quantity, { quantity = it }, KeyboardType.Text, max = 7)
            EditorField("Motivo", reason, { reason = it })
            if (amount != null && balance + amount < 0)
                Small("El saldo no puede quedar negativo.", color = Red)
            Small("El ajuste se registrará en el historial de demostración.", color = Amber)
        }
    }
}

@Composable
internal fun CreditHistoryScreen(state: PreviewState) {
    ScreenList {
        if (state.creditHistory.isEmpty())
            item {
                EmptyState(
                    "Sin movimientos",
                    "Los ajustes de prueba aparecerán aquí.",
                    Icons.Outlined.Payments,
                )
            }
        items(state.creditHistory, key = { it.id }) { row ->
            Tile(Modifier.fillMaxWidth()) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(state.user(row.userId).name, color = Ink, fontWeight = FontWeight.SemiBold)
                    Text(
                        (if (row.amount > 0) "+" else "") + row.amount,
                        color = if (row.amount > 0) Mint else Red,
                    )
                }
                Text(row.reason, color = Muted, fontSize = 14.sp)
                Small(row.time)
            }
        }
    }
}
