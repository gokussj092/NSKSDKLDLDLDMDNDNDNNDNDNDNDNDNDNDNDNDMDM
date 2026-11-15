package com.ghostdeveloper.spdecode.admin

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import org.json.JSONObject

internal val searchableModules = setOf(Page.Roles, Page.Products, Page.Finance, Page.Purchases,
    Page.Licenses, Page.Api, Page.Credits, Page.Gifts, Page.Catalog, Page.Notices, Page.Logs)

internal fun recordValue(row: JSONObject, key: String): String? =
    if (!row.has(key) || row.isNull(key)) null else row.optString(key).takeIf { it.isNotBlank() }

internal fun prettyKey(key: String): String =
    key.replace(Regex("([a-z0-9])([A-Z])"), "$1 $2").replace('_', ' ').replaceFirstChar { it.uppercase() }

internal fun matchesRecord(row: JSONObject, query: String): Boolean {
  val q = query.trim().removePrefix("@")
  if (q.isBlank()) return true
  val keys = listOf("name", "username", "email", "id", "title", "subject", "category", "status", "product_id",
      "provider", "kind", "action", "actor_id", "target_id", "code", "role", "movement_kind", "assigned_name", "allowed_ip")
  return keys.any { recordValue(row, it)?.contains(q, ignoreCase = true) == true }
}

internal fun localDate(value: String?): String? {
  if (value.isNullOrBlank()) return null
  return runCatching { DateTimeFormatter.ofPattern("dd MMM yyyy · HH:mm")
      .withZone(ZoneId.systemDefault()).format(Instant.parse(value)) }.getOrElse { value }
}

/** Day label ("dd MMM yyyy") for grouping chat messages; null when the date is missing. */
internal fun messageDay(value: String?): String? {
  if (value.isNullOrBlank()) return null
  return runCatching {
        DateTimeFormatter.ofPattern("dd MMM yyyy")
            .withZone(ZoneId.systemDefault())
            .format(Instant.parse(value))
      }
      .getOrNull()
}

internal fun displayAmount(quote: JSONObject?): String? {
  if (quote == null) return null
  val count = quote.optString("total").toLongOrNull() ?: return null
  val currency = recordValue(quote, "currency") ?: return null
  return "${money(count)} $currency"
}

@Composable
internal fun toneFor(status: String): Color = when(status) {
  "paid", "active", "answered", "enabled", "true" -> Mint
  "pending", "created", "open" -> Amber
  "failed", "revoked", "disputed", "refunded" -> Red
  else -> Muted
}

@Composable
private fun RecordHeader(title: String, subtitle: String?, icon: ImageVector, status: String? = null, tint: Color = Mint) {
  Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
    Avatar(icon, tint, 44)
    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
      Text(title.ifBlank { "Sin nombre" }, color = Ink, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
      subtitle?.takeIf { it.isNotBlank() }?.let { Text(it, color = Muted, fontSize = 12.sp, maxLines = 2, overflow = TextOverflow.Ellipsis) }
    }
    status?.takeIf { it.isNotBlank() }?.let { StatusPill(translated(it), toneFor(it)) }
  }
}

@Composable
private fun Fact(label: String, value: String?) {
  if (value.isNullOrBlank()) return
  Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.Top) {
    Small(L(label), Modifier.weight(.42f))
    Text(value, color = Ink, fontSize = 13.sp, modifier = Modifier.weight(.58f))
  }
}

@Composable
private fun ActionHint(text: String = "Ver detalles") {
  Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End, verticalAlignment = Alignment.CenterVertically) {
    Small(L(text), color = Mint)
    Icon(Icons.Outlined.ChevronRight, null, tint = Mint, modifier = Modifier.size(18.dp))
  }
}

@Composable
internal fun DashboardOverview(state: AdminState) {
  val overview = state.dashboardOverview
  val users = if (overview.has("users")) overview.optInt("users").toString() else null
  val support = overview.optJSONObject("support")
  val orders = overview.optJSONObject("orders")
  val licenses = if (overview.has("licenses")) overview.optInt("licenses").toString() else null
  if (!listOf(Page.Users, Page.Support, Page.Purchases).any { state.allowed(it) }) return
  Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
    SectionHeading("Resumen administrativo", "Datos consultados según tus permisos")
    val stats = buildList<Triple<String, String, ImageVector>> {
      users?.let { add(Triple("Usuarios registrados", it, Icons.Outlined.People)) }
      support?.let { add(Triple("Tickets abiertos · visibles", it.optInt("open").toString(), Icons.Outlined.Forum)) }
      orders?.let { add(Triple("Pedidos registrados", it.optInt("count").toString(), Icons.Outlined.ShoppingBag)) }
      licenses?.let { add(Triple("Licencias registradas", it, Icons.Outlined.VpnKey)) }
    }
    stats.chunked(2).forEach { row ->
      Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        row.forEach { (label, value, icon) -> Metric(label, value, icon, Mint, Modifier.weight(1f)) }
        if (row.size == 1) Spacer(Modifier.weight(1f))
      }
    }
    if (stats.isEmpty() && overview.length() == 0) Small(L("Consultando los datos disponibles…"))
    if (overview.keys().asSequence().any { it.endsWith("Unavailable") }) Small(L("Algunos módulos no respondieron."), color = Amber)
    orders?.let { data ->
      val totals = data.array("totals")
      if (totals.isNotEmpty()) Tile(Modifier.fillMaxWidth()) {
        Text(L("Ingresos confirmados"), color = Ink, fontWeight = FontWeight.SemiBold)
        if (data.has("live") && !data.optBoolean("live")) Small(L("Entorno de pruebas"), color = Amber)
        totals.forEach { total ->
          val cents = total.optString("cents").toLongOrNull()
          if (cents != null) Fact(total.optString("currency"), money(cents))
          if (total.has("orders")) Small(LF("%1\$s pedidos pagados", total.optInt("orders")))
        }
      }
    }
  }
}

@Composable
internal fun TicketSummary(threads: List<JSONObject>) {
  Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
    listOf("open" to "Abiertos", "answered" to "Respondidos", "closed" to "Cerrados").forEach { (key, label) ->
      Tile(Modifier.weight(1f)) {
        Text(threads.count { it.optString("status") == key }.toString(), color = toneFor(key), fontWeight = FontWeight.Bold, fontSize = 20.sp)
        Small(L(label))
      }
    }
  }
}

@Composable
internal fun StaffCard(row: JSONObject, onClick: () -> Unit) {
  Tile(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
    RecordHeader(displayName(row), userHandle(row), Icons.Outlined.AdminPanelSettings, recordValue(row, "status"))
    Fact("Cargo", recordValue(row, "role"))
    recordValue(row, "enabled")?.let { Fact("Habilitado", translated(it)) }
    ActionHint("Administrar")
  }
}

@Composable
internal fun RoleCard(row: JSONObject, onClick: () -> Unit) {
  Tile(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
    RecordHeader(recordValue(row, "name").orEmpty(), recordValue(row, "code"), Icons.Outlined.Security)
    row.optJSONArray("capabilities")?.let { Fact("Permisos", it.length().toString()) }
    ActionHint("Ver permisos")
  }
}

@Composable
internal fun ProductCard(title: String, row: JSONObject, onClick: () -> Unit) {
  val settings = row.optJSONObject("settings")
  val id = row.optString("id")
  val icon = when(id) {
    "offline-3" -> Icons.Outlined.VpnKey
    "api-ip" -> Icons.Outlined.Code
    "analysis-credits" -> Icons.Outlined.Payments
    else -> Icons.Outlined.ShoppingBag
  }
  Tile(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
    RecordHeader(L(title), L("Configuración del producto"), icon)
    settings?.let {
      if (it.has("enabled")) StatusPill(if (it.optBoolean("enabled")) "Habilitado" else "Deshabilitado", if (it.optBoolean("enabled")) Mint else Muted)
      it.optJSONObject("prices")?.let { prices ->
        prices.keys().forEach { currency -> prices.optString(currency).toLongOrNull()?.let { amount -> Fact(LF("Precio base · %1\$s", currency), money(amount)) } }
      }
      for (key in listOf("termPrices", "bundles")) {
        val terms = it.optJSONObject(key) ?: continue
        terms.keys().forEach { term ->
          terms.optJSONObject(term)?.let { prices ->
            prices.keys().forEach { currency -> prices.optString(currency).toLongOrNull()?.let { amount -> Fact("$term · $currency", money(amount)) } }
          }
        }
      }
    }
    ActionHint("Editar configuración")
  }
}

@Composable
internal fun OrderCard(title: String, row: JSONObject, onClick: () -> Unit) {
  Tile(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
    RecordHeader(L(title), displayName(row), Icons.Outlined.ShoppingBag, recordValue(row, "status"))
    displayAmount(row.optJSONObject("quote"))?.let { Text(it, color = Ink, fontWeight = FontWeight.Bold, fontSize = 24.sp) }
    Fact("Método de pago", recordValue(row, "provider"))
    Fact("Fecha", localDate(recordValue(row, "created_at")))
    userHandle(row)?.let { Small(it, color = Mint) }
    ActionHint()
  }
}

@Composable
internal fun EntitlementSummary(row: JSONObject, api: Boolean) {
  RecordHeader(displayName(row), recordValue(row, "email"), if (api) Icons.Outlined.Code else Icons.Outlined.VpnKey, recordValue(row, "status"))
  Fact("Vencimiento", localDate(recordValue(row, "expires_at")))
  Fact("Activación", localDate(recordValue(row, "claimed_at")))
  if (api) {
    Fact("IP autorizada", recordValue(row, "allowed_ip"))
    Fact("Solicitudes registradas", recordValue(row, "requests"))
    Fact("Cuota", recordValue(row, "quota"))
  }
}

@Composable
internal fun CreditCard(row: JSONObject, onClick: () -> Unit) {
  val amount = row.optString("delta").toLongOrNull()
  Tile(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
    RecordHeader(displayName(row), recordValue(row, "email"), Icons.Outlined.Payments)
    amount?.let {
      Text(LF("%1\$s créditos", (if (it > 0) "+" else "") + it.toString()), color = if (it < 0) Amber else Mint,
          fontSize = 23.sp, fontWeight = FontWeight.Bold)
    }
    Fact("Movimiento", recordValue(row, "movement_kind")?.let(::translated))
    Fact("Fecha", localDate(recordValue(row, "created_at")))
    ActionHint()
  }
}

@Composable
internal fun GiftSummary(row: JSONObject) {
  RecordHeader(row.optString("title"), L(productName(row.optString("kind"))), Icons.Outlined.CardGiftcard)
  if (row.has("enabled")) StatusPill(if (row.optBoolean("enabled")) "Habilitado" else "Deshabilitado", if (row.optBoolean("enabled")) Mint else Muted)
  val max = row.optInt("max_uses", 0)
  val used = row.optInt("used", 0)
  if (max > 0 && row.has("used")) {
    Fact("Canjes", "$used / $max")
    LinearProgressIndicator(progress = { (used.toFloat() / max).coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth(), color = Mint, trackColor = Border)
  }
  Fact("Créditos", recordValue(row, "credits"))
  Fact("Días", recordValue(row, "days"))
  Fact("Vencimiento", localDate(recordValue(row, "expires_at")))
}

@Composable
internal fun RedemptionCard(row: JSONObject, onClick: () -> Unit) {
  Tile(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
      ProfileAvatar(row, 44)
      Column(Modifier.weight(1f)) {
        Text(displayName(row), color = Ink, fontWeight = FontWeight.SemiBold)
        userHandle(row)?.let { Small(it, color = Mint) }
        Small(row.optString("title"))
      }
      Icon(Icons.Outlined.ChevronRight, null, tint = Muted)
    }
    Fact("Canje", localDate(recordValue(row, "created_at")))
  }
}

@Composable
internal fun ProviderSummary(row: JSONObject) {
  RecordHeader(row.optString("name").ifBlank { row.optString("id") }, recordValue(row, "id"), Icons.Outlined.Storage)
  if (row.has("enabled")) StatusPill(if (row.optBoolean("enabled")) "Habilitado" else "Deshabilitado", if (row.optBoolean("enabled")) Mint else Amber)
  Fact("Versión", recordValue(row, "version"))
  Fact("Revisión", recordValue(row, "revision"))
}

@Composable
internal fun NoticeSummary(row: JSONObject) {
  RecordHeader(row.optString("title"), recordValue(row, "scope"), Icons.Outlined.Notifications)
  Text(row.optString("body"), color = Ink, maxLines = 5, overflow = TextOverflow.Ellipsis)
  Fact("Fecha", localDate(recordValue(row, "created_at") ?: recordValue(row, "createdAt")))
  Fact("Entrega", recordValue(row, "delivery"))
}

@Composable
internal fun AuditCard(row: JSONObject, onClick: () -> Unit) {
  Tile(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
    RecordHeader(prettyKey(row.optString("action")), recordValue(row, "actor_role"), Icons.Outlined.History)
    Fact("Responsable", recordValue(row, "actor_name") ?: recordValue(row, "actor_id"))
    Fact("Fecha", localDate(recordValue(row, "created_at") ?: recordValue(row, "at")))
    ActionHint()
  }
}

@Composable
internal fun ServiceIndicators(services: JSONObject) {
  Tile(Modifier.fillMaxWidth()) {
    var known = false
    for ((key, title) in listOf("apiConfigured" to "API", "redisConnected" to "Redis", "workerReady" to "Worker", "redisReady" to "Redis disponible")) {
      if (!services.has(key)) continue
      known = true
      val ready = services.optBoolean(key)
      Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(L(title), color = Ink, modifier = Modifier.weight(1f))
        StatusPill(if (ready) "Disponible" else "Revisar", if (ready) Mint else Amber)
      }
    }
    if (!known) Small(L("El servidor no reportó indicadores reconocidos."))
  }
}

@Composable
internal fun ServiceOverview(data: JSONObject) {
  Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
    data.optJSONObject("services")?.let { ServiceIndicators(it) }
    data.optJSONObject("health")?.let { ServiceIndicators(it) }
    val metrics = data.optJSONObject("metrics") ?: data
    val cpu = metrics.optString("cpuPercent").toDoubleOrNull()?.takeIf { it.isFinite() && it >= 0 }
    val used = metrics.optString("memoryUsedBytes").toLongOrNull()?.takeIf { it >= 0 }
    val limit = metrics.optString("memoryLimitBytes").toLongOrNull()?.takeIf { it > 0 }
    if (cpu != null || used != null) Tile(Modifier.fillMaxWidth()) {
      SectionHeading("Recursos reportados")
      cpu?.let {
        Fact("CPU", "${it}%")
        LinearProgressIndicator(progress = { (it / 100.0).toFloat().coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth(), color = Mint, trackColor = Border)
      }
      used?.let { Fact("Memoria usada", "${it / (1024 * 1024)} MiB") }
      limit?.let { Fact("Límite de memoria", "${it / (1024 * 1024)} MiB") }
      if (used != null && limit != null) LinearProgressIndicator(progress = { (used.toDouble() / limit).toFloat().coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth(), color = Mint, trackColor = Border)
    }
    recordValue(data, "scope")?.let { Small(translated(it)) }
  }
}

@Composable
internal fun ProfileSummary(data: JSONObject) {
  Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
    listOf("orders" to "Pedidos", "entitlements" to "Accesos", "tickets" to "Tickets").forEach { (key, label) ->
      val values = data.optJSONArray(key)
      if (values != null) Tile(Modifier.weight(1f)) {
        Text(values.length().toString(), color = Mint, fontWeight = FontWeight.Bold, fontSize = 21.sp)
        Small(L(label))
      }
    }
  }
}

@Composable
internal fun ProfileRecord(group: String, row: JSONObject) {
  val title = when(group) {
    "identities" -> recordValue(row, "provider_id")
    "orders", "entitlements" -> recordValue(row, "product_id")?.let(::productName)
    "tickets" -> recordValue(row, "subject")
    "redemptions" -> recordValue(row, "title")
    "creditMovements" -> recordValue(row, "movement_kind")?.let(::translated)
    else -> null
  }
  Row(verticalAlignment = Alignment.CenterVertically) {
    Text(if (group in listOf("orders", "entitlements", "creditMovements")) L(title ?: "Registro") else title ?: L("Registro"), color = Ink, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
    recordValue(row, "status")?.let { StatusPill(translated(it), toneFor(it)) }
  }
  displayAmount(row.optJSONObject("quote"))?.let { Fact("Importe", it) }
  Fact("Fecha", localDate(recordValue(row, "created_at") ?: recordValue(row, "linked_at")))
  Fact("Vencimiento", localDate(recordValue(row, "expires_at")))
  Fact("IP autorizada", recordValue(row, "allowed_ip"))
  Fact("Créditos", recordValue(row, "delta"))
  recordValue(row, "password_set")?.let { Fact("Contraseña configurada", translated(it)) }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun DetailScreen(page: Page, row: JSONObject, onClose: () -> Unit, content: @Composable () -> Unit) {
  Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
    Scaffold(modifier = Modifier.fillMaxSize().safeDrawingPadding(), containerColor = MaterialTheme.colorScheme.background,
        topBar = { TopAppBar(title = { Text(LF("Detalle · %1\$s", L(page.title))) }, navigationIcon = {
          IconButton(onClick = onClose) { Icon(Icons.AutoMirrored.Outlined.ArrowBack, L("Volver")) }
        }) }) { padding ->
      Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(16.dp),
          verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Tile(Modifier.fillMaxWidth(), GreenPanel) {
          RecordHeader(recordValue(row, "title") ?: recordValue(row, "name") ?: recordValue(row, "product_id")?.let(::productName) ?: page.title,
              userHandle(row), page.icon, recordValue(row, "status"))
        }
        Tile(Modifier.fillMaxWidth()) { content() }
      }
    }
  }
}

@Composable
internal fun ChatHeader(thread: JSONObject) {
  Tile(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 5.dp)) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(11.dp)) {
      ProfileAvatar(thread, 46)
      Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(displayName(thread), color = Ink, fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
        userHandle(thread)?.let { Small(it, color = Mint) }
        Small(thread.optString("subject"))
      }
      recordValue(thread, "status")?.let { StatusPill(translated(it), toneFor(it)) }
    }
    recordValue(thread, "assigned_name")?.let { Small(LF("Agente: %1\$s", it)) }
  }
}

@Composable
internal fun MessageBubble(message: JSONObject, outgoing: Boolean, senderName: String? = null) {
  val shape = if (outgoing) RoundedCornerShape(18.dp, 18.dp, 4.dp, 18.dp)
      else RoundedCornerShape(18.dp, 18.dp, 18.dp, 4.dp)
  Column(Modifier.widthIn(max = 320.dp).background(if (outgoing) GreenPanel else Panel, shape)
      .padding(horizontal = 14.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
    senderName?.takeIf { it.isNotBlank() }?.let { Small(it, color = Mint) }
    Text(message.optString("text"), color = Ink, fontSize = 15.sp)
    localDate(recordValue(message, "at"))?.let { Small(it, Modifier.align(Alignment.End)) }
  }
}
