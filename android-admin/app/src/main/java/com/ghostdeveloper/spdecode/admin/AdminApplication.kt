package com.ghostdeveloper.spdecode.admin

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.Logout
import androidx.compose.material.icons.automirrored.outlined.Send
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.repeatOnLifecycle
import java.util.UUID
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

private val menuGroups =
    listOf(
        "ADMINISTRACIÓN" to listOf(Page.Dashboard, Page.Users, Page.Roles, Page.Support),
        "COMERCIO" to
            listOf(
                Page.Finance,
                Page.Purchases,
                Page.Products,
                Page.Licenses,
                Page.Gifts,
                Page.Api,
                Page.Credits),
        "PLATAFORMA" to
            listOf(
                Page.Catalog,
                Page.Server,
                Page.Notices,
                Page.Logs,
                Page.Security,
                Page.Maintenance,
                Page.Sessions,
                Page.Settings))
private val primaryPages = listOf(Page.Dashboard, Page.Users, Page.Support, Page.Settings)

private data class FormField(
    val key: String,
    val label: String,
    val initial: String = "",
    val choices: List<String> = emptyList(),
    val secret: Boolean = false
)

private data class RemoteForm(
    val title: String,
    val fields: List<FormField>,
    val submit: suspend (Map<String, String>) -> Unit
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun AdminApplication(state: AdminState) {
  if (state.checking) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
      Column(
          horizontalAlignment = Alignment.CenterHorizontally,
          verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Avatar(Icons.Outlined.VerifiedUser, Mint, 72)
            Text("SP-DECODE", color = Ink, fontSize = 24.sp, fontWeight = FontWeight.Bold)
            CircularProgressIndicator(color = Mint)
            Small(L("Conectando…"))
          }
    }
    return
  }
  var form by remember { mutableStateOf<RemoteForm?>(null) }
  var confirm by remember { mutableStateOf<Pair<String, suspend () -> Unit>?>(null) }
  var directoryFilter by rememberSaveable { mutableStateOf("Todos") }
  var ticketFilter by rememberSaveable { mutableStateOf("Todos") }
  var moduleQuery by rememberSaveable(state.page) { mutableStateOf("") }
  var moduleFilter by rememberSaveable(state.page) { mutableStateOf("Todos") }
  val drawer = rememberDrawerState(DrawerValue.Closed)
  val scope = rememberCoroutineScope()
  val lifecycle = LocalLifecycleOwner.current
  val snack = remember { SnackbarHostState() }
  LaunchedEffect(state.entered) {
    if (!state.entered) {
      form = null
      confirm = null
      directoryFilter = "Todos"
      ticketFilter = "Todos"
      moduleQuery = ""
      moduleFilter = "Todos"
      drawer.close()
    }
  }
  val snackbarText = (state.error ?: state.message)?.let { AdminErrorLabel(it) }
  LaunchedEffect(snackbarText) {
    if (snackbarText != null) {
      snack.showSnackbar(snackbarText)
      state.message = null
    }
  }
  LaunchedEffect(state.entered, state.page, state.dashboardRevision, lifecycle) {
    if (state.entered && state.page == Page.Dashboard && state.dashboardRevision > 0)
      lifecycle.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
        state.refreshDashboardOverview()
      }
  }
  LaunchedEffect(state.entered, state.page, lifecycle) {
    if (state.entered && (state.page == Page.Support || state.page == Page.Chat))
        lifecycle.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
          while (true) {
            delay(10000)
            state.refreshSupport()
          }
        }
  }
  // Re-checks with the server that the account still exists when the app returns
  // to the foreground. Network errors keep the session; see AdminState.verifyAccess.
  LaunchedEffect(state.entered, lifecycle) {
    if (!state.entered) return@LaunchedEffect
    lifecycle.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
      state.verifySessionOnResume()
    }
  }
  BackHandler(state.entered && state.page != Page.Dashboard) {
    state.navigate(
        if (state.page == Page.Chat) Page.Support
        else if (state.page == Page.UserDetail) Page.Users
        else if (state.page in listOf(Page.AppearanceSettings, Page.AboutSettings, Page.LanguageSettings)) Page.Settings
        else Page.Dashboard)
  }
  fun open(title: String, fields: List<FormField>, action: suspend (Map<String, String>) -> Unit) {
    form = RemoteForm(title, fields, action)
  }
  fun mutate(title: String, operation: String, input: JSONObject? = null) {
    confirm = title to { state.mutate(operation, input) }
  }
  if (!state.entered) {
    Scaffold(snackbarHost = { SnackbarHost(snack) }) { padding ->
      Box(Modifier.padding(padding)) { LoginScreen(state) }
    }
    return
  }
  ModalNavigationDrawer(
      drawerState = drawer,
      gesturesEnabled = !state.busy,
      drawerContent = {
        ModalDrawerSheet(
            drawerContainerColor = MaterialTheme.colorScheme.background,
            modifier = Modifier.widthIn(max = 320.dp)) {
              LazyColumn(contentPadding = PaddingValues(16.dp)) {
                item {
                  Row(
                      verticalAlignment = Alignment.CenterVertically,
                      horizontalArrangement = Arrangement.spacedBy(10.dp),
                      modifier = Modifier.padding(vertical = 12.dp)) {
                        Avatar(Icons.Outlined.Person, Mint, 44)
                        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                          Text(
                              "SP-DECODE",
                              color = Mint,
                              fontSize = 18.sp,
                              fontWeight = FontWeight.Bold)
                          Text(
                              state.principal.optString("name").ifBlank { "Administrador" },
                              color = Ink,
                              fontSize = 14.sp,
                              fontWeight = FontWeight.SemiBold)
                          Small(state.principal.optString("role"))
                        }
                      }
                }
                menuGroups.forEach { (title, pages) ->
                  item { Small(L(title), Modifier.padding(top = 16.dp, bottom = 6.dp)) }
                  items(pages.filter { state.allowed(it) }) { p ->
                    NavigationDrawerItem(
                        label = { Text(L(p.title)) },
                        selected = state.page == p,
                        icon = { Icon(p.icon, null) },
                        onClick = {
                          state.navigate(p)
                          scope.launch { drawer.close() }
                        })
                  }
                }
                item {
                  TextButton(
                      onClick = {
                        confirm = "Cerrar sesión en este dispositivo" to { state.signOut() }
                      }) {
                        Icon(Icons.AutoMirrored.Outlined.Logout, null)
                        Text(L("Cerrar sesión"))
                      }
                }
              }
            }
      }) {
        Scaffold(
            snackbarHost = { SnackbarHost(snack) },
            containerColor = MaterialTheme.colorScheme.background,
            topBar = {
              TopAppBar(
                  title = {
                    Text(
                        if (state.page == Page.Dashboard) "SP-DECODE Admin" else L(state.page.title),
                        fontSize = 19.sp)
                  },
                  navigationIcon = {
                    IconButton(
                        onClick = {
                          if (state.page == Page.Chat) state.navigate(Page.Support)
                          else if (state.page == Page.UserDetail) state.navigate(Page.Users)
                          else if (state.page in listOf(Page.AppearanceSettings, Page.AboutSettings, Page.LanguageSettings)) state.navigate(Page.Settings)
                          else scope.launch { drawer.open() }
                        }) {
                          Icon(
                              if (state.page in listOf(Page.Chat, Page.UserDetail, Page.AppearanceSettings, Page.AboutSettings, Page.LanguageSettings))
                                  Icons.AutoMirrored.Outlined.ArrowBack
                              else Icons.Outlined.Menu,
                              L("Menú"))
                        }
                  },
                  actions = {
                    IconButton(enabled = !state.busy, onClick = { state.refresh() }) {
                      Icon(Icons.Outlined.Refresh, L("Actualizar"))
                    }
                  },
                  colors =
                      TopAppBarDefaults.topAppBarColors(
                          containerColor = MaterialTheme.colorScheme.background))
            },
            bottomBar = {
              if (state.page in primaryPages)
                  NavigationBar(containerColor = MaterialTheme.colorScheme.background) {
                    primaryPages
                        .filter { state.allowed(it) }
                        .forEach { p ->
                          NavigationBarItem(
                              modifier = Modifier.testTag("nav-${p.name}"),
                              selected = state.page == p,
                              onClick = { state.navigate(p) },
                              icon = { Icon(p.icon, null) },
                              label = {
                                Text(
                                    if (p == Page.Dashboard) L("Inicio") else L(p.title),
                                    fontSize = 11.sp)
                              })
                        }
                  }
            }) { padding ->
              Column(
                  Modifier.fillMaxSize()
                      .padding(padding)
                      .consumeWindowInsets(padding)
                      .imePadding()) {
                    Box(Modifier.fillMaxWidth().height(4.dp)) {
                      if (state.busy || state.loading)
                        LinearProgressIndicator(Modifier.fillMaxWidth(), color = Mint)
                    }
                    if (state.page != Page.Chat) state.error?.let {
                      Text(
                          AdminErrorLabel(it),
                          color = Red,
                          fontSize = 13.sp,
                          modifier = Modifier.fillMaxWidth().padding(12.dp))
                    }
                    if (state.sessionUnverified)
                        Text(
                            "Sin conexión: no se pudo verificar tu cuenta. Se reintentará automáticamente.",
                            color = Amber,
                            fontSize = 13.sp,
                            modifier = Modifier.fillMaxWidth().padding(12.dp))
                    if (state.mustChangePassword && state.page != Page.Security) {
                      TextButton(onClick = { state.navigate(Page.Security) }) {
                        Text(L("Cambiar contraseña temporal"))
                      }
                    }
                    when (state.page) {
                      Page.Chat -> ChatScreen(state)
                      Page.Settings, Page.AppearanceSettings, Page.AboutSettings, Page.LanguageSettings -> SettingsScreen(state)
                      else ->
                          ScreenList(state.page) {
                             moduleSubtitle(state.page)?.let { summary ->
                               item {
                                 Tile(Modifier.fillMaxWidth(), GreenPanel) {
                                   Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                     Avatar(state.page.icon, Mint, 40)
                                     Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                       Text(L(state.page.title), color = Ink, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                                       Small(L(summary))
                                     }
                                   }
                                 }
                               }
                             }
                            if (state.data.has("live"))
                                item {
                                  Small(
                                      L(if (state.data.optBoolean("live")) "Operaciones reales"
                                      else "Entorno de pruebas de pagos configurado en el servidor"),
                                      color = Amber)
                                }
                            if (state.page in searchableModules) item {
                              SearchField(moduleQuery, { moduleQuery = it }, "Buscar en los registros cargados")
                              if (state.data.has("count") && moduleQuery.isNotBlank()) Small(L("Búsqueda en la página actual"))
                            }
                            when (state.page) {
                              Page.Dashboard -> {
                                item {
                                  Tile(Modifier.fillMaxWidth(), GreenPanel) {
                                    Small("SP-DECODE · ADMIN", color = Mint)
                                    Text(state.principal.optString("name").ifBlank { "Administrador" },
                                        color = Ink, fontSize = 24.sp, fontWeight = FontWeight.Bold)
                                    Small(state.principal.optString("role"))
                                    if (state.data.has("maintenance")) StatusPill(
                                        if (state.data.optBoolean("maintenance")) "En mantenimiento" else "Panel conectado",
                                        if (state.data.optBoolean("maintenance")) Amber else Mint)
                                  }
                                }
                                item { DashboardOverview(state) }
                                state.data.optJSONObject("metrics")?.let { metrics ->
                                  item {
                                    SectionHeading("Actividad del servicio", "Métricas reportadas por el servidor")
                                    val counters = listOf(
                                        Triple("successfulDecodes", "Procesados", Icons.Outlined.CheckCircle),
                                        Triple("failedDecodes", "Fallidos", Icons.Outlined.ErrorOutline),
                                        Triple("warnings", "Advertencias", Icons.Outlined.WarningAmber))
                                    counters.filter { metrics.has(it.first) }.chunked(2).forEach { group ->
                                      Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        group.forEach { (key, label, icon) ->
                                          Metric(label, metrics.opt(key).toString(), icon,
                                              if (key == "failedDecodes") Red else if (key == "warnings") Amber else Mint,
                                              Modifier.weight(1f))
                                        }
                                        if (group.size == 1) Spacer(Modifier.weight(1f))
                                      }
                                      Spacer(Modifier.height(6.dp))
                                    }
                                    val extraKeys = metrics.keys().asSequence().filter { it !in counters.map { entry -> entry.first } }.toList()
                                    if (extraKeys.isNotEmpty()) Tile(Modifier.fillMaxWidth()) { Fields(metrics, skip = counters.map { it.first }.toSet()) }
                                  }
                                }
                                state.data.optJSONObject("services")?.let { services ->
                                  item {
                                    SectionHeading("Estado de la plataforma")
                                    ServiceIndicators(services)
                                  }
                                }
                                if (listOf(Page.Users, Page.Support, Page.Server, Page.Gifts).any { state.allowed(it) }) item {
                                  SectionHeading("Acciones rápidas")
                                  Tile(Modifier.fillMaxWidth()) {
                                    if (state.allowed(Page.Users)) ActionRow("Buscar usuario", Icons.Outlined.Search) { state.navigate(Page.Users) }
                                    if (state.allowed(Page.Support)) ActionRow("Revisar soporte", Icons.Outlined.Forum) { state.navigate(Page.Support) }
                                    if (state.allowed(Page.Server)) ActionRow("Diagnóstico del servidor", Icons.Outlined.Dns) { state.navigate(Page.Server) }
                                    if (state.allowed(Page.Gifts)) ActionRow("Gestionar gift codes", Icons.Outlined.CardGiftcard) { state.navigate(Page.Gifts) }
                                  }
                                }
                              }
                              Page.Users -> {
                                item {
                                  SectionHeading("Directorio de usuarios", "Busca por nombre, @usuario, correo o ID")
                                  SearchField(state.search, { state.search = it.take(80) }, "Buscar usuario")
                                  TextButton(enabled = !state.busy, onClick = {
                                    state.pageIndex = 0
                                    state.refresh()
                                  }) { Text(L("Buscar en el servidor")) }
                                  if (state.data.has("count")) Small(LF("%1\$s usuarios registrados", state.data.optInt("count")))
                                  FilterRow(listOf("Todos", "Verificados", "Con compras", "Con créditos", "Sin anuncios"), directoryFilter) { directoryFilter = it }
                                  if (directoryFilter != "Todos") Small(L("Filtro aplicado a la página actual"))
                                }
                                val rows = state.data.array("users").filter { row ->
                                  when (directoryFilter) {
                                    "Verificados" -> row.optBoolean("email_verified")
                                    "Con compras" -> row.optInt("orders_count") > 0
                                    "Con créditos" -> row.optInt("credits") > 0
                                    "Sin anuncios" -> row.optBoolean("ad_free")
                                    else -> true
                                  }
                                }
                                items(rows, key = { it.getString("id") }) { row ->
                                  UserCard(row) { state.navigate(Page.UserDetail, row.getString("id")) }
                                }
                                if (!state.busy && !state.loading && state.data.has("users") && rows.isEmpty())
                                    item { EmptyState("Sin resultados", "Prueba otra búsqueda.") }
                              }
                              Page.UserDetail -> {
                                val user = state.data.optJSONObject("user")
                                if (user != null) {
                                  item {
                                    Tile(Modifier.fillMaxWidth(), GreenPanel) {
                                      Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                        ProfileAvatar(user, 56)
                                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                          Text(displayName(user), color = Ink, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                                          userHandle(user)?.let { Small(it, color = Mint) }
                                          Small(user.optString("email"))
                                          if (user.optBoolean("email_verified")) StatusPill("Correo verificado")
                                        }
                                      }
                                    }
                                  }
                                  item {
                                    ProfileSummary(state.data)
                                  }
                                  item {
                                    SectionHeading("Perfil")
                                    Tile(Modifier.fillMaxWidth()) { Fields(user, skip = setOf("name", "username", "email", "email_verified")) }
                                  }
                                  listOf("identities" to "Métodos de acceso", "orders" to "Pedidos",
                                      "entitlements" to "Licencias y productos", "redemptions" to "Canjes de gift codes",
                                      "tickets" to "Soporte", "sessions" to "Seguridad y sesiones",
                                      "creditMovements" to "Movimientos de créditos").forEach { (key, label) ->
                                    if (state.data.has(key)) item {
                                      val values = state.data.optJSONArray(key)
                                      SectionHeading(label, values?.let { LF("%1\$s registros", it.length()) })
                                      Tile(Modifier.fillMaxWidth()) {
                                        if (values != null && values.length() == 0) Small(L("Sin registros"))
                                        else if (values != null) {
                                          values.objects().forEachIndexed { index, record ->
                                            if (index > 0) HorizontalDivider(color = Border)
                                            ProfileRecord(key, record)
                                          }
                                        } else state.data.optJSONObject(key)?.let { Fields(it) }
                                      }
                                    }
                                  }
                                } else if (!state.busy && !state.loading && state.error == null) item {
                                  EmptyState("Perfil no disponible", "Actualiza para consultar los datos del servidor.")
                                }
                              }
                              Page.Roles -> {
                                if (state.owner)
                                    item {
                                      Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        TextButton(onClick = { staffForm(state, null, ::open) }) {
                                          Text(L("Crear personal"))
                                        }
                                        TextButton(onClick = { roleForm(state, null, ::open) }) {
                                          Text(L("Crear cargo"))
                                        }
                                      }
                                    }
                                items(state.data.array("staff").filter { matchesRecord(it, moduleQuery) }, key = { it.getString("id") }) { row
                                  ->
                                  StaffCard(row) {
                                        if (state.owner) staffForm(state, row, ::open)
                                        else state.detail = row
                                      }
                                }
                                item {
                                  Text(
                                      L("Cargos personalizados"),
                                      color = Ink,
                                      fontWeight = FontWeight.Bold)
                                }
                                items(
                                    state.data.array("roleDefinitions").filter { matchesRecord(it, moduleQuery) },
                                    key = { it.getString("code") }) { row ->
                                      RoleCard(row) {
                                        if (state.owner) roleForm(state, row, ::open)
                                        else state.detail = row
                                      }
                                    }
                                if (!state.busy && !state.loading && state.data.length() > 0 &&
                                    state.data.array("staff").isEmpty() &&
                                    state.data.array("roleDefinitions").isEmpty())
                                    item { EmptyState("Sin registros", "Actualiza para consultar los datos del servidor.") }
                              }
                              Page.Support -> {
                                // Unanswered first, then most recent: the inbox is a triage tool.
                                val statusRank = mapOf("open" to 0, "answered" to 1, "closed" to 2)
                                val threads = state.data.array("threads").filter { row ->
                                  if (!matchesRecord(row, moduleQuery)) return@filter false
                                  when (ticketFilter) {
                                    "Abiertos" -> row.optString("status") == "open"
                                    "Respondidos" -> row.optString("status") == "answered"
                                    "Cerrados" -> row.optString("status") == "closed"
                                    "Sin asignar" -> row.isNull("assigned_staff_id") || row.optString("assigned_staff_id").isBlank()
                                    else -> true
                                  }
                                }.sortedWith(
                                    compareBy<JSONObject> { statusRank[it.optString("status")] ?: 3 }
                                        .thenByDescending { it.optString("last_message_at") })
                                item {
                                  SectionHeading("Bandeja de soporte", "Conversaciones y estado del servidor")
                                  SearchField(moduleQuery, { moduleQuery = it }, "Buscar ticket o usuario")
                                  if (moduleQuery.isNotBlank()) Small(L("Búsqueda en la página actual"))
                                  if (state.data.has("threads")) TicketSummary(state.data.array("threads"))
                                  FilterRow(listOf("Todos", "Abiertos", "Respondidos", "Cerrados", "Sin asignar"), ticketFilter) { ticketFilter = it }
                                }
                                if (threads.isEmpty() && !state.busy && !state.loading && state.data.has("threads"))
                                    item { EmptyState("Sin conversaciones", "No hay tickets disponibles para tu cargo.", Icons.Outlined.Forum) }
                                items(threads, key = { it.getString("id") }) { row ->
                                  TicketCard(row) { state.navigate(Page.Chat, row.getString("id")) }
                                }
                              }
                              Page.Products -> {
                                val products = state.data.array("products").filter { matchesRecord(it, moduleQuery) || productName(it.optString("id")).contains(moduleQuery, true) }
                                items(products, key = { it.getString("id") }) { row ->
                                  ProductCard(productName(row.getString("id")), row) { productForm(state, row, ::open) }
                                }
                                if (products.isEmpty() && !state.busy && !state.loading && state.data.has("products"))
                                    item { EmptyState("Sin registros", "Actualiza para consultar los datos del servidor.") }
                              }
                              Page.Finance,
                              Page.Purchases -> {
                                if (state.page == Page.Finance) {
                                  item {
                                    SectionHeading(
                                        "Ingresos confirmados",
                                        "Pedidos pagados; totales separados por moneda.")
                                  }
                                  items(state.data.array("totals")) { t ->
                                    Tile(Modifier.fillMaxWidth(), GreenPanel) {
                                      t.optString("cents").toLongOrNull()?.let { amount ->
                                        Text(
                                            "${money(amount)} ${t.optString("currency")}",
                                            color = Mint,
                                            fontSize = 20.sp)
                                      }
                                      Small(LF("%1\$s pedidos pagados", t.optInt("orders")))
                                    }
                                  }
                                }
                                item {
                                  FilterRow(listOf("Todos", "Pagados", "Pendientes", "Reembolsados", "Fallidos"), moduleFilter) { moduleFilter = it }
                                  if (moduleFilter != "Todos") Small(L("Filtro aplicado a la página actual"))
                                }
                                val orders = state.data.array("items").filter { row ->
                                  matchesRecord(row, moduleQuery) && when(moduleFilter) {
                                    "Pagados" -> row.optString("status") == "paid"
                                    "Pendientes" -> row.optString("status") in listOf("pending", "created")
                                    "Reembolsados" -> row.optString("status") == "refunded"
                                    "Fallidos" -> row.optString("status") == "failed"
                                    else -> true
                                  }
                                }
                                items(orders, key = { it.getString("id") }) { row ->
                                  OrderCard(productName(row.optString("product_id")), row) { state.detail = row }
                                }
                                if (orders.isEmpty() && !state.busy && !state.loading && state.data.has("items"))
                                  item { EmptyState("Sin pedidos", "No hay pedidos que coincidan con la selección.") }
                              }
                              Page.Licenses,
                              Page.Api -> {
                                val id = if (state.page == Page.Api) "api-ip" else "offline-3"
                                item {
                                  Small(
                                      L("Los accesos corresponden a pedidos registrados. Las claves completas se entregan una sola vez al titular."))
                                }
                                val entitlements = state.data.array("items").filter {
                                  it.optString("product_id") == id && matchesRecord(it, moduleQuery)
                                }
                                items(entitlements, key = { it.getString("id") }) { row ->
                                      Tile(Modifier.fillMaxWidth()) {
                                        EntitlementSummary(row, id == "api-ip")
                                        TextButton(onClick = { state.detail = row }) { Text(L("Ver detalles")) }
                                        if (state.owner) {
                                          TextButton(
                                              enabled = !state.busy,
                                              onClick = {
                                                mutate(
                                                    if (row.optString("status") == "active")
                                                        "Revocar este acceso"
                                                    else "Restaurar este acceso",
                                                    "mobile_action",
                                                    JSONObject()
                                                        .put("action", "entitlement-status")
                                                        .put("id", row.getString("id"))
                                                        .put(
                                                            "status",
                                                            if (row.optString("status") == "active")
                                                                "revoked"
                                                            else "active"))
                                              }) {
                                                Text(
                                                    L(
                                                        if (row.optString("status") == "active")
                                                            "Revocar"
                                                        else "Restaurar"))
                                              }
                                          if (id == "api-ip")
                                              TextButton(
                                                  onClick = {
                                                    open(
                                                        "IP autorizada",
                                                        listOf(
                                                            FormField(
                                                                "ip",
                                                                "Dirección IP pública",
                                                                row.optString("allowed_ip")))) { v
                                                          ->
                                                          state.mutate(
                                                              "mobile_action",
                                                              JSONObject()
                                                                  .put("action", "api-ip")
                                                                  .put("id", row.getString("id"))
                                                                  .put("allowedIp", v["ip"]))
                                                        }
                                                  }) {
                                                    Text(L("Cambiar IP"))
                                                  }
                                        }
                                      }
                                    }
                                if (entitlements.isEmpty() && !state.busy && !state.loading && state.data.has("items"))
                                    item { EmptyState("Sin registros", "Actualiza para consultar los datos del servidor.") }
                              }
                              Page.Credits -> {
                                val movements = state.data.array("items").filter { matchesRecord(it, moduleQuery) }
                                items(movements, key = { it.getString("id") }) { row ->
                                  CreditCard(row) { state.detail = row }
                                }
                                if (movements.isEmpty() && !state.busy && !state.loading && state.data.has("items"))
                                  item { EmptyState("Sin movimientos", "No hay movimientos que coincidan con la búsqueda.") }
                              }
                              Page.Gifts -> {
                                item {
                                  PrimaryAction("Generar gift code", !state.busy) { giftForm(state, ::open) }
                                }
                                val codes = state.data.array("codes").filter { matchesRecord(it, moduleQuery) }
                                val redemptions = state.data.array("redemptions").filter { matchesRecord(it, moduleQuery) }
                                items(codes, key = { it.getString("id") }) { row
                                  ->
                                  Tile(Modifier.fillMaxWidth()) {
                                    GiftSummary(row)
                                    TextButton(onClick = { state.detail = row }) { Text(L("Ver detalles")) }
                                    if (row.optBoolean("enabled"))
                                        TextButton(
                                            onClick = {
                                              mutate(
                                                  "Desactivar este gift code",
                                                  "gifts_save",
                                                  JSONObject()
                                                      .put("action", "disable")
                                                      .put("id", row.getString("id")))
                                            }) {
                                              Text(L("Desactivar"), color = Red)
                                            }
                                  }
                                }
                                item {
                                  Text(
                                      L("Canjes recientes"), color = Ink, fontWeight = FontWeight.Bold)
                                }
                                items(redemptions) { row ->
                                  RedemptionCard(row) { state.detail = row }
                                }
                                if (codes.isEmpty() && redemptions.isEmpty() && !state.busy && !state.loading && state.data.has("codes"))
                                    item { EmptyState("Sin registros", "Actualiza para consultar los datos del servidor.") }
                              }
                              Page.Catalog -> {
                                val controls =
                                    state.data.optJSONObject("providerControls") ?: JSONObject()
                                item {
                                  Small(
                                      LF(
                                          "Versión del catálogo: %1\$s",
                                          (controls.opt("displayVersion") ?: controls.opt("catalogVersion"))
                                              ?.toString()
                                              ?: L("Sin datos")))
                                  TextButton(
                                      onClick = {
                                        mutate(
                                            "Publicar el aviso de la versión actual del catálogo",
                                            "catalog_publish")
                                      }) {
                                        Text(L("Avisar actualización"))
                                      }
                                }
                                val providers =
                                    controls.optJSONArray("providers")?.objects()
                                        ?: controls
                                            .optJSONObject("providers")
                                            ?.let { obj ->
                                              obj.keys()
                                                  .asSequence()
                                                  .mapNotNull {
                                                    obj.optJSONObject(it)?.put("id", it)
                                                  }
                                                  .toList()
                                            }
                                            .orEmpty()
                                val shownProviders = providers.filter { matchesRecord(it, moduleQuery) }
                                items(shownProviders) { row ->
                                  Tile(Modifier.fillMaxWidth()) {
                                    ProviderSummary(row)
                                    TextButton(onClick = { state.detail = row }) { Text(L("Ver datos técnicos")) }
                                    TextButton(
                                        onClick = {
                                          mutate(
                                              "Cambiar disponibilidad de ${row.optString("id")}",
                                              "providers",
                                              JSONObject()
                                                  .put("id", row.optString("id"))
                                                  .put("enabled", !row.optBoolean("enabled")))
                                        }) {
                                          Text(
                                              L(
                                                  if (row.optBoolean("enabled")) "Desactivar"
                                                  else "Activar"))
                                        }
                                  }
                                }
                                if (shownProviders.isEmpty() && !state.busy && !state.loading && state.data.length() > 0)
                                    item { EmptyState("Sin registros", "Actualiza para consultar los datos del servidor.") }
                              }
                              Page.Server -> {
                                item {
                                  SectionHeading(
                                      "Estado del servicio",
                                      "Las métricas del contenedor web no representan el consumo total del VPS.")
                                  ServiceOverview(state.data)
                                  TextButton(onClick = { state.detail = state.data }) { Text(L("Diagnóstico detallado")) }
                                }
                              }
                              Page.Notices -> {
                                item {
                                  TextButton(onClick = { noticeForm(state, ::open) }) {
                                    Icon(Icons.Outlined.Campaign, null)
                                    Text(L("Enviar notificación"))
                                  }
                                  Small(
                                      L(
                                          if (state.data.optBoolean("pushConfigured"))
                                              "Push configurado"
                                          else "Push sin configurar; consulta periódica disponible"))
                                }
                                val notices = state.data.array("notices").filter { matchesRecord(it, moduleQuery) }
                                items(notices, key = { it.getString("id") }) {
                                    row ->
                                  Tile(Modifier.fillMaxWidth()) {
                                    NoticeSummary(row)
                                    TextButton(onClick = { state.detail = row }) { Text(L("Ver detalles")) }
                                  }
                                }
                                if (notices.isEmpty() && !state.busy && !state.loading && state.data.has("notices"))
                                    item { EmptyState("Sin registros", "Actualiza para consultar los datos del servidor.") }
                              }
                              Page.Logs -> {
                                val events = state.data.array("events").filter { matchesRecord(it, moduleQuery) }
                                items(events) { row ->
                                  AuditCard(row) { state.detail = row }
                                }
                                if (events.isEmpty() && !state.busy && !state.loading && state.data.has("events"))
                                    item { EmptyState("Sin registros", "Actualiza para consultar los datos del servidor.") }
                              }
                              Page.Security -> {
                                item {
                                  Tile(Modifier.fillMaxWidth(), GreenPanel) {
                                    Text(
                                        state.principal.optString("name"),
                                        color = Ink,
                                        fontSize = 19.sp)
                                    Small(L("Conexión HTTPS autenticada"))
                                    Small(
                                        "${state.principal.optString("username")} · ${state.principal.optString("role")}")
                                  }
                                }
                                if (!state.owner)
                                    item {
                                      TextButton(
                                          onClick = {
                                            open(
                                                "Cambiar contraseña",
                                                listOf(
                                                    FormField(
                                                        "current",
                                                        "Contraseña actual",
                                                        secret = true),
                                                    FormField(
                                                        "new",
                                                        "Nueva contraseña (16–128 caracteres)",
                                                        secret = true))) { v ->
                                                  require(v.getValue("new").length in 16..128) {
                                                    "La nueva contraseña debe tener entre 16 y 128 caracteres."
                                                  }
                                                  state.mutate(
                                                      "password",
                                                      JSONObject()
                                                          .put("currentPassword", v["current"])
                                                          .put("newPassword", v["new"]))
                                                }
                                          }) {
                                            Text(
                                                if (state.mustChangePassword)
                                                    "Cambiar contraseña temporal"
                                                else "Cambiar contraseña")
                                          }
                                    }
                                if (state.owner)
                                    item {
                                      Small(
                                          L("La contraseña de propietario se administra desde el servidor."))
                                    }
                                item {
                                  Tile(Modifier.fillMaxWidth()) {
                                    ActionRow("Mi sesión", Icons.Outlined.Devices, "Acceso de este dispositivo") { state.navigate(Page.Sessions) }
                                  }
                                }
                              }
                              Page.Sessions -> {
                                item {
                                  Tile(Modifier.fillMaxWidth()) {
                                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                      Avatar(Icons.Outlined.Devices, Mint, 40)
                                      Column(Modifier.weight(1f)) {
                                        Text(L("Este dispositivo"), color = Ink, fontWeight = FontWeight.Bold)
                                        Small("Android · ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
                                      }
                                      StatusPill("Sesión actual")
                                    }
                                    Small(
                                        "${state.principal.optString("name")} · ${state.principal.optString("role")}")
                                    Small(
                                        L("La sesión dura 90 días desde el inicio de sesión. El servidor puede revocarla antes."))
                                    TextButton(
                                        enabled = !state.busy, onClick = { state.logout() }) {
                                          Text(L("Cerrar sesión"), color = Red)
                                        }
                                  }
                                }
                              }
                              Page.Maintenance -> {
                                // Estado actual según el servidor; el interruptor
                                // solo pide confirmación y ejecuta la misma acción
                                // "maintenance" que los botones anteriores.
                                val maintenanceOn = state.data.optBoolean("maintenance")
                                item {
                                  Tile(Modifier.fillMaxWidth()) {
                                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                      Avatar(Icons.Outlined.Build, if (maintenanceOn) Amber else Mint, 40)
                                      Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                        Text(L("Mantenimiento del servicio"), color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                                        Small(L("Estas acciones modifican la disponibilidad del servicio para los clientes."))
                                      }
                                      Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                        Switch(
                                            checked = maintenanceOn,
                                            enabled = !state.busy,
                                            onCheckedChange = { checked ->
                                              mutate(
                                                  if (checked) "Activar mantenimiento para todos los clientes"
                                                  else "Desactivar mantenimiento",
                                                  "maintenance",
                                                  JSONObject().put("enabled", checked))
                                            },
                                            colors = SwitchDefaults.colors(
                                                checkedTrackColor = Amber,
                                                checkedThumbColor = Ink,
                                                uncheckedThumbColor = Muted,
                                                uncheckedTrackColor = Border))
                                        StatusPill(
                                            if (maintenanceOn) "En mantenimiento" else "Inactivo",
                                            if (maintenanceOn) Amber else Muted)
                                      }
                                    }
                                  }
                                }
                                item {
                                  Tile(Modifier.fillMaxWidth()) {
                                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                      Avatar(Icons.Outlined.CleaningServices, Mint, 40)
                                      Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                        Text(L("Caché de compilación del servidor"), color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                                        Small(L("La limpieza la ejecuta el servicio de mantenimiento del VPS."))
                                      }
                                      TextButton(
                                          enabled = !state.busy,
                                          onClick = {
                                            mutate(
                                                "Solicitar limpieza de caché del servidor",
                                                "cleanup",
                                                JSONObject().put("action", "request"))
                                          }) {
                                            Text(L("Solicitar limpieza"))
                                          }
                                    }
                                  }
                                }
                              }
                              else -> item { Small(L("Selecciona una sección en el menú.")) }
                            }
                            if (state.data.has("count"))
                                item {
                                  val total = state.data.optInt("count")
                                  val size = state.data.optInt("pageSize", 50)
                                  Row(
                                      Modifier.fillMaxWidth(),
                                      horizontalArrangement = Arrangement.SpaceBetween) {
                                        TextButton(
                                            enabled = state.pageIndex > 0 && !state.busy && !state.loading,
                                            onClick = { state.next(-1) }) {
                                              Text(L("Anterior"))
                                            }
                                        Small(LF("Página %1\$s · %2\$s registros", state.pageIndex + 1, total))
                                        TextButton(
                                            enabled =
                                                (state.pageIndex + 1) * size < total && !state.busy && !state.loading,
                                            onClick = { state.next(1) }) {
                                              Text(L("Siguiente"))
                                            }
                                      }
                                }
                          }
                    }
                  }
            }
      }
  form?.let { f -> FormDialog(state, f) { form = null } }
  confirm?.let { (title, action) ->
    AlertDialog(
        onDismissRequest = { if (!state.busy) confirm = null },
        containerColor = Panel,
        title = { Text(L(title)) },
        text = { Text(L("La acción se aplicará en el servidor."), color = Muted) },
        confirmButton = {
          TextButton(
              enabled = !state.busy,
              onClick = {
                state.task {
                  action()
                  confirm = null
                }
              }) {
                Text(L("Confirmar"))
              }
        },
        dismissButton = {
          TextButton(enabled = !state.busy, onClick = { confirm = null }) { Text(L("Cancelar")) }
        })
  }
  state.detail?.let { row ->
    DetailScreen(state.page, row, { state.detail = null }) { Fields(row) }
  }
  state.oneTimeSecret?.let { row -> SecretDialog(row) { state.oneTimeSecret = null } }
}

@Composable
private fun LoginScreen(state: AdminState) {
  var username by remember { mutableStateOf("") }
  var password by remember { mutableStateOf("") }
  var visible by remember { mutableStateOf(false) }
  Column(
      Modifier.fillMaxSize()
          .safeDrawingPadding()
          .verticalScroll(rememberScrollState())
          .padding(28.dp),
      horizontalAlignment = Alignment.CenterHorizontally,
      verticalArrangement = Arrangement.Center) {
        Avatar(Icons.Outlined.VerifiedUser, Mint, 72)
        Spacer(Modifier.height(16.dp))
        Text("SP-DECODE", color = Ink, fontSize = 26.sp, fontWeight = FontWeight.Bold)
        Text("ADMINISTRACIÓN", color = Mint, fontWeight = FontWeight.SemiBold, letterSpacing = 2.sp)
        Spacer(Modifier.height(8.dp))
        Small(L("Acceso administrativo seguro"))
        Spacer(Modifier.height(22.dp))
        OutlinedTextField(
            username,
            { username = it.take(128) },
            label = { Text(L("Usuario")) },
            enabled = !state.busy,
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("login-username"),
            shape = Rounded)
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            password,
            { password = it.take(512) },
            label = { Text(L("Contraseña")) },
            enabled = !state.busy,
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("login-password"),
            shape = Rounded,
            visualTransformation =
                if (visible) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
              IconButton(onClick = { visible = !visible }) {
                Icon(
                    if (visible) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                    "Mostrar u ocultar contraseña")
              }
            })
        Spacer(Modifier.height(16.dp))
        Button(
            enabled = !state.busy && username.isNotBlank() && password.isNotEmpty(),
            onClick = {
              state.login(username, password)
              password = ""
            },
            modifier = Modifier.fillMaxWidth().testTag("login-submit"),
            shape = Rounded) {
              Text(L(if (state.busy) "Conectando…" else "Iniciar sesión"))
            }
        state.error?.let { Text(AdminErrorLabel(it), color = Red, modifier = Modifier.padding(top = 12.dp)) }
        Spacer(Modifier.height(18.dp))
        Small("Ghost Nexora Studio")
      }
}

@Composable
private fun RecordCard(title: String, subtitle: String, onClick: () -> Unit) {
  Tile(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
      Avatar(Icons.Outlined.Description, Mint, 36)
      Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(title.ifBlank { "Sin nombre" }, color = Ink, fontWeight = FontWeight.SemiBold)
        if (subtitle.isNotBlank()) Small(subtitle)
      }
      Icon(Icons.Outlined.ChevronRight, null, tint = Muted)
    }
  }
}

@Composable
private fun UserCard(row: JSONObject, onClick: () -> Unit) {
  Tile(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
      ProfileAvatar(row, 44)
      Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(displayName(row), color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
        userHandle(row)?.let { Small(it, color = Mint) }
        Small(row.optString("email"))
      }
      Icon(Icons.Outlined.ChevronRight, null, tint = Muted)
    }
    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
      if (row.has("email_verified")) StatusPill(if (row.optBoolean("email_verified")) "Verificado" else "No verificado", if (row.optBoolean("email_verified")) Mint else Muted)
      if (row.optString("providers").contains("google", ignoreCase = true)) StatusPill("Google", Blue)
      if (row.optBoolean("password_enabled")) StatusPill("Contraseña", Muted)
      if (row.optBoolean("ad_free")) StatusPill("Sin anuncios")
      if (row.optInt("credits") > 0) StatusPill(LF("%1\$s créditos", row.optInt("credits")), Purple)
    }
    if (row.has("orders_count") && row.has("open_tickets")) Small(
        LF("%1\$s pedidos · %2\$s tickets abiertos", row.optInt("orders_count"), row.optInt("open_tickets")))
  }
}

@Composable
private fun TicketCard(row: JSONObject, onClick: () -> Unit) {
  val status = row.optString("status")
  val last = row.array("messages").lastOrNull()
  Tile(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
      ProfileAvatar(row, 40)
      Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(displayName(row), color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
        userHandle(row)?.let { Small(it, color = Mint) }
        Text(row.optString("subject"), color = Ink, fontSize = 13.sp, maxLines = 1)
      }
      if (status.isNotBlank()) StatusPill(translated(status), toneFor(status))
    }
    last?.optString("text")?.takeIf { it.isNotBlank() }?.let {
      Text(it, color = Muted, maxLines = 2, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis, fontSize = 13.sp)
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
      Small(row.optString("assigned_name").takeUnless { it == "null" }.orEmpty().ifBlank { L("Sin asignar") })
      localDate(row.optString("last_message_at"))?.let { Small(it) }
    }
  }
}

private val labels =
    mapOf(
        "id" to "Identificador",
        "name" to "Nombre",
        "email" to "Correo",
        "username" to "Usuario",
        "status" to "Estado",
        "created_at" to "Fecha de creación",
        "createdAt" to "Fecha de creación",
        "expires_at" to "Vencimiento",
        "product_id" to "Producto",
        "account_id" to "Cuenta",
        "order_id" to "Pedido",
        "paid_at" to "Fecha de pago",
        "provider" to "Método de pago",
        "quote" to "Importe del pedido",
        "currency" to "Moneda",
        "total" to "Total (centavos)",
        "subtotal" to "Subtotal (centavos)",
        "tax" to "Impuestos (centavos)",
        "allowed_ip" to "IP autorizada",
        "token_prefix" to "Prefijo de clave",
        "requests" to "Solicitudes",
        "delta" to "Créditos",
        "movement_kind" to "Movimiento",
        "max_uses" to "Usos máximos",
        "used" to "Usos",
        "enabled" to "Habilitado",
        "kind" to "Tipo",
        "days" to "Vigencia (días)",
        "title" to "Título",
        "body" to "Mensaje",
        "role" to "Cargo",
        "action" to "Acción",
        "details" to "Detalles",
        "user" to "Perfil",
        "identities" to "Métodos de acceso",
        "orders" to "Pedidos",
        "entitlements" to "Licencias y productos",
        "sessions" to "Sesiones",
        "creditMovements" to "Movimientos de créditos",
        "tickets" to "Soporte",
        "services" to "Servicios",
        "metrics" to "Estadísticas",
        "cpuPercent" to "CPU (%)",
        "memoryUsedBytes" to "Memoria usada (bytes)",
        "memoryLimitBytes" to "Límite de memoria (bytes)",
        "scope" to "Alcance",
        "workerReady" to "Worker disponible",
        "redisReady" to "Redis disponible",
        "health" to "Salud del servicio",
        "window" to "Ventana",
        "mustChangePassword" to "Debe cambiar contraseña")
private val hidden =
    setOf(
        "token_digest",
        "password",
        "password_hash",
        "image",
        "avatar",
        "avatar_data",
        "ciphertext",
        "product_snapshot", "token", "token_hash", "secret", "cookie", "session_token", "accessToken", "refreshToken", "code_digest")

internal fun translated(value: String): String =
    when (value) {
      "paid" -> "Pagado"
      "pending",
      "created" -> "Pendiente"
      "refunded" -> "Reembolsado"
      "disputed" -> "En disputa"
      "failed" -> "Fallido"
      "active" -> "Activo"
      "revoked" -> "Revocado"
      "open" -> "Abierto"
      "closed" -> "Cerrado"
      "answered" -> "Respondido"
      "grant" -> "Abono"
      "refund" -> "Reversión"
      "spend" -> "Consumo"
      "true" -> "Sí"
      "false" -> "No"
      "web_container_only" -> "Solo contenedor web"
      // Ventana de métricas del servidor: nunca se muestra el valor crudo.
      // Valores no listados aquí siguen el camino actual (se muestran tal cual).
      "utc_today" -> "Hoy (UTC)"
      "utc_week" -> "Esta semana (UTC)"
      "utc_month" -> "Este mes (UTC)"
      "utc_year" -> "Este año (UTC)"
      "all_time" -> "Todo el historial"
      else -> value
    }

internal fun productName(id: String) =
    when (id) {
      "offline-3" -> "Licencia Offline"
      "api-ip" -> "API comercial"
      "analysis-credits" -> "Créditos APK"
      "ads-free" -> "Sin anuncios"
      else -> id
    }

@Composable
private fun Fields(value: JSONObject, skip: Set<String> = emptySet(), depth: Int = 0) {
  value
      .keys()
      .asSequence()
      .filter { it !in hidden && it !in skip }
      .forEach { key ->
        val item = value.opt(key)
        if (item != null && item != JSONObject.NULL) {
          when (item) {
            is JSONObject -> {
              Text(
                  L(labels[key] ?: key),
                  color = Mint,
                  fontWeight = FontWeight.Medium,
                  modifier = Modifier.padding(top = 6.dp))
              if (depth < 4) Fields(item, depth = depth + 1)
            }
            is JSONArray -> {
              Text(
                  L(labels[key] ?: key),
                  color = Mint,
                  fontWeight = FontWeight.Medium,
                  modifier = Modifier.padding(top = 6.dp))
              for (i in 0 until item.length()) {
                val row = item.optJSONObject(i)
                if (row != null && depth < 4) {
                  Fields(row, depth = depth + 1)
                  HorizontalDivider(color = Border)
                } else Small(L(translated(item.optString(i))))
              }
            }
            else -> {
              Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(L(labels[key] ?: prettyKey(key)), color = Muted, fontSize = 12.sp, modifier = Modifier.weight(.44f))
                val raw = item.toString()
                val display = translated(raw)
                Text(if (display == raw) raw else L(display), color = Ink, fontSize = 14.sp, modifier = Modifier.weight(.56f))
              }
              HorizontalDivider(color = Border.copy(alpha = .45f))
            }
          }
        }
      }
}

@Composable
private fun FormDialog(state: AdminState, form: RemoteForm, dismiss: () -> Unit) {
  val values =
      remember(form) {
        mutableStateMapOf<String, String>().apply {
          form.fields.forEach { put(it.key, it.initial) }
        }
      }
  var error by remember(form) { mutableStateOf<String?>(null) }
  AlertDialog(
      onDismissRequest = { if (!state.busy) dismiss() },
      containerColor = Panel,
      title = { Text(L(form.title)) },
      text = {
        Column(
            Modifier.heightIn(max = 480.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(10.dp)) {
              form.fields.forEach { field ->
                if (field.choices.isEmpty())
                    OutlinedTextField(
                        values[field.key].orEmpty(),
                        { values[field.key] = it.take(if (field.secret) 128 else 500) },
                        label = { Text(dynamicUiLabel(field.label)) },
                        enabled = !state.busy,
                        singleLine = field.key != "body",
                        visualTransformation =
                            if (field.secret) PasswordVisualTransformation()
                            else VisualTransformation.None,
                        modifier = Modifier.fillMaxWidth())
                else {
                  Small(dynamicUiLabel(field.label))
                  field.choices.forEach { choice ->
                    Row(
                        Modifier.fillMaxWidth().clickable(enabled = !state.busy) {
                          values[field.key] = choice
                        },
                        verticalAlignment = Alignment.CenterVertically) {
                          RadioButton(
                              values[field.key] == choice,
                              { values[field.key] = choice },
                              enabled = !state.busy)
                          Text(L(translated(choice)), color = Ink)
                        }
                  }
                }
              }
              (error ?: state.error)?.let { Text(AdminErrorLabel(it), color = Red) }
            }
      },
      confirmButton = {
        TextButton(
            enabled = !state.busy,
            onClick = {
              state.task {
                try {
                  form.submit(values.toMap())
                  dismiss()
                } catch (e: IllegalArgumentException) {
                  error = e.message ?: "Revisa los campos."
                }
              }
            }) {
              Text(L(if (state.busy) "Guardando…" else "Guardar"))
            }
      },
      dismissButton = { TextButton(enabled = !state.busy, onClick = dismiss) { Text(L("Cancelar")) } })
}

@Composable
private fun SecretDialog(value: JSONObject, dismiss: () -> Unit) {
  val clipboard = LocalClipboardManager.current
  val secret = value.optString("temporaryPassword").ifBlank { value.optString("code") }
  AlertDialog(
      onDismissRequest = dismiss,
      containerColor = Panel,
      title = { Text(L("Guarda estos datos")) },
      text = {
        Column {
          Small(L("Se muestran una sola vez."))
          value.optJSONObject("staff")?.let {
            Text("${it.optString("username")} · ${it.optString("name")}", color = Ink)
          }
          Text(
              secret, color = Mint, fontSize = 18.sp, modifier = Modifier.padding(vertical = 16.dp))
        }
      },
      confirmButton = {
        TextButton(onClick = { clipboard.setText(AnnotatedString(secret)) }) { Text(L("Copiar")) }
      },
      dismissButton = { TextButton(onClick = dismiss) { Text(L("Cerrar")) } })
}

/** Raw label key for the appearance name; callers translate it with L(). */
private fun appearanceKey(value: Appearance): String =
    when (value) {
      Appearance.Amoled -> "AMOLED"
      Appearance.Dark -> "Oscuro"
      Appearance.Light -> "Claro"
    }

@Composable
private fun SettingsScreen(state: AdminState) {
  ScreenList(state.page) {
    when (state.page) {
      Page.LanguageSettings -> {
        item { SectionHeading("Idioma", "Elige el idioma de la interfaz") }
        items(AdminLanguage.entries) { language ->
          Tile(Modifier.fillMaxWidth().testTag("language-${language.tag}").clickable { state.changeLanguage(language) }) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
              Avatar(Icons.Outlined.Language, if (state.language == language) Mint else Muted, 40)
              Column(Modifier.weight(1f)) {
                Text(language.nativeName, color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                if (state.language == language) Small(L("Idioma actual"), color = Mint)
              }
              RadioButton(state.language == language, { state.changeLanguage(language) })
            }
          }
        }
        item { Small(L("El cambio se aplica inmediatamente.")) }
      }
      Page.AppearanceSettings -> {
        item { SectionHeading("Apariencia", "Los cambios se guardan en este dispositivo") }
        items(Appearance.entries) { value ->
          Tile(Modifier.fillMaxWidth().clickable { state.theme(value) }) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
              Avatar(Icons.Outlined.Palette, if (state.appearance == value) Mint else Muted, 40)
              Column(Modifier.weight(1f)) {
                Text(L(appearanceKey(value)), color = Ink, fontWeight = FontWeight.SemiBold)
                Small(L(when(value) {
                  Appearance.Amoled -> "Negro profundo"
                  Appearance.Dark -> "Contraste suave"
                  Appearance.Light -> "Superficies claras"
                }))
              }
              RadioButton(state.appearance == value, { state.theme(value) })
            }
          }
        }
      }
      Page.AboutSettings -> item {
        Tile(Modifier.fillMaxWidth(), GreenPanel) {
          Avatar(Icons.Outlined.VerifiedUser, Mint, 48)
          Text("SP-DECODE Admin", color = Ink, fontSize = 20.sp, fontWeight = FontWeight.Bold)
          Small(LF("Versión %1\$s", BuildConfig.VERSION_NAME))
          Small("Ghost Nexora Studio")
        }
      }
      else -> {
        item {
          Tile(Modifier.fillMaxWidth(), GreenPanel) {
            Text(state.principal.optString("name"), color = Ink, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Small(state.principal.optString("role"))
          }
        }
        item {
          Tile(Modifier.fillMaxWidth()) {
            ActionRow("Idioma", Icons.Outlined.Language, state.language.nativeName) { state.navigate(Page.LanguageSettings) }
            ActionRow("Apariencia", Icons.Outlined.Palette, appearanceKey(state.appearance)) { state.navigate(Page.AppearanceSettings) }
            ActionRow("Acerca de", Icons.Outlined.Info, BuildConfig.VERSION_NAME) { state.navigate(Page.AboutSettings) }
            TextButton(enabled = !state.busy, onClick = { state.logout() }) { Text(L("Cerrar sesión"), color = Red) }
          }
        }
        item {
          SectionHeading("Cuenta y seguridad")
          Tile(Modifier.fillMaxWidth()) {
            ActionRow("Seguridad", Icons.Outlined.Security) { state.navigate(Page.Security) }
            ActionRow("Mis sesiones", Icons.Outlined.Devices) { state.navigate(Page.Sessions) }
            if (state.allowed(Page.Notices)) ActionRow("Notificaciones del sistema", Icons.Outlined.Notifications) { state.navigate(Page.Notices) }
          }
        }
      }
    }
  }
}

/** Canned replies that only fill the local draft; the admin still sends them. */
private val quickReplies =
    listOf(
        "Gracias por tu mensaje, lo revisamos ahora.",
        "¿Me puedes enviar una captura del error?",
        "Tu solicitud quedó resuelta, ¿necesitas algo más?")

@Composable
private fun ChatScreen(state: AdminState) {
  val thread = state.data.array("threads").firstOrNull { it.optString("id") == state.selectedId }
  if (thread == null) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
      if (state.busy || state.loading) CircularProgressIndicator(color = Mint)
      else Text(L("La conversación no está disponible."), color = Muted)
    }
    return
  }
  val messages = thread.array("messages")
  val list = rememberLazyListState()
  val draft = state.supportDraft(state.selectedId)
  var assignment by remember { mutableStateOf(false) }
  var assignedId by remember { mutableStateOf(thread.optString("assigned_staff_id", "")) }
  var confirmTicket by remember { mutableStateOf(false) }
  val scope = rememberCoroutineScope()
  var previousCount by remember(state.selectedId) { mutableIntStateOf(0) }
  LaunchedEffect(state.selectedId, messages.size) {
    val lastVisible = list.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: -1
    val wasNearEnd = shouldFollowNewMessages(previousCount, lastVisible)
    if (messages.isNotEmpty() && wasNearEnd) list.scrollToItem(messages.lastIndex)
    previousCount = messages.size
  }
  Column(Modifier.fillMaxSize()) {
    ChatHeader(thread)
    state.supportSyncError?.let {
      Row(
          Modifier.fillMaxWidth().padding(horizontal = 16.dp),
          verticalAlignment = Alignment.CenterVertically,
          horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Small(AdminErrorLabel(it), Modifier.weight(1f), Amber)
            TextButton(onClick = { scope.launch { state.refreshSupport() } }) {
              Text(L("Reintentar"))
            }
          }
    }
    Row {
      if (state.can("support.write"))
          TextButton(
              enabled = !state.busy,
              onClick = { confirmTicket = true }) {
                Text(L(if (thread.optString("status") == "closed") "Reabrir" else "Cerrar ticket"))
              }
      if (state.can("support.assign"))
          TextButton(enabled = !state.busy, onClick = {
            assignedId = thread.optString("assigned_staff_id").takeUnless { it == "null" }.orEmpty()
            assignment = true
          }) { Text(L("Asignar agente")) }
    }
    if (messages.isEmpty() && !state.busy && !state.loading)
        Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
          EmptyState(
              "Aún no hay mensajes",
              "Escribe la primera respuesta al usuario.",
              Icons.Outlined.Forum)
        }
    else
        LazyColumn(
            Modifier.weight(1f).fillMaxWidth(),
            state = list,
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)) {
              itemsIndexed(messages, key = { _, m -> m.getString("id") }) { index, m ->
                val outgoing = m.optString("sender") == "admin"
                val day = messageDay(m.optString("at"))
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                  if (day != null &&
                      (index == 0 || messageDay(messages[index - 1].optString("at")) != day))
                      Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        Text(
                            day,
                            color = Muted,
                            fontSize = 12.sp,
                            modifier =
                                Modifier.background(Panel, CircleShape)
                                    .padding(horizontal = 10.dp, vertical = 4.dp))
                      }
                  Row(
                      Modifier.fillMaxWidth(),
                      horizontalArrangement = if (outgoing) Arrangement.End else Arrangement.Start,
                      verticalAlignment = Alignment.Bottom) {
                        MessageBubble(
                            m,
                            outgoing,
                            if (outgoing) m.optJSONObject("agent")?.optString("name")
                            else displayName(thread).takeUnless { it == "Sin nombre" },
                            thread = thread)
                      }
                }
              }
            }
    if (thread.optString("status") == "closed")
      Small(L("Conversación cerrada. Reabre el ticket para responder."), Modifier.padding(16.dp))
    else if (!state.can("support.write"))
      Small(L("Tu cargo tiene acceso de solo lectura."), Modifier.padding(16.dp))
    if (state.can("support.write") && thread.optString("status") != "closed")
        Column {
          Row(
              Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())
                  .padding(horizontal = 10.dp),
              horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                quickReplies.forEach { reply ->
                  // Chip compacto (28 dp, texto 12 sp, ancho máx. 180 dp con
                  // elipsis): antes era un AssistChip de Material 3 con el
                  // texto completo en una línea y ocupaba casi todo el ancho.
                  // Al tocarlo sigue rellenando solo el borrador con el texto
                  // completo; solo la etiqueta visible se recorta.
                  Box(
                      Modifier.height(28.dp).widthIn(max = 180.dp).clip(CircleShape)
                          .background(Panel).border(1.dp, Border, CircleShape)
                          .clickable { state.updateSupportDraft(state.selectedId, reply) }
                          .padding(horizontal = 10.dp),
                      contentAlignment = Alignment.Center) {
                        Text(reply, maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                            fontSize = 12.sp, color = Ink)
                      }
                }
              }
          Row(
              Modifier.fillMaxWidth().padding(10.dp),
              verticalAlignment = Alignment.Bottom,
              horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    draft,
                    { state.updateSupportDraft(state.selectedId, it.take(2000)) },
                    placeholder = { Text(L("Escribe tu respuesta…")) },
                    modifier = Modifier.weight(1f).testTag("chat-draft"),
                    shape = Rounded,
                    maxLines = 4)
                FilledIconButton(
                    modifier = Modifier.size(48.dp).testTag("chat-send"),
                    enabled = !state.busy && draft.isNotBlank(),
                    onClick = {
                      state.sendSupportReply(state.selectedId, draft)
                    }) {
                      Icon(Icons.AutoMirrored.Outlined.Send, L("Enviar"))
                    }
              }
          Box(
              Modifier.fillMaxWidth().padding(horizontal = 16.dp),
              contentAlignment = Alignment.CenterEnd) {
                Small("${draft.length}/2000")
              }
        }
  }
  if (confirmTicket)
      AlertDialog(
          onDismissRequest = { confirmTicket = false },
          containerColor = Panel,
          title = { Text(L(if (thread.optString("status") == "closed") "Reabrir" else "Cerrar ticket")) },
          text = {
            Text(
                L(
                    if (thread.optString("status") == "closed") "El ticket volverá a estar abierto para el usuario."
                    else "El usuario ya no podrá responder hasta que reabras el ticket."),
                color = Muted)
          },
          confirmButton = {
            TextButton(
                onClick = {
                  confirmTicket = false
                  state.task {
                    state.mutate(
                        "support_send",
                        JSONObject()
                            .put("threadId", state.selectedId)
                            .put(
                                "action",
                                if (thread.optString("status") == "closed") "reopen" else "close"))
                  }
                }) {
                  Text(L("Confirmar"))
                }
          },
          dismissButton = { TextButton(onClick = { confirmTicket = false }) { Text(L("Cancelar")) } })
  if (assignment)
      AlertDialog(
          onDismissRequest = { assignment = false },
          containerColor = Panel,
          title = { Text(L("Asignar agente")) },
          text = {
            Column(Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState())) {
              Row(
                  Modifier.fillMaxWidth().clickable { assignedId = "" },
                  verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(assignedId.isEmpty(), { assignedId = "" })
                    Text(L("Sin asignación"), color = Ink)
                  }
              state.data.array("agents").forEach { agent ->
                Row(
                    Modifier.fillMaxWidth().clickable { assignedId = agent.getString("id") },
                    verticalAlignment = Alignment.CenterVertically) {
                      RadioButton(
                          assignedId == agent.getString("id"),
                          { assignedId = agent.getString("id") })
                      Text(
                          "${agent.optString("name")} · ${agent.optString("username")}",
                          color = Ink)
                    }
              }
              if (!state.data.has("agents"))
                  Small(L("Actualiza el servidor para consultar los agentes disponibles."))
            }
          },
          confirmButton = {
            TextButton(
                enabled = !state.busy,
                onClick = {
                  state.task {
                    state.mutate(
                        "support_send",
                        JSONObject()
                            .put("action", "assign")
                            .put("threadId", state.selectedId)
                            .put("assignedId", if (assignedId.isBlank()) JSONObject.NULL else assignedId))
                    assignment = false
                  }
                }) {
                  Text(L("Guardar"))
                }
          },
          dismissButton = { TextButton(onClick = { assignment = false }) { Text(L("Cancelar")) } })
}

private fun staffForm(
    state: AdminState,
    row: JSONObject?,
    open: (String, List<FormField>, suspend (Map<String, String>) -> Unit) -> Unit
) {
  val roles =
      state.data
          .optJSONArray("roles")
          ?.let { a -> (0 until a.length()).map { a.getString(it) } }
          .orEmpty()
  open(
      if (row == null) "Crear personal" else "Editar personal",
      listOf(
          FormField("username", "Usuario", row?.optString("username").orEmpty()),
          FormField("name", "Nombre visible", row?.optString("name").orEmpty()),
          FormField(
              "role", "Cargo", row?.optString("role") ?: roles.firstOrNull().orEmpty(), roles)) +
          (if (row != null)
              listOf(
                  FormField(
                      "enabled",
                      "Acceso habilitado",
                      row.optBoolean("enabled").toString(),
                      listOf("true", "false")),
                  FormField("reset", "Restablecer contraseña", "false", listOf("false", "true")))
          else emptyList())) { v ->
        val body =
            JSONObject()
                .put("action", if (row == null) "create" else "update")
                .put("username", v["username"])
                .put("name", v["name"])
                .put("role", v["role"])
        if (row != null) {
          body.put("id", row.getString("id")).put("enabled", v["enabled"] == "true")
          if (v["reset"] == "true") body.put("resetPassword", true)
        }
        state.mutate("staff_save", body)
      }
}

private fun roleForm(
    state: AdminState,
    row: JSONObject?,
    open: (String, List<FormField>, suspend (Map<String, String>) -> Unit) -> Unit
) {
  val perms =
      listOf("users.read", "support.read", "support.write", "support.assign", "billing.read")
  val selected =
      row?.optJSONArray("permissions")
          ?.let { a -> (0 until a.length()).map { a.optString(it) } }
          .orEmpty()
  val names =
      listOf(
          "Consultar usuarios",
          "Leer soporte",
          "Responder soporte",
          "Asignar soporte",
          "Consultar compras")
  open(
      if (row == null) "Crear cargo" else "Editar cargo",
      listOf(
          FormField("name", "Nombre del cargo", row?.optString("name").orEmpty()),
          FormField(
              "enabled",
              "Cargo habilitado",
              (row?.optBoolean("enabled") ?: true).toString(),
              listOf("true", "false"))) +
          perms.mapIndexed { i, p ->
            FormField(p, names[i], (p in selected).toString(), listOf("true", "false"))
          }) { v ->
        val ps = perms.filter { v[it] == "true" }.toMutableSet()
        if ("support.write" in ps || "support.assign" in ps) ps.add("support.read")
        state.mutate(
            "roles_save",
            JSONObject()
                .put("action", if (row == null) "create" else "update")
                .put(
                    "code",
                    row?.optString("code")
                        ?: "x_" +
                            UUID.randomUUID().toString().replace("-", "").take(10).let { "r" + it })
                .put("name", v["name"])
                .put("permissions", JSONArray(ps.toList()))
                .put("enabled", v["enabled"] == "true"))
      }
}

private fun productForm(
    state: AdminState,
    row: JSONObject,
    open: (String, List<FormField>, suspend (Map<String, String>) -> Unit) -> Unit
) {
  val settings = row.getJSONObject("settings")
  val product = row.getString("id")
  val prices = mutableListOf<Pair<String, Pair<String, String>>>()
  val base = settings.optJSONObject("prices") ?: JSONObject()
  base.keys().forEach {
    prices.add("base_$it" to ("Precio base ($it)" to money(base.optLong(it)).removePrefix("$")))
  }
  for (group in listOf("termPrices", "bundles")) {
    val nested = settings.optJSONObject(group) ?: continue
    nested.keys().forEach { term ->
      val p = nested.optJSONObject(term) ?: JSONObject()
      p.keys().forEach { currency ->
        prices.add(
            "${group}_${term}_$currency" to
                ("$term ($currency)" to money(p.optLong(currency)).removePrefix("$")))
      }
    }
  }
  open(
      productName(product),
      listOf(
          FormField(
              "enabled",
              "Habilitado",
              settings.optBoolean("enabled").toString(),
              listOf("true", "false"))) +
          prices.map { FormField(it.first, it.second.first, it.second.second) }) { v ->
        val next = JSONObject(settings.toString()).put("enabled", v["enabled"] == "true")
        prices.forEach { (key, _) ->
          val amount =
              parsePrice(v.getValue(key))
                  ?: throw IllegalArgumentException("Escribe un precio válido.")
          val parts = key.split('_')
          if (parts[0] == "base") next.getJSONObject("prices").put(parts[1], amount)
          else next.getJSONObject(parts[0]).getJSONObject(parts[1]).put(parts[2], amount)
        }
        state.mutate(
            "store_save",
            JSONObject()
                .put("action", "product")
                .put("version", row.getInt("version"))
                .put("product", next))
      }
}

private fun giftForm(
    state: AdminState,
    open: (String, List<FormField>, suspend (Map<String, String>) -> Unit) -> Unit
) {
  open(
      "Generar gift code",
      listOf(
          FormField("title", "Título"),
          FormField("kind", "Recompensa", "credits", listOf("credits", "ads-free", "offline-3")),
          FormField("amount", "Créditos o días de acceso", "30"),
          FormField("uses", "Usos máximos", "1"))) { v ->
        val body =
            JSONObject()
                .put("action", "create")
                .put("title", v["title"])
                .put("kind", v["kind"])
                .put(
                    "maxUses",
                    v["uses"]?.toIntOrNull()
                        ?: throw IllegalArgumentException("Escribe un número de usos válido."))
        body.put(
            if (v["kind"] == "credits") "credits" else "days",
            v["amount"]?.toIntOrNull()
                ?: throw IllegalArgumentException("Escribe una cantidad válida."))
        state.mutate("gifts_save", body)
      }
}

private fun noticeForm(
    state: AdminState,
    open: (String, List<FormField>, suspend (Map<String, String>) -> Unit) -> Unit
) {
  open(
      "Anuncio público para usuarios de SP-DECODE",
      listOf(
          FormField("title", "Título"),
          FormField("body", "Mensaje"),
          FormField(
              "type",
              "Tipo",
              "general",
              listOf("general", "update", "maintenance", "catalog", "security")),
          FormField("delivery", "Entrega", "push", listOf("push", "poll")),
          FormField("importance", "Importancia", "normal", listOf("normal", "important")),
          FormField("ttl", "Vigencia (horas)", "24", listOf("6", "24", "72", "168")))) { v ->
        require(
            v.getValue("title").trim().length in 1..80 &&
                v.getValue("body").trim().length in 1..500) {
              "El título debe tener hasta 80 caracteres y el mensaje hasta 500."
            }
        state.mutate(
            "notice_send",
            JSONObject()
                .put("id", UUID.randomUUID().toString())
                .put("title", v.getValue("title").trim())
                .put("body", v.getValue("body").trim())
                .put("type", v["type"])
                .put("delivery", v["delivery"])
                .put("importance", v["importance"])
                .put("ttlHours", v.getValue("ttl").toInt()))
      }
}

private fun moduleSubtitle(page: Page): String? = when (page) {
  Page.Roles -> "Personal autorizado y cargos administrativos"
  Page.Products -> "Configuración de la tienda y disponibilidad"
  Page.Finance -> "Resumen de ingresos y operaciones pagadas"
  Page.Purchases -> "Historial de pedidos y sus estados"
  Page.Licenses -> "Administración de accesos Offline"
  Page.Api -> "Accesos comerciales e IP autorizada"
  Page.Credits -> "Registro de movimientos de créditos"
  Page.Gifts -> "Emisión, disponibilidad y canjes"
  Page.Catalog -> "Versiones y disponibilidad de proveedores"
  Page.Server -> "Diagnóstico y salud de la plataforma"
  Page.Notices -> "Publicación e historial de avisos"
  Page.Logs -> "Registro de acciones administrativas"
  Page.Security -> "Credenciales y protección de la cuenta"
  Page.Sessions -> "Acceso desde este dispositivo"
  Page.Maintenance -> "Operaciones de mantenimiento controladas"
  else -> null
}

@Composable
private fun dynamicUiLabel(label: String): String =
    if (label.startsWith("Precio base (") && label.endsWith(")"))
      LF("Precio base (%1\$s)", label.removePrefix("Precio base (").removeSuffix(")"))
    else L(label)
