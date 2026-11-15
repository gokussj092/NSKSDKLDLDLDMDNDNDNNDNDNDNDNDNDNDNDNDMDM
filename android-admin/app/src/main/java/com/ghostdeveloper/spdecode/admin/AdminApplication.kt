package com.ghostdeveloper.spdecode.admin

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
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
      CircularProgressIndicator(color = Mint)
    }
    return
  }
  var form by remember { mutableStateOf<RemoteForm?>(null) }
  var confirm by remember { mutableStateOf<Pair<String, suspend () -> Unit>?>(null) }
  val drawer = rememberDrawerState(DrawerValue.Closed)
  val scope = rememberCoroutineScope()
  val lifecycle = LocalLifecycleOwner.current
  val snack = remember { SnackbarHostState() }
  LaunchedEffect(state.error, state.message) {
    val text = state.error ?: state.message
    if (text != null) {
      snack.showSnackbar(text)
      state.message = null
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
  BackHandler(state.entered && state.page != Page.Dashboard) {
    state.navigate(
        if (state.page == Page.Chat) Page.Support
        else if (state.page == Page.UserDetail) Page.Users
        else if (state.page in listOf(Page.AppearanceSettings, Page.AboutSettings)) Page.Settings
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
                  Text(
                      "SP-DECODE",
                      color = Mint,
                      fontSize = 25.sp,
                      fontWeight = FontWeight.Bold,
                      modifier = Modifier.padding(vertical = 16.dp))
                  Small(state.principal.optString("name"))
                  Small(state.principal.optString("role"))
                }
                menuGroups.forEach { (title, pages) ->
                  item { Small(title, Modifier.padding(top = 22.dp, bottom = 8.dp)) }
                  items(pages.filter { state.allowed(it) }) { p ->
                    NavigationDrawerItem(
                        label = { Text(p.title) },
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
                        Text("Cerrar sesión")
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
                        if (state.page == Page.Dashboard) "SP-DECODE Admin" else state.page.title,
                        fontSize = 19.sp)
                  },
                  navigationIcon = {
                    IconButton(
                        onClick = {
                          if (state.page == Page.Chat) state.navigate(Page.Support)
                          else if (state.page == Page.UserDetail) state.navigate(Page.Users)
                          else if (state.page in listOf(Page.AppearanceSettings, Page.AboutSettings)) state.navigate(Page.Settings)
                          else scope.launch { drawer.open() }
                        }) {
                          Icon(
                              if (state.page in listOf(Page.Chat, Page.UserDetail, Page.AppearanceSettings, Page.AboutSettings))
                                  Icons.AutoMirrored.Outlined.ArrowBack
                              else Icons.Outlined.Menu,
                              "Menú")
                        }
                  },
                  actions = {
                    IconButton(enabled = !state.busy, onClick = { state.refresh() }) {
                      Icon(Icons.Outlined.Refresh, "Actualizar")
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
                                    if (p == Page.Dashboard) "Inicio" else p.title,
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
                    if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth(), color = Mint)
                    state.error?.let {
                      Text(
                          it,
                          color = Red,
                          fontSize = 13.sp,
                          modifier = Modifier.fillMaxWidth().padding(12.dp))
                    }
                    if (state.mustChangePassword && state.page != Page.Security) {
                      TextButton(onClick = { state.navigate(Page.Security) }) {
                        Text("Cambiar contraseña temporal")
                      }
                    }
                    when (state.page) {
                      Page.Chat -> ChatScreen(state)
                      Page.Settings, Page.AppearanceSettings, Page.AboutSettings -> SettingsScreen(state)
                      else ->
                          ScreenList {
                            if (state.data.has("live"))
                                item {
                                  Small(
                                      if (state.data.optBoolean("live")) "Operaciones reales"
                                      else "Entorno de pruebas de pagos configurado en el servidor",
                                      color = Amber)
                                }
                            when (state.page) {
                              Page.Dashboard -> {
                                item {
                                  Tile(Modifier.fillMaxWidth(), GreenPanel) {
                                    Small("SP-DECODE · ADMIN", color = Mint)
                                    Text(state.principal.optString("name").ifBlank { "Administrador" },
                                        color = Ink, fontSize = 29.sp, fontWeight = FontWeight.Bold)
                                    Small(state.principal.optString("role"))
                                    if (state.data.has("maintenance")) StatusPill(
                                        if (state.data.optBoolean("maintenance")) "En mantenimiento" else "Panel conectado",
                                        if (state.data.optBoolean("maintenance")) Amber else Mint)
                                  }
                                }
                                state.data.optJSONObject("metrics")?.let { metrics ->
                                  item {
                                    SectionHeading("Actividad del servicio", "Métricas reportadas por el servidor")
                                    Tile(Modifier.fillMaxWidth()) { Fields(metrics) }
                                  }
                                }
                                state.data.optJSONObject("services")?.let { services ->
                                  item {
                                    SectionHeading("Estado de la plataforma")
                                    Tile(Modifier.fillMaxWidth()) { Fields(services) }
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
                                  }) { Text("Buscar en el servidor") }
                                  if (state.data.has("count")) Small("${state.data.optInt("count")} usuarios registrados")
                                }
                                items(state.data.array("users"), key = { it.getString("id") }) { row ->
                                  UserCard(row) { state.navigate(Page.UserDetail, row.getString("id")) }
                                }
                                if (!state.busy && state.data.has("users") && state.data.array("users").isEmpty())
                                    item { EmptyState("Sin resultados", "Prueba otra búsqueda.") }
                              }
                              Page.UserDetail -> {
                                val user = state.data.optJSONObject("user")
                                if (user != null) {
                                  item {
                                    Tile(Modifier.fillMaxWidth(), GreenPanel) {
                                      Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                                        ProfileAvatar(user, 68)
                                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                          Text(displayName(user), color = Ink, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                                          userHandle(user)?.let { Small(it, color = Mint) }
                                          Small(user.optString("email"))
                                          if (user.optBoolean("email_verified")) StatusPill("Correo verificado")
                                        }
                                      }
                                    }
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
                                      SectionHeading(label, values?.let { "${it.length()} registros" })
                                      Tile(Modifier.fillMaxWidth()) {
                                        if (values != null && values.length() == 0) Small("Sin registros")
                                        else Fields(JSONObject().put(key, state.data.opt(key)))
                                      }
                                    }
                                  }
                                } else if (!state.busy && state.error == null) item {
                                  EmptyState("Perfil no disponible", "Actualiza para consultar los datos del servidor.")
                                }
                              }
                              Page.Roles -> {
                                if (state.owner)
                                    item {
                                      Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        TextButton(onClick = { staffForm(state, null, ::open) }) {
                                          Text("Crear personal")
                                        }
                                        TextButton(onClick = { roleForm(state, null, ::open) }) {
                                          Text("Crear cargo")
                                        }
                                      }
                                    }
                                items(state.data.array("staff"), key = { it.getString("id") }) { row
                                  ->
                                  RecordCard(
                                      row.optString("name"),
                                      "${row.optString("username")} · ${row.optString("role")}") {
                                        if (state.owner) staffForm(state, row, ::open)
                                        else state.detail = row
                                      }
                                }
                                item {
                                  Text(
                                      "Cargos personalizados",
                                      color = Ink,
                                      fontWeight = FontWeight.Bold)
                                }
                                items(
                                    state.data.array("roleDefinitions"),
                                    key = { it.getString("code") }) { row ->
                                      RecordCard(row.optString("name"), row.optString("code")) {
                                        if (state.owner) roleForm(state, row, ::open)
                                        else state.detail = row
                                      }
                                    }
                              }
                              Page.Support -> {
                                val threads = state.data.array("threads")
                                item { SectionHeading("Bandeja de soporte", "Conversaciones y estado del servidor") }
                                if (threads.isEmpty() && !state.busy)
                                    item { EmptyState("Sin conversaciones", "No hay tickets disponibles para tu cargo.", Icons.Outlined.Forum) }
                                items(threads, key = { it.getString("id") }) { row ->
                                  TicketCard(row) { state.navigate(Page.Chat, row.getString("id")) }
                                }
                              }
                              Page.Products -> {
                                items(state.data.array("products"), key = { it.getString("id") }) {
                                    row ->
                                  val settings = row.optJSONObject("settings") ?: JSONObject()
                                  RecordCard(
                                      productName(row.getString("id")),
                                      if (settings.optBoolean("enabled")) "Habilitado"
                                      else "Deshabilitado") {
                                        productForm(state, row, ::open)
                                      }
                                }
                              }
                              Page.Finance,
                              Page.Purchases -> {
                                if (state.page == Page.Finance) {
                                  item {
                                    Text(
                                        "Ingresos confirmados",
                                        color = Ink,
                                        fontSize = 24.sp,
                                        fontWeight = FontWeight.Bold)
                                    Small("Pedidos pagados; totales separados por moneda.")
                                  }
                                  items(state.data.array("totals")) { t ->
                                    Tile(Modifier.fillMaxWidth(), GreenPanel) {
                                      Text(
                                          "${money(t.optString("cents").toLongOrNull()?:0)} ${t.optString("currency")}",
                                          color = Mint,
                                          fontSize = 24.sp)
                                      Small("${t.optInt("orders")} pedidos pagados")
                                    }
                                  }
                                }
                                items(state.data.array("items"), key = { it.getString("id") }) { row
                                  ->
                                  RecordCard(
                                      productName(row.optString("product_id")),
                                      "${row.optString("name")} · ${translated(row.optString("status"))}") {
                                        state.detail = row
                                      }
                                }
                              }
                              Page.Licenses,
                              Page.Api -> {
                                val id = if (state.page == Page.Api) "api-ip" else "offline-3"
                                item {
                                  Small(
                                      "Los accesos corresponden a pedidos registrados. Las claves completas se entregan una sola vez al titular.")
                                }
                                items(
                                    state.data.array("items").filter {
                                      it.optString("product_id") == id
                                    },
                                    key = { it.getString("id") }) { row ->
                                      Tile(Modifier.fillMaxWidth()) {
                                        Text(
                                            row.optString("name"),
                                            color = Ink,
                                            fontWeight = FontWeight.Bold)
                                        Small(row.optString("email"))
                                        Fields(row)
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
                                                    if (row.optString("status") == "active")
                                                        "Revocar"
                                                    else "Restaurar")
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
                                                    Text("Cambiar IP")
                                                  }
                                        }
                                      }
                                    }
                              }
                              Page.Credits -> {
                                items(state.data.array("items"), key = { it.getString("id") }) { row
                                  ->
                                  RecordCard(
                                      row.optString("name"),
                                      "${row.optInt("delta")} · ${translated(row.optString("movement_kind"))}") {
                                        state.detail = row
                                      }
                                }
                              }
                              Page.Gifts -> {
                                item {
                                  TextButton(onClick = { giftForm(state, ::open) }) {
                                    Icon(Icons.Outlined.Add, null)
                                    Text("Generar código")
                                  }
                                }
                                items(state.data.array("codes"), key = { it.getString("id") }) { row
                                  ->
                                  Tile(Modifier.fillMaxWidth()) {
                                    Text(
                                        row.optString("title"),
                                        color = Ink,
                                        fontWeight = FontWeight.Bold)
                                    Fields(row)
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
                                              Text("Desactivar", color = Red)
                                            }
                                  }
                                }
                                item {
                                  Text(
                                      "Canjes recientes", color = Ink, fontWeight = FontWeight.Bold)
                                }
                                items(state.data.array("redemptions")) { row ->
                                  RecordCard(row.optString("title"), row.optString("name")) {
                                    state.detail = row
                                  }
                                }
                              }
                              Page.Catalog -> {
                                val controls =
                                    state.data.optJSONObject("providerControls") ?: JSONObject()
                                item {
                                  Small(
                                      "Versión del catálogo: ${controls.opt("displayVersion")?:controls.opt("catalogVersion")?:"Sin datos"}")
                                  TextButton(
                                      onClick = {
                                        mutate(
                                            "Publicar el aviso de la versión actual del catálogo",
                                            "catalog_publish")
                                      }) {
                                        Text("Avisar actualización")
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
                                items(providers) { row ->
                                  Tile(Modifier.fillMaxWidth()) {
                                    Text(
                                        row.optString("name").ifBlank { row.optString("id") },
                                        color = Ink,
                                        fontWeight = FontWeight.Bold)
                                    Fields(row)
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
                                              if (row.optBoolean("enabled")) "Desactivar"
                                              else "Activar")
                                        }
                                  }
                                }
                              }
                              Page.Server -> {
                                item {
                                  Text(
                                      "Estado del servicio",
                                      color = Ink,
                                      fontSize = 24.sp,
                                      fontWeight = FontWeight.Bold)
                                  Small(
                                      "Las métricas del contenedor web no representan el consumo total del VPS.")
                                  Fields(state.data)
                                }
                              }
                              Page.Notices -> {
                                item {
                                  TextButton(onClick = { noticeForm(state, ::open) }) {
                                    Icon(Icons.Outlined.Campaign, null)
                                    Text("Enviar notificación")
                                  }
                                  Small(
                                      if (state.data.optBoolean("pushConfigured"))
                                          "Push configurado"
                                      else "Push sin configurar; consulta periódica disponible")
                                }
                                items(state.data.array("notices"), key = { it.getString("id") }) {
                                    row ->
                                  Tile(Modifier.fillMaxWidth()) {
                                    Text(
                                        row.optString("title"),
                                        color = Ink,
                                        fontWeight = FontWeight.Bold)
                                    Text(row.optString("body"), color = Ink)
                                    Fields(row, setOf("title", "body"))
                                  }
                                }
                              }
                              Page.Logs -> {
                                items(state.data.array("events")) { row ->
                                  Tile(Modifier.fillMaxWidth()) {
                                    Text(
                                        row.optString("action"),
                                        color = Ink,
                                        fontWeight = FontWeight.Bold)
                                    Fields(row)
                                  }
                                }
                              }
                              Page.Security -> {
                                item {
                                  Tile(Modifier.fillMaxWidth(), GreenPanel) {
                                    Text(
                                        state.principal.optString("name"),
                                        color = Ink,
                                        fontSize = 22.sp)
                                    Small("Conexión HTTPS autenticada")
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
                                          "La contraseña de propietario se administra desde el servidor.")
                                    }
                                item {
                                  TextButton(onClick = { state.navigate(Page.Sessions) }) {
                                    Text("Mi sesión")
                                  }
                                }
                              }
                              Page.Sessions -> {
                                item {
                                  Tile(Modifier.fillMaxWidth()) {
                                    Text(
                                        "Este dispositivo",
                                        color = Ink,
                                        fontWeight = FontWeight.Bold)
                                    Small(
                                        "${state.principal.optString("name")} · ${state.principal.optString("role")}")
                                    Small(
                                        "La sesión tiene la vigencia y revocación establecidas por el servidor.")
                                    TextButton(
                                        enabled = !state.busy, onClick = { state.logout() }) {
                                          Text("Cerrar sesión", color = Red)
                                        }
                                  }
                                }
                              }
                              Page.Maintenance -> {
                                item {
                                  Tile(Modifier.fillMaxWidth()) {
                                    Text(
                                        "Mantenimiento del servicio",
                                        color = Ink,
                                        fontWeight = FontWeight.Bold)
                                    TextButton(
                                        onClick = {
                                          mutate(
                                              "Activar mantenimiento para todos los clientes",
                                              "maintenance",
                                              JSONObject().put("enabled", true))
                                        }) {
                                          Text("Activar mantenimiento", color = Amber)
                                        }
                                    TextButton(
                                        onClick = {
                                          mutate(
                                              "Desactivar mantenimiento",
                                              "maintenance",
                                              JSONObject().put("enabled", false))
                                        }) {
                                          Text("Desactivar mantenimiento")
                                        }
                                  }
                                }
                                item {
                                  Tile(Modifier.fillMaxWidth()) {
                                    Text(
                                        "Caché de compilación del servidor",
                                        color = Ink,
                                        fontWeight = FontWeight.Bold)
                                    Small(
                                        "La limpieza la ejecuta el servicio de mantenimiento del VPS.")
                                    TextButton(
                                        onClick = {
                                          mutate(
                                              "Solicitar limpieza de caché del servidor",
                                              "cleanup",
                                              JSONObject().put("action", "request"))
                                        }) {
                                          Text("Solicitar limpieza")
                                        }
                                  }
                                }
                              }
                              else -> item { Small("Selecciona una sección en el menú.") }
                            }
                            if (state.data.has("count"))
                                item {
                                  val total = state.data.optInt("count")
                                  val size = state.data.optInt("pageSize", 50)
                                  Row(
                                      Modifier.fillMaxWidth(),
                                      horizontalArrangement = Arrangement.SpaceBetween) {
                                        TextButton(
                                            enabled = state.pageIndex > 0 && !state.busy,
                                            onClick = { state.next(-1) }) {
                                              Text("Anterior")
                                            }
                                        Small("Página ${state.pageIndex+1} · $total registros")
                                        TextButton(
                                            enabled =
                                                (state.pageIndex + 1) * size < total && !state.busy,
                                            onClick = { state.next(1) }) {
                                              Text("Siguiente")
                                            }
                                      }
                                }
                            if (!state.busy &&
                                state.error == null &&
                                state.data.length() > 0 &&
                                state.page !in
                                    listOf(
                                        Page.Dashboard,
                                        Page.Settings,
                                        Page.Server,
                                        Page.Security,
                                        Page.Sessions,
                                        Page.Maintenance))
                                item { Small("Datos recibidos de panel.spdecode.xyz") }
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
        title = { Text(title) },
        text = { Text("La acción se aplicará en el servidor.", color = Muted) },
        confirmButton = {
          TextButton(
              enabled = !state.busy,
              onClick = {
                state.task {
                  action()
                  confirm = null
                }
              }) {
                Text("Confirmar")
              }
        },
        dismissButton = {
          TextButton(enabled = !state.busy, onClick = { confirm = null }) { Text("Cancelar") }
        })
  }
  state.detail?.let { row ->
    AlertDialog(
        onDismissRequest = { state.detail = null },
        containerColor = Panel,
        title = { Text("Detalles") },
        text = {
          Column(Modifier.heightIn(max = 480.dp).verticalScroll(rememberScrollState())) {
            Fields(row)
          }
        },
        confirmButton = { TextButton(onClick = { state.detail = null }) { Text("Cerrar") } })
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
        Avatar(Icons.Outlined.VerifiedUser, Mint, 88)
        Spacer(Modifier.height(22.dp))
        Text("SP-DECODE", color = Ink, fontSize = 30.sp, fontWeight = FontWeight.Bold)
        Text("ADMINISTRATION", color = Mint)
        Spacer(Modifier.height(30.dp))
        OutlinedTextField(
            username,
            { username = it.take(128) },
            label = { Text("Usuario") },
            enabled = !state.busy,
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("login-username"),
            shape = Rounded)
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            password,
            { password = it.take(512) },
            label = { Text("Contraseña") },
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
        Spacer(Modifier.height(20.dp))
        Button(
            enabled = !state.busy && username.isNotBlank() && password.isNotEmpty(),
            onClick = {
              state.login(username, password)
              password = ""
            },
            modifier = Modifier.fillMaxWidth().testTag("login-submit"),
            shape = Rounded) {
              Text(if (state.busy) "Conectando…" else "Iniciar sesión")
            }
        state.error?.let { Text(it, color = Red, modifier = Modifier.padding(top = 12.dp)) }
        Spacer(Modifier.height(24.dp))
        Small("panel.spdecode.xyz")
        Small("Ghost Nexora Studio")
      }
}

@Composable
private fun RecordCard(title: String, subtitle: String, onClick: () -> Unit) {
  Tile(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
      Avatar(Icons.Outlined.Description, Mint, 40)
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
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
      ProfileAvatar(row, 52)
      Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(displayName(row), color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
        userHandle(row)?.let { Small(it, color = Mint) }
        Small(row.optString("email"))
      }
      Icon(Icons.Outlined.ChevronRight, null, tint = Muted)
    }
    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
      if (row.has("email_verified")) StatusPill(if (row.optBoolean("email_verified")) "Verificado" else "No verificado", if (row.optBoolean("email_verified")) Mint else Muted)
      if (row.optString("providers").contains("google", ignoreCase = true)) StatusPill("Google", Blue)
      if (row.optBoolean("password_enabled")) StatusPill("Contraseña", Muted)
      if (row.optBoolean("ad_free")) StatusPill("Sin anuncios")
      if (row.optInt("credits") > 0) StatusPill("${row.optInt("credits")} créditos", Purple)
    }
    if (row.has("orders_count") && row.has("open_tickets")) Small(
        "${row.optInt("orders_count")} pedidos · ${row.optInt("open_tickets")} tickets abiertos")
  }
}

@Composable
private fun TicketCard(row: JSONObject, onClick: () -> Unit) {
  val status = row.optString("status")
  val last = row.array("messages").lastOrNull()
  Tile(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
      ProfileAvatar(row, 48)
      Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(displayName(row), color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
        userHandle(row)?.let { Small(it, color = Mint) }
        Text(row.optString("subject"), color = Ink, fontSize = 13.sp, maxLines = 1)
      }
      if (status.isNotBlank()) StatusPill(translated(status), if (status == "closed") Muted else Mint)
    }
    last?.optString("text")?.takeIf { it.isNotBlank() }?.let {
      Text(it, color = Muted, maxLines = 2, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis, fontSize = 13.sp)
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
      Small(row.optString("assigned_name").takeUnless { it == "null" }.orEmpty().ifBlank { "Sin asignar" })
      Small(row.optString("last_message_at").take(16).replace('T', ' '))
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
        "product_snapshot")

private fun translated(value: String): String =
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
      else -> value
    }

private fun productName(id: String) =
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
                  labels[key] ?: key,
                  color = Mint,
                  fontWeight = FontWeight.Medium,
                  modifier = Modifier.padding(top = 8.dp))
              if (depth < 4) Fields(item, depth = depth + 1)
            }
            is JSONArray -> {
              Text(
                  labels[key] ?: key,
                  color = Mint,
                  fontWeight = FontWeight.Medium,
                  modifier = Modifier.padding(top = 8.dp))
              for (i in 0 until item.length()) {
                val row = item.optJSONObject(i)
                if (row != null && depth < 4) {
                  Fields(row, depth = depth + 1)
                  HorizontalDivider(color = Border)
                } else Small(translated(item.optString(i)))
              }
            }
            else -> {
              Small(labels[key] ?: key)
              Text(translated(item.toString()), color = Ink, fontSize = 14.sp)
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
      title = { Text(form.title) },
      text = {
        Column(
            Modifier.heightIn(max = 480.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(10.dp)) {
              form.fields.forEach { field ->
                if (field.choices.isEmpty())
                    OutlinedTextField(
                        values[field.key].orEmpty(),
                        { values[field.key] = it.take(if (field.secret) 128 else 500) },
                        label = { Text(field.label) },
                        enabled = !state.busy,
                        singleLine = field.key != "body",
                        visualTransformation =
                            if (field.secret) PasswordVisualTransformation()
                            else VisualTransformation.None,
                        modifier = Modifier.fillMaxWidth())
                else {
                  Small(field.label)
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
                          Text(translated(choice), color = Ink)
                        }
                  }
                }
              }
              (error ?: state.error)?.let { Text(it, color = Red) }
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
              Text(if (state.busy) "Guardando…" else "Guardar")
            }
      },
      dismissButton = { TextButton(enabled = !state.busy, onClick = dismiss) { Text("Cancelar") } })
}

@Composable
private fun SecretDialog(value: JSONObject, dismiss: () -> Unit) {
  val clipboard = LocalClipboardManager.current
  val secret = value.optString("temporaryPassword").ifBlank { value.optString("code") }
  AlertDialog(
      onDismissRequest = dismiss,
      containerColor = Panel,
      title = { Text("Guarda estos datos") },
      text = {
        Column {
          Small("Se muestran una sola vez.")
          value.optJSONObject("staff")?.let {
            Text("${it.optString("username")} · ${it.optString("name")}", color = Ink)
          }
          Text(
              secret, color = Mint, fontSize = 18.sp, modifier = Modifier.padding(vertical = 16.dp))
        }
      },
      confirmButton = {
        TextButton(onClick = { clipboard.setText(AnnotatedString(secret)) }) { Text("Copiar") }
      },
      dismissButton = { TextButton(onClick = dismiss) { Text("Cerrar") } })
}

@Composable
private fun SettingsScreen(state: AdminState) {
  ScreenList {
    when (state.page) {
      Page.AppearanceSettings -> {
        item { SectionHeading("Apariencia", "Los cambios se guardan en este dispositivo") }
        items(Appearance.entries) { value ->
          Tile(Modifier.fillMaxWidth().clickable { state.theme(value) }) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
              Avatar(Icons.Outlined.Palette, if (state.appearance == value) Mint else Muted, 44)
              Column(Modifier.weight(1f)) {
                Text(when(value) {
                  Appearance.Amoled -> "AMOLED"
                  Appearance.Dark -> "Oscuro"
                  Appearance.Light -> "Claro"
                }, color = Ink, fontWeight = FontWeight.SemiBold)
                Small(when(value) {
                  Appearance.Amoled -> "Negro profundo"
                  Appearance.Dark -> "Contraste suave"
                  Appearance.Light -> "Superficies claras"
                })
              }
              RadioButton(state.appearance == value, { state.theme(value) })
            }
          }
        }
      }
      Page.AboutSettings -> item {
        Tile(Modifier.fillMaxWidth(), GreenPanel) {
          Avatar(Icons.Outlined.VerifiedUser, Mint, 58)
          Text("SP-DECODE Admin", color = Ink, fontSize = 23.sp, fontWeight = FontWeight.Bold)
          Small("Versión ${BuildConfig.VERSION_NAME}")
          Small("Ghost Nexora Studio")
          Small("panel.spdecode.xyz")
        }
      }
      else -> {
        item {
          Tile(Modifier.fillMaxWidth(), GreenPanel) {
            Text(state.principal.optString("name"), color = Ink, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Small(state.principal.optString("role"))
          }
        }
        item {
          Tile(Modifier.fillMaxWidth()) {
            ActionRow("Apariencia", Icons.Outlined.Palette, state.appearance.name) { state.navigate(Page.AppearanceSettings) }
            ActionRow("Acerca de", Icons.Outlined.Info, BuildConfig.VERSION_NAME) { state.navigate(Page.AboutSettings) }
            TextButton(enabled = !state.busy, onClick = { state.logout() }) { Text("Cerrar sesión", color = Red) }
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

@Composable
private fun ChatScreen(state: AdminState) {
  val thread = state.data.array("threads").firstOrNull { it.optString("id") == state.selectedId }
  if (thread == null) {
    if (!state.busy)
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
          Text("La conversación no está disponible.", color = Muted)
        }
    return
  }
  val messages = thread.array("messages")
  val list = rememberLazyListState()
  var draft by rememberSaveable(state.selectedId) { mutableStateOf("") }
  var assignment by remember { mutableStateOf(false) }
  var assignedId by remember { mutableStateOf(thread.optString("assigned_staff_id", "")) }
  var previousCount by remember(state.selectedId) { mutableIntStateOf(0) }
  LaunchedEffect(state.selectedId, messages.size) {
    val lastVisible = list.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: -1
    val wasNearEnd = previousCount == 0 || lastVisible >= previousCount - 2
    if (messages.isNotEmpty() && wasNearEnd) list.scrollToItem(messages.lastIndex)
    previousCount = messages.size
  }
  Column(Modifier.fillMaxSize()) {
    Text(
        thread.optString("name"),
        color = Ink,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(horizontal = 20.dp))
    Small(thread.optString("subject"), Modifier.padding(horizontal = 20.dp))
    Row(Modifier.padding(horizontal = 20.dp, vertical = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
      ProfileAvatar(thread, 32)
      userHandle(thread)?.let { Small(it, color = Mint) }
      StatusPill(translated(thread.optString("status")), if (thread.optString("status") == "closed") Muted else Mint)
    }
    Row {
      if (state.can("support.write"))
          TextButton(
              enabled = !state.busy,
              onClick = {
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
                Text(if (thread.optString("status") == "closed") "Reabrir" else "Cerrar ticket")
              }
      if (state.can("support.assign"))
          TextButton(onClick = { assignment = true }) { Text("Asignar agente") }
    }
    LazyColumn(
        Modifier.weight(1f).fillMaxWidth(),
        state = list,
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)) {
          items(messages, key = { it.getString("id") }) { m ->
            val outgoing = m.optString("sender") == "admin"
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = if (outgoing) Arrangement.End else Arrangement.Start) {
                  Tile(Modifier.widthIn(max = 340.dp), if (outgoing) GreenPanel else Panel) {
                    m.optJSONObject("agent")?.let { Small(it.optString("name"), color = Mint) }
                    Text(m.optString("text"), color = Ink)
                    Small(m.optString("at"))
                  }
                }
          }
        }
    if (state.can("support.write") && thread.optString("status") != "closed")
        Row(
            Modifier.fillMaxWidth().padding(10.dp),
            verticalAlignment = Alignment.Bottom,
            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
              OutlinedTextField(
                  draft,
                  { draft = it.take(2000) },
                  placeholder = { Text("Mensaje") },
                  modifier = Modifier.weight(1f),
                  shape = Rounded,
                  maxLines = 4)
              FilledIconButton(
                  enabled = !state.busy && draft.isNotBlank(),
                  onClick = {
                    val sent = draft
                    state.task {
                      state.mutate(
                          "support_send",
                          JSONObject()
                              .put("threadId", state.selectedId)
                              .put("action", "reply")
                              .put("message", sent))
                      if (draft == sent) draft = ""
                    }
                  }) {
                    Icon(Icons.AutoMirrored.Outlined.Send, "Enviar")
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
              Row(
                  Modifier.fillMaxWidth().clickable { assignedId = "" },
                  verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(assignedId.isEmpty(), { assignedId = "" })
                    Text("Sin asignación", color = Ink)
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
                  Small("Actualiza el servidor para consultar los agentes disponibles.")
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
                            .put("assignedId", assignedId.ifBlank { null }))
                    assignment = false
                  }
                }) {
                  Text("Guardar")
                }
          },
          dismissButton = { TextButton(onClick = { assignment = false }) { Text("Cancelar") } })
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
      "Enviar notificación",
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
