package com.ghostdeveloper.spdecode.admin

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.Logout
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

private val primaryPages = listOf(Page.Dashboard, Page.Users, Page.Support, Page.Settings)
private val detailPages =
    setOf(
        Page.UserDetail,
        Page.UserEdit,
        Page.UserPurchases,
        Page.UserSessions,
        Page.UserLicenses,
        Page.UserActivity,
        Page.RoleDetail,
        Page.Chat,
        Page.Broadcast,
        Page.Sessions,
        Page.OrderDetail,
        Page.LicenseDetail,
        Page.ApiDetail,
        Page.GiftHistory,
        Page.CreditHistory,
    )
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
                Page.Credits,
            ),
        "PLATAFORMA" to
            listOf(
                Page.Catalog,
                Page.Server,
                Page.Notices,
                Page.Logs,
                Page.Security,
                Page.Maintenance,
                Page.Settings,
            ),
    )

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun AdminApplication(state: PreviewState) {
    var page by rememberSaveable { mutableStateOf(Page.Dashboard.name) }
    var history by rememberSaveable { mutableStateOf(listOf<String>()) }
    var selectedUser by rememberSaveable { mutableStateOf("nexor") }
    var selectedRole by rememberSaveable { mutableStateOf("admin") }
    var selectedChat by rememberSaveable { mutableStateOf("00284") }
    var selectedOrder by rememberSaveable { mutableStateOf("SPD-2048") }
    var selectedLicense by rememberSaveable { mutableStateOf("lic1") }
    var selectedApi by rememberSaveable { mutableStateOf("api1") }
    var createUser by rememberSaveable { mutableStateOf(false) }
    var createRole by rememberSaveable { mutableStateOf(false) }
    var createLicense by rememberSaveable { mutableStateOf(false) }
    var createApi by rememberSaveable { mutableStateOf(false) }
    var signOut by rememberSaveable { mutableStateOf(false) }
    var chatMenu by rememberSaveable { mutableStateOf(false) }
    var broadcast by rememberSaveable { mutableStateOf<String?>(null) }
    val current = Page.entries.firstOrNull { it.name == page } ?: Page.Dashboard
    val userId = selectedUser.takeIf { id -> state.users.any { it.id == id } } ?: "nexor"
    val roleId = selectedRole.takeIf { id -> state.roles.any { it.id == id } } ?: "admin"
    val licenseId = selectedLicense.takeIf { id -> state.licenses.any { it.id == id } } ?: "lic1"
    val apiId = selectedApi.takeIf { id -> state.apiClients.any { it.id == id } } ?: "api1"
    val drawer = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val holder = rememberSaveableStateHolder()
    val context = LocalContext.current
    fun feedback(text: String) {
        scope.launch { snackbar.showSnackbar(text) }
    }
    fun go(target: Page) {
        if (target != current) {
            history = history + current.name
            page = target.name
        }
    }
    fun root(target: Page) {
        history = emptyList()
        page = target.name
    }
    fun back() {
        if (history.isNotEmpty()) {
            page = history.last()
            history = history.dropLast(1)
        } else root(Page.Dashboard)
    }
    fun openOrder(id: String) {
        selectedOrder = id
        go(Page.OrderDetail)
    }
    fun openLicense(id: String) {
        selectedLicense = id
        go(Page.LicenseDetail)
    }
    var exportContent by rememberSaveable { mutableStateOf("") }
    fun writeExport(uri: android.net.Uri?) {
        if (uri != null) {
            runCatching {
                    val output = context.contentResolver.openOutputStream(uri) ?: error("No output")
                    output.use { it.write(exportContent.toByteArray(Charsets.UTF_8)) }
                }
                .onSuccess { feedback("Archivo de prueba exportado") }
                .onFailure { feedback("No se pudo guardar el archivo") }
            exportContent = ""
        }
    }
    val exportCsv =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) {
            writeExport(it)
        }
    val exportJson =
        rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument("application/json")
        ) {
            writeExport(it)
        }
    fun export(name: String, content: String) {
        exportContent = content
        if (name.endsWith(".json")) exportJson.launch(name) else exportCsv.launch(name)
    }
    val canBack = current in detailPages || history.isNotEmpty()
    BackHandler(state.entered && (current != Page.Dashboard || drawer.isOpen)) {
        if (drawer.isOpen) scope.launch { drawer.close() } else back()
    }
    if (!state.entered) {
        LoginScreen { state.entered = true }
        return
    }
    ModalNavigationDrawer(
        drawerState = drawer,
        gesturesEnabled = current !in detailPages,
        drawerContent = {
            ModalDrawerSheet(
                drawerContainerColor = MaterialTheme.colorScheme.background,
                modifier = Modifier.widthIn(max = 320.dp),
            ) {
                LazyColumn(
                    modifier = Modifier.testTag("drawer-list"),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    item {
                        Row(
                            Modifier.padding(vertical = 16.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            Avatar(Icons.Outlined.VerifiedUser, Mint, 52)
                            Column {
                                Text("Administrador", color = Ink, fontWeight = FontWeight.SemiBold)
                                Small("SP-DECODE", color = Mint)
                            }
                        }
                        HorizontalDivider(color = Border)
                    }
                    menuGroups.forEach { (label, pages) ->
                        item {
                            Small(
                                label,
                                Modifier.padding(start = 12.dp, top = 18.dp, bottom = 6.dp),
                                Mint,
                            )
                        }
                        items(pages, key = { it.name }) { target ->
                            NavigationDrawerItem(
                                modifier = Modifier.testTag("menu-${target.name}"),
                                label = {
                                    Text(
                                        if (target == Page.Dashboard) "Dashboard" else target.title,
                                        fontSize = 14.sp,
                                    )
                                },
                                selected = current == target,
                                icon = { Icon(target.icon, null, Modifier.size(21.dp)) },
                                badge = {
                                    if (target == Page.Support)
                                        CountBadge(state.tickets.sumOf { it.unread })
                                },
                                onClick = {
                                    root(target)
                                    scope.launch { drawer.close() }
                                },
                                shape = Rounded,
                                colors =
                                    NavigationDrawerItemDefaults.colors(
                                        selectedContainerColor = GreenPanel,
                                        selectedIconColor = Mint,
                                        selectedTextColor = Mint,
                                        unselectedContainerColor =
                                            MaterialTheme.colorScheme.background,
                                        unselectedIconColor = Muted,
                                        unselectedTextColor = Ink,
                                    ),
                            )
                        }
                    }
                    item {
                        HorizontalDivider(Modifier.padding(vertical = 12.dp), color = Border)
                        TextButton(onClick = { signOut = true }) {
                            Icon(Icons.AutoMirrored.Outlined.Logout, null, tint = Red)
                            Spacer(Modifier.width(8.dp))
                            Text("Salir de la vista previa", color = Red)
                        }
                        Small(
                            "SP-DECODE Admin · ${BuildConfig.VERSION_NAME}",
                            Modifier.padding(12.dp),
                        )
                    }
                }
            }
        },
    ) {
        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            snackbarHost = { SnackbarHost(snackbar) },
            topBar = {
                TopAppBar(
                    title = {
                        if (current == Page.Chat) {
                            val t = state.ticket(selectedChat)
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp),
                            ) {
                                UserAvatar(state.user(t.userId), 38)
                                Column {
                                    Text(
                                        state.user(t.userId).name,
                                        fontSize = 17.sp,
                                        fontWeight = FontWeight.SemiBold,
                                    )
                                    Text(
                                        if (t.closed) "Ticket cerrado"
                                        else if (
                                            WindowInsets.ime.getBottom(LocalDensity.current) > 0
                                        )
                                            "Vista previa · local"
                                        else "Chat privado",
                                        color = if (t.closed) Muted else Mint,
                                        fontSize = 11.sp,
                                        lineHeight = 15.sp,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                            }
                        } else
                            Text(
                                if (current == Page.Dashboard) "SP-DECODE Admin" else current.title,
                                fontSize = 19.sp,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                    },
                    navigationIcon = {
                        IconButton(
                            onClick = { if (canBack) back() else scope.launch { drawer.open() } }
                        ) {
                            Icon(
                                if (canBack) Icons.AutoMirrored.Outlined.ArrowBack
                                else Icons.Outlined.Menu,
                                if (canBack) "Volver" else "Abrir menú",
                            )
                        }
                    },
                    actions = {
                        when (current) {
                            Page.Users ->
                                IconButton(onClick = { createUser = true }) {
                                    Icon(
                                        Icons.Outlined.PersonAdd,
                                        "Crear usuario de prueba",
                                        tint = Mint,
                                    )
                                }
                            Page.Roles ->
                                IconButton(onClick = { createRole = true }) {
                                    Icon(Icons.Outlined.Add, "Crear cargo", tint = Mint)
                                }
                            Page.Licenses ->
                                IconButton(onClick = { createLicense = true }) {
                                    Icon(Icons.Outlined.Add, "Generar licencia", tint = Mint)
                                }
                            Page.Api ->
                                IconButton(onClick = { createApi = true }) {
                                    Icon(Icons.Outlined.Add, "Crear acceso API", tint = Mint)
                                }
                            Page.Gifts ->
                                IconButton(onClick = { go(Page.GiftHistory) }) {
                                    Icon(
                                        Icons.Outlined.History,
                                        "Historial de códigos",
                                        tint = Mint,
                                    )
                                }
                            Page.UserDetail ->
                                IconButton(onClick = { go(Page.UserEdit) }) {
                                    Icon(Icons.Outlined.Edit, "Editar usuario", tint = Mint)
                                }
                            Page.Server ->
                                IconButton(
                                    onClick = {
                                        state.refreshedAt = state.now()
                                        feedback("Instantánea de prueba actualizada")
                                    }
                                ) {
                                    Icon(
                                        Icons.Outlined.Refresh,
                                        "Actualizar estado de prueba",
                                        tint = Mint,
                                    )
                                }
                            Page.Logs ->
                                IconButton(
                                    onClick = {
                                        export("SP-DECODE-Admin-Registros.csv", state.exportLogs())
                                    }
                                ) {
                                    Icon(Icons.Outlined.Download, "Exportar registros", tint = Mint)
                                }
                            Page.Notices ->
                                IconButton(
                                    onClick = {
                                        state.notices.indices.forEach { i ->
                                            state.notices[i] = state.notices[i].copy(read = true)
                                        }
                                    }
                                ) {
                                    Icon(
                                        Icons.Outlined.DoneAll,
                                        "Marcar todas como leídas",
                                        tint = Mint,
                                    )
                                }
                            Page.Chat ->
                                Box {
                                    IconButton(onClick = { chatMenu = true }) {
                                        Icon(Icons.Outlined.MoreVert, "Opciones del ticket")
                                    }
                                    DropdownMenu(
                                        chatMenu,
                                        { chatMenu = false },
                                        containerColor = Panel,
                                    ) {
                                        DropdownMenuItem(
                                            text = {
                                                Text(
                                                    if (state.ticket(selectedChat).closed)
                                                        "Reabrir ticket"
                                                    else "Cerrar ticket"
                                                )
                                            },
                                            onClick = {
                                                val t = state.ticket(selectedChat)
                                                state.updateTicket(t.copy(closed = !t.closed))
                                                state.log(
                                                    "Ticket de prueba #${t.id}: ${if (t.closed) "reabierto" else "cerrado"}"
                                                )
                                                chatMenu = false
                                                feedback("Estado de prueba actualizado")
                                            },
                                        )
                                    }
                                }
                            else ->
                                IconButton(onClick = { go(Page.Notices) }) {
                                    BadgedBox(
                                        badge = {
                                            if (
                                                state.notificationsEnabled &&
                                                    state.notices.any { !it.read }
                                            )
                                                Badge(containerColor = Mint)
                                        }
                                    ) {
                                        Icon(Icons.Outlined.Notifications, "Notificaciones")
                                    }
                                }
                        }
                    },
                    colors =
                        TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.background
                        ),
                )
            },
            bottomBar = {
                if (current in primaryPages)
                    Column {
                        HorizontalDivider(color = Border)
                        NavigationBar(
                            containerColor = MaterialTheme.colorScheme.background,
                            tonalElevation = 0.dp,
                        ) {
                            primaryPages.forEach { target ->
                                NavigationBarItem(
                                    modifier = Modifier.testTag("nav-${target.name}"),
                                    selected = current == target,
                                    onClick = { root(target) },
                                    icon = {
                                        BadgedBox(
                                            badge = {
                                                if (
                                                    target == Page.Support &&
                                                        state.tickets.any { it.unread > 0 }
                                                )
                                                    Badge(
                                                        containerColor = Mint,
                                                        contentColor =
                                                            MaterialTheme.colorScheme.onPrimary,
                                                    ) {
                                                        Text(
                                                            state.tickets
                                                                .sumOf { it.unread }
                                                                .toString()
                                                        )
                                                    }
                                            }
                                        ) {
                                            Icon(target.icon, null)
                                        }
                                    },
                                    label = {
                                        Text(
                                            if (target == Page.Dashboard) "Inicio"
                                            else target.title,
                                            fontSize = 11.sp,
                                        )
                                    },
                                    colors =
                                        NavigationBarItemDefaults.colors(
                                            selectedIconColor = Mint,
                                            selectedTextColor = Mint,
                                            indicatorColor = GreenPanel,
                                            unselectedIconColor = Muted,
                                            unselectedTextColor = Muted,
                                        ),
                                )
                            }
                        }
                    }
            },
        ) { padding ->
            Column(
                Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding).imePadding()
            ) {
                if (current != Page.Chat || WindowInsets.ime.getBottom(LocalDensity.current) == 0)
                    PreviewBanner()
                holder.SaveableStateProvider(current.name) {
                    when (current) {
                        Page.Dashboard -> DashboardScreen(state, ::go)
                        Page.Users ->
                            UsersScreen(state) {
                                selectedUser = it
                                go(Page.UserDetail)
                            }
                        Page.UserDetail -> UserDetailScreen(state, userId, ::go, ::feedback)
                        Page.UserEdit -> UserEditorScreen(state, userId, ::back, ::feedback)
                        Page.UserPurchases,
                        Page.UserSessions,
                        Page.UserLicenses,
                        Page.UserActivity ->
                            UserRecords(state, current, userId, ::openOrder, ::openLicense)
                        Page.Roles ->
                            RolesScreen(
                                state,
                                {
                                    selectedRole = it
                                    go(Page.RoleDetail)
                                },
                                { createRole = true },
                            )
                        Page.RoleDetail -> RoleDetailScreen(state, roleId, ::feedback)
                        Page.Support ->
                            SupportScreen(state) {
                                selectedChat = it
                                state.markRead(it)
                                go(Page.Chat)
                            }
                        Page.Chat -> ChatScreen(state, selectedChat, ::feedback)
                        Page.Notices ->
                            NoticesScreen(
                                state,
                                { n ->
                                    when (n.kind) {
                                        "support" -> {
                                            selectedChat = n.target ?: "00284"
                                            state.markRead(selectedChat)
                                            go(Page.Chat)
                                        }
                                        "purchase" -> openOrder(n.target ?: "SPD-2048")
                                        "user" -> {
                                            selectedUser = n.target ?: "nexor"
                                            go(Page.UserDetail)
                                        }
                                        "service" -> go(Page.Server)
                                        "catalog" -> go(Page.Catalog)
                                        "broadcast" -> broadcast = n.target
                                    }
                                },
                                { go(Page.Broadcast) },
                            )
                        Page.Finance -> FinanceScreen(state, ::go)
                        Page.Purchases -> PurchasesScreen(state, ::openOrder)
                        Page.OrderDetail -> OrderDetailScreen(state, selectedOrder, ::feedback)
                        Page.Products -> ProductsScreen(state, ::feedback)
                        Page.Licenses ->
                            LicensesScreen(state, { createLicense = true }, ::openLicense)
                        Page.LicenseDetail -> LicenseDetailScreen(state, licenseId, ::feedback)
                        Page.Gifts -> GiftsScreen(state, { go(Page.GiftHistory) }, ::feedback)
                        Page.GiftHistory -> GiftHistoryScreen(state, ::feedback)
                        Page.Api ->
                            ApiScreen(state, { createApi = true }) {
                                selectedApi = it
                                go(Page.ApiDetail)
                            }
                        Page.ApiDetail -> ApiDetailScreen(state, apiId, ::feedback)
                        Page.Credits -> CreditsScreen(state, { go(Page.CreditHistory) }, ::feedback)
                        Page.CreditHistory -> CreditHistoryScreen(state)
                        Page.Server -> ServerScreen(state, ::feedback)
                        Page.Catalog -> CatalogScreen(state, ::feedback)
                        Page.Broadcast -> BroadcastScreen(state, ::feedback)
                        Page.Logs -> LogsScreen(state, ::export)
                        Page.Security -> SecurityScreen(::go)
                        Page.Maintenance -> MaintenanceScreen(state, ::feedback, ::export, ::go)
                        Page.Sessions -> SessionsScreen(state, ::feedback)
                        Page.Settings -> SettingsScreen(state, ::go)
                    }
                }
            }
        }
    }
    if (createUser)
        UserForm(state, dismiss = { createUser = false }) {
            createUser = false
            selectedUser = it
            go(Page.UserDetail)
        }
    if (createRole)
        RoleForm(state, dismiss = { createRole = false }) {
            createRole = false
            selectedRole = it
            go(Page.RoleDetail)
        }
    if (createLicense)
        LicenseForm(state, { createLicense = false }) {
            createLicense = false
            openLicense(it)
        }
    if (createApi)
        ApiForm(state, dismiss = { createApi = false }) {
            createApi = false
            selectedApi = it
            go(Page.ApiDetail)
        }
    broadcast?.let { SavedBroadcast(state, it) { broadcast = null } }
    if (signOut)
        ConfirmationDialog(
            "Salir de la vista previa",
            "Volverás al acceso. Los datos de prueba se conservarán mientras el proceso permanezca abierto.",
            "Salir",
            onDismiss = { signOut = false },
        ) {
            state.entered = false
            signOut = false
            root(Page.Dashboard)
            scope.launch { drawer.close() }
        }
}

@Composable
private fun LoginScreen(enter: () -> Unit) {
    var visible by rememberSaveable { mutableStateOf(false) }
    Box(
        Modifier.fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .safeDrawingPadding(),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            Modifier.widthIn(max = 440.dp)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 28.dp, vertical = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Avatar(Icons.Outlined.VerifiedUser, Mint, 88)
            Spacer(Modifier.height(22.dp))
            Text("SP-DECODE", color = Ink, fontSize = 30.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            Text("ADMINISTRATION", color = Mint, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(12.dp))
            Text("Acceso restringido", color = Muted)
            Spacer(Modifier.height(36.dp))
            Text("Usuario", Modifier.fillMaxWidth(), color = Muted, fontSize = 14.sp)
            Spacer(Modifier.height(8.dp))
            TextField(
                "Administrador",
                {},
                readOnly = true,
                leadingIcon = { Icon(Icons.Outlined.PersonOutline, null) },
                singleLine = true,
                shape = Rounded,
                colors = fieldColors(),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(18.dp))
            Text("Contraseña", Modifier.fillMaxWidth(), color = Muted, fontSize = 14.sp)
            Spacer(Modifier.height(8.dp))
            TextField(
                "demostracion",
                {},
                readOnly = true,
                leadingIcon = { Icon(Icons.Outlined.Lock, null) },
                trailingIcon = {
                    IconButton(onClick = { visible = !visible }) {
                        Icon(
                            if (visible) Icons.Outlined.Visibility
                            else Icons.Outlined.VisibilityOff,
                            if (visible) "Ocultar contraseña de ejemplo"
                            else "Mostrar contraseña de ejemplo",
                        )
                    }
                },
                visualTransformation =
                    if (visible) VisualTransformation.None else PasswordVisualTransformation(),
                singleLine = true,
                shape = Rounded,
                colors = fieldColors(),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(16.dp))
            PrimaryAction("Abrir vista previa", onClick = enter)
            Spacer(Modifier.height(28.dp))
            Icon(Icons.Outlined.Fingerprint, null, Modifier.size(44.dp), Mint)
            Spacer(Modifier.height(8.dp))
            Small("Acceso biométrico pendiente")
            Spacer(Modifier.height(24.dp))
            Text("Ghost Nexora Studio", color = Muted, fontSize = 14.sp)
            Spacer(Modifier.height(24.dp))
            PreviewBanner()
        }
    }
}

@Composable
private fun DashboardScreen(state: PreviewState, go: (Page) -> Unit) {
    ScreenList {
        item {
            Small("PANEL ADMINISTRATIVO")
            Spacer(Modifier.height(6.dp))
            Text("Resumen general", color = Ink, fontSize = 28.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            Small(
                if (state.maintenance) "● Mantenimiento de prueba"
                else "● Servidor operativo · ejemplo",
                color = if (state.maintenance) Amber else Mint,
            )
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Metric(
                    "Usuarios",
                    state.users.size.toString(),
                    Icons.Outlined.People,
                    modifier = Modifier.weight(1f).clickable { go(Page.Users) },
                )
                Metric(
                    "Ingresos netos",
                    money(state.revenue(30)),
                    Icons.Outlined.AccountBalanceWallet,
                    modifier = Modifier.weight(1f).clickable { go(Page.Finance) },
                )
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Metric(
                    "Tickets abiertos",
                    state.tickets.count { !it.closed }.toString(),
                    Icons.Outlined.Forum,
                    modifier = Modifier.weight(1f).clickable { go(Page.Support) },
                )
                Metric(
                    "Licencias activas",
                    state.licenses.count { !it.revoked }.toString(),
                    Icons.Outlined.VpnKey,
                    modifier = Modifier.weight(1f).clickable { go(Page.Licenses) },
                )
            }
        }
        item {
            Tile(Modifier.fillMaxWidth()) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Actividad del servicio", color = Ink, fontWeight = FontWeight.Medium)
                    Small("Ejemplo · 7 días", color = Mint)
                }
                Trend()
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Small("Lun")
                    Small("Mié")
                    Small("Vie")
                    Small("Dom")
                }
            }
        }
        item {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Actividad reciente", color = Ink, fontWeight = FontWeight.SemiBold)
                TextButton(onClick = { go(Page.Notices) }) { Text("Ver todo") }
            }
        }
        items(state.notices.take(2), key = { it.id }) { notice ->
            ActionRow(
                notice.title,
                if (notice.kind == "purchase") Icons.Outlined.ShoppingBag
                else Icons.Outlined.Notifications,
                notice.time,
            ) {
                go(Page.Notices)
            }
        }
    }
}
