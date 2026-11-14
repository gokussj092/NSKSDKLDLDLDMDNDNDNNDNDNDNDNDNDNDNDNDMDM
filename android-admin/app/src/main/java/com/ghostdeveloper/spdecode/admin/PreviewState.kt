package com.ghostdeveloper.spdecode.admin

import androidx.compose.runtime.*
import androidx.lifecycle.ViewModel
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import java.util.UUID

/** In-memory review data. No method in this model authenticates or changes a server. */
internal class PreviewState : ViewModel() {
    val users =
        mutableStateListOf(
            PreviewUser("alex", "Alex_L", "alex@example.com", credits = 10),
            PreviewUser("nexor", "NexorX", "nexor@example.com", "Premium", 25),
            PreviewUser("marco", "Marco_R", "marco@example.com"),
            PreviewUser("dark", "DarkTech", "dark@example.com", "Suspendido"),
        )
    val roles =
        mutableStateListOf(
            PreviewRole("owner", "Propietario", "Acceso global", Permission.entries.toSet(), true),
            PreviewRole(
                "admin",
                "Administrador",
                "Gestión administrativa",
                Permission.entries.filter { it != Permission.Security }.toSet(),
            ),
            PreviewRole(
                "support",
                "Soporte técnico",
                "Tickets y asistencia",
                setOf(Permission.UsersRead, Permission.SupportRead, Permission.SupportReply),
            ),
            PreviewRole(
                "finance",
                "Finanzas",
                "Compras y pagos",
                setOf(Permission.UsersRead, Permission.CommerceRead),
            ),
        )
    val staff =
        mutableStateListOf(
            PreviewStaff("owner", "Ghost Developer", "owner"),
            PreviewStaff("admin1", "Administrador", "admin"),
            PreviewStaff("support1", "Agente de soporte", "support"),
            PreviewStaff("finance1", "Finanzas", "finance"),
        )
    val tickets =
        mutableStateListOf(
            PreviewTicket(
                "00284",
                "nexor",
                "09:38",
                2,
                messages =
                    listOf(
                        PreviewMessage(
                            "1",
                            "Hola, tengo un problema con mi licencia Offline.",
                            "09:34",
                        ),
                        PreviewMessage(
                            "2",
                            "Hola. ¿Podrías enviarme el número de tu pedido?",
                            "09:35",
                            true,
                            "Administrador",
                        ),
                        PreviewMessage("3", "Sí, es el pedido SPD-2048.", "09:38"),
                    ),
            ),
            PreviewTicket(
                "00283",
                "alex",
                "09:21",
                0,
                true,
                listOf(PreviewMessage("1", "Muchas gracias por la ayuda.", "09:21")),
            ),
            PreviewTicket(
                "00282",
                "marco",
                "08:56",
                1,
                messages = listOf(PreviewMessage("1", "No puedo iniciar sesión.", "08:56")),
                agentId = "support1",
            ),
            PreviewTicket(
                "00281",
                "dark",
                "08:40",
                3,
                messages = listOf(PreviewMessage("1", "¿Cuándo estará disponible?", "08:40")),
            ),
        )
    val products =
        mutableStateListOf(
            PreviewProduct(
                "offline",
                "SP-DECODE Offline",
                "Licencia · 3 dispositivos",
                499,
                ProductKind.Offline,
            ),
            PreviewProduct(
                "api",
                "API comercial",
                "Acceso por IP autorizada",
                1999,
                ProductKind.Api,
            ),
            PreviewProduct(
                "credits",
                "Análisis APK",
                "Paquete de créditos",
                399,
                ProductKind.Credits,
            ),
        )
    val orders =
        mutableStateListOf(
            PreviewOrder(
                "SPD-2048",
                "nexor",
                "offline",
                "Licencia Offline",
                499,
                "PayPal",
                OrderStatus.Completed,
                0,
            ),
            PreviewOrder(
                "SPD-2047",
                "alex",
                "api",
                "API comercial",
                1999,
                "Stripe",
                OrderStatus.Completed,
                1,
            ),
            PreviewOrder(
                "SPD-2046",
                "marco",
                "credits",
                "Créditos APK",
                399,
                "Mercado Pago",
                OrderStatus.Pending,
                2,
            ),
            PreviewOrder(
                "SPD-2045",
                "dark",
                "offline",
                "Licencia Offline",
                499,
                "PayPal",
                OrderStatus.Refunded,
                3,
            ),
            PreviewOrder(
                "SPD-1999",
                "alex",
                "offline",
                "Licencia Offline",
                499,
                "PayPal",
                OrderStatus.Completed,
                42,
            ),
        )
    val licenses =
        mutableStateListOf(
            PreviewLicense("lic1", "nexor", "DEMO-SPD-0000-A81C", 2),
            PreviewLicense("lic2", "alex", "DEMO-SPD-0000-B92D", 1),
            PreviewLicense("lic3", "marco", "DEMO-SPD-0000-F34B", 3),
            PreviewLicense("lic4", "dark", "DEMO-SPD-0000-C18F", 1, revoked = true),
        )
    val gifts = mutableStateListOf<PreviewGift>()
    val apiClients =
        mutableStateListOf(
            PreviewApiClient("api1", "Cliente #001", "192.0.2.10", "DEMO-api-client-001", 8240),
            PreviewApiClient("api2", "Cliente #002", "198.51.100.24", "DEMO-api-client-002", 4602),
            PreviewApiClient(
                "api3",
                "Cliente #003",
                "203.0.113.12",
                "DEMO-api-client-003",
                revoked = true,
            ),
        )
    val creditHistory = mutableStateListOf<PreviewCredit>()
    val catalog =
        mutableStateListOf(
            PreviewCatalogApp("hc", "HTTP Custom", "Método activo", true),
            PreviewCatalogApp("hi", "HTTP Injector", "Método activo", true),
            PreviewCatalogApp("ha", "HA Tunnel Plus", "Catálogo activo", true),
            PreviewCatalogApp("litron", "Litron VPN", "Catálogo desactivado", false),
        )
    val notices =
        mutableStateListOf(
            PreviewNotice(
                "purchase",
                "Nueva compra",
                "Licencia Offline · $4.99",
                "Hace 2 minutos",
                "purchase",
                target = "SPD-2048",
            ),
            PreviewNotice(
                "support",
                "Mensaje de soporte",
                "NexorX envió un mensaje.",
                "Hace 4 minutos",
                "support",
                target = "00284",
            ),
            PreviewNotice(
                "user",
                "Nuevo usuario",
                "Una cuenta se ha registrado.",
                "Hace 15 minutos",
                "user",
                target = "nexor",
            ),
            PreviewNotice(
                "service",
                "Alerta de servicio",
                "Uso elevado de memoria.",
                "Hace 38 minutos",
                "service",
            ),
            PreviewNotice(
                "catalog",
                "Catálogo actualizado",
                "Nueva versión publicada.",
                "Hace 1 hora",
                "catalog",
            ),
        )
    val logs =
        mutableStateListOf(
            PreviewLog("l1", "INFO", "Solicitud procesada", "09:41:28"),
            PreviewLog("l2", "INFO", "Catálogo sincronizado", "09:40:12"),
            PreviewLog("l3", "WARN", "Tiempo de espera excedido", "09:38:25"),
            PreviewLog("l4", "ERROR", "Servicio no disponible", "09:35:46"),
            PreviewLog("l5", "INFO", "Servicio recuperado", "09:32:18"),
        )
    val broadcasts = mutableStateListOf<PreviewBroadcast>()
    var broadcastDraft by mutableStateOf(defaultCatalogNotice())
    var broadcastAudience by mutableStateOf("Todos los usuarios")
    var broadcastType by mutableStateOf("Actualización de catálogo")
    var broadcastInApp by mutableStateOf(true)
    var catalogVersion by mutableLongStateOf(215686799L)
    var entered by mutableStateOf(false)
    var appearance by mutableStateOf(Appearance.Amoled)
    var maintenance by mutableStateOf(false)
    var refreshedAt by mutableStateOf(now())
    var cacheMb by mutableIntStateOf(148)
    var otherSessions by mutableIntStateOf(2)
    var notificationsEnabled by mutableStateOf(true)
    var preferencesLoaded = false
    var persistPreferences: (() -> Unit)? = null

    fun id() = UUID.randomUUID().toString()

    fun now(): String = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"))

    fun user(id: String) = users.first { it.id == id }

    fun role(id: String) = roles.first { it.id == id }

    fun ticket(id: String) = tickets.first { it.id == id }

    fun product(id: String) = products.first { it.id == id }

    fun log(text: String, level: String = "INFO") {
        logs.add(0, PreviewLog(id(), level, text, now()))
    }

    fun userError(name: String, email: String, except: String? = null): String? =
        when {
            !name.trim().matches(Regex("[\\p{L}\\p{N}_.-]{3,32}")) ->
                "Usa entre 3 y 32 letras, números, puntos o guiones."
            !email.trim().matches(Regex("[^\\s@]+@[^\\s@]+\\.[^\\s@]+")) ->
                "Escribe un correo válido."
            users.any { it.id != except && it.name.equals(name.trim(), true) } ->
                "El nombre de usuario ya está en uso."
            users.any { it.id != except && it.email.equals(email.trim(), true) } ->
                "El correo ya está registrado."
            else -> null
        }

    fun saveUser(name: String, email: String, userId: String? = null): String {
        require(userError(name, email, userId) == null)
        val target = userId ?: id()
        if (userId == null) users.add(PreviewUser(target, name.trim(), email.trim()))
        else
            users[users.indexOfFirst { it.id == target }] =
                user(target).copy(name = name.trim(), email = email.trim())
        log("Perfil de prueba actualizado: ${name.trim()}")
        return target
    }

    fun toggleSuspension(userId: String) {
        val u = user(userId)
        users[users.indexOf(u)] =
            if (u.status == "Suspendido") u.copy(status = u.activeStatus)
            else u.copy(status = "Suspendido", activeStatus = u.status)
        log("Estado de prueba actualizado: ${u.name}")
    }

    fun saveRole(name: String, description: String, roleId: String? = null): String {
        require(name.trim().length in 3..40 && description.trim().length in 1..120)
        require(roles.none { it.id != roleId && it.name.equals(name.trim(), true) })
        val target = roleId ?: id()
        val old = roleId?.let { role(it) }
        require(old?.locked != true)
        val value =
            PreviewRole(target, name.trim(), description.trim(), old?.permissions ?: emptySet())
        if (old == null) roles.add(value) else roles[roles.indexOf(old)] = value
        log("Cargo de prueba guardado: ${value.name}")
        return target
    }

    fun savePermissions(roleId: String, permissions: Set<Permission>) {
        val role = role(roleId)
        require(!role.locked)
        require(Permission.SupportReply !in permissions || Permission.SupportRead in permissions)
        require(Permission.CommerceManage !in permissions || Permission.CommerceRead in permissions)
        roles[roles.indexOf(role)] = role.copy(permissions = permissions.toSet())
        log("Permisos de prueba: ${role.name}")
    }

    fun saveStaff(name: String, roleId: String, staffId: String? = null) {
        require(!role(roleId).locked && name.trim().length in 3..50)
        require(staff.none { it.id != staffId && it.name.equals(name.trim(), true) })
        val value = PreviewStaff(staffId ?: id(), name.trim(), roleId)
        if (staffId == null) staff.add(value)
        else staff[staff.indexOfFirst { it.id == staffId }] = value
        log("Personal de prueba actualizado: ${value.name}")
    }

    fun updateTicket(value: PreviewTicket) {
        tickets[tickets.indexOfFirst { it.id == value.id }] = value
    }

    fun markRead(ticketId: String) = updateTicket(ticket(ticketId).copy(unread = 0))

    fun send(ticketId: String, text: String) {
        val t = ticket(ticketId)
        if (t.closed || text.isBlank()) return
        require(text.trim().length <= 2000)
        updateTicket(
            t.copy(
                messages =
                    t.messages +
                        PreviewMessage(
                            id(),
                            text.trim(),
                            now().take(5),
                            true,
                            "Administrador",
                            true,
                        ),
                time = now().take(5),
            )
        )
    }

    fun markNoticeRead(id: String) {
        val i = notices.indexOfFirst { it.id == id }
        if (i >= 0) notices[i] = notices[i].copy(read = true)
    }

    fun saveProduct(value: PreviewProduct) {
        require(
            value.name.trim().length in 3..80 &&
                value.description.trim().length in 1..160 &&
                value.cents in 1..9_999_999
        )
        products[products.indexOfFirst { it.id == value.id }] =
            value.copy(name = value.name.trim(), description = value.description.trim())
        log("Producto de prueba editado: ${value.name}")
    }

    fun changeOrder(id: String, status: OrderStatus) {
        val i = orders.indexOfFirst { it.id == id }
        val old = orders[i]
        require(old.status != OrderStatus.Refunded && status != OrderStatus.Pending)
        orders[i] = old.copy(status = status)
        log("Operación de prueba #$id: ${status.label}")
    }

    fun revenue(days: Int): Long =
        orders
            .filter { it.ageDays < days }
            .sumOf {
                when (it.status) {
                    OrderStatus.Completed -> it.cents
                    OrderStatus.Refunded -> 0L
                    else -> 0L
                }
            }

    fun generateLicense(userId: String, devices: Int, expiryDays: Int): PreviewLicense {
        user(userId)
        require(devices in 1..10 && expiryDays in 0..3650)
        val value =
            PreviewLicense(
                id(),
                userId,
                "DEMO-SPD-${id().take(18).uppercase()}",
                devices = devices,
                expiryDays = expiryDays,
            )
        licenses.add(0, value)
        log("Licencia de prueba generada para ${user(userId).name}")
        return value
    }

    fun toggleLicense(id: String) {
        val i = licenses.indexOfFirst { it.id == id }
        licenses[i] = licenses[i].copy(revoked = !licenses[i].revoked)
        log("Estado de licencia de prueba actualizado")
    }

    fun generateGift(productId: String, uses: Int, expiryDays: Int, devices: Int): PreviewGift {
        require(
            product(productId).available &&
                uses in 1..1000 &&
                devices in 1..10 &&
                expiryDays in 0..3650
        )
        val gift =
            PreviewGift(
                id(),
                "DEMO-GIFT-${id().take(13).uppercase()}",
                productId,
                uses,
                expiryDays,
                devices,
            )
        gifts.add(0, gift)
        log("Gift code de prueba generado")
        return gift
    }

    fun toggleGift(id: String) {
        val i = gifts.indexOfFirst { it.id == id }
        gifts[i] = gifts[i].copy(revoked = !gifts[i].revoked)
        log("Estado de gift code de prueba actualizado")
    }

    fun saveApi(name: String, ip: String, clientId: String? = null): String {
        val address = requireNotNull(canonicalIp(ip))
        require(name.trim().length in 3..50)
        val old = clientId?.let { id -> apiClients.first { it.id == id } }
        val value =
            old?.copy(name = name.trim(), ip = address)
                ?: PreviewApiClient(id(), name.trim(), address, "DEMO-api-${id()}")
        if (old == null) apiClients.add(0, value) else apiClients[apiClients.indexOf(old)] = value
        log("Cliente API de prueba guardado: ${value.name}")
        return value.id
    }

    fun toggleApi(id: String) {
        val i = apiClients.indexOfFirst { it.id == id }
        apiClients[i] = apiClients[i].copy(revoked = !apiClients[i].revoked)
        log("Estado de API de prueba actualizado")
    }

    fun rotateApi(id: String) {
        val i = apiClients.indexOfFirst { it.id == id }
        apiClients[i] = apiClients[i].copy(key = "DEMO-api-${id()}")
        log("Clave API de prueba renovada")
    }

    fun adjustCredits(userId: String, amount: Int, reason: String) {
        require(amount != 0 && amount in -10000..10000 && reason.trim().length in 3..160)
        val u = user(userId)
        val balance = u.credits + amount
        require(balance in 0..1_000_000)
        users[users.indexOf(u)] = u.copy(credits = balance)
        creditHistory.add(0, PreviewCredit(id(), userId, amount, reason.trim(), now()))
        log("Créditos de prueba: ${u.name}, $amount")
    }

    fun publishCatalog(draft: Map<String, Boolean>): Boolean {
        require(draft.keys == catalog.map { it.id }.toSet())
        if (catalog.all { draft[it.id] == it.enabled }) return false
        catalog.indices.forEach { i ->
            catalog[i] = catalog[i].copy(enabled = draft.getValue(catalog[i].id))
        }
        catalogVersion++
        log("Catálogo de prueba publicado: $catalogVersion")
        notices.add(
            0,
            PreviewNotice(
                id(),
                "Catálogo actualizado",
                "Versión de prueba $catalogVersion",
                "Ahora",
                "catalog",
            ),
        )
        return true
    }

    fun publishNotice(
        audience: String,
        type: String,
        messages: Map<String, LocalizedNotice>,
        inApp: Boolean,
    ): String {
        require(audience in listOf("Todos los usuarios", "Usuarios activos", "Usuarios Premium"))
        require(type in listOf("Actualización de catálogo", "Aviso general", "Mantenimiento"))
        require(
            messages.isNotEmpty() &&
                messages.keys.all { it in noticeLanguages.map { language -> language.code } }
        )
        require(
            messages.values.all {
                it.title.trim().length in 1..80 && it.message.trim().length in 1..1000
            }
        )
        val id = id()
        broadcasts.add(0, PreviewBroadcast(id, audience, type, messages.toMap(), inApp))
        val content = messages["es"] ?: messages.values.first()
        notices.add(
            0,
            PreviewNotice(
                id,
                content.title,
                content.message,
                "Ahora · simulación",
                "broadcast",
                target = id,
            ),
        )
        log("Aviso de prueba guardado en ${messages.size} idiomas")
        return id
    }

    fun exportLogs(): String =
        "nivel,mensaje,hora\r\n" +
            logs.joinToString("\r\n") {
                listOf(it.level, it.text, it.time).joinToString(",", transform = ::csvCell)
            }

    fun updateAppearance(value: Appearance) {
        appearance = value
        persistPreferences?.invoke()
    }

    fun setNotifications(value: Boolean) {
        notificationsEnabled = value
        persistPreferences?.invoke()
    }
}
