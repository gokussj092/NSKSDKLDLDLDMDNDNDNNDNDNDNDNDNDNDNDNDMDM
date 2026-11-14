package com.ghostdeveloper.spdecode.admin

import java.math.BigDecimal
import java.net.InetAddress
import java.util.Locale

internal fun money(cents: Long): String =
    "$" + BigDecimal.valueOf(cents, 2).setScale(2).toPlainString()

internal fun parsePrice(value: String): Long? =
    runCatching {
            val text = value.trim().replace(',', '.')
            require(text.matches(Regex("[0-9]{1,5}(\\.[0-9]{1,2})?")))
            BigDecimal(text).movePointRight(2).longValueExact().also { require(it in 1..9_999_999) }
        }
        .getOrNull()

internal fun canonicalIp(value: String): String? {
    val text = value.trim()
    if (text.length !in 3..45) return null
    if (':' in text) {
        if (!text.matches(Regex("[a-fA-F0-9:.]+"))) return null
        return runCatching { InetAddress.getByName(text).hostAddress?.lowercase(Locale.ROOT) }
            .getOrNull()
    }
    val parts = text.split('.')
    if (
        parts.size != 4 ||
            parts.any { !it.matches(Regex("0|[1-9][0-9]{0,2}")) || (it.toIntOrNull() ?: 999) > 255 }
    )
        return null
    return parts.joinToString(".")
}

internal fun csvCell(value: String): String {
    val safe =
        if (value.trimStart().firstOrNull() in listOf('=', '+', '-', '@', '\t', '\r')) "'$value"
        else value
    return "\"" + safe.replace("\"", "\"\"") + "\""
}

internal enum class Permission(val label: String) {
    UsersRead("Consultar usuarios"),
    UsersEdit("Editar cuentas"),
    SupportRead("Consultar conversaciones"),
    SupportReply("Responder y asignar tickets"),
    CommerceRead("Consultar compras y licencias"),
    CommerceManage("Gestionar productos y licencias"),
    Catalog("Gestionar catálogo"),
    Notifications("Gestionar notificaciones"),
    Security("Administrar cargos y seguridad"),
}

internal fun changePermission(
    current: Set<Permission>,
    permission: Permission,
    enabled: Boolean,
): Set<Permission> =
    current.toMutableSet().apply {
        if (enabled) {
            add(permission)
            if (permission == Permission.SupportReply) add(Permission.SupportRead)
            if (permission == Permission.CommerceManage) add(Permission.CommerceRead)
        } else {
            remove(permission)
            if (permission == Permission.SupportRead) remove(Permission.SupportReply)
            if (permission == Permission.CommerceRead) remove(Permission.CommerceManage)
        }
    }

internal data class PreviewUser(
    val id: String,
    val name: String,
    val email: String,
    val status: String = "Activo",
    val credits: Int = 0,
    val activeStatus: String = "Activo",
) {
    val initials: String
        get() =
            name
                .split(Regex("[ _.-]+"))
                .filter { it.isNotBlank() }
                .take(2)
                .joinToString("") { it.take(1) }
                .let { if (it.length < 2) name.take(2).uppercase() else it.uppercase() }
}

internal data class PreviewRole(
    val id: String,
    val name: String,
    val description: String,
    val permissions: Set<Permission>,
    val locked: Boolean = false,
)

internal data class PreviewStaff(val id: String, val name: String, val roleId: String)

internal data class PreviewMessage(
    val id: String,
    val text: String,
    val time: String,
    val outgoing: Boolean = false,
    val author: String = "",
    val local: Boolean = false,
)

internal data class PreviewTicket(
    val id: String,
    val userId: String,
    val time: String,
    val unread: Int,
    val closed: Boolean = false,
    val messages: List<PreviewMessage>,
    val agentId: String = "admin1",
) {
    val lastMessage: String
        get() = messages.lastOrNull()?.text.orEmpty()
}

internal data class PreviewNotice(
    val id: String,
    val title: String,
    val text: String,
    val time: String,
    val kind: String,
    val read: Boolean = false,
    val target: String? = null,
)

internal enum class ProductKind {
    Offline,
    Api,
    Credits,
}

internal data class PreviewProduct(
    val id: String,
    val name: String,
    val description: String,
    val cents: Long,
    val kind: ProductKind,
    val available: Boolean = true,
)

internal enum class OrderStatus(val label: String) {
    Completed("Completado"),
    Pending("Pendiente"),
    Refunded("Reembolsado"),
}

internal data class PreviewOrder(
    val id: String,
    val userId: String,
    val productId: String,
    val productName: String,
    val cents: Long,
    val provider: String,
    val status: OrderStatus,
    val ageDays: Int,
)

internal data class PreviewLicense(
    val id: String,
    val userId: String,
    val code: String,
    val used: Int = 0,
    val devices: Int = 3,
    val expiryDays: Int = 0,
    val revoked: Boolean = false,
)

internal data class PreviewGift(
    val id: String,
    val code: String,
    val productId: String,
    val maxUses: Int,
    val expiryDays: Int,
    val devices: Int,
    val used: Int = 0,
    val revoked: Boolean = false,
)

internal data class PreviewApiClient(
    val id: String,
    val name: String,
    val ip: String,
    val key: String,
    val requests: Int = 0,
    val revoked: Boolean = false,
)

internal data class PreviewCredit(
    val id: String,
    val userId: String,
    val amount: Int,
    val reason: String,
    val time: String,
)

internal data class PreviewCatalogApp(
    val id: String,
    val name: String,
    val description: String,
    val enabled: Boolean,
)

internal data class PreviewLog(
    val id: String,
    val level: String,
    val text: String,
    val time: String,
)

internal data class LocalizedNotice(
    val title: String,
    val message: String,
    val confirm: String = "Actualizar",
    val cancel: String = "Cancelar",
    val acknowledge: String = "OK",
)

internal data class PreviewBroadcast(
    val id: String,
    val audience: String,
    val type: String,
    val messages: Map<String, LocalizedNotice>,
    val inApp: Boolean,
)

internal enum class Appearance {
    Amoled,
    Dark,
    Light,
}
