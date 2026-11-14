package com.ghostdeveloper.spdecode.admin

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Sort
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
internal fun UsersScreen(state: PreviewState, open: (String) -> Unit) {
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf("Todos") }
    var alphabetic by rememberSaveable { mutableStateOf(false) }
    val rows =
        state.users
            .filter {
                (filter == "Todos" ||
                    filter == "Activos" && it.status != "Suspendido" ||
                    filter == "Suspendidos" && it.status == "Suspendido") &&
                    (it.name.contains(query.trim(), true) || it.email.contains(query.trim(), true))
            }
            .let { if (alphabetic) it.sortedBy { u -> u.name.lowercase() } else it }
    ScreenList {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Metric(
                    "Registrados",
                    state.users.size.toString(),
                    Icons.Outlined.People,
                    modifier = Modifier.weight(1f),
                )
                Metric(
                    "Cuentas activas",
                    state.users.count { it.status != "Suspendido" }.toString(),
                    Icons.Outlined.PersonOutline,
                    modifier = Modifier.weight(1f),
                )
            }
        }
        item {
            SearchField(query, { query = it }, "Buscar usuario...") {
                IconButton(onClick = { alphabetic = !alphabetic }) {
                    Icon(
                        Icons.AutoMirrored.Outlined.Sort,
                        if (alphabetic) "Mostrar orden original" else "Ordenar por nombre",
                        tint = if (alphabetic) Mint else Muted,
                    )
                }
            }
        }
        item { FilterRow(listOf("Todos", "Activos", "Suspendidos"), filter) { filter = it } }
        if (rows.isEmpty())
            item { EmptyState("Sin resultados", "Prueba otro nombre, correo o filtro.") }
        items(rows, key = { it.id }) { user ->
            Column {
                Row(
                    Modifier.fillMaxWidth().clickable { open(user.id) }.padding(vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(13.dp),
                ) {
                    UserAvatar(user)
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(user.name, color = Ink, fontWeight = FontWeight.SemiBold)
                        Small(user.email)
                        Small(user.status, color = statusColor(user.status))
                    }
                    Icon(Icons.Outlined.ChevronRight, null, tint = Muted)
                }
                HorizontalDivider(color = Border)
            }
        }
        item { Small("Mostrando ${rows.size} de ${state.users.size} usuarios de prueba") }
    }
}

@Composable
internal fun UserDetailScreen(
    state: PreviewState,
    id: String,
    go: (Page) -> Unit,
    feedback: (String) -> Unit,
) {
    val user = state.user(id)
    var confirm by rememberSaveable { mutableStateOf(false) }
    ScreenList {
        item {
            Column(
                Modifier.fillMaxWidth().padding(vertical = 12.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                UserAvatar(user, 84)
                Text(user.name, color = Ink, fontWeight = FontWeight.Bold, fontSize = 27.sp)
                Text(user.email, color = Muted)
                Small(
                    if (user.status == "Suspendido") "● Cuenta suspendida"
                    else "● Cuenta activa${if (user.status == "Premium") " · Premium" else ""}",
                    color = statusColor(user.status),
                )
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Metric(
                    "Compras",
                    state.orders
                        .count { it.userId == id && it.status == OrderStatus.Completed }
                        .toString(),
                    Icons.Outlined.ShoppingBag,
                    modifier = Modifier.weight(1f),
                )
                Metric(
                    "Créditos",
                    user.credits.toString(),
                    Icons.Outlined.Payments,
                    modifier = Modifier.weight(1f),
                )
            }
        }
        items(
            listOf(
                "Editar perfil" to Page.UserEdit,
                "Historial de compras" to Page.UserPurchases,
                "Dispositivos y sesiones" to Page.UserSessions,
                "Licencias y productos" to Page.UserLicenses,
                "Historial de actividad" to Page.UserActivity,
            )
        ) { (label, page) ->
            ActionRow(label, page.icon) { go(page) }
        }
        item {
            SecondaryAction(
                if (user.status == "Suspendido") "Reactivar cuenta" else "Suspender cuenta",
                user.status != "Suspendido",
            ) {
                confirm = true
            }
        }
    }
    if (confirm)
        ConfirmationDialog(
            if (user.status == "Suspendido") "Reactivar cuenta" else "Suspender cuenta",
            "Se cambiará el estado de ${user.name} solamente en esta demostración.",
            "Confirmar",
            user.status != "Suspendido",
            { confirm = false },
        ) {
            state.toggleSuspension(id)
            confirm = false
            feedback("Estado de prueba actualizado")
        }
}

@Composable
internal fun UserForm(
    state: PreviewState,
    id: String? = null,
    dismiss: () -> Unit,
    saved: (String) -> Unit,
) {
    val user = id?.let { state.user(it) }
    var name by rememberSaveable(id) { mutableStateOf(user?.name.orEmpty()) }
    var email by rememberSaveable(id) { mutableStateOf(user?.email.orEmpty()) }
    val error = state.userError(name, email, id)
    FormDialog(
        if (id == null) "Crear usuario de prueba" else "Editar perfil",
        error == null,
        onDismiss = dismiss,
        onConfirm = { saved(state.saveUser(name, email, id)) },
    ) {
        Small("Cambios de demostración · sin acceso al servidor", color = Amber)
        EditorField("Nombre de usuario", name, { name = it }, max = 32)
        EditorField("Correo electrónico", email, { email = it }, KeyboardType.Email)
        if (error != null && (name.isNotBlank() || email.isNotBlank())) Small(error, color = Amber)
    }
}

@Composable
internal fun UserEditorScreen(
    state: PreviewState,
    id: String,
    back: () -> Unit,
    feedback: (String) -> Unit,
) {
    val user = state.user(id)
    var name by rememberSaveable(id) { mutableStateOf(user.name) }
    var email by rememberSaveable(id) { mutableStateOf(user.email) }
    val error = state.userError(name, email, id)
    ScreenList {
        item {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                UserAvatar(user, 56)
                Column {
                    Text(user.name, color = Ink, fontWeight = FontWeight.SemiBold)
                    Small("Perfil de usuario · demostración")
                }
            }
        }
        item { EditorField("Nombre de usuario", name, { name = it }, max = 32) }
        item { EditorField("Correo electrónico", email, { email = it }, KeyboardType.Email) }
        if (error != null) item { Small(error, color = Amber) }
        item {
            PrimaryAction(
                "Guardar cambios",
                error == null && (name.trim() != user.name || email.trim() != user.email),
            ) {
                state.saveUser(name, email, id)
                back()
                feedback("Perfil actualizado en la demostración")
            }
        }
        item { TextButton(onClick = back, modifier = Modifier.fillMaxWidth()) { Text("Cancelar") } }
    }
}

@Composable
internal fun UserRecords(
    state: PreviewState,
    page: Page,
    id: String,
    openOrder: (String) -> Unit,
    openLicense: (String) -> Unit,
) {
    val user = state.user(id)
    ScreenList {
        item {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                UserAvatar(user)
                Column {
                    Text(user.name, color = Ink, fontWeight = FontWeight.SemiBold)
                    Small("Registros de prueba de esta cuenta", color = Amber)
                }
            }
        }
        when (page) {
            Page.UserPurchases -> {
                val rows = state.orders.filter { it.userId == id }
                if (rows.isEmpty())
                    item {
                        EmptyState(
                            "Sin compras",
                            "Esta cuenta no tiene pedidos de prueba.",
                            Icons.Outlined.ShoppingBag,
                        )
                    }
                items(rows, key = { it.id }) { OrderCard(state, it) { openOrder(it.id) } }
            }
            Page.UserLicenses -> {
                val rows = state.licenses.filter { it.userId == id }
                if (rows.isEmpty())
                    item {
                        EmptyState(
                            "Sin licencias",
                            "Esta cuenta no tiene licencias de prueba.",
                            Icons.Outlined.VpnKey,
                        )
                    }
                items(rows, key = { it.id }) { LicenseCard(state, it) { openLicense(it.id) } }
            }
            Page.UserSessions -> {
                item {
                    Tile(Modifier.fillMaxWidth()) {
                        Icon(Icons.Outlined.PhoneAndroid, null, tint = Mint)
                        Text("Android · dispositivo de ejemplo", color = Ink)
                        Small(user.name)
                        Small("Última actividad: hoy", color = Mint)
                    }
                }
                item { Small("La revocación real requiere la integración con el servidor.") }
            }
            Page.UserActivity -> {
                val rows = state.logs.filter { it.text.contains(user.name, true) }
                if (rows.isEmpty())
                    item {
                        EmptyState(
                            "Sin actividad local",
                            "Los cambios de prueba de esta cuenta aparecerán aquí.",
                            Icons.Outlined.History,
                        )
                    }
                items(rows, key = { it.id }) { LogCard(it) }
            }
            else -> Unit
        }
    }
}

@Composable
private fun roleTint(id: String): Color =
    when (id) {
        "owner" -> Amber
        "support" -> Blue
        "finance" -> Purple
        else -> Mint
    }

private fun roleIcon(id: String) =
    when (id) {
        "owner" -> Icons.Outlined.WorkspacePremium
        "support" -> Icons.Outlined.HeadsetMic
        "finance" -> Icons.Outlined.AccountBalanceWallet
        else -> Icons.Outlined.VerifiedUser
    }

@Composable
internal fun RolesScreen(state: PreviewState, open: (String) -> Unit, create: () -> Unit) {
    ScreenList {
        item {
            Small(
                "Cargos y personal de demostración. Estos permisos no conceden acceso al servidor."
            )
        }
        items(state.roles, key = { it.id }) { role ->
            Tile(Modifier.fillMaxWidth().clickable { open(role.id) }) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Icon(roleIcon(role.id), null, Modifier.size(21.dp), roleTint(role.id))
                    Text(
                        role.name,
                        Modifier.weight(1f),
                        color = Ink,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Icon(Icons.Outlined.ChevronRight, null, tint = Muted)
                }
                Small(role.description)
                val count = state.staff.count { it.roleId == role.id }
                Small(
                    "$count ${if (count == 1) "miembro" else "miembros"}",
                    color = roleTint(role.id),
                )
            }
        }
        item { SecondaryAction("+ Crear nuevo cargo", onClick = create) }
    }
}

@Composable
internal fun RoleForm(
    state: PreviewState,
    roleId: String? = null,
    dismiss: () -> Unit,
    saved: (String) -> Unit,
) {
    val role = roleId?.let { state.role(it) }
    var name by rememberSaveable { mutableStateOf(role?.name.orEmpty()) }
    var description by rememberSaveable { mutableStateOf(role?.description.orEmpty()) }
    val duplicate = state.roles.any { it.id != roleId && it.name.equals(name.trim(), true) }
    FormDialog(
        if (role == null) "Crear nuevo cargo" else "Editar cargo",
        name.trim().length >= 3 && description.isNotBlank() && !duplicate,
        onDismiss = dismiss,
        onConfirm = { saved(state.saveRole(name, description, roleId)) },
    ) {
        EditorField("Nombre del cargo", name, { name = it }, max = 40)
        EditorField("Descripción", description, { description = it }, max = 120)
        if (duplicate) Small("Ya existe un cargo con ese nombre.", color = Red)
    }
}

@Composable
internal fun RoleDetailScreen(state: PreviewState, id: String, feedback: (String) -> Unit) {
    val role = state.role(id)
    var permissions by remember(id) { mutableStateOf(role.permissions) }
    var edit by rememberSaveable { mutableStateOf(false) }
    var add by rememberSaveable { mutableStateOf(false) }
    var member by remember { mutableStateOf<PreviewStaff?>(null) }
    ScreenList {
        item {
            Tile(Modifier.fillMaxWidth()) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Avatar(roleIcon(id), roleTint(id), 52)
                    Column(Modifier.weight(1f)) {
                        Text(
                            role.name,
                            color = Ink,
                            fontSize = 21.sp,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Small(role.description)
                    }
                    if (!role.locked)
                        IconButton(onClick = { edit = true }) {
                            Icon(Icons.Outlined.Edit, "Editar cargo", tint = Mint)
                        }
                }
            }
        }
        item { Text("Personal", color = Ink, fontWeight = FontWeight.SemiBold) }
        items(state.staff.filter { it.roleId == id }, key = { it.id }) { staff ->
            Row(
                Modifier.fillMaxWidth()
                    .clickable(enabled = !role.locked) { member = staff }
                    .padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Avatar(Icons.Outlined.PersonOutline, roleTint(id))
                Column(Modifier.weight(1f)) {
                    Text(staff.name, color = Ink)
                    Small(role.name)
                }
                if (!role.locked) Icon(Icons.Outlined.Edit, null, Modifier.size(18.dp), Muted)
            }
        }
        if (!role.locked) item { SecondaryAction("Añadir miembro de prueba") { add = true } }
        item {
            Text("Permisos", color = Ink, fontWeight = FontWeight.SemiBold)
            Small(
                if (role.locked) "El propietario conserva el acceso global de la demostración."
                else "Cambios de demostración",
                color = Amber,
            )
        }
        items(Permission.entries) { permission ->
            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(permission.label, Modifier.weight(1f), color = Ink, fontSize = 14.sp)
                Switch(
                    permission in permissions,
                    { permissions = changePermission(permissions, permission, it) },
                    enabled = !role.locked,
                )
            }
        }
        if (!role.locked)
            item {
                PrimaryAction("Guardar permisos", permissions != role.permissions) {
                    state.savePermissions(id, permissions)
                    feedback("Permisos guardados en la demostración")
                }
            }
    }
    if (edit) RoleForm(state, id, { edit = false }) { edit = false }
    if (add || member != null) {
        var name by remember(member?.id) { mutableStateOf(member?.name.orEmpty()) }
        val duplicate = state.staff.any { it.id != member?.id && it.name.equals(name.trim(), true) }
        FormDialog(
            if (member == null) "Añadir miembro" else "Cambiar nombre",
            name.trim().length >= 3 && !duplicate,
            onDismiss = {
                add = false
                member = null
            },
            onConfirm = {
                state.saveStaff(name, id, member?.id)
                add = false
                member = null
                feedback("Personal de prueba actualizado")
            },
        ) {
            Small(
                "Perfil visual de prueba. Las credenciales reales requieren la integración administrativa.",
                color = Amber,
            )
            EditorField("Nombre visible", name, { name = it }, max = 50)
            if (duplicate) Small("Ese nombre ya está en uso.", color = Red)
        }
    }
}
