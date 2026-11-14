package com.ghostdeveloper.spdecode.admin

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ReceiptLong
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.core.content.edit
import androidx.lifecycle.ViewModelProvider

internal val Mint: Color
    @Composable get() = MaterialTheme.colorScheme.primary
internal val Panel: Color
    @Composable get() = MaterialTheme.colorScheme.surface
internal val GreenPanel: Color
    @Composable get() = MaterialTheme.colorScheme.secondaryContainer
internal val Muted: Color
    @Composable get() = MaterialTheme.colorScheme.onSurfaceVariant
internal val Ink: Color
    @Composable get() = MaterialTheme.colorScheme.onSurface
internal val Border: Color
    @Composable get() = MaterialTheme.colorScheme.outlineVariant
internal val Amber: Color
    @Composable
    get() =
        if (MaterialTheme.colorScheme.background == Color(0xFFF3F6F4)) Color(0xFF956300)
        else Color(0xFFF4C76A)
internal val Red: Color
    @Composable get() = MaterialTheme.colorScheme.error
internal val Blue: Color
    @Composable
    get() =
        if (MaterialTheme.colorScheme.background == Color(0xFFF3F6F4)) Color(0xFF2468A8)
        else Color(0xFF60A5FA)
internal val Purple: Color
    @Composable
    get() =
        if (MaterialTheme.colorScheme.background == Color(0xFFF3F6F4)) Color(0xFF7552A5)
        else Color(0xFFC4A0FF)

@Composable
internal fun AdminTheme(appearance: Appearance, content: @Composable () -> Unit) {
    val colors =
        if (appearance == Appearance.Light)
            lightColorScheme(
                primary = Color(0xFF007956),
                onPrimary = Color.White,
                background = Color(0xFFF3F6F4),
                onBackground = Color(0xFF12201A),
                surface = Color.White,
                onSurface = Color(0xFF12201A),
                onSurfaceVariant = Color(0xFF586860),
                secondaryContainer = Color(0xFFD9F2E6),
                onSecondaryContainer = Color(0xFF007956),
                outline = Color(0xFF87998F),
                outlineVariant = Color(0xFFD5DFD9),
                error = Color(0xFFB33838),
            )
        else
            darkColorScheme(
                primary = Color(0xFF34D9A4),
                onPrimary = Color(0xFF003322),
                background =
                    if (appearance == Appearance.Amoled) Color.Black else Color(0xFF0C1310),
                onBackground = Color(0xFFF7F7F7),
                surface = Color(0xFF111516),
                onSurface = Color(0xFFF7F7F7),
                onSurfaceVariant = Color(0xFFA5ADAA),
                secondaryContainer = Color(0xFF102E24),
                onSecondaryContainer = Color(0xFF34D9A4),
                outline = Color(0xFF66766C),
                outlineVariant = Color(0xFF232C27),
                error = Color(0xFFF87171),
            )
    MaterialTheme(colorScheme = colors, content = content)
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.BLACK),
        )
        val state = ViewModelProvider(this)[PreviewState::class.java]
        val preferences = getSharedPreferences("admin-display", MODE_PRIVATE)
        if (!state.preferencesLoaded) {
            state.appearance =
                runCatching { Appearance.valueOf(preferences.getString("appearance", "Amoled")!!) }
                    .getOrDefault(Appearance.Amoled)
            state.notificationsEnabled = preferences.getBoolean("notifications", true)
            state.preferencesLoaded = true
        }
        state.persistPreferences = {
            preferences.edit {
                putString("appearance", state.appearance.name)
                putBoolean("notifications", state.notificationsEnabled)
            }
        }
        setContent {
            LaunchedEffect(state.appearance) {
                val light = state.appearance == Appearance.Light
                enableEdgeToEdge(
                    statusBarStyle =
                        if (light)
                            SystemBarStyle.light(
                                android.graphics.Color.TRANSPARENT,
                                android.graphics.Color.TRANSPARENT,
                            )
                        else SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
                    navigationBarStyle =
                        if (light)
                            SystemBarStyle.light(
                                android.graphics.Color.WHITE,
                                android.graphics.Color.WHITE,
                            )
                        else SystemBarStyle.dark(android.graphics.Color.BLACK),
                )
            }
            AdminTheme(state.appearance) { AdminApplication(state) }
        }
    }
}

internal enum class Page(val title: String, val icon: ImageVector) {
    Dashboard("Resumen general", Icons.Outlined.Dashboard),
    Users("Usuarios", Icons.Outlined.People),
    Roles("Roles y permisos", Icons.Outlined.AdminPanelSettings),
    Support("Soporte", Icons.Outlined.Forum),
    Finance("Finanzas", Icons.Outlined.AccountBalanceWallet),
    Purchases("Transacciones", Icons.AutoMirrored.Outlined.ReceiptLong),
    Products("Productos", Icons.Outlined.ShoppingBag),
    Licenses("Licencias Offline", Icons.Outlined.VpnKey),
    Gifts("Gift codes", Icons.Outlined.CardGiftcard),
    Api("API comercial", Icons.Outlined.Code),
    Credits("Créditos", Icons.Outlined.Payments),
    Catalog("Catálogo VPN", Icons.Outlined.Storage),
    Server("Estado del servidor", Icons.Outlined.Dns),
    Notices("Notificaciones", Icons.Outlined.Notifications),
    Broadcast("Enviar notificación", Icons.Outlined.Campaign),
    Logs("Actividad del sistema", Icons.Outlined.History),
    Security("Centro de seguridad", Icons.Outlined.Security),
    Maintenance("Mantenimiento", Icons.Outlined.Build),
    Sessions("Mis sesiones", Icons.Outlined.Devices),
    Settings("Ajustes", Icons.Outlined.Settings),
    UserDetail("Detalles de usuario", Icons.Outlined.Person),
    UserEdit("Editar perfil", Icons.Outlined.Edit),
    UserPurchases("Compras del usuario", Icons.Outlined.ShoppingBag),
    UserSessions("Dispositivos y sesiones", Icons.Outlined.Devices),
    UserLicenses("Licencias y productos", Icons.Outlined.VpnKey),
    UserActivity("Actividad del usuario", Icons.Outlined.History),
    RoleDetail("Administración de personal", Icons.Outlined.AdminPanelSettings),
    Chat("Chat de soporte", Icons.Outlined.Forum),
    OrderDetail("Detalle de transacción", Icons.AutoMirrored.Outlined.ReceiptLong),
    LicenseDetail("Detalle de licencia", Icons.Outlined.VpnKey),
    ApiDetail("Acceso API", Icons.Outlined.Code),
    GiftHistory("Historial de gift codes", Icons.Outlined.CardGiftcard),
    CreditHistory("Movimientos de créditos", Icons.Outlined.Payments),
}
