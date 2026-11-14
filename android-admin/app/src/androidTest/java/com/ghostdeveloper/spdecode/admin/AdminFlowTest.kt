package com.ghostdeveloper.spdecode.admin

import android.content.pm.ActivityInfo
import android.content.res.Configuration
import android.graphics.Bitmap
import android.os.ParcelFileDescriptor
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AdminFlowTest {
    @get:Rule val ui = createAndroidComposeRule<MainActivity>()

    private fun enter() {
        ui.onNodeWithText("Abrir vista previa").performScrollTo().performClick()
    }

    private fun menu(page: String) {
        ui.onNodeWithContentDescription("Abrir menú").performClick()
        ui.onNodeWithTag("drawer-list").performScrollToNode(hasTestTag("menu-$page"))
        ui.onNodeWithTag("menu-$page").performClick()
    }

    private fun button(text: String) = ui.onNode(hasText(text) and hasClickAction())

    private fun scrollText(text: String, substring: Boolean = false): SemanticsNodeInteraction {
        ui.onNodeWithTag("screen-list").performScrollToNode(hasText(text, substring = substring))
        return ui.onNodeWithText(text, substring = substring)
    }

    private fun scrollButton(text: String): SemanticsNodeInteraction {
        ui.onNodeWithTag("screen-list").performScrollToNode(hasText(text) and hasClickAction())
        return button(text)
    }

    private fun capture(name: String) {
        ui.waitForIdle()
        val folder =
            File(
                    InstrumentationRegistry.getInstrumentation()
                        .targetContext
                        .getExternalFilesDir(null),
                    "review",
                )
                .apply { mkdirs() }
        val bitmap =
            InstrumentationRegistry.getInstrumentation().uiAutomation.takeScreenshot()
                ?: ui.onRoot().captureToImage().asAndroidBitmap()
        try {
            File(folder, "$name.png").outputStream().use {
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)
            }
        } finally {
            bitmap.recycle()
        }
    }

    @Test
    fun nativeAndroidBridgeLoadsAndEncodesUnicodeQueries() {
        assertEquals(
            "/api/admin/users?page=2&q=a%26%C3%B1",
            NativeAdminRoutes.plan("users", "a&ñ", 2).path,
        )
    }

    @Test
    fun editUserKeepsSelectedAccountAndOtherAccounts() {
        enter()
        ui.onNodeWithTag("nav-Users").performClick()
        scrollText("NexorX").performClick()
        ui.onNodeWithText("nexor@example.com").assertIsDisplayed()
        ui.onNodeWithContentDescription("Editar usuario").performClick()
        ui.onNodeWithText("Nombre de usuario").performTextClearance()
        ui.onNodeWithText("Nombre de usuario").performTextInput("NexorQA")
        scrollButton("Guardar cambios").performClick()
        ui.onNodeWithText("NexorQA").assertIsDisplayed()
        ui.onNodeWithContentDescription("Volver").performClick()
        scrollText("NexorQA").assertIsDisplayed()
        scrollText("Alex_L").assertIsDisplayed()
    }

    @Test
    fun supportUsesLocalRepliesAndClosesTheSelectedTicket() {
        enter()
        ui.onNodeWithTag("nav-Support").performClick()
        ui.onNodeWithText("NexorX").performClick()
        ui.onNodeWithContentDescription("Añadir mensaje local").assertIsNotEnabled()
        ui.onNode(hasSetTextAction()).performTextInput("Prueba local")
        ui.onNodeWithContentDescription("Añadir mensaje local").assertIsDisplayed().performClick()
        ui.onNodeWithText("Prueba local").assertIsDisplayed()
        ui.onNodeWithText("Local").assertIsDisplayed()
        ui.onNodeWithContentDescription("Opciones del ticket").performClick()
        button("Cerrar ticket").performClick()
        button("Reabrir ticket").assertIsDisplayed()
    }

    @Test
    fun createRoleOpensItsOwnMembersAndPermissions() {
        enter()
        menu("Roles")
        ui.onNodeWithContentDescription("Crear cargo").performClick()
        ui.onNodeWithText("Nombre del cargo").performTextInput("Moderación QA")
        ui.onNodeWithText("Descripción").performTextInput("Atención de prueba")
        button("Guardar").performClick()
        ui.onNodeWithText("Moderación QA").assertIsDisplayed()
        button("Añadir miembro de prueba").assertIsDisplayed()
        scrollText("Consultar usuarios").assertIsDisplayed()
    }

    @Test
    fun productEditorChangesTheListAndRetainsTheOriginalOrderPrice() {
        enter()
        menu("Products")
        ui.onAllNodesWithText("Editar producto").onFirst().performClick()
        ui.onNodeWithText("Precio en USD").performTextClearance()
        ui.onNodeWithText("Precio en USD").performTextInput("12.34")
        button("Guardar").performClick()
        ui.onNodeWithText("$12.34").assertIsDisplayed()
        menu("Purchases")
        scrollText("#SPD-2048").performClick()
        scrollText("$4.99").assertIsDisplayed()
    }

    @Test
    fun licenseGenerationAndRevocationUpdateTheSelectedDetail() {
        enter()
        menu("Licenses")
        ui.onNodeWithContentDescription("Generar licencia").performClick()
        button("Generar").performClick()
        scrollText("DEMO-SPD-", true).assertIsDisplayed()
        scrollButton("Revocar licencia").performClick()
        button("Confirmar").performClick()
        scrollText("● Revocada").assertIsDisplayed()
    }

    @Test
    fun apiFormRejectsDomainsThenCreatesASingleAddressClient() {
        enter()
        menu("Api")
        ui.onNodeWithContentDescription("Crear acceso API").performClick()
        ui.onNodeWithText("Cliente").performTextInput("Cliente QA")
        ui.onNodeWithText("IP autorizada").performTextInput("example.com")
        button("Guardar").assertIsNotEnabled()
        ui.onNodeWithText("IP autorizada").performTextClearance()
        ui.onNodeWithText("IP autorizada").performTextInput("198.51.100.80")
        button("Guardar").performClick()
        scrollText("198.51.100.80").assertIsDisplayed()
        scrollText("DEMO-api-", true).assertIsDisplayed()
    }

    @Test
    fun catalogPublicationUpdatesVersionAndNotificationCenter() {
        enter()
        menu("Catalog")
        ui.onAllNodes(isToggleable()).onFirst().performClick()
        scrollButton("Publicar actualización").performClick()
        button("Publicar prueba").performClick()
        scrollText("215686800").assertIsDisplayed()
        menu("Notices")
        scrollText("Versión de prueba 215686800").assertIsDisplayed()
    }

    @Test
    fun broadcastFormKeepsFourteenLocalesAndAddsOnlyASimulatedNotice() {
        enter()
        menu("Notices")
        scrollButton("Enviar notificación").performClick()
        scrollText("14 idiomas · Multiidioma").assertIsDisplayed()
        scrollButton("Vista previa del aviso").performClick()
        ui.onNodeWithText("Nueva actualización disponible").assertIsDisplayed()
        button("Actualizar").performClick()
        scrollButton("Enviar notificación").performClick()
        button("Guardar simulación").performClick()
        ui.onNodeWithContentDescription("Volver").performClick()
        scrollText("Ahora · simulación").assertIsDisplayed()
    }

    @Test
    fun captureAllReferenceSections() {
        capture("01-login")
        enter()
        capture("02-dashboard")
        ui.onNodeWithTag("nav-Users").performClick()
        capture("03-users")
        scrollText("NexorX").performClick()
        capture("04-user-detail")
        ui.onNodeWithContentDescription("Volver").performClick()
        menu("Roles")
        capture("05-roles")
        menu("Support")
        capture("06-support")
        ui.onNodeWithText("NexorX").performClick()
        capture("07-chat")
        ui.onNodeWithContentDescription("Volver").performClick()
        for ((page, name) in
            listOf(
                "Finance" to "08-finance",
                "Purchases" to "09-transactions",
                "Products" to "10-products",
                "Licenses" to "11-licenses",
                "Gifts" to "12-gifts",
                "Api" to "13-api",
                "Credits" to "14-credits",
                "Server" to "15-server",
                "Catalog" to "16-catalog",
                "Notices" to "17-notifications",
                "Logs" to "19-activity",
                "Security" to "20-security",
                "Maintenance" to "21-maintenance",
                "Settings" to "22-settings",
            )) {
            menu(page)
            capture(name)
        }
        menu("Notices")
        scrollButton("Enviar notificación").performClick()
        capture("18-broadcast")
    }

    private fun shell(command: String) {
        val fd =
            InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command)
        ParcelFileDescriptor.AutoCloseInputStream(fd).use { it.readBytes() }
    }

    @Test
    fun compactScreenKeepsTheComposerVisibleWithLargeTextAndKeyboard() {
        enter()
        try {
            shell("wm size 640x1136")
            shell("wm density 320")
            shell("settings put system font_scale 1.3")
            shell("settings put secure show_ime_with_hard_keyboard 1")
            ui.waitUntil(15000) {
                runCatching {
                        ui.activity.resources.configuration.screenWidthDp <= 330 &&
                            ui.activity.resources.configuration.fontScale > 1.2f
                    }
                    .getOrDefault(false)
            }
            ui.onNodeWithTag("nav-Support").performClick()
            scrollText("NexorX").performClick()
            ui.onNode(hasSetTextAction())
                .performClick()
                .performTextInput("Prueba local en pantalla compacta")
            ui.waitUntil(15000) {
                ViewCompat.getRootWindowInsets(ui.activity.window.decorView)
                    ?.isVisible(WindowInsetsCompat.Type.ime()) == true
            }
            ui.onNodeWithContentDescription("Añadir mensaje local")
                .assertIsDisplayed()
                .performClick()
            ui.onNodeWithText("Prueba local en pantalla compacta").assertIsDisplayed()
            capture("23-compact-keyboard-130pct")
        } finally {
            shell("input keyevent 4")
            shell("settings put system font_scale 1.0")
            shell("wm density reset")
            shell("wm size reset")
        }
    }

    @Test
    fun landscapeAndLightThemeRemainScrollable() {
        enter()
        try {
            ui.runOnUiThread {
                ui.activity.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
            }
            ui.waitUntil(15000) {
                runCatching {
                        ui.activity.resources.configuration.orientation ==
                            Configuration.ORIENTATION_LANDSCAPE
                    }
                    .getOrDefault(false)
            }
            menu("Products")
            scrollText("Análisis APK").assertIsDisplayed()
            capture("24-landscape-products")
            menu("Settings")
            scrollText("Claro").performClick()
            capture("25-light-theme")
            scrollText("AMOLED").performClick()
        } finally {
            ui.runOnUiThread {
                ui.activity.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED
            }
        }
    }
}
