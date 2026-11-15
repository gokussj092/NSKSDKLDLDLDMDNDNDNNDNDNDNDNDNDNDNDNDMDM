package com.ghostdeveloper.spdecode.admin

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AdminFlowTest {
  @get:Rule val compose = createAndroidComposeRule<MainActivity>()

  @Test
  fun authenticatedNativeFlowDisplaysServerUserAndLogsOut() {
    AdminHttpsFixture.install()
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    try {
      compose.waitUntil(10000) {
        compose.onAllNodesWithTag("login-username").fetchSemanticsNodes().isNotEmpty()
      }
      compose.onNodeWithTag("login-username").performTextInput("fixture.owner")
      compose.onNodeWithTag("login-password").performTextInput("fixture-only-password")
      compose.onNodeWithTag("login-submit").performScrollTo().performClick()
      compose.waitUntil(10000) {
        compose.onAllNodesWithTag("nav-Users").fetchSemanticsNodes().isNotEmpty()
      }
      compose.onNodeWithTag("nav-Users").performClick()
      compose.waitUntil(10000) {
        compose.onAllNodesWithText("Usuario recibido por HTTPS").fetchSemanticsNodes().isNotEmpty()
      }
      compose.onNodeWithText("Usuario recibido por HTTPS").assertIsDisplayed()
      compose.onNodeWithText("@fixture.user").assertExists()
      compose.onNodeWithText("Usuario recibido por HTTPS").performClick()
      compose.waitUntil(10000) {
        compose.onAllNodesWithText("Correo verificado").fetchSemanticsNodes().isNotEmpty()
      }
      compose.onNodeWithText("Correo verificado").assertExists()
      compose.runOnUiThread { compose.activity.onBackPressedDispatcher.onBackPressed() }
      compose.waitUntil(10000) {
        compose.onAllNodesWithTag("nav-Users").fetchSemanticsNodes().isNotEmpty()
      }
      compose.onNodeWithTag("nav-Support").performClick()
      compose.waitUntil(10000) {
        compose.onAllNodesWithText("Ticket de integración").fetchSemanticsNodes().isNotEmpty()
      }
      compose.onNodeWithText("Ticket de integración").performClick()
      compose.waitUntil(10000) {
        compose.onAllNodesWithTag("chat-draft").fetchSemanticsNodes().isNotEmpty()
      }
      compose.onNodeWithTag("chat-draft").performTextInput("Respuesta de integración")
      compose.onNodeWithTag("chat-draft").assertTextContains("Respuesta de integración")
      compose.onNodeWithTag("chat-send").performClick()
      compose.waitUntil(10000) {
        compose.onAllNodesWithText("Respuesta de integración", substring = false).fetchSemanticsNodes().isNotEmpty()
      }
      compose.onNodeWithText("Respuesta de integración").assertExists()
      compose.runOnUiThread { compose.activity.onBackPressedDispatcher.onBackPressed() }
      compose.waitUntil(10000) {
        compose.onAllNodesWithTag("nav-Settings").fetchSemanticsNodes().isNotEmpty()
      }
      assertTrue(AdminHttpsFixture.paths.contains("/api/admin/support"))
      assertTrue(AdminHttpsFixture.paths.contains("/api/admin/login"))
      assertTrue(AdminHttpsFixture.paths.contains("/api/admin/users"))
      compose.onNodeWithTag("nav-Settings").performClick()
      compose.onNodeWithText("Idioma").performClick()
      compose.onNodeWithTag("language-en").performClick()
      compose.onNodeWithText("Current language").assertExists()
      assertEquals("en", context.getSharedPreferences("admin-display", 0).getString("language", null))
      compose.onNodeWithTag("language-es").performClick()
      compose.onNodeWithText("Idioma actual").assertExists()
      compose.runOnUiThread { compose.activity.onBackPressedDispatcher.onBackPressed() }
      compose.waitUntil(10000) {
        compose.onAllNodesWithText("Cerrar sesión").fetchSemanticsNodes().isNotEmpty()
      }
      compose.onNodeWithText("Cerrar sesión").performClick()
      compose.waitUntil(10000) {
        compose.onAllNodesWithTag("login-username").fetchSemanticsNodes().isNotEmpty()
      }
      assertTrue(AdminHttpsFixture.paths.contains("/api/admin/logout"))
      assertNull(SessionVault(context).restore())
    } finally {
      SessionVault(context).clear()
      context.getSharedPreferences("admin-display", 0).edit().remove("language").apply()
    }
  }

  @Test
  fun credentialsAreEditableAndLoginRequiresInput() {
    compose.waitUntil(10000) {
      compose.onAllNodesWithTag("login-username").fetchSemanticsNodes().isNotEmpty()
    }
    compose.onNodeWithTag("login-submit").assertIsNotEnabled()
    compose.onNodeWithTag("login-username").performTextInput("owner.test")
    compose.onNodeWithTag("login-password").performTextInput("password-for-ui-only")
    compose.onNodeWithTag("login-submit").assertIsEnabled()
    compose.onAllNodesWithText("Abrir vista previa").assertCountEquals(0)
  }

  @Test
  fun nativeTransportRejectsArbitraryRoutesAndCookieInjectionBeforeNetwork() {
    fun call(op: String, cookie: String = "") =
        NativeAdminRoutes.exchangeNative(
            op.toByteArray(), "".toByteArray(), 0, byteArrayOf(), cookie.toByteArray())
    assertEquals("0", call("https://example.invalid")[0].toString(Charsets.UTF_8))
    assertEquals("401", call("session")[0].toString(Charsets.UTF_8))
    assertEquals(
        "0", call("session", "spdecode_admin_session=x\r\nInjected:x")[0].toString(Charsets.UTF_8))
    assertTrue(NativeAdminRoutes.plan("mobile", "orders").path.contains("section=orders"))
  }

  @Test
  fun sessionVaultPersistsCiphertextAndClearsIt() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    val vault = SessionVault(context)
    vault.save("session-fixture-not-a-real-token")
    assertEquals("session-fixture-not-a-real-token", vault.restore())
    assertFalse(
        context
            .getSharedPreferences("admin-session", 0)
            .getString("session", "")!!
            .contains("session-fixture"))
    vault.clear()
    assertNull(vault.restore())
  }
}
