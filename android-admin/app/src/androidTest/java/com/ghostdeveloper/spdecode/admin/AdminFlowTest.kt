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
