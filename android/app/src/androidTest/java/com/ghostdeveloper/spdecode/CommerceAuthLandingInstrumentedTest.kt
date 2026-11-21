package com.ghostdeveloper.spdecode

import android.util.Patterns
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CommerceAuthLandingInstrumentedTest {
    @get:Rule val ui = createComposeRule()

    private var email by mutableStateOf("")
    private var password by mutableStateOf("")
    private var passwordStep by mutableStateOf(false)
    private var accepted by mutableStateOf(false)
    private var attemptedSignIns = 0
    private var googleRequests = 0

    private fun label(id: Int) =
        InstrumentationRegistry.getInstrumentation().targetContext.getString(id)

    private fun showLogin() {
        ui.setContent {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                CommerceAuthLanding(
                    language = "en",
                    accepted = accepted,
                    busy = false,
                    error = null,
                    email = email,
                    onEmailChange = { email = it },
                    validEmail = Patterns.EMAIL_ADDRESS.matcher(email.trim()).matches(),
                    passwordStep = passwordStep,
                    password = password,
                    onPasswordChange = { password = it },
                    onEmailNext = { passwordStep = true },
                    onEditEmail = { passwordStep = false; password = "" },
                    onEmailSignIn = { attemptedSignIns++ },
                    onQuickSignIn = null,
                    onAccepted = { accepted = it },
                    onLegalLink = {},
                    onGoogle = { googleRequests++ },
                    onClearError = {},
                )
            }
        }
    }

    @Test fun validEmailAdvancesWithoutSigningInAndPasswordCanBeRevealed() {
        showLogin()
        val next = ui.onNodeWithText(label(R.string.account_auth_next))
        next.assertIsNotEnabled()
        ui.onNodeWithText("Password").assertDoesNotExist()
        ui.onNode(hasSetTextAction()).performClick().performTextInput("tester@example.com")
        next.assertIsEnabled().performScrollTo().performClick()
        ui.runOnIdle { assertEquals(0, attemptedSignIns) }
        ui.onNodeWithText("tester@example.com").assertExists()
        ui.onNode(hasSetTextAction()).performTextInput("a fictional password")
        ui.onNodeWithContentDescription(label(R.string.account_auth_show_password)).performClick()
        ui.onNodeWithContentDescription(label(R.string.account_auth_hide_password)).assertExists()
        ui.onNode(hasText("Sign in") and hasClickAction()).performScrollTo().performClick()
        ui.runOnIdle { assertEquals(1, attemptedSignIns) }
        ui.onNodeWithText(label(R.string.account_auth_edit_email)).performScrollTo().performClick()
        ui.onNodeWithText("Password").assertDoesNotExist()
        ui.runOnIdle {
            assertEquals("tester@example.com", email)
            assertEquals("", password)
        }
    }

    @Test fun googleUsesLegalConsentAndRegistrationHasNoEmailForm() {
        showLogin()
        val google = ui.onNodeWithText("Google")
        google.performScrollTo().performClick()
        ui.onNodeWithText(label(R.string.account_auth_consent_required)).assertExists()
        ui.runOnIdle { assertEquals(0, googleRequests) }
        ui.onNode(isToggleable()).performScrollTo().performClick()
        google.performScrollTo().performClick()
        ui.runOnIdle { assertEquals(1, googleRequests) }
        ui.onNode(hasText("Create account") and hasClickAction()).performScrollTo().performClick()
        ui.onNode(hasSetTextAction()).assertDoesNotExist()
        ui.onNodeWithText("Create account with Google").assertExists()
    }
}
