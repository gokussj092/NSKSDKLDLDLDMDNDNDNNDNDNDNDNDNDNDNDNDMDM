package com.ghostdeveloper.spdecode

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Cloud-only visual regressions; no APK picker, purchase or network request. */
@RunWith(AndroidJUnit4::class)
class ApkFeedbackUxInstrumentedTest {
    @get:Rule val compose=createComposeRule()
    private val context get()=InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun feedbackDetailsRemainHiddenUntilAUserChoosesCategory() {
        compose.setContent {
            SpDecodeAmoledTheme {
                FeedbackScreen(onBack={},onSend={ "00000000-0000-0000-0000-000000000000" })
            }
        }
        compose.onNodeWithTag("feedback_screen").assertExists()
        compose.onNodeWithTag("feedback_type_card").assertExists()
        compose.onNodeWithTag("feedback_details").assertDoesNotExist()
        compose.onNodeWithTag("feedback_app_link").assertDoesNotExist()
        compose.onNodeWithTag("feedback_submit").assertIsNotEnabled()

        compose.onNodeWithTag("feedback_category_method").performClick()
        compose.onNodeWithTag("feedback_details").assertExists()
        compose.onNodeWithTag("feedback_app_link").assertExists()
        compose.onNodeWithTag("feedback_extra").assertExists()

        compose.onNodeWithTag("feedback_category_bug").performClick()
        compose.onNodeWithTag("feedback_app_link").assertDoesNotExist()
        compose.onNodeWithTag("feedback_issue_decode").assertExists()

        compose.onNodeWithTag("feedback_category_suggestion").performClick()
        compose.onNodeWithTag("feedback_details").assertExists()
        compose.onNodeWithTag("feedback_issue_decode").assertDoesNotExist()
        compose.onNodeWithTag("feedback_submit").assertIsNotEnabled()
    }

    @Test fun apkIsCompactAndCannotImportFiles() {
        compose.setContent { SpDecodeAmoledTheme { ApkAnalysisComingSoonScreen() } }
        compose.onNodeWithTag("apk_analysis_placeholder").assertExists()
        compose.onNodeWithTag("apk_analysis_import_disabled").assertIsNotEnabled()
        compose.onNodeWithText(context.getString(R.string.apk_analysis_coming_soon)).assertExists()
        compose.onNodeWithTag("apk_analysis_pricing").assertDoesNotExist()
    }

    @Test fun creditsHaveNoEnabledPurchasesOrActualPrice() {
        compose.setContent { SpDecodeAmoledTheme { ApkCreditsComingSoonScreen() } }
        compose.onNodeWithTag("apk_credits_screen").assertExists()
        compose.onNodeWithTag("apk_credits_buy").assertExists()
        compose.onNodeWithTag("apk_buy_one_disabled").assertIsNotEnabled()
        compose.onNodeWithTag("apk_buy_bundle_disabled").assertIsNotEnabled()
        compose.onNodeWithTag("apk_credits_prices").assertExists()
        compose.onNodeWithText(context.getString(R.string.apk_analysis_credit_cost)).assertDoesNotExist()
        compose.onNodeWithText(context.getString(R.string.apk_analysis_credit_price)).assertDoesNotExist()
    }
}
