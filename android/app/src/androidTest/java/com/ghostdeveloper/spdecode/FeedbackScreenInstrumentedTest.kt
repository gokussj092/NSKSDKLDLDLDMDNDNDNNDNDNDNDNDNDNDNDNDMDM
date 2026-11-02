package com.ghostdeveloper.spdecode

import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FeedbackScreenInstrumentedTest {
    @get:Rule val ui=createComposeRule()

    @Test fun bugsAcceptCheckboxWithoutMandatoryFreeText() {
        ui.setContent { FeedbackScreen(onBack={},onSend={ "77cdd781-e98d-4276-bf0d-e4980d2e1719" }) }
        ui.onNodeWithTag("feedback_submit").assertIsNotEnabled()
        ui.onNodeWithTag("feedback_category_bug").performClick()
        ui.onNodeWithTag("feedback_submit").assertIsNotEnabled()
        ui.onNodeWithTag("feedback_issue_decode_failed").performClick()
        ui.onNodeWithTag("feedback_submit").assertIsEnabled()
        ui.onNodeWithTag("feedback_issue_catalog_download").performClick()
        ui.onNodeWithTag("feedback_submit").assertIsEnabled()
    }

    @Test fun newMethodRequiresLinkAndDescription() {
        ui.setContent { FeedbackScreen(onBack={},onSend={ "77cdd781-e98d-4276-bf0d-e4980d2e1719" }) }
        ui.onNodeWithTag("feedback_app_link").assertExists()
        ui.onNodeWithTag("feedback_submit").assertIsNotEnabled()
        ui.onNodeWithTag("feedback_app_link").performTextInput(
            "https://sample.en.uptodown.com/android")
        ui.onNodeWithTag("feedback_submit").assertIsNotEnabled()
        ui.onNodeWithTag("feedback_description").performTextInput(
            "Add support for this APK file format.")
        ui.onNodeWithTag("feedback_submit").assertIsEnabled()
    }

    @Test fun suggestionHidesAppLinkAndRequiresDescription() {
        ui.setContent { FeedbackScreen(onBack={},onSend={ "77cdd781-e98d-4276-bf0d-e4980d2e1719" }) }
        ui.onNodeWithTag("feedback_category_suggestion").performClick()
        ui.onNodeWithTag("feedback_app_link").assertDoesNotExist()
        ui.onNodeWithTag("feedback_submit").assertIsNotEnabled()
        ui.onNodeWithTag("feedback_description").performTextInput(
            "Improve the list of formats in settings.")
        ui.onNodeWithTag("feedback_submit").assertIsEnabled()
    }
}
