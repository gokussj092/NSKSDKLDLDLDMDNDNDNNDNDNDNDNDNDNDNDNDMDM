package com.ghostdeveloper.spdecode

import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Controls requested in actual Android-user feedback, not decorative mocks. */
@RunWith(AndroidJUnit4::class)
class SettingsEnhancementsInstrumentedTest {
    @get:Rule val ui=createAndroidComposeRule<MainActivity>()

    @Test fun settingsNavigatesToStandaloneAboutWithVersionAndOfficialLinks(){
        val ctx=ui.activity
        ui.waitUntil(10000) {
            ui.onAllNodesWithContentDescription(ctx.getString(R.string.settings))
                .fetchSemanticsNodes().isNotEmpty()
        }
        if(ui.onAllNodesWithText(ctx.getString(R.string.whats_new_continue)).fetchSemanticsNodes().isNotEmpty())
            ui.onNodeWithText(ctx.getString(R.string.whats_new_continue)).performClick()
        ui.onNodeWithContentDescription(ctx.getString(R.string.settings)).performClick()
        // This is now a dedicated full-screen destination, not the old
        // ModalBottomSheet. LazyColumn does not compose all 15 rows at once.
        ui.onNodeWithTag("settings_language_screen").assertDoesNotExist()
        ui.onNodeWithText(ctx.getString(R.string.language_title)).performClick()
        ui.onNodeWithTag("settings_language_screen").assertExists()
        ui.onNodeWithTag("language_option_system").assertExists()
        ui.onNodeWithTag("language_option_es").assertExists()
        ui.onNodeWithTag("settings_language_list")
            .performScrollToNode(hasTestTag("language_option_it"))
        ui.onNodeWithTag("language_option_it").assertExists()
        // Return to Settings before testing privacy and developer links.
        ui.onNodeWithTag("settings_language_back").performClick()
        ui.onNodeWithTag("settings_language_screen").assertDoesNotExist()
        ui.onNodeWithText(ctx.getString(R.string.mask_passwords_title)).assertExists()
        // Phase 6 moves all version and community data into a dedicated destination.
        ui.onNodeWithTag("settings_about_entry").performScrollTo().performClick()
        ui.onNodeWithTag("about_screen").assertExists()
        ui.onNodeWithText(ctx.getString(R.string.contact_developer)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.telegram_group)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.telegram_channel)).assertExists()
        ui.onNodeWithText(
            ctx.getString(R.string.about_screen_version_badge,
                BuildConfig.VERSION_NAME,BuildConfig.VERSION_CODE)
        ).assertExists()
        ui.onNodeWithTag("about_back").performClick()
        ui.onNodeWithTag("about_screen").assertDoesNotExist()
        ui.onNodeWithText(ctx.getString(R.string.guide_replay)).assertExists()
    }
}
