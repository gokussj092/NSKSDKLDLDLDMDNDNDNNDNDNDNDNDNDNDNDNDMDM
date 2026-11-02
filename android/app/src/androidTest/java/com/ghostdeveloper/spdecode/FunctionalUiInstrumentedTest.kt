package com.ghostdeveloper.spdecode

import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.hasSetTextAction
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** The first real UI must launch, match its accepted layout elements and
 * maintain explicit prototype state; no synthetic sample counts as decoded. */
class FunctionalUiInstrumentedTest {
    @get:Rule val ui=createAndroidComposeRule<MainActivity>()

    private fun awaitStartup() {
        val ctx=ui.activity
        ui.waitUntil(10000) {
            ui.onAllNodesWithContentDescription(ctx.getString(R.string.home))
                .fetchSemanticsNodes().isNotEmpty()
        }
        if(ui.onAllNodesWithText(ctx.getString(R.string.whats_new_continue)).fetchSemanticsNodes().isNotEmpty())
            ui.onNodeWithText(ctx.getString(R.string.whats_new_continue)).performClick()
    }

    @Test fun mainScreenContainsScreenshotLayoutAndFourTabs(){
        awaitStartup()
        val ctx=ui.activity
        ui.onNodeWithText("SP-DECODE").assertExists()
        // The last tab is intentionally persistent; navigate explicitly.
        ui.onNodeWithContentDescription(ctx.getString(R.string.home)).performClick()
        ui.onNodeWithText(ctx.getString(R.string.home_import_action)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.text_decode_title)).assertExists()
        // No permanent large text editor on the default home screen.
        ui.onNodeWithText(ctx.getString(R.string.text_decode_hint)).assertDoesNotExist()
        ui.onNodeWithText(ctx.getString(R.string.illustrative)).assertExists()
        ui.onNodeWithContentDescription(ctx.getString(R.string.home)).assertExists()
        ui.onNodeWithContentDescription(ctx.getString(R.string.history)).assertExists()
        ui.onNodeWithContentDescription(ctx.getString(R.string.apk_analysis_title)).assertExists()
        ui.onNodeWithContentDescription(ctx.getString(R.string.settings)).assertExists()
    }

    @Test fun textEditorExpandsAndCollapsesWithoutRemovingResultArea(){
        awaitStartup()
        val ctx=ui.activity
        ui.onNodeWithContentDescription(ctx.getString(R.string.home)).performClick()
        ui.onNodeWithText(ctx.getString(R.string.text_decode_title)).performClick()
        ui.onNodeWithText(ctx.getString(R.string.text_decode_hint)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.result)).assertExists()
        ui.onAllNodesWithText(ctx.getString(R.string.text_decode_title))[0].performClick()
        ui.onNodeWithText(ctx.getString(R.string.text_decode_hint)).assertDoesNotExist()
        ui.onNodeWithText(ctx.getString(R.string.result)).assertExists()
    }

    @Test fun formatsAvailableFromSettingsAndCanGoBack(){
        awaitStartup()
        val ctx=ui.activity
        ui.onNodeWithContentDescription(ctx.getString(R.string.settings)).performClick()
        ui.onNodeWithTag("settings_formats_entry").performClick()
        ui.onNode(hasSetTextAction()).performTextInput("sksrv.png")
        ui.onNodeWithText(".sksrv.png").assertExists()
        ui.onNodeWithText("SKS Server").assertExists()
        ui.onNodeWithText(ctx.getString(R.string.catalog_note)).assertExists()
        ui.onNodeWithTag("settings_formats_back").performClick()
        ui.onNodeWithTag("settings_formats_entry").assertExists()
    }

    @Test fun formerFormatsTabShowsOnlyApkComingSoon(){
        awaitStartup()
        val ctx=ui.activity
        ui.onNodeWithContentDescription(ctx.getString(R.string.apk_analysis_title)).performClick()
        ui.onNodeWithTag("apk_analysis_placeholder").assertExists()
        ui.onNodeWithText(ctx.getString(R.string.apk_analysis_coming_soon)).assertExists()
        ui.onNode(hasSetTextAction()).assertDoesNotExist()
    }

    @Test fun settingsTabClarifiesLocalEncryptedPersistentHistory(){
        awaitStartup()
        val ctx=ui.activity
        ui.onNodeWithContentDescription(ctx.getString(R.string.settings)).performClick()
        ui.onNodeWithText(ctx.getString(R.string.privacy_text)).assertExists()
    }

    @Test fun redactionNeverMutatesOriginalDecoderOutput(){
        val raw="│[۞] Server: example.org\n│[۞] Password: dummy-private\n│[۞] Port: 443"
        val masked=RedactionPolicy.mask(raw)
        assertFalse(masked.contains("dummy-private"))
        assertTrue(masked.contains("Server: example.org"))
        assertTrue(masked.contains("Port: 443"))
        assertEquals(raw,"│[۞] Server: example.org\n│[۞] Password: dummy-private\n│[۞] Port: 443")
    }
}
