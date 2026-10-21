package com.ghostdeveloper.spdecode

import androidx.compose.ui.test.assertExists
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** The Settings language picker is a real screen, not a modal sheet. */
class LanguageSelectionScreenInstrumentedTest {
    @get:Rule val compose=createComposeRule()

    @Test fun fullScreenLanguagePickerChangesSelectionAndSupportsBack() {
        var selected:String?=null
        var backed=false
        compose.setContent {
            SpDecodeAmoledTheme {
                LanguageSelectionScreen(
                    selectedLanguage="en",
                    onBack={backed=true},
                    onSelect={selected=it},
                )
            }
        }
        compose.onNodeWithTag("settings_language_screen").assertExists()
        compose.onNodeWithTag("language_option_es").performClick()
        compose.runOnIdle { assertEquals("es",selected) }
        compose.onNodeWithTag("settings_language_back").performClick()
        compose.runOnIdle { assertTrue(backed) }
    }

    @Test fun selectedLanguageIsPartOfSupportedRegistry() {
        val tags=SupportedLanguages.options.map { it.tag }
        assertEquals(15,tags.size)
        assertEquals(tags.size,tags.toSet().size)
        assertTrue(tags.containsAll(listOf("system","es","en","tr","vi","hi","ja","it")))
    }
}
