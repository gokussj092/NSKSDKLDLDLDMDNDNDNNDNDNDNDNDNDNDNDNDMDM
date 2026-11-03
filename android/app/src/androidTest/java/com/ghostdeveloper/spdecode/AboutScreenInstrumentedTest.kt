package com.ghostdeveloper.spdecode

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Phase 6 verifies real callbacks, official invite and Android-sourced version. */
@RunWith(AndroidJUnit4::class)
class AboutScreenInstrumentedTest {
    @get:Rule val ui=createComposeRule()

    @Test fun versionLanguageCountAndBackCallback(){
        var wentBack=false
        ui.setContent {
            AboutScreen(onBack={wentBack=true},onExternalLink={},onLegalLink={},
                cloudEnabled=false)
        }
        ui.onNodeWithTag("about_screen").assertExists()
        ui.onNodeWithText("14").assertExists()
        ui.onNodeWithText("SP-DECODE").assertExists()
        ui.onNodeWithTag("about_back").performClick()
        assertEquals(true,wentBack)
        ui.onNodeWithTag("about_privacy").assertDoesNotExist()
    }

    @Test fun officialCommunityUsesCorrectInviteInsteadOfLegacyGroup(){
        var actual=""
        ui.setContent {
            AboutScreen(onBack={},onExternalLink={actual=it},onLegalLink={},
                cloudEnabled=true)
        }
        ui.onNodeWithTag("about_community").performScrollTo().performClick()
        assertEquals("https://t.me/+Ntu6EJMirrAwMzgx",actual)
    }

    @Test fun legalRowsUseExistingLegalFlow(){
        var actual=""
        ui.setContent {
            AboutScreen(onBack={},onExternalLink={},onLegalLink={actual=it},
                cloudEnabled=true)
        }
        ui.onNodeWithTag("about_privacy").performScrollTo().performClick()
        assertEquals("privacy",actual)
        ui.onNodeWithTag("about_terms").performScrollTo().performClick()
        assertEquals("terms",actual)
    }
}
